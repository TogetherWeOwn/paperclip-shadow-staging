//! End-to-end play path against a synthetic NNTP server (std-only):
//! grant → pool → fetch → yEnc → decrypt → Range stream → R2 writeback.
//!
//! Acceptance probes: a warm pool performs no per-play reconnect, even across
//! two *uncached* tracks (the server counts connections); the miss path
//! streams segment by segment; `Range` yields `206` on hits and misses; a
//! gone article fails one play without quarantining the pool, while a
//! provider outage does quarantine and recovers; TTFB is measured on both
//! paths (targets documented in `workers/stream/README.md`).

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::{Duration, Instant};

use nntune_stream::cache::ContentCache;
use nntune_stream::grant;
use nntune_stream::meter::{MemoryMeter, MeterKind};
use nntune_stream::play::{play, PlayError, PlayInput, PlayStream, StreamPool};
use nntune_stream::pool::Pool;
use nntune_stream::yenc::{self, PartSpec};

const SECRET: &[u8] = b"stream-integration-secret";
const NOW_UNIX: u64 = 1_700_000_000;
const EXP_UNIX: u64 = 9_999_999_999;
const CIPHER_KEY: u8 = 0x5A;

type Fixture = (Vec<u8>, Vec<String>, HashMap<String, Vec<u8>>);

/// Deterministic pseudo-audio covering every byte value (exercises yEnc
/// escapes), posted the way Usenet does it: one yEnc *multipart* article per
/// `seg_len` bytes (`=ybegin part= total=`, `=ypart`, `pcrc32=`; the
/// whole-file `crc32=` only on the last part).
fn fixture_track(tag: &str, len: usize, seg_len: usize) -> Fixture {
    let mut plain = Vec::with_capacity(len);
    for i in 0..len {
        plain.push(((i * 7919 + tag.len()) % 256) as u8);
    }
    let ciphered: Vec<u8> = plain.iter().map(|b| b ^ CIPHER_KEY).collect();
    let file_crc = yenc::crc32(&ciphered);
    let total = ciphered.len().div_ceil(seg_len) as u32;
    let mut articles = HashMap::new();
    let mut segments = Vec::new();
    for (i, chunk) in ciphered.chunks(seg_len).enumerate() {
        let part = i as u32 + 1;
        let mid = format!("<{tag}-seg{i}@synthetic.test>");
        let text = yenc::encode_part(
            chunk,
            &format!("{tag}.flac"),
            PartSpec {
                file_size: len as u64,
                part,
                total,
                offset: (i * seg_len) as u64,
                file_crc: (part == total).then_some(file_crc),
            },
        );
        articles.insert(mid.clone(), text);
        segments.push(mid);
    }
    (plain, segments, articles)
}

fn merge(mut a: HashMap<String, Vec<u8>>, b: HashMap<String, Vec<u8>>) -> HashMap<String, Vec<u8>> {
    a.extend(b);
    a
}

/// Minimal NNTP server: greeting + `BODY <mid>` with dot-stuffing.
struct FakeNntp {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    connects: Arc<AtomicUsize>,
    bodies: Arc<AtomicUsize>,
    handle: Option<thread::JoinHandle<()>>,
}

impl FakeNntp {
    fn start(articles: HashMap<String, Vec<u8>>) -> Self {
        Self::start_closing_after(articles, usize::MAX)
    }

    /// Like `start`, but the server hangs up after `close_after` BODY
    /// commands on a connection (a provider reaping idle/busy sessions).
    fn start_closing_after(articles: HashMap<String, Vec<u8>>, close_after: usize) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake NNTP");
        let addr = listener.local_addr().expect("local addr");
        listener.set_nonblocking(true).expect("nonblocking");
        let stop = Arc::new(AtomicBool::new(false));
        let connects = Arc::new(AtomicUsize::new(0));
        let bodies = Arc::new(AtomicUsize::new(0));
        let (stop_c, connects_c, bodies_c) = (
            Arc::clone(&stop),
            Arc::clone(&connects),
            Arc::clone(&bodies),
        );
        let handle = thread::spawn(move || {
            while !stop_c.load(Ordering::SeqCst) {
                let (stream, _) = match listener.accept() {
                    Ok(pair) => pair,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                        continue;
                    }
                    Err(_) => break,
                };
                connects_c.fetch_add(1, Ordering::SeqCst);
                Self::serve(stream, &articles, close_after, &bodies_c);
            }
        });
        Self {
            addr,
            stop,
            connects,
            bodies,
            handle: Some(handle),
        }
    }

    fn serve(
        stream: TcpStream,
        articles: &HashMap<String, Vec<u8>>,
        close_after: usize,
        bodies: &AtomicUsize,
    ) {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut reader = BufReader::new(stream.try_clone().expect("clone conn"));
        let mut writer = stream;
        let _ = writer.write_all(b"200 synthetic NNTP ready\r\n");
        let mut line = Vec::new();
        let mut served = 0usize;
        loop {
            if served >= close_after {
                break;
            }
            line.clear();
            match reader.read_until(b'\n', &mut line) {
                Ok(0) => break,
                Ok(_) => {}
                Err(_) => break,
            }
            while line.last() == Some(&b'\n') || line.last() == Some(&b'\r') {
                line.pop();
            }
            let cmd = String::from_utf8_lossy(&line).into_owned();
            if let Some(mid) = cmd
                .strip_prefix("BODY ")
                .map(|s| s.trim().trim_matches(|c| c == '<' || c == '>'))
            {
                served += 1;
                bodies.fetch_add(1, Ordering::SeqCst);
                let full_mid = format!("<{mid}>");
                match articles.get(&full_mid) {
                    Some(article) => {
                        let _ =
                            writer.write_all(format!("222 0 {full_mid} follows\r\n").as_bytes());
                        for raw_line in article.split(|&b| b == b'\n') {
                            // Normalize to CRLF; strip a pre-existing CR first.
                            let text_line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
                            // Dot-stuff per RFC 3977 §3.1.
                            if text_line.first() == Some(&b'.') {
                                let _ = writer.write_all(b".");
                            }
                            let _ = writer.write_all(text_line);
                            let _ = writer.write_all(b"\r\n");
                        }
                        let _ = writer.write_all(b".\r\n");
                    }
                    None => {
                        let _ = writer.write_all(b"430 no such article\r\n");
                    }
                }
            } else if cmd == "QUIT" {
                let _ = writer.write_all(b"205 bye\r\n");
                break;
            } else {
                let _ = writer.write_all(b"500 unknown command\r\n");
            }
        }
    }

    fn connects(&self) -> usize {
        self.connects.load(Ordering::SeqCst)
    }

    /// BODY commands received so far.
    fn bodies(&self) -> usize {
        self.bodies.load(Ordering::SeqCst)
    }
}

impl Drop for FakeNntp {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake the accept loop promptly.
        let _ = TcpStream::connect(self.addr);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn drain_to_vec(mut stream: PlayStream) -> (Vec<u8>, PlayStream) {
    let mut body = Vec::new();
    for chunk in stream.by_ref() {
        body.extend_from_slice(&chunk);
    }
    (body, stream)
}

#[allow(clippy::too_many_arguments)]
fn input<'a>(
    token: &'a str,
    track_id: &'a str,
    range: Option<&'a str>,
    server: &FakeNntp,
    segments: &'a [String],
    up_next: Option<&'a str>,
) -> PlayInput<'a> {
    PlayInput {
        token,
        track_id,
        range,
        server_addr: server.addr,
        segments,
        cipher_key: CIPHER_KEY,
        now_unix: NOW_UNIX,
        up_next,
    }
}

fn grant_for(track: &str) -> String {
    grant::issue("user-1", track, EXP_UNIX, SECRET)
}

#[test]
fn warm_pool_serves_two_uncached_tracks_on_one_connection() {
    let (plain_a, segs_a, arts_a) = fixture_track("a", 40_000, 20_000);
    let (plain_b, segs_b, arts_b) = fixture_track("b", 30_000, 10_000);
    let server = FakeNntp::start(merge(arts_a, arts_b));
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    for (track, segs, plain) in [
        ("track-a", &segs_a, &plain_a),
        ("track-b", &segs_b, &plain_b),
    ] {
        let token = grant_for(track);
        let inp = input(&token, track, None, &server, segs, None);
        let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("miss play");
        assert!(!resp.cache_hit && resp.stream.is_writeback());
        let (body, stream) = drain_to_vec(resp.stream);
        assert_eq!(&body, plain, "{track}: miss path must reproduce plaintext");
        stream
            .finalize(&mut pool, &mut cache, &mut meter)
            .expect("finalize");
    }
    assert_eq!(
        server.connects(),
        1,
        "two uncached plays share one NNTP connection"
    );
    assert_eq!((pool.connects(), pool.reuses()), (1, 1));
    assert_eq!((pool.idle(), pool.in_use()), (1, 0));
}

#[test]
fn miss_streams_segment_by_segment_and_hit_needs_no_dial() {
    let (plain, segments, articles) = fixture_track("a", 60_000, 20_000);
    let server = FakeNntp::start(articles);
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    let token = grant_for("track-a");
    let inp = input(&token, "track-a", None, &server, &segments, Some("track-b"));
    let t0 = Instant::now();
    let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("miss play");
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body_len as usize, plain.len());
    let mut stream = resp.stream;
    let first = stream.next().expect("first chunk");
    let ttfb_miss = t0.elapsed();
    assert_eq!(
        server.bodies(),
        1,
        "first byte arrives after ONE of three segments, not the whole track"
    );
    let mut body = first;
    for chunk in stream.by_ref() {
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body, plain);
    assert_eq!(server.bodies(), 3);
    stream
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("finalize");
    println!("miss-path TTFB (dial + first segment + decode): {ttfb_miss:?}");

    // Hit: served from cache, nothing dialed.
    let token2 = grant_for("track-a");
    let inp2 = input(&token2, "track-a", None, &server, &segments, None);
    let t0 = Instant::now();
    let resp2 = play(&mut pool, &mut cache, &mut meter, SECRET, &inp2).expect("hit play");
    assert!(resp2.cache_hit && !resp2.stream.is_writeback());
    let mut stream2 = resp2.stream;
    let first2 = stream2.next().expect("first cached chunk");
    let ttfb_hit = t0.elapsed();
    let mut body2 = first2;
    for chunk in stream2.by_ref() {
        body2.extend_from_slice(&chunk);
    }
    assert_eq!(body2, plain);
    stream2
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("hit finalize");
    assert_eq!((server.connects(), server.bodies()), (1, 3));
    println!("hit-path TTFB (authorize+cache to first byte): {ttfb_hit:?}");
    assert!(
        ttfb_hit < Duration::from_millis(100),
        "local hit TTFB budget: {ttfb_hit:?}"
    );

    for kind in [
        MeterKind::PlayStart,
        MeterKind::CacheMiss,
        MeterKind::CacheHit,
        MeterKind::BytesServed,
        MeterKind::PrefetchEnqueued,
    ] {
        assert!(meter.has_kind(kind), "missing {kind:?}");
    }
    let served: u64 = meter
        .events
        .iter()
        .filter(|e| e.kind == MeterKind::BytesServed)
        .map(|e| e.bytes)
        .sum();
    assert_eq!(served as usize, 2 * plain.len());
}

#[test]
fn prefetch_is_not_enqueued_when_it_would_take_the_last_connection() {
    let (_, segments, articles) = fixture_track("a", 20_000, 10_000);
    let server = FakeNntp::start(articles);
    let mut pool: StreamPool = Pool::new(1);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();
    let token = grant_for("track-a");
    let inp = input(&token, "track-a", None, &server, &segments, Some("track-b"));
    let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("play");
    let (_, stream) = drain_to_vec(resp.stream);
    stream
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("finalize");
    assert!(!meter.has_kind(MeterKind::PrefetchEnqueued));
}

#[test]
fn range_on_a_hit_returns_206_and_unsatisfiable_is_416() {
    let (plain, segments, articles) = fixture_track("a", 40_000, 20_000);
    let server = FakeNntp::start(articles);
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    let token = grant_for("track-a");
    let inp = input(&token, "track-a", None, &server, &segments, None);
    let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("seed play");
    let (body, stream) = drain_to_vec(resp.stream);
    assert_eq!(body, plain);
    stream
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("finalize");

    let token2 = grant_for("track-a");
    let inp2 = input(
        &token2,
        "track-a",
        Some("bytes=0-99"),
        &server,
        &segments,
        None,
    );
    let resp2 = play(&mut pool, &mut cache, &mut meter, SECRET, &inp2).expect("range play");
    assert_eq!(resp2.status, 206);
    assert_eq!(
        resp2.content_range.as_deref(),
        Some(format!("bytes 0-99/{}", plain.len()).as_str())
    );
    let (slice, _) = drain_to_vec(resp2.stream);
    assert_eq!(slice, &plain[..100]);

    let token3 = grant_for("track-a");
    let inp3 = input(
        &token3,
        "track-a",
        Some("bytes=99999999-"),
        &server,
        &segments,
        None,
    );
    assert!(matches!(
        play(&mut pool, &mut cache, &mut meter, SECRET, &inp3),
        Err(PlayError::RangeUnsatisfiable)
    ));
}

#[test]
fn seek_on_a_cold_cache_fetches_the_prefix_before_the_first_byte() {
    // Known limitation (see README TTFB notes): without NZB segment sizes
    // the play path cannot know which article covers a mid-track offset, so
    // it walks segments in order. A seek's TTFB costs the whole prefix.
    let (plain, segments, articles) = fixture_track("a", 60_000, 20_000);
    let server = FakeNntp::start(articles);
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    let token = grant_for("track-a");
    let inp = input(
        &token,
        "track-a",
        Some("bytes=45000-45099"),
        &server,
        &segments,
        None,
    );
    let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("seek miss");
    assert_eq!(resp.status, 206);
    let mut stream = resp.stream;
    let first = stream.next().expect("first chunk");
    assert_eq!(
        server.bodies(),
        3,
        "seek to segment 2 walks segments 0-2 first"
    );
    let mut body = first;
    for chunk in stream.by_ref() {
        body.extend_from_slice(&chunk);
    }
    assert_eq!(body, &plain[45_000..45_100]);
    stream
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("finalize");
}

#[test]
fn range_on_a_miss_serves_the_slice_and_still_caches_the_whole_track() {
    let (plain, segments, articles) = fixture_track("a", 60_000, 20_000);
    let (plain_b, segs_b, arts_b) = fixture_track("b", 30_000, 10_000);
    let server = FakeNntp::start(merge(articles, arts_b));
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    // Seek into the middle segment on a cold cache.
    let token = grant_for("track-a");
    let inp = input(
        &token,
        "track-a",
        Some("bytes=25000-25099"),
        &server,
        &segments,
        None,
    );
    let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("range miss");
    assert_eq!(resp.status, 206);
    assert_eq!(
        resp.content_range.as_deref(),
        Some(format!("bytes 25000-25099/{}", plain.len()).as_str())
    );
    let (slice, stream) = drain_to_vec(resp.stream);
    assert_eq!(slice, &plain[25_000..25_100]);
    assert!(
        cache.get_track("track-a").is_none(),
        "not cached before finalize"
    );
    stream
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("finalize drains the rest");
    assert_eq!(
        cache.get_track("track-a").as_deref(),
        Some(plain.as_slice()),
        "the whole track is cached even though the client wanted 100 bytes"
    );

    // Suffix range on a cold cache resolves against the declared file size.
    let token_b = grant_for("track-b");
    let inp_b = input(
        &token_b,
        "track-b",
        Some("bytes=-50"),
        &server,
        &segs_b,
        None,
    );
    let resp_b = play(&mut pool, &mut cache, &mut meter, SECRET, &inp_b).expect("suffix miss");
    assert_eq!(resp_b.status, 206);
    let (tail, stream_b) = drain_to_vec(resp_b.stream);
    assert_eq!(tail, &plain_b[plain_b.len() - 50..]);
    stream_b.abort(&mut pool);
    assert!(cache.get_track("track-b").is_none(), "abort must not cache");
    assert_eq!(pool.in_use(), 0, "abort returns the lease");
}

#[test]
fn a_segment_id_with_crlf_never_reaches_the_provider() {
    let (_, _, articles) = fixture_track("ok", 20_000, 10_000);
    let server = FakeNntp::start(articles);
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    // NZB-supplied id smuggling a second NNTP command.
    let evil = "x>\r\nBODY <injected@article>".to_string();
    let segs = [evil];
    let token = grant_for("track-evil");
    let inp = input(&token, "track-evil", None, &server, &segs, None);
    assert!(matches!(
        play(&mut pool, &mut cache, &mut meter, SECRET, &inp),
        Err(PlayError::InvalidSegment(_))
    ));
    assert_eq!(server.bodies(), 0, "nothing may be sent for a bad id");
    assert_eq!(server.connects(), 0, "no dial for a bad id");
    assert!(!pool.quarantined(), "bad metadata is not an outage");
    assert_eq!(pool.in_use(), 0);
}

#[test]
fn dropping_a_stream_frees_its_slot_and_still_meters_served_bytes() {
    let (_plain_a, segs_a, arts_a) = fixture_track("a", 40_000, 20_000);
    let (plain_b, segs_b, arts_b) = fixture_track("b", 20_000, 10_000);
    let server = FakeNntp::start(merge(arts_a, arts_b));
    let mut pool: StreamPool = Pool::new(1);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    // Client disconnects mid-track: no finalize, no abort.
    let token = grant_for("track-a");
    let inp = input(&token, "track-a", None, &server, &segs_a, None);
    let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("miss play");
    let mut stream = resp.stream;
    let first = stream.next().expect("first chunk");
    assert!(!first.is_empty());
    let served_a = first.len() as u64;
    drop(stream);
    assert_eq!(pool.in_use(), 0, "a dropped stream must free its slot");
    assert_eq!(
        pool.idle(),
        0,
        "the half-read connection is dropped, never re-parked"
    );

    // The freed slot serves the next play, which also flushes the orphaned
    // metering from the dropped stream.
    let token_b = grant_for("track-b");
    let inp_b = input(&token_b, "track-b", None, &server, &segs_b, None);
    let resp_b =
        play(&mut pool, &mut cache, &mut meter, SECRET, &inp_b).expect("slot freed by drop");
    let (body_b, stream_b) = drain_to_vec(resp_b.stream);
    assert_eq!(body_b, plain_b);
    stream_b
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("finalize");
    let orphaned: u64 = meter
        .events
        .iter()
        .filter(|e| e.kind == MeterKind::BytesServed && e.track_id == "track-a")
        .map(|e| e.bytes)
        .sum();
    assert_eq!(orphaned, served_a, "dropped play must still be metered");
}

#[test]
fn aborted_miss_stream_meters_bytes_already_served() {
    let (_plain_a, segs_a, arts_a) = fixture_track("a", 40_000, 20_000);
    let (plain_b, segs_b, arts_b) = fixture_track("b", 20_000, 10_000);
    let server = FakeNntp::start(merge(arts_a, arts_b));
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    // Client disconnects mid-track via the documented path: no finalize.
    let token = grant_for("track-a");
    let inp = input(&token, "track-a", None, &server, &segs_a, None);
    let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("miss play");
    let mut stream = resp.stream;
    let first = stream.next().expect("first chunk");
    let served_a = first.len() as u64;
    assert!(served_a > 0);
    stream.abort(&mut pool);
    assert_eq!(pool.in_use(), 0, "abort returns the lease");
    assert_eq!(pool.idle(), 1, "healthy connection is kept warm");

    // The next play flushes the orphaned metering from the aborted stream.
    let token_b = grant_for("track-b");
    let inp_b = input(&token_b, "track-b", None, &server, &segs_b, None);
    let resp_b = play(&mut pool, &mut cache, &mut meter, SECRET, &inp_b).expect("next play");
    let (body_b, stream_b) = drain_to_vec(resp_b.stream);
    assert_eq!(body_b, plain_b);
    stream_b
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("finalize");
    let orphaned: u64 = meter
        .events
        .iter()
        .filter(|e| e.kind == MeterKind::BytesServed && e.track_id == "track-a")
        .map(|e| e.bytes)
        .sum();
    assert_eq!(orphaned, served_a, "aborted play must still be metered");
    assert!(cache.get_track("track-a").is_none(), "abort must not cache");
}

#[test]
fn dropped_and_aborted_hit_streams_meter_served_bytes() {
    let (plain, segments, articles) = fixture_track("a", 40_000, 20_000);
    let server = FakeNntp::start(articles);
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    // Seed the cache: a full miss play meters the whole track on finalize.
    let token = grant_for("track-a");
    let inp = input(&token, "track-a", None, &server, &segments, None);
    let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("seed play");
    let (body, stream) = drain_to_vec(resp.stream);
    assert_eq!(body, plain);
    stream
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("finalize");
    let full = plain.len() as u64;

    // Hit stream dropped after one chunk: no lease, no finalize, no abort.
    let token2 = grant_for("track-a");
    let inp2 = input(&token2, "track-a", None, &server, &segments, None);
    let resp2 = play(&mut pool, &mut cache, &mut meter, SECRET, &inp2).expect("hit play");
    assert!(resp2.cache_hit);
    let mut dropped = resp2.stream;
    let c1 = dropped.next().expect("first hit chunk").len() as u64;
    drop(dropped);

    // Hit stream aborted after one chunk.
    let token3 = grant_for("track-a");
    let inp3 = input(&token3, "track-a", None, &server, &segments, None);
    let resp3 = play(&mut pool, &mut cache, &mut meter, SECRET, &inp3).expect("hit play");
    let mut aborted = resp3.stream;
    let c2 = aborted.next().expect("first hit chunk").len() as u64;
    aborted.abort(&mut pool);

    // A final full hit play flushes both orphaned records.
    let token4 = grant_for("track-a");
    let inp4 = input(&token4, "track-a", None, &server, &segments, None);
    let resp4 = play(&mut pool, &mut cache, &mut meter, SECRET, &inp4).expect("hit play");
    let (body4, stream4) = drain_to_vec(resp4.stream);
    assert_eq!(body4, plain);
    stream4
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("finalize");
    let total: u64 = meter
        .events
        .iter()
        .filter(|e| e.kind == MeterKind::BytesServed && e.track_id == "track-a")
        .map(|e| e.bytes)
        .sum();
    assert_eq!(
        total,
        full + c1 + c2 + full,
        "seed + dropped-hit + aborted-hit + final hit must all be metered"
    );
    assert_eq!(pool.in_use(), 0);
}

#[test]
fn a_gone_article_fails_that_play_but_never_quarantines_the_pool() {
    let (_, segs_gone, _) = fixture_track("gone", 20_000, 10_000);
    let (plain_ok, segs_ok, arts_ok) = fixture_track("ok", 20_000, 10_000);
    // "gone" articles are absent from the server: 430.
    let server = FakeNntp::start(arts_ok);
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    for _ in 0..4 {
        let token = grant_for("track-gone");
        let inp = input(&token, "track-gone", None, &server, &segs_gone, None);
        assert!(matches!(
            play(&mut pool, &mut cache, &mut meter, SECRET, &inp),
            Err(PlayError::ArticleMissing(_))
        ));
        assert!(!pool.quarantined(), "430 says nothing about the provider");
    }
    assert!(!meter.has_kind(MeterKind::ProviderError));
    assert_eq!(pool.in_use(), 0);

    let token = grant_for("track-ok");
    let inp = input(&token, "track-ok", None, &server, &segs_ok, None);
    let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("healthy track");
    let (body, stream) = drain_to_vec(resp.stream);
    assert_eq!(body, plain_ok);
    stream
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("finalize");
    assert_eq!(server.connects(), 1, "the same connection served all five");
}

#[test]
fn an_article_that_vanishes_mid_track_fails_the_stream_without_caching() {
    let (_, segments, mut articles) = fixture_track("a", 30_000, 10_000);
    articles.remove(&segments[1]);
    let server = FakeNntp::start(articles);
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    let token = grant_for("track-a");
    let inp = input(&token, "track-a", None, &server, &segments, None);
    let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("first segment ok");
    let (partial, stream) = drain_to_vec(resp.stream);
    assert_eq!(partial.len(), 10_000, "only segment 0 was served");
    assert!(matches!(stream.error(), Some(PlayError::ArticleMissing(_))));
    assert!(matches!(
        stream.finalize(&mut pool, &mut cache, &mut meter),
        Err(PlayError::ArticleMissing(_))
    ));
    assert!(
        cache.get_track("track-a").is_none(),
        "no partial cache entry"
    );
    assert!(!pool.quarantined());
    assert_eq!(
        (pool.in_use(), pool.idle()),
        (0, 1),
        "healthy connection kept"
    );
}

#[test]
fn a_connection_the_provider_closed_is_redialed_transparently() {
    let (plain_a, segs_a, arts_a) = fixture_track("a", 20_000, 10_000);
    let (plain_b, segs_b, arts_b) = fixture_track("b", 20_000, 10_000);
    // The server hangs up after 2 BODYs: exactly one track per connection.
    let server = FakeNntp::start_closing_after(merge(arts_a, arts_b), 2);
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    for (track, segs, plain) in [
        ("track-a", &segs_a, &plain_a),
        ("track-b", &segs_b, &plain_b),
    ] {
        let token = grant_for(track);
        let inp = input(&token, track, None, &server, segs, None);
        let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp).expect("play");
        let (body, stream) = drain_to_vec(resp.stream);
        assert_eq!(&body, plain);
        stream
            .finalize(&mut pool, &mut cache, &mut meter)
            .expect("finalize");
    }
    assert_eq!(server.connects(), 2, "stale warm connection was redialed");
    assert!(
        !pool.quarantined(),
        "a stale pooled connection is not an outage"
    );
}

#[test]
fn provider_outage_quarantines_then_recovers() {
    let (plain, segments, articles) = fixture_track("a", 40_000, 20_000);
    let server = FakeNntp::start(articles);
    let mut pool: StreamPool = Pool::new(4);
    let mut cache = ContentCache::new();
    let mut meter = MemoryMeter::default();

    // Point at a dead port: the dial fails and quarantines the pool.
    let dead: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let token = grant_for("track-a");
    let mut inp = input(&token, "track-a", None, &server, &segments, None);
    inp.server_addr = dead;
    assert!(matches!(
        play(&mut pool, &mut cache, &mut meter, SECRET, &inp),
        Err(PlayError::Upstream(_))
    ));
    assert!(pool.quarantined());
    assert!(meter.has_kind(MeterKind::ProviderError));
    assert_eq!(pool.in_use(), 0);

    // Still quarantined: the next play is rejected without dialing out.
    let token2 = grant_for("track-a");
    let inp2 = input(&token2, "track-a", None, &server, &segments, None);
    assert!(matches!(
        play(&mut pool, &mut cache, &mut meter, SECRET, &inp2),
        Err(PlayError::PoolQuarantined { .. })
    ));
    assert_eq!(server.connects(), 0, "quarantined pool must not dial out");

    // Backoff elapses: the pool recovers and the play succeeds.
    pool.advance(300_000);
    let token3 = grant_for("track-a");
    let inp3 = input(&token3, "track-a", None, &server, &segments, None);
    let resp = play(&mut pool, &mut cache, &mut meter, SECRET, &inp3).expect("recovered play");
    let (body, stream) = drain_to_vec(resp.stream);
    assert_eq!(body, plain);
    stream
        .finalize(&mut pool, &mut cache, &mut meter)
        .expect("finalize");
    assert!(!pool.quarantined(), "success clears the quarantine");
}
