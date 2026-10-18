//! Play path: authorize → cache hit → `200`/`206`; miss → lease a pool
//! connection → fetch segments one at a time → yEnc → decrypt → stream each
//! to the client while staging the R2 multipart write, then prefetch the
//! next track.
//!
//! Decryption here is a demo XOR stream cipher standing in for the
//! ingest-owned content encryption (key delivery via the BYOP vault is a
//! sibling card). The byte flow — fetch, decode, decrypt, fan out to client
//! chunks *and* the multipart upload — is the production shape.
//!
//! Miss-path streaming: [`play`] fetches only the first segment (its yEnc
//! `=ybegin size=` reveals the file size, so `Range`/`206` resolves before a
//! byte is sent); later segments are fetched lazily as the client pulls
//! [`PlayStream`] chunks. A mid-track `Range` still walks every earlier
//! segment first — segment sizes live in NZB metadata this slice does not
//! own yet, so the covering article cannot be addressed directly (see the
//! README TTFB notes). Memory is one decoded segment at a time (plus the
//! staged write, which R2 holds in production). [`PlayStream::finalize`]
//! drains any segments the client's range did not need so the cache still
//! gets the whole track, then completes the upload and hands the healthy
//! connection back to the pool. [`PlayStream::abort`] returns the connection
//! without caching (client went away).
//!
//! Failure handling: only connection-level trouble (I/O, protocol errors)
//! quarantines the pool. A missing article or a bad segment fails that play
//! alone — the connection is fine and goes back to the pool warm.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use crate::cache::{ContentCache, MultipartUpload};
use crate::grant::{self, GrantError};
use crate::meter::{Meter, MeterEvent, MeterKind};
use crate::nntp::{valid_message_id, NntpClient, NntpError};
use crate::pool::{Lane, Lease, OrphanedPlay, Pool, PoolError};
use crate::prefetch::should_prefetch;
use crate::range::{self, RangeOutcome};
use crate::yenc::{self, Decoded, YencError};

/// Client chunk size for served streams.
const CHUNK: usize = 16 * 1024;

/// Why a play failed.
#[derive(Debug, PartialEq, Eq)]
pub enum PlayError {
    Unauthorized(GrantError),
    WrongTrack,
    RangeUnsatisfiable,
    PoolExhausted,
    PoolQuarantined {
        retry_after_ms: u64,
    },
    /// An article is gone (`430`/`423`): this track fails, the pool is fine.
    ArticleMissing(String),
    /// A segment id from NZB metadata failed validation and was never sent
    /// to the provider: this track fails, the pool is fine.
    InvalidSegment(String),
    /// The provider connection failed or misbehaved (quarantines the pool).
    Upstream(String),
    /// A segment could not be decoded (corrupt or mis-placed yEnc part).
    Decode(YencError),
}

/// Everything the play path needs, by reference.
pub struct PlayInput<'a> {
    /// Signed grant from the `api` Worker.
    pub token: &'a str,
    pub track_id: &'a str,
    /// Value of the HTTP `Range` header, if any.
    pub range: Option<&'a str>,
    /// Provider NNTP address (a pooled connection dials this).
    pub server_addr: SocketAddr,
    /// Ordered segment message-IDs composing the track.
    pub segments: &'a [String],
    /// Demo cipher key (see module docs).
    pub cipher_key: u8,
    /// Current time, unix seconds (grant expiry check).
    pub now_unix: u64,
    /// Next track in the queue, for prefetch.
    pub up_next: Option<&'a str>,
}

/// A servable play: status line, headers and a chunk stream.
pub struct PlayResponse {
    /// 200 (full) or 206 (partial).
    pub status: u16,
    /// `Content-Range` value for 206 responses.
    pub content_range: Option<String>,
    /// Bytes this response will serve.
    pub body_len: u64,
    pub cache_hit: bool,
    pub stream: PlayStream,
}

/// A failure plus whether it indicts the provider connection.
type Failure = (PlayError, bool);

/// The pool that [`play`] drives.
pub type StreamPool = Pool<NntpClient>;

/// Chunked body. Pull chunks with [`Iterator::next`], then call
/// [`PlayStream::finalize`] (or [`PlayStream::abort`]) so the lease returns
/// to the pool and, on a miss, the cache write completes. Dropping the
/// stream instead is still safe: the slot is freed, the half-read
/// connection is discarded, and served bytes are metered on the next
/// `play`/`finalize` — but the cache write is lost, so prefer `finalize`.
/// `abort` likewise meters the bytes served so far. Either way the hit path
/// (which holds no lease) is metered exactly like a miss.
pub struct PlayStream {
    user_id: String,
    track_id: String,
    /// Next absolute byte to emit, and the exclusive end of the response.
    pos: u64,
    end: u64,
    served: u64,
    /// `None` once `finalize`/`abort` consumed the stream (or it was dropped).
    source: Option<Source>,
    /// Pool-level orphan queue: `Drop` pushes an [`OrphanedPlay`] here when
    /// a mid-flight stream served bytes, on either the miss or the hit path.
    orphans: Arc<Mutex<Vec<OrphanedPlay>>>,
}

impl Drop for PlayStream {
    fn drop(&mut self) {
        // Only fires mid-flight: finalize/abort took `source` first. The
        // lease guard's Drop frees the slot and the half-read client is
        // discarded with `live` (its buffered position is untrustworthy, so
        // it is never re-parked warm). Served bytes ride the pool-level
        // orphan queue so the pool owner can still meter them — for `Live`
        // and `Cached` alike.
        if self.source.take().is_some() && self.served > 0 {
            if let Ok(mut orphaned) = self.orphans.lock() {
                orphaned.push(OrphanedPlay {
                    user_id: self.user_id.clone(),
                    track_id: self.track_id.clone(),
                    bytes: self.served,
                });
            }
        }
    }
}

enum Source {
    Cached(Arc<[u8]>),
    Live(Box<Live>),
}

/// A miss in flight: the leased connection, the segment cursor and the
/// staged cache write.
struct Live {
    client: NntpClient,
    lease: Lease,
    segments: Vec<String>,
    next_seg: usize,
    cipher_key: u8,
    /// File size declared by the first segment.
    total: u64,
    /// Bytes decoded so far (end offset of `buf`).
    fetched: u64,
    buf: Vec<u8>,
    buf_start: u64,
    upload: MultipartUpload,
    failed: Option<Failure>,
}

/// Serve `track_id` to its granted owner.
pub fn play(
    pool: &mut StreamPool,
    cache: &mut ContentCache,
    meter: &mut dyn Meter,
    secret: &[u8],
    input: &PlayInput<'_>,
) -> Result<PlayResponse, PlayError> {
    let grant =
        grant::verify(input.token, secret, input.now_unix).map_err(PlayError::Unauthorized)?;
    if grant.track_id != input.track_id {
        return Err(PlayError::WrongTrack);
    }
    let user = grant.user_id.clone();
    flush_orphaned(pool, meter);
    meter.emit(ev(MeterKind::PlayStart, &user, input.track_id, 0));

    if let Some(full) = cache.get_track(input.track_id) {
        meter.emit(ev(MeterKind::CacheHit, &user, input.track_id, 0));
        let window = resolve_range(full.len() as u64, input.range)?;
        return Ok(respond(
            window,
            true,
            &user,
            input.track_id,
            Source::Cached(full),
            pool.orphan_sink(),
        ));
    }

    meter.emit(ev(MeterKind::CacheMiss, &user, input.track_id, 0));
    if input.segments.is_empty() {
        return Err(PlayError::Upstream("track has no segments".into()));
    }
    // Fail fast on hostile metadata: no lease, no dial, nothing on the wire.
    // (`NntpClient::article` re-validates as defense in depth.)
    if let Some(bad) = input.segments.iter().find(|s| !valid_segment_id(s)) {
        return Err(PlayError::InvalidSegment(bad.clone()));
    }
    let lease = pool.try_acquire(Lane::Playback).map_err(|e| match e {
        PoolError::Quarantined { retry_after_ms } => PlayError::PoolQuarantined { retry_after_ms },
        PoolError::Exhausted => PlayError::PoolExhausted,
    })?;

    let (client, first) = match open_and_fetch_first(pool, input) {
        Ok(pair) => pair,
        Err((client, failure)) => {
            return Err(settle(
                pool,
                meter,
                lease,
                client,
                failure,
                &user,
                input.track_id,
            ))
        }
    };
    pool.record_success();
    let mut live = Live {
        client,
        lease,
        segments: input.segments.to_vec(),
        next_seg: 0,
        cipher_key: input.cipher_key,
        total: first.file_size,
        fetched: 0,
        buf: Vec::new(),
        buf_start: 0,
        upload: MultipartUpload::begin(input.track_id),
        failed: None,
    };
    if let Err(failure) = live.ingest(first) {
        return Err(live.settle(pool, meter, Some(failure), &user, input.track_id));
    }
    let window = match resolve_range(live.total, input.range) {
        Ok(window) => window,
        Err(e) => {
            // The connection is healthy; hand it back warm.
            pool.release(live.lease, Some(live.client));
            return Err(e);
        }
    };
    if let Some(next) = input.up_next {
        if should_prefetch(pool) {
            meter.emit(ev(MeterKind::PrefetchEnqueued, &user, next, 0));
        }
    }
    Ok(respond(
        window,
        false,
        &user,
        input.track_id,
        Source::Live(Box::new(live)),
        pool.orphan_sink(),
    ))
}

/// Dial or reuse a connection and fetch + decode segment 0. A warm
/// connection the provider silently closed is redialed once.
fn open_and_fetch_first(
    pool: &mut StreamPool,
    input: &PlayInput<'_>,
) -> Result<(NntpClient, Decoded), (Option<NntpClient>, Failure)> {
    let mut warm = pool.take_idle();
    let was_warm = warm.is_some();
    for attempt in 0..2 {
        let mut client = match warm.take() {
            Some(client) => client,
            None => match NntpClient::connect(&input.server_addr) {
                Ok(client) => {
                    pool.record_connect();
                    client
                }
                Err(e) => return Err((None, nntp_failure(e, &input.segments[0]))),
            },
        };
        match fetch_segment(&mut client, &input.segments[0]) {
            Ok(decoded) => return Ok((client, decoded)),
            Err(SegmentError::Nntp(e)) if was_warm && attempt == 0 && e.is_provider_failure() => {
                // Stale pooled connection: drop it and redial once.
                continue;
            }
            Err(SegmentError::Nntp(e)) => {
                let failure = nntp_failure(e, &input.segments[0]);
                let keep = if failure.1 { None } else { Some(client) };
                return Err((keep, failure));
            }
            Err(SegmentError::Decode(e)) => {
                return Err((Some(client), (PlayError::Decode(e), false)));
            }
        }
    }
    unreachable!("second attempt always returns")
}

enum SegmentError {
    Nntp(NntpError),
    Decode(YencError),
}

/// Same stripping as `NntpClient::article`: outer whitespace and `<>`.
fn valid_segment_id(message_id: &str) -> bool {
    valid_message_id(message_id.trim().trim_matches(|c| c == '<' || c == '>'))
}

fn fetch_segment(client: &mut NntpClient, message_id: &str) -> Result<Decoded, SegmentError> {
    let raw = client.article(message_id).map_err(SegmentError::Nntp)?;
    yenc::decode_part(&raw).map_err(SegmentError::Decode)
}

fn nntp_failure(e: NntpError, message_id: &str) -> Failure {
    let provider = e.is_provider_failure();
    let err = match e {
        NntpError::NoSuchArticle(_) => PlayError::ArticleMissing(message_id.to_string()),
        NntpError::InvalidMessageId(id) => PlayError::InvalidSegment(id),
        other => PlayError::Upstream(format!("{other:?}")),
    };
    (err, provider)
}

/// Return the lease (and the connection, if still healthy) and account for
/// the failure: only provider-level trouble quarantines the pool.
fn settle(
    pool: &mut StreamPool,
    meter: &mut dyn Meter,
    lease: Lease,
    client: Option<NntpClient>,
    (err, provider): Failure,
    user: &str,
    track: &str,
) -> PlayError {
    pool.release(lease, if provider { None } else { client });
    if provider {
        pool.record_provider_error();
        meter.emit(ev(MeterKind::ProviderError, user, track, 0));
    }
    err
}

impl Live {
    /// Take one decoded segment: check its placement, decrypt, stage the
    /// upload part and make it the current buffer.
    fn ingest(&mut self, mut d: Decoded) -> Result<(), Failure> {
        let multi_segment = self.segments.len() > 1;
        let misplaced = d.offset != self.fetched
            || d.file_size != self.total
            || (multi_segment && !d.multipart);
        if misplaced {
            return Err((PlayError::Decode(YencError::BadPart), false));
        }
        // Demo cipher (see module docs): the production content key arrives
        // via the BYOP vault and the ingest-owned envelope.
        for b in d.data.iter_mut() {
            *b ^= self.cipher_key;
        }
        self.upload.part(&d.data);
        self.buf_start = self.fetched;
        self.fetched += d.data.len() as u64;
        self.buf = d.data;
        self.next_seg += 1;
        if self.next_seg == self.segments.len() && self.fetched != self.total {
            return Err((
                PlayError::Decode(YencError::SizeMismatch {
                    expected: self.total,
                    actual: self.fetched as usize,
                }),
                false,
            ));
        }
        Ok(())
    }

    fn load_next(&mut self) -> Result<(), Failure> {
        let mid = self.segments[self.next_seg].clone();
        match fetch_segment(&mut self.client, &mid) {
            Ok(decoded) => self.ingest(decoded),
            Err(SegmentError::Nntp(e)) => Err(nntp_failure(e, &mid)),
            Err(SegmentError::Decode(e)) => Err((PlayError::Decode(e), false)),
        }
    }

    /// Release the lease for good, returning how the play ended.
    fn settle(
        self,
        pool: &mut StreamPool,
        meter: &mut dyn Meter,
        failure: Option<Failure>,
        user: &str,
        track: &str,
    ) -> PlayError {
        let failure = failure.unwrap_or((PlayError::Upstream("play failed".into()), false));
        settle(
            pool,
            meter,
            self.lease,
            Some(self.client),
            failure,
            user,
            track,
        )
    }
}

/// `(status, content_range, start, end_exclusive)` for a body of `len`.
type Window = (u16, Option<String>, u64, u64);

fn resolve_range(len: u64, range: Option<&str>) -> Result<Window, PlayError> {
    match range::parse(range, len) {
        RangeOutcome::Full => Ok((200, None, 0, len)),
        RangeOutcome::Partial(r) => Ok((
            206,
            Some(range::content_range_value(r, len)),
            r.start,
            r.end + 1,
        )),
        RangeOutcome::Unsatisfiable => Err(PlayError::RangeUnsatisfiable),
    }
}

fn respond(
    (status, content_range, start, end): Window,
    cache_hit: bool,
    user: &str,
    track: &str,
    source: Source,
    orphans: Arc<Mutex<Vec<OrphanedPlay>>>,
) -> PlayResponse {
    PlayResponse {
        status,
        content_range,
        body_len: end - start,
        cache_hit,
        stream: PlayStream {
            user_id: user.to_string(),
            track_id: track.to_string(),
            pos: start,
            end,
            served: 0,
            source: Some(source),
            orphans,
        },
    }
}

fn ev(kind: MeterKind, user: &str, track: &str, bytes: u64) -> MeterEvent {
    MeterEvent {
        kind,
        user_id: user.to_string(),
        track_id: track.to_string(),
        bytes,
    }
}

/// Emit `BytesServed` for plays that were dropped before `finalize` ran.
fn flush_orphaned(pool: &mut StreamPool, meter: &mut dyn Meter) {
    for orphan in pool.take_orphaned() {
        meter.emit(ev(
            MeterKind::BytesServed,
            &orphan.user_id,
            &orphan.track_id,
            orphan.bytes,
        ));
    }
}

impl PlayStream {
    /// True on the miss path (chunks feed a staged multipart upload).
    pub fn is_writeback(&self) -> bool {
        matches!(self.source, Some(Source::Live(_)))
    }

    /// Why the stream stopped early, if it did (miss path only).
    pub fn error(&self) -> Option<&PlayError> {
        match &self.source {
            Some(Source::Live(live)) => live.failed.as_ref().map(|(e, _)| e),
            _ => None,
        }
    }

    /// Finish the play: meter the bytes served, and on a miss pull any
    /// segments the client's range skipped, complete the staged write into
    /// `cache` and return the connection to `pool`. Errors (a gone article,
    /// a bad segment, a dead connection) leave the cache untouched.
    pub fn finalize(
        mut self,
        pool: &mut StreamPool,
        cache: &mut ContentCache,
        meter: &mut dyn Meter,
    ) -> Result<(), PlayError> {
        flush_orphaned(pool, meter);
        meter.emit(ev(
            MeterKind::BytesServed,
            &self.user_id,
            &self.track_id,
            self.served,
        ));
        let mut live = match self.source.take() {
            Some(Source::Live(live)) => live,
            _ => return Ok(()),
        };
        while live.failed.is_none() && live.next_seg < live.segments.len() {
            if let Err(failure) = live.load_next() {
                live.failed = Some(failure);
            }
        }
        match live.failed.take() {
            None => {
                let Live {
                    client,
                    lease,
                    upload,
                    ..
                } = *live;
                pool.release(lease, Some(client));
                pool.record_success();
                cache.put_track(&self.track_id, upload.complete());
                Ok(())
            }
            Some(failure) => {
                let live = *live;
                let (client, lease) = (live.client, live.lease);
                Err(settle(
                    pool,
                    meter,
                    lease,
                    Some(client),
                    failure,
                    &self.user_id,
                    &self.track_id,
                ))
            }
        }
    }

    /// The client went away: return the connection without caching. Bytes
    /// already served are still metered: they ride the pool-level orphan
    /// queue and are emitted as `BytesServed` on the next `play`/`finalize`
    /// — on the hit path (which holds no lease) exactly like on a miss.
    /// `source` is taken first so `Drop` cannot record the same bytes twice.
    pub fn abort(mut self, pool: &mut StreamPool) {
        let source = self.source.take();
        if self.served > 0 {
            pool.push_orphan(OrphanedPlay {
                user_id: self.user_id.clone(),
                track_id: self.track_id.clone(),
                bytes: self.served,
            });
        }
        if let Some(Source::Live(live)) = source {
            let live = *live;
            let healthy = !matches!(live.failed, Some((_, true)));
            pool.release(live.lease, healthy.then_some(live.client));
        }
    }
}

impl Iterator for PlayStream {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        if self.pos >= self.end {
            return None;
        }
        let chunk = match self.source.as_mut() {
            Some(Source::Cached(bytes)) => {
                let to = (self.pos as usize + CHUNK).min(self.end as usize);
                bytes[self.pos as usize..to].to_vec()
            }
            Some(Source::Live(live)) => loop {
                if live.failed.is_some() {
                    return None;
                }
                let buf_end = live.buf_start + live.buf.len() as u64;
                if self.pos >= live.buf_start && self.pos < buf_end {
                    let from = (self.pos - live.buf_start) as usize;
                    let to = (from + CHUNK)
                        .min(live.buf.len())
                        .min((self.end - live.buf_start) as usize);
                    break live.buf[from..to].to_vec();
                }
                if live.next_seg >= live.segments.len() {
                    live.failed = Some((PlayError::Decode(YencError::Truncated), false));
                    return None;
                }
                if let Err(failure) = live.load_next() {
                    live.failed = Some(failure);
                    return None;
                }
            },
            // finalize/abort consumed the stream; `next` after that is empty.
            None => return None,
        };
        self.pos += chunk.len() as u64;
        self.served += chunk.len() as u64;
        Some(chunk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrong_track_grant_is_rejected() {
        let secret = b"s";
        let token = grant::issue("u", "track-a", 9_999_999_999, secret);
        let mut pool = Pool::new(1);
        let mut cache = ContentCache::new();
        let mut meter = crate::meter::MemoryMeter::default();
        let addr: SocketAddr = "127.0.0.1:119".parse().unwrap();
        let input = PlayInput {
            token: &token,
            track_id: "track-b",
            range: None,
            server_addr: addr,
            segments: &[],
            cipher_key: 0,
            now_unix: 1,
            up_next: None,
        };
        assert!(matches!(
            play(&mut pool, &mut cache, &mut meter, secret, &input),
            Err(PlayError::WrongTrack)
        ));
    }

    #[test]
    fn garbage_token_is_unauthorized_without_touching_the_pool() {
        let secret = b"s";
        let mut pool = Pool::new(1);
        let mut cache = ContentCache::new();
        let mut meter = crate::meter::MemoryMeter::default();
        let addr: SocketAddr = "127.0.0.1:119".parse().unwrap();
        let input = PlayInput {
            token: "not-a-token",
            track_id: "t",
            range: None,
            server_addr: addr,
            segments: &[],
            cipher_key: 0,
            now_unix: 1,
            up_next: None,
        };
        assert!(matches!(
            play(&mut pool, &mut cache, &mut meter, secret, &input),
            Err(PlayError::Unauthorized(GrantError::Malformed))
        ));
        assert_eq!(pool.connects(), 0, "rejected plays must not dial out");
    }
}
