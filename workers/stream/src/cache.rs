//! Content-addressed audio cache: the R2 shape behind a testable interface.
//!
//! - Blobs live under `audio/<sha256-hex-of-plaintext>`; identical audio
//!   uploaded for two tracks is stored once (dedup).
//! - `track/<track_id>` is a tiny pointer to the current blob hash.
//! - [`MultipartUpload`] models the R2 multipart write the Worker streams
//!   into while serving a miss: parts buffer, `complete` concatenates.
//!
//! [`ContentCache`] is the in-memory stand-in; production swaps it for R2
//! calls with identical semantics (see `wrangler.toml` bindings).

use std::collections::HashMap;
use std::sync::Arc;

use crate::grant::sha256;

pub struct ContentCache {
    blobs: HashMap<String, Arc<[u8]>>,
    index: HashMap<String, String>,
}

impl ContentCache {
    pub fn new() -> Self {
        Self {
            blobs: HashMap::new(),
            index: HashMap::new(),
        }
    }

    /// Store `plaintext` for `track_id`; returns the blob hash hex.
    pub fn put_track(&mut self, track_id: &str, plaintext: Vec<u8>) -> String {
        let hash = Self::hex_hash(&plaintext);
        self.blobs
            .entry(hash.clone())
            .or_insert_with(|| Arc::from(plaintext));
        self.index.insert(track_id.to_string(), hash.clone());
        hash
    }

    /// Fetch the cached plaintext for `track_id`, if any. Shared, not
    /// copied: a hit never duplicates the track in memory.
    pub fn get_track(&self, track_id: &str) -> Option<Arc<[u8]>> {
        self.index
            .get(track_id)
            .and_then(|h| self.blobs.get(h))
            .cloned()
    }

    /// Distinct blobs held (dedup probe).
    pub fn blob_count(&self) -> usize {
        self.blobs.len()
    }

    /// Lowercase hex SHA-256 of `data`.
    pub fn hex_hash(data: &[u8]) -> String {
        sha256(data).iter().map(|b| format!("{b:02x}")).collect()
    }
}

impl Default for ContentCache {
    fn default() -> Self {
        Self::new()
    }
}

/// R2 multipart part floor: every part except the last must be at least
/// this big, and all non-final parts must be the same size (R2 errors
/// 10011/10048 otherwise). Flushed parts are exactly this size.
pub const R2_MIN_PART: usize = 5 * 1024 * 1024;

/// A streaming R2 multipart write. Decoded segments (typically < 1 MiB)
/// coalesce into fixed [`R2_MIN_PART`]-byte parts: each full part is flushed
/// (production uploads it to R2 and retains nothing) while the remainder
/// stages toward the next. Steady-state memory is one part plus the segment
/// being decoded. This in-memory stand-in keeps flushed parts so `complete`
/// can hand the bytes over without a copy.
pub struct MultipartUpload {
    flushed: Vec<Vec<u8>>,
    pending: Vec<u8>,
}

impl MultipartUpload {
    pub fn begin(track_id: &str) -> Self {
        let _ = track_id;
        Self {
            flushed: Vec::new(),
            pending: Vec::new(),
        }
    }

    pub fn part(&mut self, data: &[u8]) {
        self.pending.extend_from_slice(data);
        while self.pending.len() >= R2_MIN_PART {
            let rest = self.pending.split_off(R2_MIN_PART);
            self.flushed
                .push(std::mem::replace(&mut self.pending, rest));
        }
    }

    pub fn complete(mut self) -> Vec<u8> {
        let mut full: Vec<u8> = self.flushed.concat();
        full.append(&mut self.pending);
        full
    }

    /// Total bytes staged (flushed + pending).
    pub fn bytes_staged(&self) -> u64 {
        (self.flushed.iter().map(Vec::len).sum::<usize>() + self.pending.len()) as u64
    }

    /// Sizes of the flushed full parts (each exactly [`R2_MIN_PART`]).
    pub fn flushed_part_sizes(&self) -> Vec<usize> {
        self.flushed.iter().map(Vec::len).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tracks_resolve_to_their_plaintext() {
        let mut cache = ContentCache::new();
        assert!(cache.get_track("t1").is_none());
        cache.put_track("t1", b"audio-bytes".to_vec());
        assert_eq!(cache.get_track("t1").as_deref(), Some(&b"audio-bytes"[..]));
    }

    #[test]
    fn identical_audio_is_stored_once() {
        let mut cache = ContentCache::new();
        let h1 = cache.put_track("t1", b"same-bytes".to_vec());
        let h2 = cache.put_track("t2", b"same-bytes".to_vec());
        assert_eq!(h1, h2);
        assert_eq!(cache.blob_count(), 1);
    }

    #[test]
    fn overwriting_a_track_repoints_it() {
        let mut cache = ContentCache::new();
        cache.put_track("t1", b"v1".to_vec());
        cache.put_track("t1", b"v2-longer".to_vec());
        assert_eq!(cache.get_track("t1").as_deref(), Some(&b"v2-longer"[..]));
    }

    #[test]
    fn multipart_buffers_parts_until_complete() {
        let mut up = MultipartUpload::begin("t1");
        up.part(b"hel");
        up.part(b"lo");
        assert_eq!(up.bytes_staged(), 5);
        assert!(up.flushed_part_sizes().is_empty());
        assert_eq!(up.complete(), b"hello");
    }

    #[test]
    fn sub_5mib_segments_coalesce_into_fixed_r2_parts() {
        // Usenet segments (~0.7 MB) can never go to R2 one-per-part: every
        // non-final part must be >= 5 MiB and all non-final parts the same
        // size. Sixteen 700 KiB segments = 11.2 MiB must flush exactly two
        // full 5 MiB parts and keep the 1.2 MiB remainder staged.
        let mut up = MultipartUpload::begin("t1");
        let seg = vec![0xABu8; 700 * 1024];
        for _ in 0..16 {
            up.part(&seg);
        }
        assert_eq!(up.flushed_part_sizes(), &[R2_MIN_PART, R2_MIN_PART]);
        assert_eq!(up.bytes_staged(), 16 * seg.len() as u64);
        let full = up.complete();
        assert_eq!(full.len(), 16 * seg.len());
        assert!(full.iter().all(|&b| b == 0xAB));
    }
}
