//! HTTP `Range` handling for the play path (seeking + `206 Partial Content`).
//!
//! Only single `bytes=` ranges are honoured; anything else (missing header,
//! multiple ranges, unparseable units) falls back to `200 OK` full-body per
//! RFC 9110 §14.2. An unsatisfiable range resolves to `416`.

/// A resolved inclusive byte range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRange {
    pub start: u64,
    /// Inclusive end.
    pub end: u64,
}

impl ByteRange {
    pub fn len(&self) -> u64 {
        self.end - self.start + 1
    }

    pub fn is_empty(&self) -> bool {
        // Ranges are inclusive with `end >= start` by construction, so this
        // is always false; provided for the `len`/`is_empty` convention.
        self.end < self.start
    }
}

/// How to answer a play request for a body of `len` bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RangeOutcome {
    /// No (usable) Range header: serve `200 OK` with the full body.
    Full,
    /// Serve `206 Partial Content` with this slice.
    Partial(ByteRange),
    /// Serve `416 Range Not Satisfiable`.
    Unsatisfiable,
}

/// Parse `header` (the value of the `Range` header, if any) for a body of
/// `len` bytes.
pub fn parse(header: Option<&str>, len: u64) -> RangeOutcome {
    let spec = match header {
        Some(h) => match h.trim().strip_prefix("bytes=") {
            Some(s) => s.trim(),
            None => return RangeOutcome::Full,
        },
        None => return RangeOutcome::Full,
    };
    if spec.contains(',') {
        // Multi-range: not supported, serve the full body.
        return RangeOutcome::Full;
    }
    let (start_s, end_s) = match spec.split_once('-') {
        Some(pair) => (pair.0.trim(), pair.1.trim()),
        None => return RangeOutcome::Full,
    };
    if start_s.is_empty() {
        // Suffix range: the last N bytes.
        let n: u64 = match end_s.parse() {
            Ok(n) => n,
            Err(_) => return RangeOutcome::Full,
        };
        if len == 0 || n == 0 {
            return if len == 0 {
                RangeOutcome::Unsatisfiable
            } else {
                RangeOutcome::Full
            };
        }
        let n = n.min(len);
        RangeOutcome::Partial(ByteRange {
            start: len - n,
            end: len - 1,
        })
    } else {
        let start: u64 = match start_s.parse() {
            Ok(s) => s,
            Err(_) => return RangeOutcome::Full,
        };
        if end_s.is_empty() {
            if start >= len {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial(ByteRange {
                start,
                end: len - 1,
            })
        } else {
            let end: u64 = match end_s.parse() {
                Ok(e) => e,
                Err(_) => return RangeOutcome::Full,
            };
            if start > end {
                return RangeOutcome::Full;
            }
            if start >= len {
                return RangeOutcome::Unsatisfiable;
            }
            RangeOutcome::Partial(ByteRange {
                start,
                end: end.min(len - 1),
            })
        }
    }
}

/// Value for the `Content-Range` header of a `206` response.
pub fn content_range_value(range: ByteRange, len: u64) -> String {
    format!("bytes {}-{}/{}", range.start, range.end, len)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_or_garbage_header_serves_full_body() {
        assert_eq!(parse(None, 100), RangeOutcome::Full);
        assert_eq!(parse(Some(""), 100), RangeOutcome::Full);
        assert_eq!(parse(Some("items=0-10"), 100), RangeOutcome::Full);
        assert_eq!(parse(Some("bytes=abc-def"), 100), RangeOutcome::Full);
        assert_eq!(parse(Some("bytes=0-10,20-30"), 100), RangeOutcome::Full);
    }

    #[test]
    fn open_ended_range_runs_to_end_of_body() {
        assert_eq!(
            parse(Some("bytes=10-"), 100),
            RangeOutcome::Partial(ByteRange { start: 10, end: 99 })
        );
    }

    #[test]
    fn closed_range_is_clamped_to_body() {
        assert_eq!(
            parse(Some("bytes=0-49"), 100),
            RangeOutcome::Partial(ByteRange { start: 0, end: 49 })
        );
        assert_eq!(
            parse(Some("bytes=50-9999"), 100),
            RangeOutcome::Partial(ByteRange { start: 50, end: 99 })
        );
    }

    #[test]
    fn suffix_range_serves_the_tail() {
        assert_eq!(
            parse(Some("bytes=-20"), 100),
            RangeOutcome::Partial(ByteRange { start: 80, end: 99 })
        );
        // Suffix longer than the body: whole body.
        assert_eq!(
            parse(Some("bytes=-500"), 100),
            RangeOutcome::Partial(ByteRange { start: 0, end: 99 })
        );
    }

    #[test]
    fn start_past_end_of_body_is_unsatisfiable() {
        assert_eq!(parse(Some("bytes=100-"), 100), RangeOutcome::Unsatisfiable);
        assert_eq!(
            parse(Some("bytes=200-300"), 100),
            RangeOutcome::Unsatisfiable
        );
        assert_eq!(parse(Some("bytes=90-10"), 100), RangeOutcome::Full);
    }

    #[test]
    fn empty_body_has_no_satisfiable_range() {
        assert_eq!(parse(Some("bytes=0-"), 0), RangeOutcome::Unsatisfiable);
        assert_eq!(parse(None, 0), RangeOutcome::Full);
    }

    #[test]
    fn content_range_header_value() {
        let range = ByteRange { start: 10, end: 99 };
        assert_eq!(content_range_value(range, 100), "bytes 10-99/100");
    }
}
