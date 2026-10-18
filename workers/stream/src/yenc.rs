//! Minimal yEnc codec for the miss path: NNTP segments arrive yEnc-encoded;
//! the play path decodes them before decrypting.
//!
//! Everything is byte-based: encoded bodies routinely contain bytes ≥ 128,
//! which are not valid UTF-8. [`encode`] exists so tests (and the synthetic
//! NNTP fixture) can build byte-exact articles; the Worker only ever calls
//! [`decode`].

/// Why a yEnc body was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum YencError {
    Truncated,
    BadEscape,
    /// Missing/inconsistent `=ypart` placement on a multipart article.
    BadPart,
    SizeMismatch {
        expected: u64,
        actual: usize,
    },
    CrcMismatch {
        expected: u32,
        actual: u32,
    },
}

/// IEEE CRC-32 over `data` (bitwise; no table needed at this size).
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for b in data {
        crc ^= *b as u32;
        for _ in 0..8 {
            crc = if crc & 1 == 1 {
                (crc >> 1) ^ 0xEDB88320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

const WRAP_COL: usize = 128;

/// Encode `data` as a yEnc article naming `name` (CRLF line endings).
pub fn encode(data: &[u8], name: &str) -> Vec<u8> {
    let mut out = format!(
        "=ybegin line={WRAP_COL} size={} name={name}\r\n",
        data.len()
    )
    .into_bytes();
    push_body(&mut out, data);
    out.extend_from_slice(
        format!(
            "\r\n=yend size={} crc32={:08x}\r\n",
            data.len(),
            crc32(data)
        )
        .as_bytes(),
    );
    out
}

/// One decoded article: the payload plus where it sits in its file.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decoded {
    pub data: Vec<u8>,
    /// Whole-file size declared by `=ybegin size=` (for a single-part
    /// article, the article's own size).
    pub file_size: u64,
    /// 0-based byte offset of this part within the file.
    pub offset: u64,
    /// True for `=ybegin part=N` posts (what NZB segments are).
    pub multipart: bool,
}

/// Placement of one multipart part, for [`encode_part`].
#[derive(Clone, Copy, Debug)]
pub struct PartSpec {
    /// Whole-file size.
    pub file_size: u64,
    /// 1-based part number and part count.
    pub part: u32,
    pub total: u32,
    /// 0-based offset of this part within the file.
    pub offset: u64,
    /// Whole-file CRC-32 (posters usually put it only on the last part).
    pub file_crc: Option<u32>,
}

/// Encode `data` as one part of a multipart yEnc post: `=ybegin part= total=`,
/// `=ypart begin= end=`, body, `=yend size= part= pcrc32=` (CRLF endings).
pub fn encode_part(data: &[u8], name: &str, spec: PartSpec) -> Vec<u8> {
    let begin = spec.offset + 1;
    let end = spec.offset + data.len() as u64;
    let mut out = format!(
        "=ybegin part={} total={} line={WRAP_COL} size={} name={name}\r\n=ypart begin={begin} end={end}\r\n",
        spec.part, spec.total, spec.file_size
    )
    .into_bytes();
    push_body(&mut out, data);
    let file_crc = spec
        .file_crc
        .map(|c| format!(" crc32={c:08x}"))
        .unwrap_or_default();
    out.extend_from_slice(
        format!(
            "\r\n=yend size={} part={} pcrc32={:08x}{file_crc}\r\n",
            data.len(),
            spec.part,
            crc32(data)
        )
        .as_bytes(),
    );
    out
}

/// Append the escaped, line-wrapped body (no trailing newline).
fn push_body(out: &mut Vec<u8>, data: &[u8]) {
    let mut col = 0usize;
    for b in data {
        let c = b.wrapping_add(42);
        let width = if matches!(c, 0x00 | 0x0A | 0x0D | 0x3D) {
            2
        } else {
            1
        };
        if col + width > WRAP_COL {
            out.extend_from_slice(b"\r\n");
            col = 0;
        }
        if width == 2 {
            out.push(b'=');
            out.push(c.wrapping_add(64));
        } else {
            out.push(c);
        }
        col += width;
    }
}

/// Decode a full single-part yEnc article to bytes, verifying size and CRC.
pub fn decode(text: &[u8]) -> Result<Vec<u8>, YencError> {
    decode_part(text).map(|d| d.data)
}

/// Decode a yEnc article (single- or multipart) and report its placement.
///
/// - Single-part: size from `=yend`, `crc32=` (when present) over the data.
/// - Multipart: `=ypart begin= end=` gives the placement and must agree with
///   the payload length; `pcrc32=` (when present) covers the part. A
///   `crc32=` on a part is the whole-file CRC and is *not* checked here.
pub fn decode_part(text: &[u8]) -> Result<Decoded, YencError> {
    let mut out = Vec::new();
    let mut in_body = false;
    let mut seen_begin = false;
    let mut seen_trailer = false;
    let mut file_size: Option<u64> = None;
    let mut multipart = false;
    let mut part_range: Option<(u64, u64)> = None;
    let mut yend_size: Option<u64> = None;
    let mut crc: Option<u32> = None;
    let mut pcrc: Option<u32> = None;
    for raw_line in text.split(|&b| b == b'\n') {
        let line = raw_line.strip_suffix(b"\r").unwrap_or(raw_line);
        if line.starts_with(b"=ybegin") {
            in_body = true;
            seen_begin = true;
            // Byte-based: the line carries `name=<poster bytes>`, which is
            // often Latin-1/CP1252 and not UTF-8. The numeric tags precede it
            // and are pure ASCII, so parse them from bytes.
            file_size = tag_u64(line, b"size");
            multipart = tag_u64(line, b"part").is_some();
            continue;
        }
        if line.starts_with(b"=ypart") {
            part_range = match (tag_u64(line, b"begin"), tag_u64(line, b"end")) {
                (Some(b), Some(e)) if b >= 1 && e >= b => Some((b, e)),
                _ => return Err(YencError::BadPart),
            };
            continue;
        }
        if line.starts_with(b"=yend") {
            in_body = false;
            seen_trailer = true;
            yend_size = tag_u64(line, b"size");
            crc = tag_hex_u32(line, b"crc32");
            pcrc = tag_hex_u32(line, b"pcrc32");
            continue;
        }
        if !in_body || line.is_empty() {
            continue;
        }
        let mut i = 0;
        while i < line.len() {
            if line[i] == b'=' {
                i += 1;
                if i >= line.len() {
                    return Err(YencError::BadEscape);
                }
                out.push(line[i].wrapping_sub(64).wrapping_sub(42));
            } else {
                out.push(line[i].wrapping_sub(42));
            }
            i += 1;
        }
    }
    let (Some(file_size), Some(yend_size)) = (file_size, yend_size) else {
        return Err(YencError::Truncated);
    };
    if !seen_begin || !seen_trailer {
        return Err(YencError::Truncated);
    }
    if yend_size as usize != out.len() {
        return Err(YencError::SizeMismatch {
            expected: yend_size,
            actual: out.len(),
        });
    }
    let offset = if multipart {
        let (begin, end) = part_range.ok_or(YencError::BadPart)?;
        if end - begin + 1 != out.len() as u64 || end > file_size {
            return Err(YencError::BadPart);
        }
        begin - 1
    } else {
        if file_size as usize != out.len() {
            return Err(YencError::SizeMismatch {
                expected: file_size,
                actual: out.len(),
            });
        }
        0
    };
    // Single-part: `crc32` covers the data. Multipart: only `pcrc32` does.
    let covering = if multipart { pcrc } else { crc.or(pcrc) };
    if let Some(expected) = covering {
        let actual = crc32(&out);
        if actual != expected {
            return Err(YencError::CrcMismatch { expected, actual });
        }
    }
    Ok(Decoded {
        data: out,
        file_size,
        offset,
        multipart,
    })
}

/// Value of the ASCII `key=` tag on a yEnc header line, parsed from bytes so
/// a non-UTF-8 `name=` later on the same line cannot break decoding.
fn tag_value<'a>(line: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
    line.split(|&b| b == b' ' || b == b'\t')
        .filter_map(|tok| {
            let (k, v) = tok.split_at_checked(key.len())?;
            (k == key && v.first() == Some(&b'=')).then(|| &v[1..])
        })
        .next()
}

fn tag_u64(line: &[u8], key: &[u8]) -> Option<u64> {
    std::str::from_utf8(tag_value(line, key)?)
        .ok()?
        .parse()
        .ok()
}

fn tag_hex_u32(line: &[u8], key: &[u8]) -> Option<u32> {
    u32::from_str_radix(std::str::from_utf8(tag_value(line, key)?).ok()?, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_matches_published_test_vector() {
        // "123456789" -> 0xCBF43926
        assert_eq!(crc32(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn round_trip_covers_every_byte_value() {
        let all: Vec<u8> = (0..=255u8).collect();
        let text = encode(&all, "all.bin");
        assert_eq!(decode(&text).expect("decode"), all);
    }

    #[test]
    fn escaping_is_present_for_special_bytes() {
        // Plaintext bytes whose +42 lands on NUL/LF/CR/'=' must be escaped.
        let data = [214u8, 224, 227, 19];
        let text = encode(&data, "esc.bin");
        assert!(text.contains(&b'='), "expected escape sequences");
        assert_eq!(decode(&text).expect("decode"), data);
    }

    #[test]
    fn tampered_body_fails_crc() {
        let data = b"hello streaming world, this is a longer payload for crc";
        let mut text = encode(data, "t.bin");
        // Flip the first body byte (right after the =ybegin line).
        let body_pos = text.iter().position(|&b| b == b'\n').unwrap() + 1;
        text[body_pos] = text[body_pos].wrapping_add(1);
        assert!(matches!(decode(&text), Err(YencError::CrcMismatch { .. })));
    }

    #[test]
    fn missing_trailer_is_truncated() {
        let text = encode(b"some data here", "x.bin");
        let pos = text
            .windows(5)
            .rposition(|w| w == b"=yend")
            .expect("trailer present");
        assert_eq!(decode(&text[..pos]), Err(YencError::Truncated));
    }

    fn part(data: &[u8], spec: PartSpec) -> Vec<u8> {
        encode_part(data, "m.bin", spec)
    }

    #[test]
    fn multipart_part_with_only_pcrc32_decodes_with_placement() {
        let data: Vec<u8> = (0..=255u8).cycle().take(1000).collect();
        let text = part(
            &data,
            PartSpec {
                file_size: 3000,
                part: 2,
                total: 3,
                offset: 1000,
                file_crc: None,
            },
        );
        let got = decode_part(&text).expect("decode multipart");
        assert_eq!(got.data, data);
        assert_eq!(
            (got.file_size, got.offset, got.multipart),
            (3000, 1000, true)
        );
    }

    #[test]
    fn whole_file_crc_on_a_part_is_not_checked_against_the_part() {
        let data = b"last part payload bytes".to_vec();
        let text = part(
            &data,
            PartSpec {
                file_size: 5000,
                part: 3,
                total: 3,
                offset: 4977,
                file_crc: Some(0xDEAD_BEEF),
            },
        );
        assert_eq!(decode_part(&text).expect("decode").data, data);
    }

    #[test]
    fn multipart_tampered_body_fails_pcrc32() {
        let data = b"some multipart payload that is long enough to tamper with".to_vec();
        let mut text = part(
            &data,
            PartSpec {
                file_size: 100,
                part: 1,
                total: 2,
                offset: 0,
                file_crc: None,
            },
        );
        let body_pos = text
            .windows(2)
            .position(|w| w == b"\r\n")
            .and_then(|first| {
                text[first + 2..]
                    .windows(2)
                    .position(|w| w == b"\r\n")
                    .map(|second| first + 2 + second + 2)
            })
            .expect("body after =ypart");
        text[body_pos] = text[body_pos].wrapping_add(1);
        assert!(matches!(
            decode_part(&text),
            Err(YencError::CrcMismatch { .. })
        ));
    }

    #[test]
    fn multipart_without_ypart_or_with_wrong_length_is_bad_part() {
        let data = b"abcdef".to_vec();
        let spec = PartSpec {
            file_size: 6,
            part: 1,
            total: 1,
            offset: 0,
            file_crc: None,
        };
        let good = part(&data, spec);
        let no_ypart: Vec<u8> = good
            .split(|&b| b == b'\n')
            .filter(|l| !l.starts_with(b"=ypart"))
            .flat_map(|l| [l, b"\n"].concat())
            .collect();
        assert_eq!(decode_part(&no_ypart), Err(YencError::BadPart));
        let at = good
            .windows(6)
            .position(|w| w == b"end=6\r")
            .expect("ypart end tag");
        let mut wrong_len = good.clone();
        wrong_len[at + 4] = b'9';
        assert_eq!(decode_part(&wrong_len), Err(YencError::BadPart));
    }

    #[test]
    fn latin1_filename_does_not_break_decode() {
        // Legacy posters encode names in Latin-1/CP1252; the tags precede
        // `name=` and are pure ASCII, so decode must not care.
        let data: Vec<u8> = (0..=255u8).cycle().take(500).collect();
        let text = part(
            &data,
            PartSpec {
                file_size: 1500,
                part: 1,
                total: 3,
                offset: 0,
                file_crc: None,
            },
        );
        let mut latin1 = text.clone();
        let from = b"name=m.bin";
        let at = latin1
            .windows(from.len())
            .position(|w| w == from)
            .expect("name tag present");
        latin1.splice(
            at..at + from.len(),
            b"name="
                .iter()
                .chain(b"Bj\xf6rk - Joga.flac".iter())
                .copied(),
        );
        let got = decode_part(&latin1).expect("latin-1 name must decode");
        assert_eq!(got.data, data);
        assert_eq!((got.file_size, got.offset, got.multipart), (1500, 0, true));
    }

    #[test]
    fn single_part_without_crc_still_checks_size() {
        let text = b"=ybegin line=128 size=3 name=a\r\nXYZ\r\n=yend size=3\r\n";
        assert_eq!(decode(text).expect("size-only").len(), 3);
        let bad = b"=ybegin line=128 size=4 name=a\r\nXYZ\r\n=yend size=4\r\n";
        assert!(matches!(decode(bad), Err(YencError::SizeMismatch { .. })));
    }
}
