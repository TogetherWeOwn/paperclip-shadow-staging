//! NZB upload intake guard.
//!
//! Uploads are untrusted user input: cap the bytes, require an NZB-looking
//! document, and bound files/segments before anything downstream (pool
//! probes, par2 verify) spends provider connections on them. Full NZB
//! parsing (subject decoding, segment maps) lives in `nntune-core`
//! (core card); this module is the cheap pre-filter at the worker edge.

/// Largest accepted upload: NZBs are XML metadata, never content.
pub const MAX_NZB_BYTES: usize = 2 * 1024 * 1024;
/// Upper bound on `<segment>` elements in one NZB: reachable inside
/// [`MAX_NZB_BYTES`] (a 2 MiB NZB holds tens of thousands of segments at
/// realistic per-segment overhead), so this fires before the size cap does.
pub const MAX_SEGMENTS: usize = 60_000;
/// Upper bound on `<file` elements in one NZB.
pub const MAX_FILES: usize = 5_000;

/// Why an upload was refused (surfaced as 400/413, never logged with body).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntakeRejection {
    Empty,
    TooLarge,
    NotNzb,
    TooManyFiles,
    TooManySegments,
}

/// Cheap structural estimate from one bounded scan of the document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntakeEstimate {
    pub file_count: usize,
    pub segment_count: usize,
}

/// True for bytes that can continue an XML element name: anything after
/// `<{name}` in this set means this is a longer name (`<segments>`,
/// `<segmentx>`), not the element we count.
fn is_name_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':')
}

/// Count `<{name}` element starts, stopping once `over` is exceeded.
///
/// An occurrence only counts when the byte after the name is *not* a name
/// character, so whitespace of any kind (` `, `\t`, `\r`, `\n`), `>` and
/// `/` (self-closing) all count, while the `<segments>` container and
/// longer names (`<segmentx>`) do not. Operates on bytes so it cannot miss
/// a spelling the XML spec allows.
fn count_elements(haystack: &str, name: &str, over: usize) -> usize {
    let needle = format!("<{name}");
    let mut n = 0;
    let mut rest = haystack;
    while let Some(i) = rest.find(needle.as_str()) {
        let after = rest.as_bytes().get(i + needle.len()).copied();
        // A truncated tail (`<segment` at the very end) counts: it is still
        // attacker-controlled shape the parser would have to deal with.
        if after.is_none() || !is_name_char(after.unwrap_or(0)) {
            n += 1;
            if n > over {
                break;
            }
        }
        rest = &rest[i + needle.len()..];
    }
    n
}

/// Validate an upload body and estimate its shape.
pub fn estimate_nzb(body: &str) -> Result<IntakeEstimate, IntakeRejection> {
    if body.is_empty() {
        return Err(IntakeRejection::Empty);
    }
    if body.len() > MAX_NZB_BYTES {
        return Err(IntakeRejection::TooLarge);
    }
    // Work on bytes, never on a str slice: a multibyte char straddling byte
    // 1024 would make `&body[..1024]` panic and abort the isolate on wasm.
    let head = &body.as_bytes()[..body.len().min(1024)];
    let head_has_nzb = head.windows(4).any(|w| w == b"<nzb");
    let head_has_xml = head.windows(5).any(|w| w == b"<?xml");
    // The full-body check needs no slicing and is therefore panic-free.
    if !(head_has_nzb || (head_has_xml && body.contains("<nzb"))) {
        return Err(IntakeRejection::NotNzb);
    }
    let file_count = count_elements(body, "file", MAX_FILES);
    if file_count > MAX_FILES {
        return Err(IntakeRejection::TooManyFiles);
    }
    let segment_count = count_elements(body, "segment", MAX_SEGMENTS);
    if segment_count > MAX_SEGMENTS {
        return Err(IntakeRejection::TooManySegments);
    }
    Ok(IntakeEstimate {
        file_count,
        segment_count,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SMALL_NZB: &str = r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<file poster="a@b" date="1" subject="track01.flac">
<groups><group>alt.binaries.music</group></groups>
<segments>
<segment bytes="100" number="1">seg-one@news</segment>
<segment bytes="100" number="2">seg-two@news</segment>
</segments>
</file>
</nzb>"#;

    #[test]
    fn accepts_small_nzb_with_counts() {
        let est = estimate_nzb(SMALL_NZB).unwrap();
        assert_eq!(est.file_count, 1);
        assert_eq!(est.segment_count, 2);
    }

    #[test]
    fn rejects_empty_oversize_and_non_nzb() {
        assert_eq!(estimate_nzb(""), Err(IntakeRejection::Empty));
        assert_eq!(
            estimate_nzb(&"x".repeat(MAX_NZB_BYTES + 1)),
            Err(IntakeRejection::TooLarge)
        );
        assert_eq!(
            estimate_nzb("<html><body>hi</body></html>"),
            Err(IntakeRejection::NotNzb)
        );
        assert_eq!(
            estimate_nzb(r#"{"json": "not xml"}"#),
            Err(IntakeRejection::NotNzb)
        );
    }

    #[test]
    fn multibyte_char_at_head_boundary_does_not_panic() {
        // '€' is 3 bytes (1023..1026): a str slice at byte 1024 would panic.
        let mut body = String::from("<nzb>");
        body.push_str(&"a".repeat(1018));
        body.push('€');
        body.push_str("</nzb>");
        let est = estimate_nzb(&body).unwrap();
        assert_eq!(est.segment_count, 0);
    }

    #[test]
    fn segment_delimiter_variants_all_count() {
        // Every legal byte after the element name counts…
        for sep in [" ", "\t", "\r", "\n", ">", "/"] {
            let doc = format!("<?xml?><nzb><segment{sep}></segment></nzb>");
            let est = estimate_nzb(&doc).unwrap();
            assert_eq!(est.segment_count, 1, "separator {sep:?} must count");
        }
        // …while the container and longer names do not.
        let doc = "<?xml?><nzb><segments><segment >x</segment></segments></nzb>";
        assert_eq!(estimate_nzb(doc).unwrap().segment_count, 1);
        let doc = "<?xml?><nzb><segmentx>y</segmentx></nzb>";
        assert_eq!(estimate_nzb(doc).unwrap().segment_count, 0);
    }

    #[test]
    fn newline_segment_bomb_hits_the_segment_cap() {
        // 70_010 newline-separated segments exceed the 60k cap in ~1.5 MB,
        // so the segment cap (not the size cap) must fire.
        let mut bomb = String::from("<?xml?><nzb>");
        for i in 0..(MAX_SEGMENTS + 10) {
            bomb.push_str(&format!("<segment\n>{i}</segment>"));
        }
        bomb.push_str("</nzb>");
        assert!(bomb.len() < MAX_NZB_BYTES);
        assert_eq!(estimate_nzb(&bomb), Err(IntakeRejection::TooManySegments));
    }

    #[test]
    fn rejects_segment_bomb() {
        // Compact segments stay under MAX_NZB_BYTES so the segment cap
        // (not the size cap) is what fires.
        let mut bomb = String::from("<?xml?><nzb>");
        for i in 0..(MAX_SEGMENTS + 10) {
            bomb.push_str(&format!("<segment>{i}</segment>"));
        }
        bomb.push_str("</nzb>");
        assert!(bomb.len() < MAX_NZB_BYTES);
        assert_eq!(estimate_nzb(&bomb), Err(IntakeRejection::TooManySegments));
    }
}
