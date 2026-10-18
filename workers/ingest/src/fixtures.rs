//! Synthetic ingest fixtures for unit + pipeline tests.
//!
//! Stand-in for the synthetic NNTP corpus owned by the synthetic-server
//! card: same shapes (yEnc single/multi-part subjects, one gapped set, one
//! par2 set), embedded so the pipeline E2E runs in CI today. When that card
//! lands, these fixtures defer to its corpus; the message-ids below are
//! reserved for that handoff.

/// Minimal two-segment NZB used across dispatch/parse/probe tests.
pub const SMALL_NZB: &str = r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<file poster="a@b" date="1" subject="track01.flac">
<groups><group>alt.binaries.music</group></groups>
<segments>
<segment bytes="100" number="1">seg-one@synthetic.invalid</segment>
<segment bytes="100" number="2">seg-two@synthetic.invalid</segment>
</segments>
</file>
</nzb>"#;

/// Message-ids referenced by [`SMALL_NZB`].
pub const SMALL_NZB_SEGMENTS: [&str; 2] =
    ["seg-one@synthetic.invalid", "seg-two@synthetic.invalid"];

/// A gapped NZB: the second segment is missing server-side (430), so the
/// probe reports it missing and the repair path must cover it.
pub const GAPPED_NZB: &str = r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
<file poster="a@b" date="1" subject="track02 [01/02] - &quot;track02.flac&quot; yEnc (1/2)">
<groups><group>alt.binaries.music</group></groups>
<segments>
<segment bytes="100" number="1">gap-one@synthetic.invalid</segment>
<segment bytes="100" number="2">gap-missing@synthetic.invalid</segment>
</segments>
</file>
</nzb>"#;

/// par2 set id covering [`GAPPED_NZB`].
pub const GAPPED_PAR2_SET: &str = "par2-gap-demo-01";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nzb_intake::estimate_nzb;

    #[test]
    fn fixtures_pass_the_intake_guard() {
        let small = estimate_nzb(SMALL_NZB).unwrap();
        assert_eq!(small.file_count, 1);
        assert_eq!(small.segment_count, 2);
        let gapped = estimate_nzb(GAPPED_NZB).unwrap();
        assert_eq!(gapped.segment_count, 2);
    }
}
