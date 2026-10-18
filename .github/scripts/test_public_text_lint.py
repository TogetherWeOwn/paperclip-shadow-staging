"""Unit tests for public_text_lint.

FIXTURE NOTE: this file holds manufactured violations (fake TOG ids,
internal hosts, agent handles) to trial the check. It is excluded from the
lint itself via FIXTURE_EXCLUSIONS in public_text_lint — exact path only,
no directory or extension exemptions.
"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from public_text_lint import (
    FIXTURE_EXCLUSIONS,
    HOST_FIXTURE_EXCLUSIONS,
    find_violations,
    is_artifact_path,
    scan_path,
)


def rules_for(text, path=""):
    return sorted({rule for _, rule in find_violations(text, path)})


class TestTogIds(unittest.TestCase):
    def test_flags_real_tog_id(self):
        self.assertIn("tog-id", rules_for("see TOG-23644 for details"))

    def test_star_form_is_not_an_id(self):
        self.assertEqual([], find_violations("no `TOG-*` ids in public text"))

    def test_rule_sentence_with_real_id_is_flagged(self):
        # No sentence exemption exists: a real id on a rule line fails
        # like anywhere else. (Manufactured id; this file is excluded
        # from the lint via FIXTURE_EXCLUSIONS.)
        self.assertIn(
            "tog-id",
            rules_for("No tracker IDs (e.g. TOG-00000) are required here"),
        )

    def test_finding_ids_are_public(self):
        self.assertEqual([], find_violations("see F-VAULT-02 in kek-rotation.md"))


class TestInternalHosts(unittest.TestCase):
    def test_flags_dot_internal(self):
        self.assertIn("internal-host", rules_for("dashboard at db.internal:3000"))

    def test_flags_private_ipv4(self):
        self.assertIn("internal-host", rules_for("proxy to http://10.0.3.9:8080/x"))

    def test_flags_metadata_ip(self):
        self.assertIn("internal-host", rules_for("curl 169.254.169.254/latest"))

    def test_flags_workforce_host(self):
        self.assertIn(
            "internal-host", rules_for("see https://workforce.example.net/abc")
        )

    def test_flags_absolute_instance_link(self):
        self.assertIn(
            "internal-host",
            rules_for("see https://tracker.example.com/NNTUNE/issues/99"),
        )

    def test_docker_dev_hostname_is_allowed(self):
        self.assertEqual(
            [], find_violations("connect to host.docker.internal:5432")
        )

    def test_dotenv_filename_is_allowed(self):
        self.assertEqual(
            [], find_violations("copy .env.example to .env.local")
        )

    def test_attribute_access_is_not_a_hostname(self):
        self.assertEqual([], find_violations("value = self.internal()"))
        self.assertEqual([], find_violations("value = self.internal.timeout"))

    def test_bare_dotted_name_at_end_still_flags(self):
        # Indistinguishable from a hostname: reword instead of widening.
        self.assertIn("internal-host", rules_for("point it at db.internal"))

    def test_private_suffix_with_path_flags(self):
        self.assertIn("internal-host", rules_for("fetch db.local/rows"))

    def test_sentence_end_punctuation_flags(self):
        # The most common place for a hostname in prose docs: the end of
        # a sentence or wrapped in markup. All of these must flag.
        for text in [
            "The control plane lives at ops.acme.internal.",
            "see <ops.acme.internal> for details",
            "is it ops.acme.internal?",
            "watch out for ops.acme.internal!",
            "config {host: ops.acme.internal}",
            "point at **ops.acme.internal** today",
            "db.internal:3000 is the default",
        ]:
            self.assertIn("internal-host", rules_for(text), text)

    def test_chains_and_calls_still_do_not_match(self):
        self.assertEqual([], find_violations("value = self.internal()"))
        self.assertEqual([], find_violations("see foo.internal.bar docs"))
        self.assertEqual([], find_violations("dash is db.internal-legacy"))

    def test_loopback_and_localhost_are_dev_docs(self):
        self.assertEqual([], find_violations("listen on 127.0.0.1:3000"))
        self.assertEqual([], find_violations("open http://localhost:3000"))


class TestInstancePaths(unittest.TestCase):
    def test_flags_relative_instance_path(self):
        self.assertIn("instance-path", rules_for("see /NNTUNE/issues/99 for context"))

    def test_lowercase_routes_are_code(self):
        self.assertEqual([], find_violations("GET /api/issues/42 returns JSON"))


class TestAgentNames(unittest.TestCase):
    def test_flags_agent_deeplink(self):
        self.assertIn(
            "agent-name", rules_for("ping agent://11111111-2222-3333-4444-555555555555")
        )

    def test_flags_runner_handle(self):
        self.assertIn("agent-name", rules_for("run as paperclip-agent-7"))

    def test_flags_uuid_valued_internal_id(self):
        self.assertIn(
            "agent-name",
            rules_for("PAPERCLIP_AGENT_ID=11111111-2222-3333-4444-555555555555"),
        )

    def test_bare_env_names_are_documentable(self):
        self.assertEqual([], find_violations("set PAPERCLIP_API_URL in the environment"))

    def test_role_titles_are_not_agent_names(self):
        self.assertEqual([], find_violations("Owner: CISO"))


class TestHostFixtureExclusions(unittest.TestCase):
    # SSRF-guard negative tests must name RFC-reserved ranges to assert
    # rejection. Without a path-scoped exemption those tests are
    # unmergeable; with a whole-file exemption a real leak there would
    # be missed. So: internal-host only, exact paths only.
    SSRF_FIXTURE = '"10.0.0.5",\n"http://169.254.169.254/latest/meta-data/"'

    def test_reserved_ranges_flagged_without_path(self):
        self.assertIn("internal-host", rules_for(self.SSRF_FIXTURE))

    def test_exempt_paths_skip_internal_host_only(self):
        self.assertTrue(HOST_FIXTURE_EXCLUSIONS)  # never an empty bypass
        for path in sorted(HOST_FIXTURE_EXCLUSIONS):
            self.assertNotIn("internal-host", rules_for(self.SSRF_FIXTURE, path))

    def test_exempt_paths_still_flag_tog_ids(self):
        for path in sorted(HOST_FIXTURE_EXCLUSIONS):
            self.assertIn("tog-id", rules_for("see TOG-23644", path))

    def test_exempt_paths_still_flag_other_host_shapes(self):
        # Only the private-IPv4 pattern is skipped on these paths: a
        # pasted hostname, control-plane host or UI link must still fail.
        for path in sorted(HOST_FIXTURE_EXCLUSIONS):
            self.assertIn(
                "internal-host",
                rules_for("dashboard at db.internal:3000", path),
                path,
            )
            self.assertIn(
                "internal-host",
                rules_for("see https://workforce.example.net/abc", path),
                path,
            )
            self.assertIn(
                "internal-host",
                rules_for(
                    "see https://tracker.example.com/NNTUNE/issues/99", path
                ),
                path,
            )

    def test_exempt_paths_still_flag_agent_names(self):
        for path in sorted(HOST_FIXTURE_EXCLUSIONS):
            self.assertIn("agent-name", rules_for("run as paperclip-agent-7", path))

    def test_exclusions_are_files_not_directories(self):
        for path in HOST_FIXTURE_EXCLUSIONS:
            self.assertFalse(path.endswith("/"))


class TestBinaries(unittest.TestCase):
    # A tracked binary IS public text once merged: NUL bytes must not
    # hide content, and compiled artifacts must never be tracked at all
    # (a .pyc once leaked an internal worktree path with CI green).
    NUL_FIXTURE = b"\x00\x01TOG-90000\x00\x02"

    def test_nul_bytes_do_not_hide_content(self):
        with tempfile.TemporaryDirectory() as tmp:
            fixture = os.path.join(tmp, "fixture.bin")
            with open(fixture, "wb") as fh:
                fh.write(self.NUL_FIXTURE)
            self.assertIn((1, "tog-id"), scan_path(fixture))

    def test_artifact_paths_are_rejected_without_reading(self):
        self.assertTrue(is_artifact_path(".github/scripts/__pycache__/x.pyc"))
        self.assertTrue(is_artifact_path("a/b/__pycache__/y.py"))
        self.assertTrue(is_artifact_path("docs/note.pyc"))
        self.assertFalse(is_artifact_path("workers/api/src/session.rs"))
        with tempfile.TemporaryDirectory() as tmp:
            artifact = os.path.join(tmp, "__pycache__", "lint.pyc")
            os.makedirs(os.path.dirname(artifact))
            with open(artifact, "wb") as fh:
                fh.write(b"clean\x00bytes")
            self.assertEqual([(1, "binary-artifact")], scan_path(artifact))


class TestMechanics(unittest.TestCase):
    def test_reports_line_numbers(self):
        lines = find_violations("clean line\nsee TOG-99 here\n")
        self.assertEqual([(2, "tog-id")], lines)

    def test_emoji_before_violation_keeps_line_number(self):
        # The ✅ glyph is bytes E2 9C 85 in UTF-8; scan_path decodes raw
        # bytes as latin-1, so 0x85 becomes U+0085 (NEL), which
        # str.splitlines() treats as a line break. Only the bytes ->
        # latin-1 -> split path pins the split("\n") fix: calling
        # find_violations on a str passes even with splitlines().
        with tempfile.TemporaryDirectory() as tmp:
            fixture = os.path.join(tmp, "emoji.md")
            with open(fixture, "wb") as fh:
                fh.write("✅ ok\nx\nsee TOG-99 here\n".encode("utf-8"))
            self.assertEqual([(3, "tog-id")], scan_path(fixture))

    def test_fixture_path_is_excluded(self):
        self.assertIn(
            ".github/scripts/test_public_text_lint.py", FIXTURE_EXCLUSIONS
        )


if __name__ == "__main__":
    unittest.main()
