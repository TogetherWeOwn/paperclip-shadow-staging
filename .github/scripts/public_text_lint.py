#!/usr/bin/env python3
"""Public-text hygiene lint: fail closed on internal identifiers.

Owner rule (threat-model section 1, CONTRIBUTING.md): this public repo
carries no TOG ids, internal hosts, or agent names in any public text.
This script enforces the file-content half: it scans tracked text files
and exits 1 on any match. Wire it into CI as part of ``ci-ok``.

Banned classes (rule id -> shape):

  tog-id
    ``TOG-`` followed by digits (e.g. the ``TOG-`` + ``<n>`` shape).
    The ``TOG-*`` star form used by rule statements is NOT an id and
    never matches (a ``*`` is not a digit).
  internal-host
    Host shapes that only exist inside our walls: dotted hostnames under
    a private DNS suffix (a label, a dot, then ``internal``, ``local``,
    ``lan``, ``intranet`` or ``corp``, with an optional port — see
    ``_INTERNAL_SUFFIX`` for the exact shape), RFC-1918 IPv4, the cloud
    metadata IP, ``workforce`` control-plane hosts, and absolute
    instance-UI links
    (``https`` + ``://`` + any host + ``/<PREFIX>/issues|agents|.../``).
    The suffix rule is a negative lookahead: anything may follow the
    host except identifier continuations (letters, digits, ``_``, ``(``,
    ``-``) and dotted chains (``.`` + letter/digit/``_``/``(``). So a
    sentence-ending period, ``<...>``, ``!``, ``?``, ``}`` and ``**``
    all flag — they are the most common place for a hostname in prose.
    Attribute access followed by ``(`` or ``.`` (calls, chains) does not
    match; reword or extend the allowlist instead of widening the rule.
  instance-path
    Relative instance-UI paths (``/<PREFIX>/issues|agents|projects|
    approvals|runs/``). These deep-link the internal tracker even with
    no hostname attached. Lowercase app routes (``/api/issues/``) do
    not match: the prefix must be 2-6 capitals.
  agent-name
    Agent-scheme deep-links (the ``agent`` scheme followed by ``://``
    plus an identifier), ``paperclip`` runner handles (the word
    ``paperclip``, then ``-`` or ``_``, then ``agent``), and
    ``PAPERCLIP_*_(AGENT|RUN|TASK|SESSION|CHAT)_ID`` variables carrying
    a UUID value. Bare variable names (no value) stay documentable;
    role titles (``CISO``) are not agent names.

Allowlist (exact and reviewable — a widened allowlist destroys the
property, so every entry names its reason):

  * ``host.docker.internal`` is a standard Docker dev hostname, not our
    infrastructure: it is masked before matching. (The mask pattern below
    spells the suffix via a group so this file itself stays clean.)
  * The dotenv filename ``.env.local`` is the standard local-dev file
    for this stack, not our infrastructure: it is masked before
    matching. (The mask pattern below spells it via a group so this
    file itself stays clean.) Rule statements use the ``TOG-*`` star
    form, which never matches the id pattern — there is deliberately NO
    sentence exemption, so a real id pasted onto a rule line fails like
    anywhere else.
  * FIXTURE_EXCLUSIONS: exact test-fixture paths holding manufactured
    violations for this lint's own unit tests. No directory, extension,
    or generated-file exemptions.
  * HOST_FIXTURE_EXCLUSIONS: exact product-test paths where ONLY the
    private-IPv4 pattern is skipped. SSRF-guard negative tests must name
    RFC-reserved ranges (10/8, 169.254/16, IPv4-mapped embeddings) to
    assert rejection, so that one pattern would make them unmergeable.
    The suffix, workforce-host and absolute-UI-link patterns stay active
    on these files — a pasted hostname there must still fail. Every other
    rule still scans these files, and gitleaks plus secret scanning still
    apply. Exact paths, never directories.
  * Compiled artifacts (`__pycache__/`, `*.pyc`, `*.pyo`) must never be
    tracked: they embed absolute build paths (finding: a tracked `.pyc`
    leaked an internal worktree path). They are reported as
    `binary-artifact`, not scanned for content.

Scope limit (by design, not a gap to widen silently): this lint scans
tracked FILE CONTENTS only. Branch names, commit messages, and PR
titles/bodies are contributor discipline (CONTRIBUTING.md); squash-merge
keeps branch names off main. Prefer id-free branch names for new work.

Reports print file:line + rule id only — never the matched bytes. CI
logs on this repo are public (threat-model section 2), so the report
itself must not re-publish the leak.

Usage:
  python3 .github/scripts/public_text_lint.py [PATH ...]
  No PATHs: scan all git-tracked files. Explicit PATHs (e.g. new files
  not yet staged) are scanned as given.
"""

import re
import subprocess
import sys

# Exact lint-fixture paths only. No directory, extension or generated-file
# exemptions.
FIXTURE_EXCLUSIONS = frozenset(
    {
        ".github/scripts/test_public_text_lint.py",
    }
)

# Exact product-test paths exempt from the internal-host rule ONLY (see
# docstring). Each entry names its reason; never directories.
HOST_FIXTURE_EXCLUSIONS = frozenset(
    {
        # SSRF negative-test vectors: reserved ranges asserted rejected.
        "workers/api/tests/api_tests.rs",
        "workers/api/tests/security_regressions.rs",
        # SSRF negative-test vectors (web vault validation): private IPv4
        # and metadata IP asserted rejected client-side.
        "apps/web/src/lib/vault-validation.test.ts",
    }
)

_TOG = re.compile(r"\bTOG-\d+\b")

# Hostname-looking only: one or more labels, a private suffix, an optional
# port, then a negative lookahead. Anything may follow except identifier
# continuations and dotted chains, so sentence-ending punctuation flags
# while attribute access (`.foo(`, `.foo.bar`) and bare suffix words never
# match.
_INTERNAL_SUFFIX = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:[A-Za-z0-9-]+\.)+(?:internal|local|lan|intranet|corp)"
    r"(?::\d+)?(?![A-Za-z0-9_(-]|\.[A-Za-z0-9_(])",
    re.IGNORECASE,
)
_WORKFORCE_HOST = re.compile(r"\bworkforce\.[A-Za-z0-9.-]+", re.IGNORECASE)
_ABSOLUTE_UI_LINK = re.compile(
    r"\bhttps?://\S+/[A-Z]{2,6}/(?:issues|agents|projects|approvals|runs)/"
)
_PRIVATE_IPV4 = re.compile(
    r"(?:\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"
    r"|\b192\.168\.\d{1,3}\.\d{1,3}\b"
    r"|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"
    r"|\b169\.254\.169\.254\b)"
)
_RELATIVE_UI_PATH = re.compile(r"/[A-Z]{2,6}/(?:issues|agents|projects|approvals|runs)/")

_AGENT_DEEPLINK = re.compile(r"\bagent://\S+")
_RUNNER_HANDLE = re.compile(r"\bpaperclip[-_]agent\b", re.IGNORECASE)
_UUID_VALUED_ID = re.compile(
    r"\bPAPERCLIP_[A-Z_]*(?:AGENT|RUN|TASK|SESSION|CHAT)[A-Z_]*\s*[:=]\s*"
    r"['\"]?[0-9a-fA-F]{8}-"
)

RULES = (
    ("tog-id", (_TOG,)),
    ("internal-host", (_INTERNAL_SUFFIX, _WORKFORCE_HOST, _ABSOLUTE_UI_LINK, _PRIVATE_IPV4)),
    ("instance-path", (_RELATIVE_UI_PATH,)),
    ("agent-name", (_AGENT_DEEPLINK, _RUNNER_HANDLE, _UUID_VALUED_ID)),
)

# Group forms keep these definitional lines out of their own rules.
_DOCKER_HOST_MASK = re.compile(r"host\.docker\.(?:internal)\b", re.IGNORECASE)
_ENV_LOCAL_MASK = re.compile(r"\.env\.(?:local)\b", re.IGNORECASE)

# Host patterns that stay active even on HOST_FIXTURE_EXCLUSIONS paths:
# only the private-IPv4 pattern is skipped there (SSRF negative-test
# vectors), never the hostname shapes.
_HOST_PATTERNS_STRICT = (_INTERNAL_SUFFIX, _WORKFORCE_HOST, _ABSOLUTE_UI_LINK)

# Tracked compiled artifacts: they embed absolute build paths and must
# never be committed. Matched on path, reported as binary-artifact.
_ARTIFACT_PATH = re.compile(r"(?:^|/)__pycache__(?:/|$)|\.py[co]$")


def is_artifact_path(path):
    """True when a tracked path is a compiled artifact, never public text."""
    return bool(_ARTIFACT_PATH.search(path.replace("\\", "/")))


def find_violations(text, path=""):
    """Return [(line_number, rule_id)] for banned shapes in text.

    One hit per rule per line at most. Never returns matched bytes —
    callers report file:line + rule id only. There is no sentence
    exemption: a real id matches on any line, including a rule line.
    Paths in HOST_FIXTURE_EXCLUSIONS skip the private-IPv4 pattern only;
    the other internal-host patterns and every other rule still apply.
    """
    masked = _DOCKER_HOST_MASK.sub("host.docker.example", text)
    masked = _ENV_LOCAL_MASK.sub(".env.example", masked)
    host_exempt = path in HOST_FIXTURE_EXCLUSIONS
    hits = []
    # Split on '\n' only: str.splitlines() also splits on U+0085 (NEL),
    # U+000B, U+000C and U+001C-U+001E, and the latin-1 decode in scan_path
    # turns UTF-8 continuation bytes (e.g. the ✅ in threat-model.md) into
    # those code points — shifting every reported line number after one.
    for lineno, line in enumerate(masked.split("\n"), start=1):
        for rule_id, patterns in RULES:
            if rule_id == "internal-host" and host_exempt:
                patterns = _HOST_PATTERNS_STRICT
            if any(p.search(line) for p in patterns):
                hits.append((lineno, rule_id))
    return hits


def tracked_files():
    out = subprocess.run(
        ["git", "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout.decode("utf-8", errors="replace")
    return [p for p in out.split("\0") if p and p not in FIXTURE_EXCLUSIONS]


def scan_path(path):
    if is_artifact_path(path):
        return [(1, "binary-artifact")]
    with open(path, "rb") as fh:
        data = fh.read()
    # No binary early-return: a tracked binary IS public text once merged,
    # so the same patterns run over a lossless latin-1 decode (a tracked
    # .pyc once leaked an internal path while NUL bytes kept CI green).
    return find_violations(data.decode("latin-1"), path)


def main(argv):
    paths = argv[1:] or tracked_files()
    total_hits = 0
    per_rule = {}
    for path in paths:
        try:
            hits = scan_path(path)
        except (OSError, UnicodeError) as exc:
            print(f"::warning file={path}::public-text: unreadable, skipped ({exc})")
            continue
        for lineno, rule_id in hits:
            print(f"::error file={path},line={lineno}::public-text: {rule_id}")
            total_hits += 1
            per_rule[rule_id] = per_rule.get(rule_id, 0) + 1
    print(f"public-text: scanned {len(paths)} files, {total_hits} hits {per_rule}")
    return 1 if total_hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
