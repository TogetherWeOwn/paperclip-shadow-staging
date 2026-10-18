# Contributing to NNTune v2

## Commits

[Conventional Commits](https://www.conventionalcommits.org/): `type(scope): summary`.

- Types: `feat` `fix` `perf` `refactor` `test` `docs` `build` `ci` `chore` `revert` `style` `security`
- Scope is optional: `feat(search): fuzzy artist matching`.
- Summary is imperative, lowercase-first, <= 100 chars, no trailing period.

## PR title format

The PR title **is** the squash-commit header, so it must be a valid
Conventional Commits header: `type(scope): summary`, <= 100 chars, no
trailing period. The `pr-lint` check enforces this.

No tracker IDs (e.g. `TOG-*`) are required in PR titles or bodies — this is a
public repo. Do not paste internal links or card IDs. The `public-text` CI
job (part of `ci-ok`, which fails on any needed-job failure) enforces this
on all tracked file contents. Scope is file contents only: branch names,
commit messages, and PR text stay clean by contributor discipline (prefer
id-free branch names; squash-merge keeps branch names off main).

## PR body

Follow `.github/pull_request_template.md`: what changed, why, how tested.

## Pull-request size labels (advisory)

`.github/workflows/pr-size.yml` labels every pull request `size/S` (up to 100
counted lines), `size/M` (up to 400), `size/L` (up to 1000) or `size/XL`, and
keeps one advisory comment on pull requests over the 400-line threshold.
Counted lines are additions + deletions excluding lockfiles, generated files
and fixtures. The labeller lives once in the org
[TogetherWeOwn/.github](https://github.com/TogetherWeOwn/.github) repository
(`CI-STANDARD.md`, "Advisory PR-size labels"); the workflow here is a thin
caller pinned to a central SHA and passes only this repo's generated paths
(none today — the central exclusions already cover this repo's lockfiles and
fixture/test data). This is advisory only: it is not a required check and
never blocks a merge. A Monday run of the same workflow prints the weekly
tally of merged pull requests per size; the labels are the durable record
behind it.

## Merge policy

- Squash-merge only; the squash commit title is the PR title.
- Delete the branch on merge (automatic).
- Every PR must pass **`ci-ok` + `gitleaks` + `pr-lint` + Paperclip Review 5/5**
  before merge. These are required status checks on `main`.
- Never commit secrets. The `gitleaks` gate and push protection enforce this.
