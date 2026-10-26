# AGENTS.md

Guidance for AI coding agents working in this repository.

Work, status and binding decisions live on the [OpenVIBES project board](https://github.com/orgs/openvibes-project/projects/1): one issue per epic, feature or task (labels `type:*`, `area:*`, nested as sub-issues), and one closed `type:decision` issue per ruling (the board's *Decisions* view). Read the issue you work on, its parent and the relevant decisions at the start of a session; write progress and hand-offs as issue comments, and link PRs with `Closes #N`. The local handover routine shared by all AI tools is in `../AGENTS.md`.

This repository is the single source of truth for everything exchanged between
the OpenVIBES Agent and the platform's ingest and distribution services.

- `spec/contracts-v1.md` is authoritative; `schemas/v1/` must agree with it.
- Every message has valid and invalid fixtures in `fixtures/v1/<message>/`;
  `valid*` must pass and `invalid*` must fail. Check with
  `python3 tools/validate.py` after installing `tools/requirements.txt`.
- Any contract change updates `PLAN.md` for both sides in the same commit.
- The agent pins this repository as a submodule and tests every fixture against
  its Rust types; a new message needs a matching agent change.
