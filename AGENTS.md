# AGENTS.md

Guidance for AI coding agents working in this repository.

Cross-repo status, decisions, and the handover routine shared by all AI tools live outside this repository in `../AGENTS.md`, `../status.md`, and `../decisions.md` (local only, never pushed). Read them at the start of a session.

This repository is the single source of truth for everything exchanged between
the OpenVIBES Agent and the platform's ingest and distribution services.

- `spec/contracts-v1.md` is authoritative; `schemas/v1/` must agree with it.
- Every message has valid and invalid fixtures in `fixtures/v1/<message>/`;
  `valid*` must pass and `invalid*` must fail. Check with
  `python3 tools/validate.py` after installing `tools/requirements.txt`.
- Any contract change updates `PLAN.md` for both sides in the same commit.
- The agent pins this repository as a submodule and tests every fixture against
  its Rust types; a new message needs a matching agent change.
