# Dependencies

This repository holds the wire contracts: the spec, JSON Schemas, fixtures
and test vectors. It is not built into a program of its own.

Checked against `main` on 2026-10-22. Update this page in the same change
that adds, removes or bumps a dependency.

## 1. In the finished builds

Nothing here has dependencies at run time. The agent carries this
repository as its `protocol/` git submodule, and the platform gets the
agent's Rust types (`openvibes-core`) from the agent repository; their own
`docs/dependencies.md` pages list what those builds ship.

## 2. For development only

### Fixture check (`tools/validate.py`)

Python 3 with the packages in `tools/requirements.txt`, installed with
`--no-deps` and checked by hash:

| Package | Version | Licence | Used for |
|---|---|---|---|
| jsonschema | 4.26.0 | MIT | Checking fixtures against the schemas (Draft 2020-12) |
| jsonschema-specifications | 2025.9.1 | MIT | The JSON Schema meta-schemas |
| referencing | 0.37.0 | MIT | Resolving `$ref` between schemas |
| rpds-py | 2026.6.3 | MIT | Data structures under referencing |
| attrs | 26.1.0 | MIT | Classes under jsonschema and referencing |
| typing_extensions | 4.16.0 (Python older than 3.13 only) | PSF-2.0 | Typing backports |

The rest of `validate.py` uses the standard library.

### Continuous integration

| What | Version | Used for |
|---|---|---|
| GitHub runner | `ubuntu-24.04` | The fixture check |
| actions/checkout | pinned by commit | Workflow step |
