# OpenVIBES Protocol

The single source of truth for everything exchanged between the
[OpenVIBES Agent](https://github.com/openvibes-project/openvibes-agent) and the
OpenVIBES Platform's **collector service**, and the synced plan both sides
build against.

```
Online:      Agent  --- HTTPS + mTLS, port 18423 --->  Collector service
Local-only:  Agent  --- export file --- (import) --->  Collector service

Collector service  --->  platform internals: storage, correlation,
                         third-party/CMDB sync, web interface (443)
```

Only the agent ↔ collector boundary is specified here. The platform's other
modules (correlation, third-party and CMDB integration, the web interface on
443) talk to each other internally and are out of scope.

- [`spec/contracts-v1.md`](spec/contracts-v1.md): the authoritative wire
  contracts, HTTP API, and resource limits.
- [`PLAN.md`](PLAN.md): every message that crosses the boundary, its status on
  each side, and the paired milestones.
- [`CONTRIBUTING.md`](CONTRIBUTING.md): how contract changes are made.

- [`schemas/v1/`](schemas/v1): JSON Schema (draft 2020-12) for every message.
- [`fixtures/v1/`](fixtures/v1): valid and invalid examples per message, for
  both implementations' tests. `valid*` files must pass, `invalid*` must fail.

The spec is language-neutral. The agent's Rust types in `openvibes-core` are a
reference implementation, not the definition. Schemas cannot express every
rule: UTF-8 byte limits (`maxLength` counts characters), cross-field rules
such as expiry after creation, unique rule IDs, digests, and signatures remain
implementation checks defined by the spec.

Check the fixtures locally:

```sh
python3 -m venv .venv && .venv/bin/pip install --no-deps -r tools/requirements.txt
.venv/bin/python tools/validate.py
```

Licensed under the [MIT License](LICENSE).
