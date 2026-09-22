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

The spec is language-neutral. The agent's Rust types in `openvibes-core` are a
reference implementation, not the definition; JSON Schemas and shared fixtures
for other implementations are the next milestone.

Licensed under the [MIT License](LICENSE).
