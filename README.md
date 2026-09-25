<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/brand/openvibes-wordmark-dark.svg">
    <img src="docs/brand/openvibes-wordmark-light.svg" alt="OpenVIBES" width="560">
  </picture>
</p>

<h3 align="center">OpenVIBES Protocol</h3>

<p align="center">
  The contract between the OpenVIBES agent and platform: one spec, JSON
  Schemas, and shared fixtures that both sides test against.
</p>

---

## What OpenVIBES is

OpenVIBES (Open Vulnerability Inspection &amp; Baseline Evaluation System) is
an open-source, self-hosted vulnerability and configuration auditing system
for fleets of **1,000 to 50,000 hosts**. A small, read-only agent on every
host collects facts, evaluates signed audit rules against them, and reports
the results over mutually authenticated TLS. The platform keeps agent
identities, distributes rules, matches every host's packages against
security advisories, and ranks what to fix. No vendor cloud, no telemetry,
and air-gapped hosts are supported.

## The repositories

| Repository | What it is |
|---|---|
| [openvibes-agent](https://github.com/openvibes-project/openvibes-agent) | The endpoint agent (Rust; Linux, Windows, macOS): collectors, signed-rule evaluation, a durable local queue, and the mTLS client. |
| [openvibes-platform](https://github.com/openvibes-project/openvibes-platform) | The server side: ingest (port 18423), rule distribution (18424), vulnerability matching and enrichment, the admin CLI, the built-in PKI, packaging, and, in progress, the web console with its AI assistant. |
| **openvibes-protocol** (this one) | Everything that crosses the agent–platform boundary. Both other repositories pin it as their `protocol/` submodule and run its fixtures in their tests, so a contract change lands here first. |

## What the protocol covers

Version 1, all specified with schemas and fixtures:

| Message | Direction | Endpoint | Status |
|---|---|---|---|
| Enrollment and renewal | agent → ingest | `/v1/enroll` (token), `/v1/renew` (mTLS) | Built on both sides |
| Heartbeat, with enabled collectors | agent → ingest | `/v1/heartbeat` | Built on both sides |
| Finding batches and per-finding acknowledgement | agent → ingest | `/v1/findings` | Built on both sides |
| Inventory report (OS, packages, running kernel) | agent → ingest | `/v1/inventory` | Built on both sides |
| Structured errors, including `identity_revoked` | ingest → agent | any mTLS call | Built on both sides |
| Signed rule bundles | agent → distribution | `/v1/rule-bundle`, port 18424 | Built on both sides |
| Finding and inventory export files | agent → file → platform | file import | Agent built; platform import planned |
| Enrollment token, platform CA, rule-signing keys | operator → agent | out of band (install time) | Built |

Also fixed by the spec:

- **Signing:** the signing-preimage byte format and how finding IDs are
  derived.
- **Resource limits:** bytes, depth, strings, and collections, in V1.
- **Identity:** a random `install_id` per installation for local-only
  agents.

Rule-signing keys never travel over the protocol, so a compromised platform
cannot make agents trust new rules.

## Planned

- **P10, dpkg source packages:** the spec and schema are done, and the
  agent reports them (openvibes-project/openvibes-agent#11). The platform
  will match Debian and Ubuntu hosts by source package via OSV.dev.
- **Platform import of export files** (P3): findings and inventory from
  air-gapped hosts, stored as imported and unauthenticated. Agent-signed
  exports may come in a later version.
- **Match start and end:** report when a match starts and ends instead of
  on every scan, to cut finding volume at 50,000 hosts.
- **Trust-root rotation:** rotate rule-signing keys and the platform CA
  without reinstalling agents (open question 6 in [`PLAN.md`](PLAN.md)).
- **Online upload of further fact families** beyond packages (open
  question 3).

## Scope and routes

This repository is the single source of truth for everything exchanged
between the [OpenVIBES Agent](https://github.com/openvibes-project/openvibes-agent)
and the OpenVIBES Platform's **ingest** and **distribution** services, and
the synced plan both sides build against.

```
Online:      Agent --- HTTPS + mTLS, port 18423 --->  Ingest service --> platform storage
             Agent <-- HTTPS + mTLS, port 18424 ----  Distribution service (signed rule bundles)
Local-only:  Agent --- export file ---- (import) --->  Ingest service --> platform storage
```

The ingest service (formerly called the collector service; the agent's
*collectors* are something else: they read host facts) only receives data from
agents and stores it. It does
not process, correlate, or forward anything. Rule bundles reach agents from a separate
**distribution service**, so the ingest service stays receive-only. The platform's other modules
(correlation, third-party and CMDB integration, the web interface on 443) work
from platform storage on their own and never talk to agents. Only the agent's boundaries
with the ingest service and the distribution service are specified here; everything behind storage is out of
scope.

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
