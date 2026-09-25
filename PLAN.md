# Synced Agent–Platform Plan

The ingest service is receive-only: it accepts agent data and stores it.
Anything sent to agents beyond replies to their own requests (rule bundles)
comes from a separate distribution service.

What crosses the boundary between the OpenVIBES Agent and the platform's
ingest and distribution services, what each side has built, and the order both sides deliver
in. Update this file in the same change as any contract change.

Status: **done** (implemented and tested), **todo** (specified, not built),
**design** (not yet specified), **n/a** (no work on that side).

## Routes

1. **Online.** The agent connects to the ingest service over HTTPS with mutual TLS
   on port 18423 (explicit port overrides it). Only the agent initiates
   connections; the ingest service never calls the agent.
2. **Local-only.** An agent without a configured platform never touches the
   network. It keeps findings in its own state and exports them to a file on
   request. The ingest service may later import such files, for example from
   air-gapped hosts.

## Message Inventory

| # | Message | Direction | Route | Endpoint | Agent | Ingest |
|---|---|---|---|---|---|---|
| 1 | `EnrollmentRequest` → `EnrollmentResponse` | agent → ingest | online | `/v1/enroll`, no client cert | done (key reuse, refused token after revocation) | done (multi-use tokens, revoked-key refusal) |
| 2 | `RenewalRequest` → `EnrollmentResponse` | agent → ingest | online | `/v1/renew`, mTLS | done (expiry re-enrollment) | done |
| 3 | `Heartbeat` | agent → ingest | online | `/v1/heartbeat`, mTLS | done | done |
| 4 | `FindingBatch` → `DeliveryAcknowledgement` | agent → ingest | online | `/v1/findings`, mTLS | done (`rejected_findings`) | done (per-finding refusal) |
| 5 | `PlatformError` (`identity_revoked`) | ingest → agent | online | 401/403 body on any mTLS call | done | done |
| 6 | `RuleBundleRequest` → `SignedRuleEnvelope` (rule bundles) | agent → distribution | online | `/v1/rule-bundle` on the distribution service (port 18424), mTLS | done | done (openvibes-distribution) |
| 7 | `FindingExport` file | agent → file → ingest | local-only | file import | done | todo |
| 7a | `InventoryExport` file | agent → file → ingest | local-only | file import | done | todo |
| 8 | Enrollment token | operator → agent | out of band | token file | done | done (issuance, single- and multi-use) |
| 9 | Platform CA bundle | operator → agent | out of band | config file | done | done (built-in PKI) |
| 10 | Rule-signing trust keys | operator → agent | out of band | agent config | done (per rule set) | n/a |

Items 8–10 never travel over the agent protocol: they are provisioned at
install time. In particular, rule-signing keys are not distributed by the
ingest service, so a compromised ingest service cannot make agents trust new rules.

## Ingest Service Obligations Already Fixed by the Spec

The agent is built and tested against these; the ingest service must honour them.

- TLS 1.3, a server certificate chaining to the CA the agent is configured
  with, and client certificates issued by the platform CA.
- Complete the TLS handshake for any certificate the platform CA issued, and
  signal refusal at the HTTP level. Rejecting a revoked client during the
  handshake is not reliably detectable by the agent.
- Revocation is only a 401/403 carrying `PlatformError` with code
  `identity_revoked`. A bare 401/403 means "refused, keep your identity".
- Enrollment tokens have a number of uses (one by default; more for fleet
  tokens). A retry with the same token and a CSR for the same public key
  returns the same identity without consuming a use, unless that agent was
  revoked (401). A new key consumes a use; none left, expired, or revoked
  is 401.
- Renewals must be issued for the requesting agent's `agent_id`.
- Findings are acknowledged per ID once durably stored, including duplicates
  of findings stored earlier; delivery is idempotent on `finding_id`. A
  finding refused permanently is acknowledged too and listed in
  `rejected_findings` with a reason; one finding never fails its batch.
- A heartbeat may carry the OS-reported `hostname`; ingest stores the latest
  present value as an operator label and never uses it for authorisation.
- Never answer with a redirect; agents treat 3xx as a rejected request.
- Validate every request against the V1 limits before trusting it.

## Paired Milestones

Each milestone lists both sides. It is complete when both sides are done and
a real agent passes against a real ingest service, not only against mocks.

### P0: Contract source (this repository)

- [x] Move the wire contracts from the agent repository into `spec/`.
- [x] JSON Schema (draft 2020-12) for every specified message
  (`schemas/v1/`).
- [x] Shared fixtures: valid and invalid examples per message
  (`fixtures/v1/`), checked against the schemas by `tools/validate.py` in CI.
- [x] One-off cross-check: the agent's Rust types accept every valid fixture
  and reject every invalid one. It found and fixed one gap (`rule_version: 0`
  was accepted in findings).
- [x] Agent CI runs that cross-check on every change: the agent pins this
  repository as its `protocol/` submodule and tests every fixture against its
  contract types.
- [x] Ingest service tests use the same fixtures (`openvibes-platform` pins
  this repository as `protocol/`). Both sides share `openvibes-core` types,
  so these tests cannot catch a divergence between them; the schemas and
  `tools/validate.py` are the independent check.

### P1: Online ingest

- Agent: done (enrollment, heartbeat, mTLS delivery, retries).
- [x] Ingest service: `/v1/enroll`, `/v1/heartbeat`, `/v1/findings`, durable
  storage before acknowledging, request limits (`openvibes-platform`
  sub-project 1).
- [x] Ingest service: store an optional heartbeat `hostname` as the agent's
  latest operator label, never as identity.
- [x] Platform: CA and token issuance.
- [x] Cross-repository integration test: a real agent enrolls, delivers a
  finding once, and reconnects after restart (`scripts/integration-agent.sh`,
  in platform CI).

### P2: Identity lifecycle

- Agent: done (renewal at two thirds of the lifetime, revocation recovery).
- [x] Ingest service: `/v1/renew`; revoking an agent returns `identity_revoked` on
  its next request.
- [x] Integration test: renew, revoke, re-enroll with a new token.

### P3: Local-only route

- [x] Agent: standalone mode when no platform is configured; no network use.
- [x] Specify the export file format: `FindingExport`, the findings of one
  delivery batch plus `install_id`, optional `agent_id` and `hostname`.
  Unsigned in version 1; export consumes the exported findings.
- [x] Agent: `export` command writing that format (plus `InventoryExport`).
- [ ] Ingest service: import path, with imported findings marked as such.

### P4: Rule distribution

- [x] Specify how agents fetch signed rule bundles: `RuleBundleRequest` to
  `/v1/rule-bundle` on the distribution service (default port 18424), one
  request per configured rule set before each scan, `204` when nothing is
  newer.
- [x] Agent: fetch, verify, persist through the existing `RuleStore`.
- [x] Distribution service: a separate platform service, not the ingest service,
  serves bundles signed offline and never holds the signing key. The agent
  pulls from it over mTLS with the same client identity.

### P5: Review follow-up (2026-09-24)

Decided after the cross-repository review. Done in agent `3f8fc10` and
platform `931d365`.

- [x] Agent: store the host key before the first enrollment attempt and reuse
  it until enrollment succeeds.
- [x] Agent: never enroll again with the token of a revoked identity.
- [x] Agent: when the certificate has expired by the local clock, delete the
  identity (keep the queue) and enroll with the token file.
- [x] Agent: read `rejected_findings`; remove every acknowledged finding and
  count the rejected ones by reason.
- [x] Agent: refuse U+0000 in every text field.
- [x] Agent: an inventory over either limit is reported and skipped; finding
  export files are written regardless.
- [x] Ingest: answer a batch finding by finding (`future_observation` beyond
  1 hour, `retention_expired`, `out_of_range`, `unstorable`); never fail a
  batch for one finding.
- [x] Ingest: a same-key retry for a revoked agent is 401.
- [x] Integration test: expired-certificate re-enrollment runs with the real
  agent (`scripts/integration-agent.sh`). The lost-response retry and the
  future-dated finding are covered by each side's own tests (agent
  `tests/enrollment.rs`, platform `tests/delivery.rs`).

### Review follow-up, remaining (2026-09-24)

- [x] Spec: a heartbeat's `agent_id` must be the authenticated agent's (400
  otherwise); enrollment and heartbeat cadence stated.
- [x] `tools/validate.py`: every invalid fixture fails with exactly one
  schema error.
- [x] Agent: delivery batches stay under the 1 MiB document limit (sized by
  bytes as well as count).

### P6: Findings name their rule set (user, 2026-09-24)

- [x] Spec and schema: `Finding.rule_set_id` (optional in v1 for earlier
  senders; scanners always send it).
- [x] Agent: set `rule_set_id` from the verified bundle that produced the
  finding (agent `ed5cbb1`).
- [x] Ingest: store it; current state per agent, rule set, and rule
  (platform `3e21065`, migration 5; the integration test checks the real
  agent's findings).

### P7: Heartbeats report enabled collectors (user, 2026-09-24)

- [x] Spec: `Heartbeat.capabilities` names the enabled features; version 1
  defines `collector.processes`, `collector.packages`, `collector.ports`;
  readers ignore unknown identifiers. Fixture `valid-collector-capabilities`.
- [x] Agent: optional `collectors` setting; run only those; report them as
  capabilities (agent `e0f4240`).
- [x] Ingest: stores the list per agent (`agents.capabilities`), and a
  changed list at once (platform `149bda7`).

### P8: Inventory reports for vulnerability matching (user, 2026-09-25)

- [x] Spec and schema: `InventoryReport` on `POST /v1/inventory` (os-release
  `id` and `version_id`, up to 10,000 packages, on change only); heartbeat
  capability `inventory.packages`. Fixtures `inventory-report/*`.
- [x] Agent: os-release collector; send on change; retry on failure
  (openvibes-agent #7).
- [x] Ingest: store compactly; notify the vulnerability service
  (openvibes-platform #17).

### P9: Running kernel in inventory reports (user, 2026-09-25)

A kernel fix counts only once the host runs it; until a reboot the platform
shows "fix installed, reboot needed".

- [x] Spec and schema: optional `running_kernel` (`uname -r`) in
  `InventoryReport`, part of the content that decides whether to send.
- [x] Agent: report the running kernel (openvibes-agent #8).
- [x] Platform: store it; reboot-needed state for kernel advisories
  (openvibes-platform #20).

## Open Questions

1. ~~**Export provenance.**~~ Decided 2026-09-23: version 1 exports are
   unsigned; the ingest service stores imports as imported and unauthenticated.
   Signing by enrolled agents may come in a later schema version.
2. ~~**Local-only identity.**~~ Decided 2026-09-23: a random `install_id`
   generated once per installation, plus `agent_id` when enrolled and the OS
   hostname for operators. Other host facts wait for question 3.
3. **Inventory upload.** Partly decided 2026-09-23: installed packages leave
   the agent as an `InventoryExport` file on the local-only route (up to
   10,000 packages, 1 MiB). Online upload to the ingest service, and any
   other fact families, are still open.
4. ~~**Rule-set assignment.**~~ Decided 2026-09-23: local. Each agent's
   configuration names its rule sets and their trusted keys; the agent asks
   the distribution service for exactly those.
5. ~~**Distribution service address.**~~ Decided 2026-09-23: configured as
   `distribution_url`, default port 18424, same platform CA and client
   certificate as ingest.
6. **Trust-root rotation.** How rule-signing keys and the platform CA are
   rotated without reinstalling agents.
