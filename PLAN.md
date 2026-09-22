# Synced Agent–Collector Plan

What crosses the boundary between the OpenVIBES Agent and the platform's
collector service, what each side has built, and the order both sides deliver
in. Update this file in the same change as any contract change.

Status: **done** (implemented and tested), **todo** (specified, not built),
**design** (not yet specified), **n/a** (no work on that side).

## Routes

1. **Online.** The agent connects to the collector over HTTPS with mutual TLS
   on port 18423 (explicit port overrides it). Only the agent initiates
   connections; the collector never calls the agent.
2. **Local-only.** An agent without a configured platform never touches the
   network. It keeps findings in its own state and exports them to a file on
   request. The collector may later import such files, for example from
   air-gapped hosts.

## Message Inventory

| # | Message | Direction | Route | Endpoint | Agent | Collector |
|---|---|---|---|---|---|---|
| 1 | `EnrollmentRequest` → `EnrollmentResponse` | agent → collector | online | `/v1/enroll`, no client cert | done | todo |
| 2 | `RenewalRequest` → `EnrollmentResponse` | agent → collector | online | `/v1/renew`, mTLS | done | todo |
| 3 | `Heartbeat` | agent → collector | online | `/v1/heartbeat`, mTLS | done | todo |
| 4 | `FindingBatch` → `DeliveryAcknowledgement` | agent → collector | online | `/v1/findings`, mTLS | done | todo |
| 5 | `PlatformError` (`identity_revoked`) | collector → agent | online | 401/403 body on any mTLS call | done | todo |
| 6 | `SignedRuleEnvelope` (rule bundles) | collector → agent | online | not yet specified | design (loader and store done) | design |
| 7 | Finding export file | agent → file → collector | local-only | file import | design | design |
| 8 | Enrollment token | operator → agent | out of band | token file | done | todo (issuance) |
| 9 | Platform CA bundle | operator → agent | out of band | config file | done | todo (PKI) |
| 10 | Rule-signing trust keys | operator → agent | out of band | agent config | design | n/a |

Items 8–10 never travel over the agent protocol: they are provisioned at
install time. In particular, rule-signing keys are not distributed by the
collector, so a compromised collector cannot make agents trust new rules.

## Collector Obligations Already Fixed by the Spec

The agent is built and tested against these; the collector must honour them.

- TLS 1.3, a server certificate chaining to the CA the agent is configured
  with, and client certificates issued by the platform CA.
- Complete the TLS handshake for any certificate the platform CA issued, and
  signal refusal at the HTTP level. Rejecting a revoked client during the
  handshake is not reliably detectable by the agent.
- Revocation is only a 401/403 carrying `PlatformError` with code
  `identity_revoked`. A bare 401/403 means "refused, keep your identity".
- Enrollment tokens are single-use. A retry with the same token and a CSR for
  the same public key returns the same identity; any other reuse is 401.
- Renewals must be issued for the requesting agent's `agent_id`.
- Findings are acknowledged per ID once durably stored, including duplicates
  of findings stored earlier; delivery is idempotent on `finding_id`.
- Never answer with a redirect; agents treat 3xx as a rejected request.
- Validate every request against the V1 limits before trusting it.

## Paired Milestones

Each milestone lists both sides. It is complete when both sides are done and
a real agent passes against a real collector, not only against mocks.

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
- [ ] Collector tests use the same fixtures.

### P1: Online ingest

- Agent: done (enrollment, heartbeat, mTLS delivery, retries).
- [ ] Collector: `/v1/enroll`, `/v1/heartbeat`, `/v1/findings`, durable
  storage before acknowledging, request limits.
- [ ] Platform: CA and single-use token issuance.
- [ ] Cross-repository integration test: a real agent enrolls, delivers a
  finding once, and reconnects after restart.

### P2: Identity lifecycle

- Agent: done (renewal at two thirds of the lifetime, revocation recovery).
- [ ] Collector: `/v1/renew`; revoking an agent returns `identity_revoked` on
  its next request.
- [ ] Integration test: renew, revoke, re-enroll with a new token.

### P3: Local-only route

- [ ] Agent: standalone mode when no platform is configured; no network use.
- [ ] Specify the export file format. It reuses `FindingBatch`, wrapped with
  export metadata (see open questions).
- [ ] Agent: `export` command writing that format.
- [ ] Collector: import path, with imported findings marked as such.

### P4: Rule distribution

- [ ] Specify how agents fetch signed rule bundles (endpoint, polling, what the
  agent sends about its current versions).
- [ ] Agent: fetch, verify, persist through the existing `RuleStore`.
- [ ] Collector: serve bundles signed offline; the collector never holds the
  signing key.

## Open Questions

1. **Export provenance.** An imported file is not authenticated by mTLS.
   Should an enrolled agent sign its exports with its host key, and how does
   the collector treat unsigned files from never-enrolled agents?
2. **Local-only identity.** A never-enrolled agent has no `agent_id`. What
   identifies the host in an export: a generated local ID, host facts, or
   both?
3. **Inventory upload.** Correlation and CMDB matching may want host facts,
   not only findings. Do agents send fact snapshots, and under what size and
   privacy limits?
4. **Rule-set assignment.** How does the collector decide which rule sets an
   agent receives, and does the agent report which ones it runs?
5. **Trust-root rotation.** How rule-signing keys and the platform CA are
   rotated without reinstalling agents.
