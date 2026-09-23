# OpenVIBES Protocol Contracts, Version 1

Wire contracts between the OpenVIBES Agent ("scanner") and the platform's
ingest service, including the local-only export file. Rust reference types live in the agent's
`openvibes-core` crate; this document is authoritative.

## Compatibility Policy

Every top-level wire document contains a required numeric `schema_version`.
Version 1 payload readers ignore additional object fields so optional fields can
be introduced compatibly. The outer signed envelope rejects unknown fields:
its signing format covers a fixed field set, so extra fields must never be
mistaken for authenticated metadata. Envelope extensions require a new signing
format and schema version. Readers reject unknown enum values, missing required
fields, invalid bounded values, and any unsupported schema version.

Inputs are size-checked before JSON or YAML decoding and semantically validated
immediately afterward. Deserialization alone does not make a document trusted.

## Identifier and Time Encoding

Identifiers contain 1 to 128 ASCII letters, digits, dots, underscores, colons,
or hyphens. They never contain paths, whitespace, control characters, or
user-facing text.

Timestamps are signed integers containing milliseconds since the Unix epoch.
Clock-based acceptance windows are enforced by the component consuming the
document; structural validation additionally requires rule-envelope expiration
to be later than creation.

## Fact Model

Version 1 facts are deliberately typed and cannot contain arbitrary nested
objects. Supported values are booleans, signed 64-bit integers, strings, and
lists of strings. Each fact has a stable namespaced key and source collector.
A fact set also carries structured collector errors so partial scans remain
observable.

The CEL binding is a flat map named `facts`, from each canonical key to its
unwrapped typed value. For example, `process.names` is a string-list fact and
the example rule uses `'sshd' in facts['process.names']`. A string-list fact
holds at most 10,000 values, sorted by byte order without duplicates; an
evaluator refuses any other list, and `in` is a binary search over it. A missing fact, or one
whose collector reported an error, produces an unavailable result rather than
silently implying compliance.

The approved subset is `facts['<literal key>']`, Boolean/integer/string
literals, `!`, unary `-`, `&&`, `||`, `==`, `!=`, `<`, `<=`, `>`, `>=`, and
`string in string_list`. Other identifiers, functions, macros, member access,
and triple-quoted strings are rejected. Every referenced fact and operand type
is checked before execution, including branches a short circuit would skip.

## Rules and Findings

A rule set contains declarative CEL rules with stable IDs, positive monotonic
versions, severity, confidence from 0 to 100, a bounded expression, and a
finding message. JSON and YAML examples live beside the agent's contract tests
(until they move to `fixtures/` here, see [`PLAN.md`](../PLAN.md)):

- `openvibes-agent/crates/openvibes-core/tests/fixtures/rule-set-v1.json`
- `openvibes-agent/crates/openvibes-core/tests/fixtures/rule-set-v1.yaml`

A finding records the generating scan, exact rule ID and version, severity,
confidence, message, and bounded evidence fact keys. Its ID is generated once,
persisted with the queue record, and reused for every delivery attempt.

## Signed Rule Envelope

The signature covers a deterministic, domain-separated preimage. Version 1 is:

1. ASCII `OPENVIBES-RULE-ENVELOPE-V1` followed by a zero byte.
2. Schema version as an unsigned 16-bit big-endian integer.
3. Rule-set ID as unsigned 32-bit big-endian byte length plus UTF-8 bytes.
4. Rule-set version as an unsigned 64-bit big-endian integer.
5. Issuer key ID as unsigned 32-bit big-endian byte length plus UTF-8 bytes.
6. Creation and expiration times as signed 64-bit big-endian integers.
7. Encoding byte: `1` for JSON or `2` for YAML.
8. Payload as unsigned 64-bit big-endian byte length plus exact UTF-8 bytes.
9. Raw 32-byte SHA-256 payload digest.

The signature field is excluded from the preimage. The digest is lowercase
hexadecimal on the wire. The 64-byte Ed25519 signature is encoded as unpadded
base64url. The payload string is the exact UTF-8 byte sequence after outer JSON
string decoding; JSON escape spelling and envelope field order are not signed.
Payload whitespace and line endings are signed and must not be normalized.

The loader first parses a bounded JSON envelope and checks its fields and the
expected rule-set identity. It resolves a trusted key scoped to that identity,
checks the SHA-256 digest, and verifies Ed25519 strictly. It checks time and
rollback policy before parsing the authenticated payload as JSON or YAML.

### Trust, Time, and Accepted Versions

`RuleLoader` takes provisioned `TrustedRuleKey` records, each containing a
rule-set ID, issuer-key ID, and Ed25519 public key. Weak public keys and duplicate
scope/key identifiers are rejected. Keys carried in incoming bundles are never
trusted. No private signing key is required by the scanner.

`LoadContext` supplies the expected rule-set ID, trusted current Unix time, and
the last accepted version. Validity is `created_at <= now < expires_at`, with no
implicit clock-skew grace period. Negative clock values and state for another
rule set are rejected.

The acceptance record contains the rule-set ID, version, and SHA-256 of the
entire signing preimage. A lower version is rejected. An equal version is
accepted only when the preimage digest is identical, allowing reload after
restart without allowing new content under the same version. Changing expiry,
issuer, encoding, or payload requires a higher version.

The loader performs no I/O. The composition root must atomically persist the
accepted bundle and record, serialize concurrent acceptance, and restore that
record before future loads. A missing/corrupted record after prior enrollment
must not be treated as first use. An identical cached bundle still requires a
currently trusted key and an unexpired signature interval. The agent persists
accepted bundles and records durably; authenticated trust-root rotation remains
open.

### Parser Boundaries

The JSON envelope and decoded payload each have a 1 MiB byte ceiling. Envelope
metadata and JSON escaping count toward the outer ceiling, so a payload near
1 MiB may not fit within an envelope.

A common bounded visitor traverses every JSON/YAML value, including ignored
optional fields, and limits depth, nodes, collection lengths, individual
strings, and aggregate decoded string bytes. Duplicate keys and trailing
documents are rejected. CEL expressions receive their separate 16 KiB allowance
only in the rule expression field. Parser error output does not echo input.

YAML additionally limits events, retained anchors, alias replay, comments, and
scalar bytes. Merge keys, unsupported tags, and external includes are rejected;
property interpolation and include features are disabled. An entire-stream
preflight also rejects malformed content following an explicit `...` end marker.

Only a successful load creates `VerifiedRuleSet`, whose fields are private and
whose rule access is immutable. It proves authentication and contract validity
at load time; it does not prove CEL syntax, types, or evaluation budgets.
`Evaluator` accepts only this type and rechecks expiry throughout evaluation.

## Machine-Readable Schemas

`schemas/v1/` holds a JSON Schema for every message below, and
`fixtures/v1/` holds valid and invalid examples of each. Where this document
and a schema disagree, this document wins and the schema is a bug. Rules no
schema can state (byte limits on non-ASCII text, cross-field comparisons,
unique rule IDs, digests, signatures) are defined only here.

## Platform HTTP API

All requests are `POST` with a JSON body of the named contract, sent over
HTTPS to the configured platform base URL. The agent API listens on its own
port, 18423, used whenever the base URL names no port; an explicit port (for
example `:443` on networks that only allow web ports) overrides it. The
platform's web interface is a separate service on 443 and is never contacted
by scanners. The scanner uses TLS 1.3 only,
trusts only the configured platform CA bundle (never system roots), follows no
redirects, ignores proxy environment variables, and reads at most one
serialized document of response body. Every response is validated before use.

| Path | Client certificate | Request | Success response |
|---|---|---|---|
| `/v1/enroll` | none | `EnrollmentRequest` | `EnrollmentResponse` |
| `/v1/renew` | required | `RenewalRequest` | `EnrollmentResponse` |
| `/v1/findings` | required | `FindingBatch` | `DeliveryAcknowledgement` |
| `/v1/heartbeat` | required | `Heartbeat` | any 2xx; body ignored |

`EnrollmentRequest.csr_pem` is a PEM PKCS#10 request signed by a fresh
ECDSA P-256 host key; its signature proves possession of the key being
certified. The CSR subject is empty: the platform assigns `agent_id` and binds
it into the issued certificate. A token is consumed when a certificate is issued
for it. Repeating the request with the same token and a CSR for the same public
key before the token expires returns the same identity (ECDSA CSRs are
randomized, so a retried CSR is never byte-identical), so a lost response can be retried;
any other reuse is refused with 401.

`FindingBatch` holds one to `delivery_batch_items` findings in queue order.
The platform acknowledges each finding it has durably accepted, including
duplicates of findings it accepted before, so delivery is idempotent.

`Heartbeat.hostname` is the optional, bounded host name the operating system
reports. It is an operator-facing label only: it is spoofable, may change,
and is never used to authenticate or authorise the agent. It is absent when
the agent cannot obtain a non-empty UTF-8 name. When present, ingest records it
as the latest reported hostname for the authenticated `agent_id`.

Renewal: once two thirds of a certificate's lifetime has passed, measured
from the scanner's local time when it obtained the certificate, the scanner
sends a CSR for a new key, authenticated by the current certificate. The
platform must issue for the same `agent_id`; the scanner rejects any other and
keeps its identity. Using the local clock for both ends of the interval makes
the schedule independent of platform clock skew.

Status handling: 2xx is success. 401 and 403 mean the credentials were
refused. Revocation is signalled only by a 401 or 403 whose body is a
`PlatformError` with code `identity_revoked`; the scanner then deletes its
identity, keeps its queued findings, and waits for a new enrollment token. A
bare 401 or 403, an unknown code, or an unsupported schema version never
deletes the identity, so a misconfigured proxy or load balancer cannot strand
a scanner. The platform must complete the TLS handshake for any certificate
its CA issued and answer at the HTTP level, because a TLS 1.3 post-handshake
rejection races the request write and is indistinguishable from a network
failure. Any other status, including 3xx, is a rejected request.

## Rule Distribution

Signed rule bundles come from the platform's **distribution service**, never
from the ingest service. The agent reaches it at its own configured
`distribution_url`, which follows the same rules as the platform base URL
except that its default port is **18424**. The agent trusts the same platform
CA bundle and authenticates with the same client certificate as for ingest.

| Path | Client certificate | Request | Success response |
|---|---|---|---|
| `/v1/rule-bundle` | required | `RuleBundleRequest` | `200`: `SignedRuleEnvelope`; `204`: none |

`RuleBundleRequest` names one `rule_set_id` and, when the agent has accepted
that rule set before, its `current_version`. The service answers `200` with
the rule set's current envelope, byte for byte as signed, if its version is
higher than `current_version` (or `current_version` is absent), and `204`
with no body otherwise. A rule set the service does not know is `404`.
Status handling, including revocation, is the same as for the ingest service.

Assignment is local. The agent asks only for the rule sets named in its own
configuration, each with its own trusted keys, and polls once before every
scan. A distribution service therefore cannot add, remove, or re-scope rule
sets, and cannot sign rules: it serves envelopes signed offline. The worst it
can do is withhold updates or serve refused bundles.

Every fetched envelope goes through the same loader and rollback floor as a
provisioned file. A refused envelope (bad signature, untrusted issuer,
expired, lower version, or different content under an accepted version)
never replaces the last accepted bundle, which the agent keeps evaluating
while it is still valid. A failed request is retried at the next scan.
Local-only and not yet enrolled agents never contact the distribution service.

## Local-Only Export

An agent with no platform configured never uses the network. Its findings stay
in its durable queue until an operator runs the agent's export command, which
writes them to files for the ingest service to import later.

Each file is one `FindingExport` document: `schema_version`, `install_id`, an
optional `agent_id`, an optional `hostname`, `scanner_version`,
`exported_at_unix_ms`, and one to `delivery_batch_items` findings in queue
order. The serialized document is bounded by the 1 MiB document limit.

- `install_id` is a random identifier the agent generates once, on first start,
  and keeps in its state directory. It survives enrollment and revocation,
  so the ingest service can link imports from a host that enrolls later.
- `agent_id` is present only while the agent holds a platform identity.
- `hostname` is the name the OS reports, for operators recognising the host.
  It is absent when unavailable and is never used for authentication.

Export consumes: each file is written and flushed to disk before its findings
are marked acknowledged in the queue, so a finding appears in exactly one
completed file. An interrupted export leaves at most one incomplete file, which
fails validation, and its findings stay queued for the next export. The agent
never overwrites an existing file. Losing an exported file loses its findings.

Version 1 exports are **unsigned**: a file has no mTLS channel, and a
never-enrolled host has no key the platform trusts. The ingest service validates an
import exactly like a `FindingBatch`, stores its findings marked as imported
and unauthenticated, including the `install_id` it came from, and never lets
an import update or authenticate an enrolled agent's identity. Import is
idempotent on `finding_id` within an `install_id`. A later schema version may
add a signature for enrolled agents.

### Inventory Export

The same export command also writes one `InventoryExport` file per run: a
snapshot of the host's installed packages, taken at export time, beside the
`FindingExport` files. It carries `install_id`, optional `agent_id` and
`hostname`, `scanner_version`, `collected_at_unix_ms`, and up to 10,000
`packages`, within the 1 MiB document limit. Each package names its `manager`
(`rpm` or `dpkg`), `name`, and upstream `version`, and optionally its
distribution `release`, `epoch`, `arch`, and the `vendor` its database
records. Package records are copied from the package database and are
neither verified nor normalised to CPE names.

An inventory export is unsigned and stored like an imported finding export.
It does not consume anything: every export writes a fresh snapshot. When the
package collector fails, no inventory file is written and the export command
reports the failure. Online inventory upload is not specified yet.

## Initial Resource Limits

| Resource | Version 1 limit |
|---|---:|
| Serialized document | 1 MiB |
| Document nesting depth | 32 |
| Parsed rule-document values and mapping keys | 20,000 |
| Aggregate decoded string bytes per document | 1 MiB |
| General string | 4 KiB |
| Identifier | 128 bytes |
| Facts per scan | 10,000 |
| Rules per set | 512 |
| YAML alias replay | 10,000 events, depth 16, 64 expansions per anchor |
| CEL expression | 16 KiB |
| General list | 1,024 items |
| String-list fact | 10,000 items, sorted and unique |
| Evidence per finding | 128 keys |
| CEL operations per rule | 50,000 |
| CEL expression depth | 32 |
| Evaluation wall time | 100 ms |
| Complete scan | 300 seconds |
| SQLite queue | 256 MiB |
| Queue retention | 30 days |
| Delivery batch | 500 findings |
| Retry delay | 15 seconds to 1 hour, with equal jitter (half to all of the delay) |
| Platform connect, including TLS | 10 seconds |
| Platform request, end to end | 60 seconds |

These are security limits, not performance targets. Raising them requires test
coverage and a resource-exhaustion review.

The loader accepts tighter limits but rejects zero general limits or limits
above these safety ceilings. Alias limits can be set to zero to disable replay.
The evaluator enforces the CEL expression, operation, depth, evidence, fact
input, and wall-time limits. The SQLite queue enforces the queue, retention, batch, and retry limits, and
the transport enforces the document and network limits on every request. Scan
deadlines will be enforced by the scan scheduler.
