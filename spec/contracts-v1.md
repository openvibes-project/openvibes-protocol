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

Timestamps are non-negative integers containing milliseconds since the Unix
epoch.

Text fields never contain U+0000 (NUL). Readers refuse a document that does:
common stores cannot hold it, and a platform must never be handed a finding
it cannot store.
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
holds at most 10,000 values (`package.names`: 50,000, the inventory limit),
sorted by byte order without duplicates; an
evaluator refuses any other list, and `in` is a binary search over it. A missing fact, or one
whose collector reported an error, produces an unavailable result rather than
silently implying compliance.

The approved subset is `facts['<literal key>']`, Boolean/integer/string
literals, `!`, unary `-`, `&&`, `||`, `==`, `!=`, `<`, `<=`, `>`, `>=`, and
`string in string_list`. Other identifiers, functions, macros, member access,
and triple-quoted strings are rejected. Every referenced fact and operand type
is checked before execution, including branches a short circuit would skip.

**Subset v2 (P14)** adds three methods on a string operand:
`s.startsWith('lit')`, `s.endsWith('lit')` and `s.contains('lit')`. The
argument must be one plain single- or double-quoted string literal (not
raw, bytes or triple-quoted) of at most 256 bytes after escapes are
decoded (`'\x61'` is 1 byte, `'é'` is 2). Implementations must run
each method in time linear in the receiver's and the literal's length
(for example Two-Way or a similar algorithm, as Rust's `str::contains`), so
the length-based charge below bounds the real work. A loader refuses a rule with any other
argument, a non-string receiver, any other method or function (including
the global form `contains(s, 'x')` and `size`), or a non-literal map index,
so a signed rule can never carry one. Each call charges the evaluation
budget by the receiver's length: one operation per started 64 bytes (at
least one). A loader also computes each rule's worst case from the key
bounds below (for example 4,096 operations per call on the 256 KiB
`process.cmdline`) and refuses a rule whose worst case exceeds the per-rule
operation limit, so no input an attacker controls can push a signed rule
over its budget. The methods are allowed in both rule kinds. There are no
regular expressions. An agent before P14 refuses any method call as an
invalid expression, per rule, so a rule set that older agents load must not
use them. Test vectors: `vectors/cel-subset-v2.json` (`refused` = the loader
rejects the rule; `unavailable` = a referenced value is missing).

## Rules and Findings

A rule set contains declarative CEL rules with stable IDs, positive monotonic
versions, severity, confidence from 0 to 100, a bounded expression, and a
finding message. Examples live in `fixtures/v1/rule-set/`:

- `fixtures/v1/rule-set/valid.json`
- `openvibes-agent/crates/openvibes-core/tests/fixtures/rule-set-v1.yaml`

A finding records the generating scan, the rule set and the exact rule ID
and version, severity, confidence, message, and bounded evidence fact keys.
`rule_set_id` names the rule set whose verified bundle produced the finding:
rule IDs are unique only within a rule set, and each rule set has its own
trusted keys, so a finding is attributable only with it. Scanners always
send it; it is optional in schema version 1 only so that documents from
earlier senders stay valid, and a reader treats its absence as "unknown". Its ID is generated once,
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

All requests except `GET /v1/ca` are `POST` with a JSON body of the named contract, sent over
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
| `/v1/heartbeat` | required | `Heartbeat` | any 2xx; body ignored; 409 `PlatformError` `findings_resync` (P13, only when the heartbeat carried `match_sha256`) |
| `/v1/inventory` | required | `InventoryReport` | any 2xx; body ignored |
| `/v1/inventory/changes` | required | `InventoryChanges` | any 2xx; body ignored; 409 `PlatformError` `inventory_resync` |
| `/v1/findings/changes` | required | `FindingChanges` | any 2xx; body ignored; 409 `PlatformError` `findings_resync` |
| `/v1/alarms` | required | `AlarmBatch` (P14) | any 2xx; body ignored |
| `/v1/ca` (`GET`) | none | none | the platform's root CA certificate, PEM |

`GET /v1/ca` returns the root certificate that issued the platform's server
certificates, as one PEM `CERTIFICATE` block (`Content-Type:
application/x-pem-file`), or 503 when the platform has none yet. It is public
data: a client that does not trust the platform yet fetches it without
verifying the server, accepts it only if its SHA-256 (of the DER) equals a
fingerprint it got out of band (the install command), then verifies the
server against it before use. The scanner never calls it.

`EnrollmentRequest.csr_pem` is a PEM PKCS#10 request signed by a fresh
ECDSA P-256 host key; its signature proves possession of the key being
certified. The CSR subject is empty: the platform assigns `agent_id` and binds
it into the issued certificate.

An enrollment token allows a fixed number of uses: one by default, more for
tokens an operator creates to enroll a fleet (for example in a deployment
package). A use is consumed when a certificate is issued for a public key
not enrolled with that token before. The token is refused with 401 once its
uses are spent, once it expires, or once it is revoked.

Repeating the request with the same token and a CSR for the same public key
returns the same identity without consuming a use (ECDSA CSRs are randomized,
so a retried CSR is never byte-identical). This is how a lost response is
retried, so the scanner stores its host key **before** its first enrollment
attempt and reuses that key for every attempt until one succeeds. If the
agent that key was enrolled as has since been revoked, the repeated request
is refused with 401; it never returns a revoked identity.

`FindingBatch` holds one to `delivery_batch_items` findings in queue order.
`DeliveryAcknowledgement.accepted_finding_ids` lists every finding the
scanner may remove from its queue:

- findings the platform has durably stored, including duplicates of findings
  it stored before, so delivery is idempotent;
- findings the platform refuses **permanently**. Each of these is also
  listed, with a reason, in the optional `rejected_findings`.

A single finding never fails its batch. A batch that parses and validates
as a whole is answered finding by finding; only a malformed or invalid batch
is refused as a whole (400), and a platform fault (503) acknowledges nothing.
The scanner removes every acknowledged finding and counts the rejected ones
by reason, so an operator can see them: the counts are reported in
`Heartbeat.health.queue.rejected_total` (P12).

| `reason` | Meaning |
|---|---|
| `future_observation` | `observed_at_unix_ms` is more than 1 hour ahead of the platform's clock |
| `retention_expired` | older than the platform's finding retention; nothing to store it in |
| `out_of_range` | a value the platform cannot represent (for example a `rule_version` above 2^63 − 1) |
| `unstorable` | refused by the platform's store for this finding alone |

Readers ignore reasons they do not know, and still remove the finding.

`Heartbeat.agent_id` must be the authenticated agent's own id; a heartbeat
for another agent is refused with 400.

The scanner attempts enrollment and sends a heartbeat once per tick (every
60 seconds), without further backoff: at most one enrollment request per
minute while it waits for a usable token. Finding delivery retries follow the
queue's jittered backoff (see the limits below).

`Heartbeat.hostname` is the optional, bounded host name the operating system
reports. It is an operator-facing label only: it is spoofable, may change,
and is never used to authenticate or authorise the agent. It is absent when
the agent cannot obtain a non-empty UTF-8 name. When present, ingest records it
as the latest reported hostname for the authenticated `agent_id`.

`Heartbeat.capabilities` lists the features this agent currently runs, each
an identifier, without repeats. Version 1 defines one family: the collectors
the agent's configuration enables, `collector.processes`,
`collector.packages`, and `collector.ports`. A rule whose facts come only
from a collector the agent does not list reports those facts as
unavailable. Each heartbeat carries the complete current list; ingest
records it as the agent's latest capabilities, replacing the previous list.
Readers ignore identifiers they do not know, so later versions may add
capabilities without a schema change. An agent that reports its inventory (below) also lists
`inventory.packages`. An empty list means the agent reports
none (senders before this definition always sent it empty).

`Heartbeat.health` (P12) is the agent's optional health report, sent with
each heartbeat. It is within schema version 1: readers before P12 ignore
it and senders before P12 omit it. It carries counts and codes only, never
paths, file contents or finding data:

- `queue`: `pending` findings, `oldest_pending_age_s`, `bytes` used,
  `max_bytes`, and two totals kept across restarts: `dropped_total` (findings
  the rotating queue dropped, below) and `rejected_total` (findings the
  platform refused permanently, by reason; at most 16 reasons, later ones
  counted under `other`);
- `last_scan` (absent before the first scan): when it finished, the scan
  interval, rules evaluated, unavailable and failed, and each enabled
  collector's outcome: `ok` or a collector error code (`permission_denied`,
  `not_found`, `timed_out`, `invalid_data`, `unsupported`, `internal`).
  `unsupported` and `not_found` mean the host has nothing that collector
  can read (another operating system, no supported package database) and
  are not failures;
- `rule_sets`: each configured rule set's version in use and its expiry
  (`null` before a bundle was accepted) and `refused`: `null`, or why the
  last provisioned bundle was refused (`signature`, `expired`,
  `rolled_back`, `invalid`);
- `storage_errors` since the agent started, and `clock_jump_s`, a
  wall-clock jump the agent detected in the last hour (absent otherwise).

Collector outcomes and refusal codes are open identifiers, so later
versions can add values: a reader treats an outcome it does not know as a
failure, and a refusal code it does not know as `invalid`.

At most 16 collectors and 64 rule sets. An invalid `health` makes the
heartbeat invalid (400), so an agent validates its report and leaves it out
rather than send it invalid.

The queue rotates (P12): when a new finding would exceed the queue's byte
limit, the agent drops the oldest pending findings, only as many as
needed, and counts them in `dropped_total`; a full queue never refuses the
newest observation.

`InventoryReport` (`POST /v1/inventory`) carries the host's operating system
and installed packages, for the platform's vulnerability matching. `os.id`
and `os.version_id` are the `ID` and `VERSION_ID` of the host's os-release
file (for example `fedora` and `44`). `packages` holds up to 50,000
`InstalledPackage` records, the same shape as in `InventoryExport`, and the
document stays within the inventory document limit (8 MiB), not the 1 MiB
limit of other documents. `agent_id` must be the authenticated agent's
own id, or the report is refused with 400. Each report replaces the host's
stored inventory. The agent sends one only when its operating system or
package set has changed since the platform last accepted one, when its
`packages` collector is enabled, and never in local-only mode. A send that
fails on the network, with a 5xx (a busy platform answers 503), a 408 (the
request took too long, for example a large body on a slow link) or a 429 is
retried with a back-off (1, 2, 4 … minutes, up to an hour; a changed
inventory is sent at once). A platform gives inventory requests a longer
deadline than other requests, so a large report arrives over a slow link; a report the agent cannot send because it is over
the limits, or that the platform refuses with another 4xx (not 401/403), is
not resent until the inventory changes. A host without an os-release file sends no
report. The optional `running_kernel` is the running kernel's release
as `uname -r` reports it (for example `6.17.4-300.fc44.x86_64`); it counts
as part of the report's content, so the first report after a reboot into
another kernel is sent. With it the platform can tell a kernel fix that is
installed but not yet running from one that is running. Readers accept
reports without it (senders before P9).

Both inventory endpoints accept a body with `Content-Encoding: gzip`
(P11); agents that implement P11 send one, and a platform still accepts
uncompressed bodies from older agents. Any other content encoding is
refused with 400. A platform before P11 reads the body as plain JSON and
refuses a gzip body with 400: an agent whose gzip full report is refused
sends it again uncompressed in the same tick, and when that is accepted it
sends full reports uncompressed, and no change sets, until it restarts. The 8 MiB inventory document limit applies to the
compressed body and to what it expands to; a platform decompresses as a
stream and refuses (400) a body that would expand past it.

#### Inventory changes (P11)

After the platform has acknowledged a full report, an agent sends only
what changed: `InventoryChanges` to `POST /v1/inventory/changes`.
`base_sha256` is the fingerprint (below) of the inventory the platform last
acknowledged for this agent; `sha256` is the fingerprint after applying the
changes. `os` and `running_kernel` are always sent, so an operating-system
or kernel change needs no special case; a kernel-only change has empty
`added` and `removed`. A package is identified by its whole record: an
update is one `removed` (the old version) and one `added` (the new).
`added` and `removed` together hold at most 50,000 packages, and the body is
within the inventory document limit.

The platform applies a change set under the host's lock only if its stored
fingerprint equals `base_sha256`, every `removed` package is present, every
`added` package is absent, and the result's fingerprint equals `sha256`. It
then stores the result exactly as a full report. Otherwise it answers 409
with `PlatformError` code `inventory_resync` and stores nothing; the agent
then sends the full `InventoryReport`, in the same tick. The platform always
holds the complete list: a change set never replaces a check.

An agent keeps the last inventory the platform acknowledged (with a 2xx)
as its base, and sends the full report instead of changes when it has no
base whose fingerprint matches the acknowledged one, when the changes would
be larger than half the full report, or after the platform answered 404 to
the changes endpoint (a platform before P11), until the agent restarts. A
change set the platform refuses for another reason (any other 4xx) is also
followed by the full report in the same tick. Retries and refusals follow
the full report's rules above.

#### Inventory fingerprint

Agent and platform compute the same fingerprint, byte for byte: SHA-256 of
the UTF-8 compact JSON (no whitespace; non-ASCII characters not escaped) of

    [[os.id, os.version_id], running_kernel, [record, …]]

where `running_kernel` is `null` when absent and each record is the
package normalised as the platform stores it:

    [manager, name, epoch, version, release, arch, source, source_version]

with `epoch` 0 when absent, `release` and `arch` `""` when absent, and
`source` and `source_version` `null` when absent; `vendor` is not part of
it. Records are deduplicated and sorted by their compact JSON text, in byte
order. Test vectors (inventory → digest) are in
`vectors/inventory-fingerprint.json`. Agents before P11 used another digest
for their own bookkeeping; after upgrading, each sends one full report.

Renewal: once two thirds of a certificate's lifetime has passed, measured
from the scanner's local time when it obtained the certificate, the scanner
sends a CSR for a new key, authenticated by the current certificate. The
platform must issue for the same `agent_id`; the scanner rejects any other and
keeps its identity. The lifetime is `expires_at_unix_ms` from the response
minus the local time the certificate was obtained, so a scanner clock that is
far behind the platform's shortens the effective renewal window.

Expiry: a scanner whose certificate has expired by its local clock can no
longer renew, because renewal needs a valid certificate. It then deletes its
identity, keeps its queued findings, and enrolls again when an enrollment
token with uses left is available (a fleet token, or a new one). A bare 401
never triggers this; only the certificate's own expiry does.

Status handling: 2xx is success. 401 and 403 mean the credentials were
refused. Revocation is signalled only by a 401 or 403 whose body is a
`PlatformError` with code `identity_revoked`; the scanner then deletes its
identity, keeps its queued findings, and waits for a new enrollment token. It
never enrolls again with the token it last enrolled with, so revoking an agent
enrolled with a fleet token cuts it off; operators revoke the fleet token as
well if the host itself is no longer trusted. A
bare 401 or 403, an unknown code, or an unsupported schema version never
deletes the identity, so a misconfigured proxy or load balancer cannot strand
a scanner. The platform must complete the TLS handshake for any certificate
its CA issued and answer at the HTTP level, because a TLS 1.3 post-handshake
rejection races the request write and is indistinguishable from a network
failure. Any other status, including 3xx, is a rejected request.

#### Finding changes (P13)

An agent using P13 reports rule matches as changes, not per scan. A match
is one rule set and rule on the agent; it is open from the scan that first
matched until a scan that evaluates the rule and does not match, or until
the rule is gone: absent from the rule set's currently accepted bundle, or
its rule set no longer configured on the agent. A rule the scan could not
evaluate (bundle expired or refused, collector unavailable, budget
exceeded) keeps its match open; it is counted in
`health.last_scan.rules_unavailable` or `rules_failed`. A host that stops
reporting is stale, never "ended".

The agent keeps at most 500 current matches, and at most what fits in one
8 MiB `FindingChanges` body. A match already acknowledged by the platform
keeps its place; a new match that would pass either bound is left out and
counted in `health.matches_truncated`, so no match is ever reported ended
to make room, and a replace always fits.

After a scan, if its current match set differs from the set the platform
last acknowledged, or it holds transient matches, the agent sends one
`FindingChanges` to `POST /v1/findings/changes` (mTLS, gzip as for
inventory, within the 8 MiB inventory document limit):

- `started`: matches not in the acknowledged set, as `Finding` documents
  with `rule_set_id` required and `observed_at_unix_ms` the time the match
  started; `changed`: acknowledged matches whose rule version, severity,
  message or evidence differ, as `Finding` documents; `ended`: acknowledged
  matches that ended (above). A `finding_id` is new for each entry. Each
  rule set and rule appears at most once across `started`, `changed` and
  `ended`.
- `transient`: matches that started and ended since the last
  acknowledgement (the platform never saw them start), at most 100;
  `transient_dropped` counts those not kept.
- `base_sha256` and `sha256`: the match digest (below) of the acknowledged
  set and of the set after the changes. With nothing acknowledged,
  `base_sha256` is the empty set's digest.
- `started`, `changed` and `ended` together hold at most 500 entries; a
  change set that would hold more is sent as a replace instead.

The platform applies the changes under the agent's lock only if its stored
digest equals `base_sha256`, every `started` match is not open, every
`changed` and `ended` match is open, and the result's digest equals
`sha256`. Otherwise it answers 409 with `PlatformError` code
`findings_resync` and stores nothing. The agent then sends
`replace: true`: its whole current set in `started`, `changed` and `ended`
empty, `base_sha256` ignored; the platform ends every open match missing
from it at `scanned_at_unix_ms`, as approximate.

Entries are never refused one by one. A `started` or `changed` finding
whose `observed_at_unix_ms` is older than the platform's finding retention
or more than one hour ahead of its clock is stored as observed at receipt,
keeping the reported start as the match's approximate start. A document
the platform can never accept (invalid, a rule set and rule listed twice,
a value it cannot store such as a `rule_version` above 2^63 − 1) is
answered 400, never 409.

On a 2xx the agent records the new set as acknowledged and drops its
transients. An agent with nothing acknowledged (first start, or after
re-enrolling) sends a replace after its first scan, even when its set is
empty. A 409 that answers a replace, a 400, and any other 4xx except 404
are refused requests: the agent retries with the delivery backoff, never
at once. A platform before P13 answers 404: the agent then sends per-scan
`FindingBatch` deliveries as before, until it restarts. Local-only export
is unchanged.

A heartbeat from an agent using P13 carries `match_sha256`, the digest of
its acknowledged set; an agent with nothing acknowledged yet, or in the 404
fallback, leaves it out. A platform whose stored digest differs (restored,
lost, or never received) stores the heartbeat as usual and answers 409
`findings_resync`. The agent treats that heartbeat as delivered and sends a
replace, unless a replace is already pending or waiting on its backoff. A
heartbeat without `match_sha256` is never answered 409, so agents before
P13 are unaffected.

#### Match digest (P13)

The agent and the platform both compute the digest of an agent's current
match set and must agree byte for byte. A match is the JSON array
`[rule_set_id, rule_id, rule_version, severity, message, evidence]`, with
`evidence` deduplicated and sorted in byte order. The digest is the
lowercase hex SHA-256 of the UTF-8 compact JSON array (no spaces) of all
current matches, deduplicated and sorted by their compact JSON text in byte
order; the empty set is `[]`. Compact JSON is written as for the
inventory fingerprint: no whitespace, non-ASCII characters not escaped,
`"` and `\` escaped with a backslash, control characters as `\b`, `\f`,
`\n`, `\r`, `\t` or lowercase `\u00xx`, `/` not escaped, integers in plain
decimal. When a match started is not part of it. Test
vectors (match set → digest) are in `vectors/match-digest.json`.

#### Process events and alarms (P14)

A rule's optional `kind` is `snapshot` (the default) or `process_event`;
only a `process_event` rule may carry `programs`. A `process_event` rule is
evaluated once per process start on the host, against a flat map named
`event`, and may reference only `event[...]` keys from the table below; a
snapshot rule may reference only `facts[...]`. A loader refuses the other
binding and any `event` key not in the table (the set is closed, unlike
facts, so a typo is caught at signing, not silently never matched). Alarm
rules ship in their own rule sets (for example `baseline-alarms`): an agent
before P14 ignores `kind` and would fail every `event[...]` rule, so it is
not configured with one.

| `event` key | Type |
|---|---|
| `process.exe`, `process.name`, `process.cmdline` (args joined by single spaces, at most 256 KiB), `process.cwd` | string |
| `process.cmdline_truncated` (the command line was longer than 256 KiB and was cut) | boolean |
| `process.uid` | integer |
| `parent.exe`, `parent.name`, `parent.cmdline` (cut like `process.cmdline`) | string |
| `ancestors.names`, `ancestors.exes` (the parent and up to 4 further ancestors) | string list, sorted, no duplicates |

`exe` is the executed file's path and `name` its basename. A process the
agent learnt from `/proc` when it started, not from an exec event, is
*seeded*: its `name` is the kernel's `comm` (`/proc/<pid>/stat`, at most 15
bytes, e.g. `nginx` for an nginx worker), and its `exe` is the
`/proc/<pid>/exe` link when readable, otherwise `argv[0]` when it is an
absolute path, otherwise `[comm]` in brackets. Neither is ever empty
(`[unknown]` as a last resort). Seeded values are real values, not missing
ones, so a rule on `parent.name` works for a parent that started before the
agent. A key whose value the agent does not know (no parent at all, a cwd it
cannot read) is missing, and the rule is `Unavailable`, never a match.

Values come from the kernel as bytes. An agent decodes them as UTF-8,
replacing each invalid sequence with U+FFFD, before binding, masking or
sending, and every cut in this section falls on a character boundary.
Rules see the full, unmasked command line up to the 256 KiB cut; a longer
one is cut rather than dropped, and a rule may treat
`process.cmdline_truncated` itself as suspicious. The optional `programs`
list (exact exe paths or basenames) lets an agent skip evaluation for
events no rule names. The evaluation wall-time limit applies to each rule
on each event.

A match becomes an alarm, identified by an `alarm_id` the agent makes once.
Repeats collapse: a match with the same rule set, rule, `process.exe`,
`parent.exe` (empty when there is no parent) and masked `process.cmdline`
within 10 minutes of the alarm's `first_seen_unix_ms` raises that alarm's
`count` and `last_seen_unix_ms` instead of creating one. The command line is
part of the key so that a harmless first command cannot hide a later,
different one under the same alarm; an identical loop still collapses. An alarm already delivered is
sent again, with the same `alarm_id`, when its `count` has grown. A platform
keeps one record per agent and `alarm_id`: a repeat updates `count` and
`last_seen_unix_ms` to the larger values and keeps everything else from the
first delivery, so a retry or a late update never creates a second alarm and
never lowers the count.

Before an alarm is queued, the agent masks every `args` entry of the process
and its ancestors (vectors: `vectors/alarm-masking.json`). Each rule below
marks secret characters of an argument, and each run of marked characters
is replaced by `***`; everything else, spacing included, is kept. An empty
value (`--password=`) stays empty. Names match with ASCII case folding only.
A *`-p` program* is `mysql`, `mariadb`, `mysqldump`, `mariadb-dump`,
`mysqladmin` or `sshpass`; a *program word* is an argument after `argv[0]`
(or any script word, below) whose basename, after dropping one leading
`$(`, `(`, backtick, `'` or `"`, is a `-p` program.

- `-p<value>` (attached) when the basename of the process's `exe` (not of
  `argv[0]`) is a `-p` program, and in every argument after a program word
  (so `sudo mysql -p…`, `timeout 10 mysql -p…` and `docker exec db mysql
  -p…` are masked; a later `ssh -p22` in the same line is masked too,
  which is harmless). A bare `-p` prompts for the MySQL tools, so the next
  word is kept, except for `sshpass` (as the `exe` or a program word),
  whose `-p value` is masked. Other programs keep `-p` (a port for `ssh`,
  `scp`, `nc`);
- the value of a flag, in `=value` and next-argument form, when the flag is
  `--NAME` with `NAME` ending in `password`, `passwd`, `pass`,
  `passphrase`, `token`, `secret` or `key` (`--db-password`,
  `--client-secret`, `--api-key`), or `-NAME` with `NAME` ending in
  `password`, `passwd`, `passphrase`, `storepass` or `keypass` (`-password`,
  keytool's `-storepass`);
- the password in `-u user:password`, `-uuser:password`, `--user[=]` and
  `--proxy-user[=]` (`-U` is `-u` by case folding);
- the value of a `Name: value` header (after the colon and any spaces) when
  `Name` is `authorization`, `proxy-authorization`, `cookie`, `x-api-key` or
  `private-token`, or ends in `token`, `key` or `secret`: an argument that
  is the header, or that starts with `-H` or `--header=` directly followed
  by it;
- the value of an argument starting with `pass:` (`-pass pass:secret`, as
  OpenSSL takes them);
- each `NAME=value` pair in an argument whose upper-cased `NAME` ends in
  `PASSWORD`, `PASSWD`, `PASS`, `PWD`, `PASSPHRASE`, `SECRET`, `TOKEN`, `KEY`
  or `AUTH`. `NAME` is the text before the `=` back to the previous `=`,
  `,`, `&`, `?`, `;` or the argument's start, and the value runs to the next
  `,`, `&`, `;` or the end, so `MYSQL_PWD=x`, `--env=DB_PASSWORD=x`,
  `-Dspring.datasource.password=x`, `-o user=u,password=x`,
  `?user=a&password=x` and `PGPASSWORD=x;` are masked and the `;` is kept;
- the password in URL userinfo anywhere in an argument: after `://`, up to
  the first `/`, `?`, `#` or the end, the userinfo runs to the last `@` and
  its password from the first `:` (`https://bob:p@ss@host` masks `p@ss`).

A shell script is masked word by word with the same rules. It is the
argument after a `-c` flag, or after a single-dash cluster of letters that
contains `c` (`-lc`, `-ec`), when the `exe` basename is `sh`, `bash`,
`dash`, `zsh`, `ash`, `su` or `runuser`, or `busybox` with an `argv[0]`
whose basename is one of the shells. The script is split on ASCII
whitespace; a next-argument form takes the next word; quoting and shell
grammar are not interpreted.

This list is a floor, not a guarantee. Known gaps: program-specific short
flags (`redis-cli -a`, `ldapsearch -w`, `docker login -p`, `smbclient -U
user%password`, `7z -p`, `zip -P`), structured bodies (`-d
'{"password":"x"}'`), a quoted value that spans words inside a script
(`--password 'two words'`, `-H 'Authorization: Bearer x'` inside `-c`), and
a command passed as one argument to a program that is not a shell above
(`ssh host 'mysql -px'`). `exe` and `cwd` are never masked.
After masking, each process's `args` is cut to at most 4096 UTF-8 bytes
counted as joined by single spaces: whole arguments are kept from the start
while they fit, and when even the first does not fit it is cut to fit. A cut
sets `truncated`; nothing is appended.

`AlarmBatch` (`POST /v1/alarms`, optionally `Content-Encoding: gzip`)
carries up to 100 alarms and the agent's `dropped_total`, a cumulative count
that never decreases (a platform keeps the largest it has seen, so a retried
batch cannot double-count). `agent_id` must be the authenticated agent's own
id, or the batch is refused with 400. An agent fills a batch with alarms
until the next one would take it past 100 alarms or 256 KiB serialized.
One alarm serializes to at most 64 KiB: before queueing, an agent cuts
further arguments (the farthest ancestor first, with `truncated` set) until
it fits. Readers check what the schema cannot: `last_seen_unix_ms` is not
before `first_seen_unix_ms`, the `args` bound above, and the size limits
(413 otherwise). An agent drops a batch refused with 400 or 413 and adds its
alarms to `dropped_total`, so one bad batch never blocks the queue; on 404
(a platform before P14) it keeps its alarms and retries hourly; any other
failure is retried as findings are.

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
writes them to files for the platform to import later (`openvibes-admin import`).

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
never-enrolled host has no key the platform trusts. The platform's importer validates an
import exactly like a `FindingBatch`, stores its findings marked as imported
and unauthenticated, including the `install_id` it came from, and never lets
an import update or authenticate an enrolled agent's identity.

Import rules: each `install_id` is one imported host, separate from any
enrolled agent. Findings are idempotent on `finding_id` within an
`install_id`. Of several `InventoryExport` files, the one with the newest
`collected_at_unix_ms` wins; an older or equal one is ignored, so files
can be imported in any order. An inventory without `os` cannot be matched
for vulnerabilities and is refused. `agent_id` and `hostname` in a file are
labels for operators, never identity. A later schema version may add a
signature for enrolled agents.

### Inventory Export

The same export command also writes one `InventoryExport` file per run: a
snapshot of the host's installed packages, taken at export time, beside the
`FindingExport` files. It carries `install_id`, optional `agent_id` and
`hostname`, `scanner_version`, `collected_at_unix_ms`, and up to 50,000
`packages`. The whole document must also fit the inventory document limit
(8 MiB; about 134 bytes per RPM package, so 50,000 packages fit). Each package names its `manager`
(`rpm` or `dpkg`), `name`, and upstream `version`, and optionally its
distribution `release`, `epoch`, `arch`, and the `vendor` its database
records. A package may also name its `source` package (dpkg's `Source`
field, or the name in RPM's `SOURCERPM`; absent when the source has the
binary's name). A dpkg package whose source version differs from its own (a
binNMU) also carries the full `source_version`
(`[epoch:]upstream[-revision]`); RPM subpackages share their source's
version, so RPM packages never carry it. Debian, Ubuntu and Rocky Linux
publish vulnerabilities per source package, so the platform matches those
hosts by source (P10). Package records are copied from the package database and are
neither verified nor normalised to CPE names.

It also carries the host's `os` (os-release `ID` and `VERSION_ID`) and
`running_kernel`, as in `InventoryReport`. Both are optional in the schema
so files from older agents stay valid.

An inventory export is unsigned and stored like an imported finding export.
It does not consume anything: every export writes a fresh snapshot. When the
package collector fails, or the inventory would exceed either limit, no
inventory file is written and the export command reports why. The finding
export files are written regardless: an inventory problem never blocks the
export of findings. Online inventory reports are `InventoryReport` (P8).

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
| String-list fact | 10,000 items, sorted and unique (`package.names`: 50,000) |
| Inventory packages (`InventoryReport`, `InventoryExport`; `InventoryChanges` added and removed together) | 50,000 |
| Inventory document (one `InventoryReport`, `InventoryChanges` or `FindingChanges` body, compressed and expanded, or `InventoryExport` file); the 1 MiB document and aggregate string limits do not apply to these | 8 MiB |
| Evidence per finding | 128 keys |
| CEL operations per rule | 50,000 |
| CEL expression depth | 32 |
| CEL expression nodes | 256 |
| Fact input per scan | 16 MiB |
| Evaluation wall time | 100 ms |
| Complete scan | 300 seconds |
| SQLite queue | 256 MiB |
| Queue retention | 30 days |
| Delivery batch | 500 findings |
| `FindingChanges` entries (`started`, `changed` and `ended` together) | 500 |
| `FindingChanges` transient matches | 100 |
| Current matches per agent (P13) | 500 |
| Retry delay | Nominal 15 seconds, doubling per failed attempt up to 1 hour; each wait is drawn between half and all of the nominal delay (the first retry comes after 7.5 to 15 seconds) |
| Platform connect, including TLS | 10 seconds |
| Platform request, end to end | 60 seconds |
| Alarms per `AlarmBatch` | 100 |
| `AlarmBatch` document, uncompressed | 256 KiB |
| One alarm, serialized | 64 KiB |
| `args` per process in an alarm | 256 entries, 4 KiB joined |
| Ancestors per alarm | 5 |
| `process.cmdline` and `parent.cmdline` in the `event` binding | 256 KiB (longer is cut; `process.cmdline_truncated`) |
| Other strings in the `event` binding (`*.exe`, `*.name`, `process.cwd`, each `ancestors` entry) | 4 KiB (longer is cut) |
| String literal argument of a subset v2 method | 256 bytes, decoded UTF-8 |

These are security limits, not performance targets. Raising them requires test
coverage and a resource-exhaustion review.

The loader accepts tighter limits but rejects zero general limits or limits
above these safety ceilings. Alias limits can be set to zero to disable replay.
The evaluator enforces the CEL expression, operation, depth, evidence, fact
input, and wall-time limits. The SQLite queue enforces the queue, retention, batch, and retry limits, and
the transport enforces the document and network limits on every request. Scan
deadlines will be enforced by the scan scheduler.
