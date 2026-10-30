# Feed format v1: signed vulnerability data for a mirror or a bundle

Status: draft, approved in design by lime on 2026-10-30
(`planning/airgap-feed-spec-2026-10-30.md`). Not part of the agent protocol:
the agent never sees a feed. It lives here because it is a signed format with
shared vectors, like the rule envelope. Schema version 1; `schemas/v1/feed-*.schema.json`
must agree with this page, which is authoritative.

A **feed** is what `openvibes-feed` builds from the upstream sources the
platform used to fetch itself, and what a platform with `feed_mirror_url` set
reads instead of the internet. A **bundle** is the same feed in a tar file.

## Layout

```
feed/
  feed.json            the signed envelope; replaced atomically, written last
  blobs/<sha256-hex>   immutable files named by their own SHA-256 (lowercase)
```

A mirror serves this tree as static files over HTTPS. A reader fetches
`feed.json` (conditional requests with `ETag` are allowed) and then only the
blobs it does not already have. A builder writes new blobs first and renames
`feed.json` last; it keeps the blobs of the previous 3 sequences, then removes
older ones. Because blobs never change, a reader that sees the old `feed.json`
while a new one is being published still finds every blob it names.

### Bundle (tar)

A plain POSIX tar (no compression; the blobs are already compressed), entries
in this order: `feed.json`, then `blobs/<sha256-hex>` for each blob. Only
regular files with exactly those names are allowed. A reader refuses the whole
bundle on any other entry type (links, devices, directories other than the
implicit `blobs/` path component, so no directory entries at all), any other name, a duplicate name, an absolute or `..`
path, or a total size above its limits. Entries are never extracted by their
own paths: a reader copies each into its own state directory under the name it
computed. A bundle may omit blobs of sources the builder was told to skip
(`--sources`); the manifest then lists only the included sources.

## Envelope (`feed.json`, at most 1 MiB)

```json
{
  "format": 1,
  "feed_id": "acme-dmz",
  "key_id": "k1",
  "signature": "<86 characters, unpadded base64url of the 64-byte Ed25519 signature>",
  "manifest": "<the manifest as one JSON text>"
}
```

`format` is 1; readers refuse any other value. `feed_id` and `key_id` are
identifiers as in `common.schema.json`. The `manifest` string is signed **byte
for byte**: it is never re-serialized, so whitespace and field order are part
of what is signed and a reader parses it only after the signature verifies.

## Manifest

```json
{
  "sequence": 412,
  "created_at": 1793360000,
  "expires_at": 1793964800,
  "files": [ { "source": "kev", "kind": "kev", "name": "known_exploited_vulnerabilities.json",
               "sha256": "<hex>", "size": 123456, "fetched_at": 1793359400,
               "upstream": "https://www.cisa.gov/..." } ]
}
```

- `sequence`: unsigned 64-bit integer, 1 or more. Rises with every build.
- `created_at`, `expires_at`: Unix seconds. `expires_at` is greater than
  `created_at`. The builder sets `expires_at = created_at + valid_days`
  (default 7 days).
- `files`: 1 to 64 entries, each unique by `(source, name)`.
- `source` and `kind` per file:

| `kind` | `source` | Blob contents | Largest `size` |
|---|---|---|---|
| `repomd` | `fedora-<release>-<arch>` | Fedora `repomd.xml`, raw bytes | 1 MiB |
| `updateinfo` | `fedora-<release>-<arch>` | `updateinfo.xml` or `.xml.zst`, raw bytes | 256 MiB |
| `osv` | `debian`, `ubuntu`, `rocky-linux` or `almalinux` | the ecosystem's OSV `all.zip`, raw bytes; `releases` (required) lists the platform sources it feeds (`ubuntu-24.04`, ...) | 8 GiB |
| `kev` | `kev` | CISA KEV JSON, raw bytes | 64 MiB |
| `epss` | `epss` | EPSS CSV (`.csv.gz` or plain), raw bytes | 128 MiB |
| `euvd` | `euvd` | one JSON document `{"items":[...],"total":N}` in the shape of ENISA's EUVD search response, all exploited entries joined | 64 MiB |
| `nvd` | `nvd` | gzip JSON, the slim NVD form below, one file per CVE year | 512 MiB |

  The sizes are the format's hard maxima. A reader may apply lower limits of
  its own and refuses a file whose `size` exceeds them.
- `name`: `[A-Za-z0-9._-]{1,64}`. It is a label for people; a reader finds the
  blob only by `sha256` and never builds a path from a manifest.
- `sha256`: lowercase hex of the blob. `size`: the blob's length in bytes.
- `fetched_at`: Unix seconds, when the builder obtained the bytes.
- `upstream`: where it came from, for people and audit. A reader never fetches it.
- `releases`: required on `osv` files and allowed on no other; unique release names of 1 to 32 characters
  from `[a-z0-9.-]`, naming the platform sources the file feeds.

### Slim NVD (`kind: nvd`)

After gunzip, one JSON object:

```json
{ "format": 1, "year": 2024, "records": [
  { "id": "CVE-2024-1234",
    "modified": "2026-03-01T10:20:30.000",
    "cvss": { "version": "3.1", "score": 9.8, "severity": "CRITICAL", "vector": "CVSS:3.1/AV:N/..." },
    "cwe": ["CWE-79"],
    "description": "English text, at most 4096 bytes",
    "ranges": [ { "cpe": "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
                  "start_including": "1.0", "end_excluding": "1.2.3" } ] } ] }
```

`year` is the year in the CVE ids of its records. `cvss` is the newest
version scored (4.0, 3.1, 3.0, 2.0), within it NVD's own score over a CNA's,
or absent. `cwe` is deduplicated. `ranges` holds the `cpeMatch` entries with
`vulnerable: true` and an application part (`cpe:2.3:a:`); each has up to four
of `start_including`, `start_excluding`, `end_including`, `end_excluding`, and
a record has at most 5,000 of them. Absent keys mean "not given". This is the
information the platform reads from NVD's `cves/2.0` API today, in about a
fifth of the size.

## Signature preimage

The signed bytes are the concatenation of:

1. ASCII `OPENVIBES-FEED-MANIFEST-V1` followed by a zero byte.
2. `format` as an unsigned 16-bit big-endian integer.
3. `feed_id` as an unsigned 32-bit big-endian byte length plus its UTF-8 bytes.
4. `key_id`, the same way.
5. The manifest string as an unsigned 64-bit big-endian byte length plus its
   exact UTF-8 bytes.

The algorithm is Ed25519 (RFC 8032), verified as `ed25519-dalek`'s
`verify_strict` does, with its `is_weak` check on the public key: canonical
encodings of `A` and `R`, `S < L`, and neither `A` nor `R` of small order.
Keys are 32 bytes and signatures 64 bytes, in **canonical** unpadded
base64url on the wire (no padding, the URL-safe alphabet only, zero spare
bits; the same rule as the Rust `base64` crate's `URL_SAFE_NO_PAD`), the same
encoding the rule envelope uses. A non-canonical string is refused wherever it
is read: a signature in an envelope is `bad_format`, a public key given to
`feeds trust add` is an error. The `signature` field is not part of the preimage.
The **manifest digest** is the SHA-256 of the whole preimage; it identifies a
manifest for the equal-sequence rule below.

## Trust

A reader holds trusted keys, each scoped to a `(feed_id, key_id)` and added
by its administrator. A key is never taken from a feed. Several keys may be
trusted at once, so a builder can rotate: trust the new key, switch the
builder, then remove the old one as soon as the new one has been applied:
sequence state is kept per key, so while both are trusted the last manifest
signed by the old key is still accepted again (its files are bounded by the
`fetched_at` rule and its expiry). Key ids are not re-used for a different key.
A key's **fingerprint** is the SHA-256 of its 32 public-key bytes, shown as 8
groups of 4 lowercase hex characters (the first 128 bits) wherever a key is
displayed or compared.

## Verification order

A reader checks, in this order, and stops at the first failure. The reasons
are fixed strings used by `vectors/feed-verification.json`.

1. The envelope has at most 1 MiB, parses (duplicate keys and numbers that
   are not integers are errors), matches `feed-envelope.schema.json`, and its
   signature is canonical base64url: otherwise `bad_format`.
2. A key is trusted for `(feed_id, key_id)`: otherwise `unknown_key`.
3. The signature verifies over the preimage: otherwise `bad_signature`.
   **Nothing in the manifest is parsed before this.**
4. The manifest parses as JSON (duplicate keys and numbers that are not
   integers are errors, as `412.0`), is an object, and matches
   `feed-manifest.schema.json`; `expires_at > created_at`; `(source, name)`
   are unique; `releases` appears only on `osv` files: otherwise `bad_manifest`.
5. `created_at <= now + 600` (a builder's clock may run up to 10 minutes
   ahead): otherwise `not_yet_valid`. `now < expires_at`: otherwise `expired`.
6. Sequence, against the highest accepted for the same `(feed_id, key_id)`:
   lower is `sequence_replay`; equal with a different manifest digest is
   `sequence_conflict`; equal with the same digest is accepted again (a
   restart or repeated import changes nothing); higher is accepted.
7. For each file: the blob is read at most `size` bytes (and within the
   reader's own limits), its SHA-256 and length must equal the manifest, and
   only then is it parsed by the importer for its kind with that importer's
   usual limits and per-record validation. A file that fails here does not
   stop the others; it is reported as refused and retried on the next run.

A reader records a feed as accepted after step 6, so a replayed older
manifest stays refused even when a file failed in step 7.

Step 7 is exercised by `vectors/feed-files.json` (reasons `too_large`,
`size_mismatch`, `hash_mismatch`, `older_than_applied`); the other steps by
`vectors/feed-verification.json`, whose cases include ones with two defects, to
show which check must win.

Per source, a reader also skips a file whose `fetched_at` is older than the
one it applied before for that source, and reports it as older than applied.
This stops a newly signed manifest from carrying a stale file back in.

## Failure behaviour

A refused or unreachable feed changes nothing the reader already holds: the
data applied before keeps serving, and the failure is recorded for display
and audit with its reason. A reader never falls back from a configured feed to
direct fetching on its own. The signature says that the builder fetched
these exact bytes at that time; it does not say the data is true, because the
upstream sources are not signed.

## Vectors

- `vectors/feed-signature.json`: preimage digests and signatures with their
  public keys, valid and invalid, from test keys that are public. The invalid
  strictness cases (non-canonical `S`, `R` and `A`, small-order `R` and `A`)
  all pass a lax RFC 8032 check, so each tests strictness; they were checked
  against `ed25519-dalek` 3.0.0 `verify_strict` with `is_weak`.
- `vectors/feed-files.json`: the per-file checks of step 7.
- `vectors/feed-verification.json`: whole-feed cases with trusted keys,
  state and `now`, each with the expected outcome and reason. `tools/validate.py`
  runs a reference verifier over them, and implementations run the same cases.
- `fixtures/v1/feed-envelope/`, `fixtures/v1/feed-manifest/`: schema fixtures.
