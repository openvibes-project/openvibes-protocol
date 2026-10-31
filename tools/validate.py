#!/usr/bin/env python3
"""Checks every fixture against its schema.

fixtures/v1/<message>/valid*.json must validate against
schemas/v1/<message>.schema.json, and invalid*.json must not. Exits non-zero
on any mismatch. Requires the packages pinned in tools/requirements.txt.
"""

import hashlib
import json
import re
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent.parent


def fingerprint(inventory: dict) -> str:
    """spec/contracts-v1.md, "Inventory fingerprint"."""

    def compact(value) -> str:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)

    records = sorted(
        {
            compact(
                [
                    p["manager"], p["name"], p.get("epoch", 0), p["version"],
                    p.get("release", ""), p.get("arch", ""),
                    p.get("source"), p.get("source_version"),
                ]
            )
            for p in inventory["packages"]
        }
    )
    os = inventory["os"]
    text = "[{},{},[{}]]".format(
        compact([os["id"], os["version_id"]]),
        compact(inventory.get("running_kernel")),
        ",".join(records),
    )
    return hashlib.sha256(text.encode()).hexdigest()


def match_digest(matches: list) -> str:
    """spec/contracts-v1.md, "Match digest (P13)"."""

    def compact(value) -> str:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)

    rows = sorted(
        {
            compact(
                [
                    m["rule_set_id"], m["rule_id"], m["rule_version"],
                    m["severity"], m["message"], sorted(set(m["evidence"])),
                ]
            )
            for m in matches
        }
    )
    return hashlib.sha256(("[" + ",".join(rows) + "]").encode()).hexdigest()


def services_digest(listeners: list, services: list) -> str:
    """spec/contracts-v1.md, "Services digest (P15)"."""

    def compact(value) -> str:
        return json.dumps(value, separators=(",", ":"), ensure_ascii=False)

    listener_rows = sorted(
        {
            compact(
                [
                    l["protocol"], l["address"], l["port"], l["exposed"],
                    l.get("service"), l.get("program"),
                ]
            )
            for l in listeners
        }
    )
    service_rows = sorted(
        {
            compact([s["unit"], sorted(set(s["programs"])), s["processes"], s.get("user")])
            for s in services
        }
    )
    text = "[[" + ",".join(listener_rows) + "],[" + ",".join(service_rows) + "]]"
    return hashlib.sha256(text.encode()).hexdigest()


# --- Signed feeds (spec/feed-v1.md): Ed25519 per RFC 8032, written out so the
# checker needs no package beyond the pinned validator.

_P = 2**255 - 19
_L = 2**252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, -1, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _add(a, b):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = a, b
    aa, bb = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    cc, dd = 2 * t1 * t2 * _D % _P, 2 * z1 * z2 % _P
    e, f, g, h = bb - aa, dd - cc, dd + cc, bb + aa
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(n, point):
    result = (0, 1, 1, 0)
    while n:
        if n & 1:
            result = _add(result, point)
        point = _add(point, point)
        n >>= 1
    return result


def _decode(data: bytes):
    """A canonical point encoding, or None."""
    if len(data) != 32:
        return None
    y = int.from_bytes(data, "little")
    sign, y = y >> 255, y & (2**255 - 1)
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, -1, _P) % _P
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _I % _P
    if (x * x - x2) % _P:
        return None
    if x == 0 and sign:
        return None
    if x & 1 != sign:
        x = _P - x
    return (x, y, 1, x * y % _P)


def _same(a, b):
    return (a[0] * b[2] - b[0] * a[2]) % _P == 0 and (a[1] * b[2] - b[1] * a[2]) % _P == 0


_BASE = _decode(((4 * pow(5, -1, _P)) % _P).to_bytes(32, "little"))


def ed25519_verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """ed25519-dalek's `verify_strict`: canonical A and R, S < L, and neither
    A nor R of small order."""
    if len(signature) != 64:
        return False
    a, r = _decode(public), _decode(signature[:32])
    s = int.from_bytes(signature[32:], "little")
    identity = (0, 1, 1, 0)
    if (
        a is None or r is None or s >= _L
        or _same(_mul(8, a), identity) or _same(_mul(8, r), identity)
    ):
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    return _same(_mul(s, _BASE), _add(r, _mul(k, a)))


def b64url(text: str) -> bytes:
    """Canonical unpadded base64url only: no padding, no other alphabet, and
    zero spare bits (like the Rust `base64` crate's URL_SAFE_NO_PAD)."""
    import base64

    if not re.fullmatch(r"[A-Za-z0-9_-]*", text) or len(text) % 4 == 1:
        raise ValueError("not base64url")
    data = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    if base64.urlsafe_b64encode(data).rstrip(b"=").decode() != text:
        raise ValueError("non-canonical base64url")
    return data


def strict_json(text: str):
    """JSON as serde reads it for these structs: duplicate keys and numbers
    that are not integers are errors."""

    def pairs(items):
        keys = [k for k, _ in items]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        return dict(items)

    def refuse(_):
        raise ValueError("non-integer number")

    return json.loads(text, object_pairs_hook=pairs, parse_float=refuse)


def feed_preimage(fmt: int, feed_id: str, key_id: str, manifest: bytes) -> bytes:
    """spec/feed-v1.md, "Signature preimage"."""
    import struct

    f, k = feed_id.encode(), key_id.encode()
    return (
        b"OPENVIBES-FEED-MANIFEST-V1\0" + struct.pack(">H", fmt)
        + struct.pack(">I", len(f)) + f + struct.pack(">I", len(k)) + k
        + struct.pack(">Q", len(manifest)) + manifest
    )


def slim_nvd_valid(file) -> bool:
    """spec/feed-v1.md, "Slim NVD": whether a reader accepts the file. Written
    out rather than as a schema because the limits are byte counts."""
    import re

    def clean(text, limit):
        return isinstance(text, str) and len(text.encode()) <= limit and not any(ord(c) < 32 or 0x7F <= ord(c) < 0xA0 for c in text)

    if file.get("format") != 1 or not isinstance(file.get("year"), int) or not isinstance(file.get("records"), list):
        return False
    for r in file["records"]:
        m = re.fullmatch(r"CVE-(\d{4})-\d{4,19}", r.get("id", ""))
        if not m or int(m.group(1)) != file["year"]:
            return False
        c = r.get("cvss")
        if c is not None and not (
            c["version"] in ("4.0", "3.1", "3.0", "2.0") and 0 <= c["score"] <= 10 and len(c["vector"].encode()) <= 512
        ):
            return False
        if any(not re.fullmatch(r"CWE-\d{1,9}", w) for w in r.get("cwe", [])):
            return False
        if "description" in r and len(r["description"].encode()) > 4096:
            return False
        ranges = r.get("ranges", [])
        if len(ranges) > 5000:
            return False
        for g in ranges:
            if not g["cpe"].startswith("cpe:2.3:a:") or not clean(g["cpe"], 512):
                return False
            for k in ("start_including", "start_excluding", "end_including", "end_excluding"):
                if k in g and not clean(g[k], 64):
                    return False
        osl = r.get("os", [])
        if len(osl) > 256 or any(not re.fullmatch(r"[a-z0-9._~+-]{1,64}:[a-z0-9._~+-]{1,64}:[a-z0-9._~+-]{1,64}", o) for o in osl):
            return False
    return True


def verify_feed(envelope, trusted, state, now, validators):
    """The reference verifier of spec/feed-v1.md, "Verification order".
    Returns ("accepted", None) or ("refused", reason)."""
    envelope_validator, manifest_validator = validators
    if not envelope_validator.is_valid(envelope):
        return ("refused", "bad_format")
    try:
        signature = b64url(envelope["signature"])
    except ValueError:
        return ("refused", "bad_format")
    key = f"{envelope['feed_id']}/{envelope['key_id']}"
    if key not in trusted:
        return ("refused", "unknown_key")
    text = envelope["manifest"].encode()
    pre = feed_preimage(1, envelope["feed_id"], envelope["key_id"], text)
    if not ed25519_verify(b64url(trusted[key]), pre, signature):
        return ("refused", "bad_signature")
    try:
        manifest = strict_json(envelope["manifest"])
    except ValueError:
        return ("refused", "bad_manifest")
    if not isinstance(manifest, dict):
        return ("refused", "bad_manifest")
    names = [(f["source"], f["name"]) for f in manifest.get("files", []) if isinstance(f, dict)]
    if (
        not manifest_validator.is_valid(manifest)
        or manifest["expires_at"] <= manifest["created_at"]
        or len(names) != len(set(names))
        or any("releases" in f and f["kind"] != "osv" for f in manifest["files"])
    ):
        return ("refused", "bad_manifest")
    if manifest["created_at"] > now + 600:
        return ("refused", "not_yet_valid")
    if now >= manifest["expires_at"]:
        return ("refused", "expired")
    applied = state.get(key)
    if applied:
        if manifest["sequence"] < applied["sequence"]:
            return ("refused", "sequence_replay")
        if manifest["sequence"] == applied["sequence"] and hashlib.sha256(pre).hexdigest() != applied["manifest_digest"]:
            return ("refused", "sequence_conflict")
    return ("accepted", None)


def check_file(entry, blob: bytes, applied_fetched_at, reader_limit: int):
    """Step 7 of "Verification order" for one file. Returns "ok" or a reason:
    `too_large` (the entry's size or the blob is over the reader's limit),
    `size_mismatch`, `hash_mismatch`, or `older_than_applied`."""
    if entry["size"] > reader_limit or len(blob) > reader_limit:
        return "too_large"
    if len(blob) != entry["size"]:
        return "size_mismatch"
    if hashlib.sha256(blob).hexdigest() != entry["sha256"]:
        return "hash_mismatch"
    if applied_fetched_at is not None and entry["fetched_at"] < applied_fetched_at:
        return "older_than_applied"
    return "ok"


def main() -> int:
    schemas = {
        path.name.removesuffix(".schema.json"): json.loads(path.read_text())
        for path in sorted((ROOT / "schemas/v1").glob("*.schema.json"))
    }
    registry = Registry().with_resources(
        (schema["$id"], Resource.from_contents(schema)) for schema in schemas.values()
    )
    failures = 0
    checked = 0
    for schema in schemas.values():
        Draft202012Validator.check_schema(schema)
    for directory in sorted((ROOT / "fixtures/v1").iterdir()):
        if directory.name not in schemas:
            print(f"no schema for fixtures/{directory.name}")
            failures += 1
            continue
        validator = Draft202012Validator(schemas[directory.name], registry=registry)
        for fixture in sorted(directory.glob("*.json")):
            expect_valid = fixture.name.startswith("valid")
            errors = list(validator.iter_errors(json.loads(fixture.read_text())))
            checked += 1
            if (not errors) != expect_valid:
                print(f"FAIL {directory.name}/{fixture.name}: valid={not errors}")
                failures += 1
            elif not expect_valid and len(errors) != 1:
                # An invalid fixture shows one defect, the one its name
                # states; a second error would hide what it tests.
                print(f"FAIL {directory.name}/{fixture.name}: {len(errors)} errors, want 1")
                failures += 1
    # Generated, not checked in: inventories at the package limits.
    base = json.loads((ROOT / "fixtures/v1/inventory-report/valid.json").read_text())
    report = Draft202012Validator(schemas["inventory-report"], registry=registry)
    for count, expect_valid in [(10_001, True), (50_000, True), (50_001, False)]:
        document = dict(
            base, packages=[dict(base["packages"][0], name=f"p{i}") for i in range(count)]
        )
        valid = report.is_valid(document)
        checked += 1
        if valid != expect_valid:
            print(f"FAIL generated inventory-report with {count} packages: valid={valid}")
            failures += 1
    # Generated, not checked in: alarm batches at their limits (P14).
    base = json.loads((ROOT / "fixtures/v1/alarm-batch/valid.json").read_text())
    batch = Draft202012Validator(schemas["alarm-batch"], registry=registry)
    alarm = base["alarms"][0]
    cases = [
        ("100 alarms", dict(base, alarms=[dict(alarm, alarm_id=f"a{i}") for i in range(100)]), True),
        ("101 alarms", dict(base, alarms=[dict(alarm, alarm_id=f"a{i}") for i in range(101)]), False),
    ]
    for count, expect_valid in [(256, True), (257, False)]:
        process = dict(alarm["process"], args=["x"] * count)
        cases.append((f"{count} args", dict(base, alarms=[dict(alarm, process=process)]), expect_valid))
    for name, document, expect_valid in cases:
        valid = batch.is_valid(document)
        checked += 1
        if valid != expect_valid:
            print(f"FAIL generated alarm-batch with {name}: valid={valid}")
            failures += 1
    # Generated, not checked in: host services at their limits (P15).
    base = json.loads((ROOT / "fixtures/v1/host-services/valid.json").read_text())
    services_validator = Draft202012Validator(schemas["host-services"], registry=registry)
    listener = base["listeners"][0]
    service = base["services"][0]
    cases = [
        ("4096 listeners", dict(base, listeners=[dict(listener, port=1 + i % 65535, address=f"10.0.{i // 250}.{i % 250}") for i in range(4096)]), True),
        ("4097 listeners", dict(base, listeners=[dict(listener, port=1 + i % 65535) for i in range(4097)]), False),
        ("2048 services", dict(base, services=[dict(service, unit=f"u{i}.service") for i in range(2048)]), True),
        ("2049 services", dict(base, services=[dict(service, unit=f"u{i}.service") for i in range(2049)]), False),
    ]
    for name, document, expect_valid in cases:
        valid = services_validator.is_valid(document)
        checked += 1
        if valid != expect_valid:
            print(f"FAIL generated host-services with {name}: valid={valid}")
            failures += 1
    # The inventory fingerprint (protocol P11): each vector's digest must be
    # the SHA-256 of the canonical JSON the contract defines.
    for vector in json.loads((ROOT / "vectors/inventory-fingerprint.json").read_text()):
        checked += 1
        if fingerprint(vector["inventory"]) != vector["sha256"]:
            print(f"FAIL fingerprint vector {vector['name']}")
            failures += 1
    # The match digest (protocol P13).
    for vector in json.loads((ROOT / "vectors/match-digest.json").read_text()):
        checked += 1
        if match_digest(vector["matches"]) != vector["sha256"]:
            print(f"FAIL match digest vector {vector['name']}")
            failures += 1
    # The services digest (protocol P15).
    # The fact catalog (P19): unique identifier keys, known types, and an
    # `unset` value of the fact's own type where one is given.
    catalog = json.loads((ROOT / "vectors/fact-catalog.json").read_text())["facts"]
    keys = [fact["key"] for fact in catalog]
    if len(keys) != len(set(keys)):
        print("FAIL fact catalog: duplicate keys")
        failures += 1
    for fact in catalog:
        problem = None
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,128}", fact["key"]):
            problem = "key is not an identifier"
        elif fact["type"] not in ("bool", "int", "string", "string_list"):
            problem = f"unknown type {fact['type']}"
        elif "unset" in fact and {"int": "-1", "string": ""}.get(fact["type"]) != fact["unset"]:
            problem = f"unset {fact['unset']!r} does not fit {fact['type']}"
        elif set(fact) - {"key", "type", "collector", "since", "note", "unset"}:
            problem = "unknown field"
        if problem:
            print(f"FAIL fact catalog {fact['key']}: {problem}")
            failures += 1

    for vector in json.loads((ROOT / "vectors/services-digest.json").read_text()):
        checked += 1
        if services_digest(vector["listeners"], vector["services"]) != vector["sha256"]:
            print(f"FAIL services digest vector {vector['name']}")
            failures += 1
    # CEL subset v2 (P14): semantics are checked by the agent's tests; here
    # only the shape, so a malformed vector cannot silently test nothing.
    kinds = {"snapshot", "process_event"}
    expects = {"true", "false", "unavailable", "refused"}
    names = set()
    for vector in json.loads((ROOT / "vectors/cel-subset-v2.json").read_text()):
        checked += 1
        ok = (
            set(vector) == {"name", "kind", "expression", "bindings", "expect"}
            and vector["kind"] in kinds
            and vector["expect"] in expects
            and isinstance(vector["expression"], str) and vector["expression"]
            and isinstance(vector["bindings"], dict)
            and all(
                isinstance(v, (str, int, bool))
                or (isinstance(v, list) and v == sorted(set(v)) and all(isinstance(s, str) for s in v))
                for v in vector["bindings"].values()
            )
            and vector["name"] not in names
        )
        names.add(vector.get("name"))
        if not ok:
            print(f"FAIL cel vector {vector.get('name')!r}")
            failures += 1
    # Alarm masking (P14): the agent's tests check the rewriting; here only
    # the shape, and that masking never changes the number of arguments.
    names = set()
    for vector in json.loads((ROOT / "vectors/alarm-masking.json").read_text()):
        checked += 1
        ok = (
            set(vector) == {"name", "exe", "args", "masked"}
            and isinstance(vector["exe"], str) and vector["exe"].startswith("/")
            and all(isinstance(x, list) and all(isinstance(a, str) for a in x) for x in (vector["args"], vector["masked"]))
            and len(vector["args"]) == len(vector["masked"])
            and vector["name"] not in names
        )
        names.add(vector.get("name"))
        if not ok:
            print(f"FAIL masking vector {vector.get('name')!r}")
            failures += 1
    # Project rule sets (P20): the agent's tests run the cases; here the
    # shape, and that every case follows the rule in spec/contracts-v1.md.
    project = json.loads((ROOT / "vectors/project-rule-sets.json").read_text())
    assignable = {s["id"]: s["assignable"] for s in project["sets"]}
    if len(assignable) != len(project["sets"]) or any(
        s["os_family"] not in ("any", "linux") for s in project["sets"]
    ):
        print("FAIL project rule sets: duplicate id or unknown os_family")
        failures += 1
    for case in project["cases"]:
        checked += 1
        added = not case["configured"]
        switched = added and assignable.get(case["rule_set_id"])
        # Only an added assignable set can be held as not assigned.
        withdrawn = case.get("withdrawn", False)
        if case["status"] == 404:
            if not added:
                want = "refused"
            elif withdrawn:
                want = "not_assigned"
            else:
                want = "refused" if case.get("accepted", False) else "not_offered"
        elif case["status"] == 410:
            want = "not_assigned" if switched else "refused"
        else:
            want = None
        if (
            (added and case["rule_set_id"] not in assignable)
            or (withdrawn and not switched)
            or case["agent"] != want
        ):
            print(f"FAIL project rule sets case {case['name']!r}")
            failures += 1
    # Signed feeds (spec/feed-v1.md): signature vectors, then the reference
    # verifier against every verification case.
    for case in json.loads((ROOT / "vectors/feed-signature.json").read_text())["cases"]:
        checked += 1
        pre = feed_preimage(case["format"], case["feed_id"], case["key_id"], case["manifest"].encode())
        if hashlib.sha256(pre).hexdigest() != case["preimage_sha256"] or (
            ed25519_verify(b64url(case["public_key"]), pre, b64url(case["signature"])) != case["valid"]
        ):
            print(f"FAIL feed signature vector {case['name']!r}")
            failures += 1
    feed_validators = (
        Draft202012Validator(schemas["feed-envelope"], registry=registry),
        Draft202012Validator(schemas["feed-manifest"], registry=registry),
    )
    for case in json.loads((ROOT / "vectors/feed-verification.json").read_text())["cases"]:
        checked += 1
        outcome, reason = verify_feed(case["envelope"], case["trusted"], case["state"], case["now"], feed_validators)
        if (outcome, reason) != (case["expect"], case.get("reason")):
            print(f"FAIL feed verification case {case['name']!r}: got {outcome} {reason}")
            failures += 1
    for case in json.loads((ROOT / "vectors/feed-files.json").read_text())["cases"]:
        checked += 1
        got = check_file(case["entry"], bytes.fromhex(case["blob_hex"]), case.get("applied_fetched_at"), case["reader_limit"])
        if got != case["expect"]:
            print(f"FAIL feed file case {case['name']!r}: got {got}")
            failures += 1
    for case in json.loads((ROOT / "vectors/feed-slim-nvd.json").read_text())["cases"]:
        checked += 1
        if slim_nvd_valid(case["file"]) != case["valid"]:
            print(f"FAIL slim NVD case {case['name']!r}")
            failures += 1
    # Generated, not checked in: an envelope over 1 MiB is bad_format.
    good = json.loads((ROOT / "fixtures/v1/feed-envelope/valid.json").read_text())
    checked += 1
    big = dict(good, manifest="x" * 1048577)
    if verify_feed(big, {}, {}, 0, feed_validators) != ("refused", "bad_format"):
        print("FAIL generated oversized feed envelope")
        failures += 1
    # Generated, not checked in: every kind at its largest size, and one over.
    maxima = {"repomd": 1 << 20, "updateinfo": 256 << 20, "osv": 8 << 30, "kev": 64 << 20,
              "epss": 128 << 20, "euvd": 64 << 20, "nvd": 512 << 20}
    sources = {"repomd": "fedora-44-x86_64", "updateinfo": "fedora-44-x86_64", "osv": "ubuntu",
               "kev": "kev", "epss": "epss", "euvd": "euvd", "nvd": "nvd"}
    base = json.loads((ROOT / "fixtures/v1/feed-manifest/valid.json").read_text())
    by_kind = {f["kind"]: f for f in base["files"]}
    for kind, limit in maxima.items():
        for size, expect_valid in [(limit, True), (limit + 1, False)]:
            document = dict(base, files=[dict(by_kind[kind], source=sources[kind], size=size)])
            checked += 1
            if feed_validators[1].is_valid(document) != expect_valid:
                print(f"FAIL generated feed-manifest with {kind} of {size} bytes")
                failures += 1
    # Generated, not checked in: a manifest at its file limit (64) and over.
    base = json.loads((ROOT / "fixtures/v1/feed-manifest/valid.json").read_text())
    for count, expect_valid in [(64, True), (65, False)]:
        document = dict(base, files=[dict(base["files"][3], source="kev", name=f"k{i}.json") for i in range(count)])
        checked += 1
        if feed_validators[1].is_valid(document) != expect_valid:
            print(f"FAIL generated feed-manifest with {count} files")
            failures += 1
    print(f"{checked} fixtures checked, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
