#!/usr/bin/env python3
"""Checks every fixture against its schema.

fixtures/v1/<message>/valid*.json must validate against
schemas/v1/<message>.schema.json, and invalid*.json must not. Exits non-zero
on any mismatch. Requires the packages pinned in tools/requirements.txt.
"""

import hashlib
import json
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
    print(f"{checked} fixtures checked, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
