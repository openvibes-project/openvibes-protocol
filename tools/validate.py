#!/usr/bin/env python3
"""Checks every fixture against its schema.

fixtures/v1/<message>/valid*.json must validate against
schemas/v1/<message>.schema.json, and invalid*.json must not. Exits non-zero
on any mismatch. Requires the packages pinned in tools/requirements.txt.
"""

import json
import sys
from pathlib import Path

from jsonschema import Draft202012Validator
from referencing import Registry, Resource

ROOT = Path(__file__).resolve().parent.parent


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
    print(f"{checked} fixtures checked, {failures} failures")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
