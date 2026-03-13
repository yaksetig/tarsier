#!/usr/bin/env python3
"""Fast drift checks for cert-suite manifests, schema docs, and hashes."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any


DOC_NEEDLES = [
    "`enforce_library_coverage`",
    "`enforce_corpus_breadth`",
    "`enforce_model_hash_consistency`",
    "`enforce_known_bug_sentinels`",
    "`required_known_bug_families`",
    "`required_variant_groups`",
    "`model_sha256`",
    "`notes`",
    "`family`",
    "`class`",
]

ENTRY_REQUIRED_FIELDS = ["file", "family", "class", "notes", "model_sha256"]
TOP_LEVEL_REQUIRED_FIELDS = ["schema_version", "entries"]


def load_json(path: Path) -> dict[str, Any]:
    raw = json.loads(path.read_text())
    if not isinstance(raw, dict):
        raise ValueError(f"{path} must contain a top-level JSON object")
    return raw


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def resolve_library_dir(manifest_path: Path, manifest: dict[str, Any]) -> Path:
    library_dir = manifest.get("library_dir", ".")
    if not isinstance(library_dir, str) or not library_dir.strip():
        raise ValueError("manifest field 'library_dir' must be a non-empty string")
    return (manifest_path.parent / library_dir).resolve()


def resolve_entry_path(base_dir: Path, rel: str) -> Path:
    path = Path(rel)
    if not path.is_absolute():
        path = (base_dir / path).resolve()
    return path


def check_manifest_schema_sync(
    manifest: dict[str, Any],
    schema: dict[str, Any],
    schema_path: Path,
    schema_doc_text: str,
) -> list[str]:
    errors: list[str] = []

    properties = schema.get("properties")
    if not isinstance(properties, dict):
        return [f"{schema_path} is missing object-valued 'properties'"]

    entry_properties = (
        schema.get("$defs", {})
        .get("entry", {})
        .get("properties")
    )
    if not isinstance(entry_properties, dict):
        errors.append(f"{schema_path} is missing object-valued '$defs.entry.properties'")
        return errors

    for key in manifest.keys():
        if key not in properties:
            errors.append(
                f"Manifest top-level key '{key}' is missing from {schema_path} properties."
            )

    entries = manifest.get("entries")
    if not isinstance(entries, list):
        errors.append("Manifest field 'entries' must be an array.")
        return errors

    for idx, entry in enumerate(entries):
        if not isinstance(entry, dict):
            errors.append(f"Manifest entry {idx} must be an object.")
            continue
        for key in entry.keys():
            if key not in entry_properties:
                errors.append(
                    f"Manifest entry key '{key}' is missing from {schema_path} entry properties."
                )

    schema_version = properties.get("schema_version", {}).get("const")
    if not isinstance(schema_version, int):
        errors.append(f"{schema_path} is missing integer properties.schema_version.const")
        return errors

    manifest_version = manifest.get("schema_version")
    if manifest_version != schema_version:
        errors.append(
            f"Manifest schema_version={manifest_version!r} does not match "
            f"{schema_path} const {schema_version}."
        )

    expected_schema_name = f"cert-suite-schema-v{schema_version}.json"
    if schema_path.name != expected_schema_name:
        errors.append(
            f"Expected cert-suite schema artifact name '{expected_schema_name}', got '{schema_path.name}'."
        )

    required = schema.get("required")
    if not isinstance(required, list):
        errors.append(f"{schema_path} is missing array-valued 'required'")
    else:
        required_set = {item for item in required if isinstance(item, str)}
        for field in TOP_LEVEL_REQUIRED_FIELDS:
            if field not in required_set:
                errors.append(f"{schema_path} required[] is missing '{field}'.")

    entry_required = schema.get("$defs", {}).get("entry", {}).get("required")
    if not isinstance(entry_required, list):
        errors.append(f"{schema_path} is missing array-valued '$defs.entry.required'")
    else:
        entry_required_set = {item for item in entry_required if isinstance(item, str)}
        for field in ENTRY_REQUIRED_FIELDS:
            if field not in entry_required_set:
                errors.append(f"{schema_path} $defs.entry.required[] is missing '{field}'.")

    if f"schema_version == {schema_version}" not in schema_doc_text:
        errors.append(
            "docs/CERT_SUITE_SCHEMA.md does not document the exact schema_version contract."
        )
    try:
        schema_doc_ref = schema_path.relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        schema_doc_ref = schema_path.as_posix()

    if schema_doc_ref not in schema_doc_text:
        errors.append(
            f"docs/CERT_SUITE_SCHEMA.md is missing a reference to {schema_doc_ref}."
        )
    for needle in DOC_NEEDLES:
        if needle not in schema_doc_text:
            errors.append(f"docs/CERT_SUITE_SCHEMA.md is missing expected contract reference {needle}.")

    return errors


def check_library_coverage(manifest_path: Path, manifest: dict[str, Any]) -> list[str]:
    if not manifest.get("enforce_library_coverage", False):
        return []

    errors: list[str] = []
    library_dir = resolve_library_dir(manifest_path, manifest)
    if not library_dir.exists():
        return [f"Library directory '{library_dir}' does not exist."]
    if not library_dir.is_dir():
        return [f"Library directory '{library_dir}' is not a directory."]

    entries = manifest.get("entries", [])
    if not isinstance(entries, list):
        return ["Manifest field 'entries' must be an array."]

    on_disk_files = {
        path.name
        for path in library_dir.iterdir()
        if path.is_file() and path.suffix.lower() == ".trs"
    }

    manifest_files: set[str] = set()
    seen_files: set[str] = set()
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        file_value = entry.get("file", "")
        if not isinstance(file_value, str) or not file_value.strip():
            continue
        file_name = Path(file_value).name
        if file_name in seen_files:
            errors.append(f"Manifest contains duplicate entry for '{file_name}'.")
        seen_files.add(file_name)
        manifest_files.add(file_name)

    for missing in sorted(on_disk_files - manifest_files):
        errors.append(
            f"Library file '{missing}' has no entry in cert_suite.json. "
            f"Add an expectation entry under {manifest_path}."
        )
    for stale in sorted(manifest_files - on_disk_files):
        errors.append(
            f"Manifest contains '{stale}' but '{library_dir}' has no such protocol file."
        )

    return errors


def check_model_hashes(manifest_path: Path, manifest: dict[str, Any]) -> list[str]:
    if not manifest.get("enforce_model_hash_consistency", False):
        return []

    errors: list[str] = []
    entries = manifest.get("entries", [])
    if not isinstance(entries, list):
        return ["Manifest field 'entries' must be an array."]

    base_dir = manifest_path.parent
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        rel = entry.get("file", "")
        if not isinstance(rel, str) or not rel.strip():
            continue
        path = resolve_entry_path(base_dir, rel)
        if not path.exists():
            errors.append(
                f"Entry '{rel}' points to missing protocol file '{path}'."
            )
            continue
        actual = sha256_file(path)
        expected = entry.get("model_sha256")
        if expected != actual:
            errors.append(
                f"Entry '{rel}' has stale model_sha256 (expected {expected}, actual {actual}). "
                f"Run `python3 scripts/update-cert-suite-hashes.py --manifest {manifest_path}`."
            )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--manifest",
        default="examples/library/cert_suite.json",
        help="Path to the canonical cert-suite manifest.",
    )
    parser.add_argument(
        "--schema",
        default="docs/cert-suite-schema-v2.json",
        help="Path to the cert-suite JSON schema artifact.",
    )
    parser.add_argument(
        "--schema-doc",
        default="docs/CERT_SUITE_SCHEMA.md",
        help="Path to the human-readable cert-suite schema contract doc.",
    )
    args = parser.parse_args()

    manifest_path = Path(args.manifest).resolve()
    schema_path = Path(args.schema).resolve()
    schema_doc_path = Path(args.schema_doc).resolve()

    manifest = load_json(manifest_path)
    schema = load_json(schema_path)
    schema_doc_text = schema_doc_path.read_text()

    errors: list[str] = []
    errors.extend(check_manifest_schema_sync(manifest, schema, schema_path, schema_doc_text))
    errors.extend(check_library_coverage(manifest_path, manifest))
    errors.extend(check_model_hashes(manifest_path, manifest))

    if errors:
        print("Generated artifact drift detected:")
        for error in errors:
            print(f"  - {error}")
        print()
        print("Suggested local fixes:")
        print("  - Run `just artifact-drift` to reproduce this check locally.")
        print(
            "  - Run `just refresh-cert-suite-hashes` after protocol edits that change model_sha256."
        )
        return 1

    print(
        "Generated artifact drift checks passed for "
        f"{manifest_path.name}, {schema_path.name}, and {schema_doc_path.name}."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
