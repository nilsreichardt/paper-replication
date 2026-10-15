#!/usr/bin/env python3
"""Merge split attack result files into one enumeration-style JSON payload."""

from __future__ import annotations

import argparse
import json
from datetime import datetime
from pathlib import Path
from typing import Any


DEFAULT_OUTPUT_NAME = "attack_results_merged.json"


def _natural_sort_key(path: Path) -> list[int | str]:
    parts: list[int | str] = []
    current = ""
    is_digit: bool | None = None

    for char in path.name:
        char_is_digit = char.isdigit()
        if is_digit is None or char_is_digit == is_digit:
            current += char
            is_digit = char_is_digit
            continue

        parts.append(int(current) if is_digit else current.lower())
        current = char
        is_digit = char_is_digit

    if current:
        parts.append(int(current) if is_digit else current.lower())
    return parts


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as file:
        payload = json.load(file)
    if not isinstance(payload, dict):
        raise ValueError(f"{path} must contain a JSON object.")
    return payload


def _repositories_from_payload(
    payload: dict[str, Any], path: Path
) -> tuple[list[dict[str, Any]], str]:
    if isinstance(payload.get("ai_enumeration"), list):
        return [
            entry for entry in payload["ai_enumeration"] if isinstance(entry, dict)
        ], "ai_enumeration"

    enumeration = payload.get("enumeration")
    if isinstance(enumeration, dict) and isinstance(enumeration.get("repositories"), list):
        return [
            entry
            for entry in enumeration["repositories"]
            if isinstance(entry, dict)
        ], "enumeration.repositories"

    raise ValueError(
        f"{path} must contain either 'ai_enumeration' or 'enumeration.repositories'."
    )


def _merge_scopes(existing: list[str], incoming: Any) -> list[str]:
    if not isinstance(incoming, list):
        return existing

    merged = list(existing)
    seen = set(existing)
    for scope in incoming:
        if isinstance(scope, str) and scope not in seen:
            merged.append(scope)
            seen.add(scope)
    return merged


def merge_attack_results(
    input_dir: Path,
    *,
    username: str | None = None,
    scopes: list[str] | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    files = [
        path
        for path in input_dir.glob("*.json")
        if path.name != DEFAULT_OUTPUT_NAME and path.is_file()
    ]
    files.sort(key=_natural_sort_key)
    if not files:
        raise ValueError(f"No JSON files found in {input_dir}.")

    merged_repositories: list[dict[str, Any]] = []
    merged_organizations: list[Any] = []
    seen_organizations: set[str] = set()
    source_summary: list[dict[str, Any]] = []
    inferred_username = username
    merged_scopes = list(scopes or [])
    enumeration_timestamp: str | None = None

    for path in files:
        payload = _load_json(path)
        repositories, source_shape = _repositories_from_payload(payload, path)
        merged_repositories.extend(repositories)

        if inferred_username is None and isinstance(payload.get("username"), str):
            inferred_username = payload["username"]
        merged_scopes = _merge_scopes(merged_scopes, payload.get("scopes"))

        enumeration = payload.get("enumeration")
        if isinstance(enumeration, dict):
            timestamp = enumeration.get("timestamp")
            if enumeration_timestamp is None and isinstance(timestamp, str):
                enumeration_timestamp = timestamp

            organizations = enumeration.get("organizations")
            if isinstance(organizations, list):
                for organization in organizations:
                    identity = json.dumps(organization, sort_keys=True, default=str)
                    if identity not in seen_organizations:
                        merged_organizations.append(organization)
                        seen_organizations.add(identity)

        source_summary.append(
            {
                "file": path.name,
                "source_shape": source_shape,
                "repositories": len(repositories),
            }
        )

    if inferred_username is None:
        inferred_username = ""
    if enumeration_timestamp is None:
        enumeration_timestamp = ""

    result = {
        "username": inferred_username,
        "scopes": merged_scopes,
        "enumeration": {
            "timestamp": enumeration_timestamp,
            "organizations": merged_organizations,
            "repositories": merged_repositories,
        },
    }
    summary = {
        "files": len(files),
        "repositories": len(merged_repositories),
        "sources": source_summary,
    }
    return result, summary


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Merge attack result JSON files. Supports both legacy "
            "'ai_enumeration' files and canonical 'enumeration.repositories' files."
        )
    )
    parser.add_argument(
        "--input-dir",
        type=Path,
        required=True,
        help="Directory containing attack result JSON files.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help=(
            "Output JSON path. Defaults to attack_results_merged.json inside "
            "--input-dir."
        ),
    )
    parser.add_argument(
        "--username",
        help="Override the username in the merged payload.",
    )
    parser.add_argument(
        "--scope",
        action="append",
        dest="scopes",
        help="Scope to include in the merged payload. May be passed multiple times.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    input_dir = args.input_dir.expanduser()
    output = args.output.expanduser() if args.output else input_dir / DEFAULT_OUTPUT_NAME

    merged, summary = merge_attack_results(
        input_dir,
        username=args.username,
        scopes=args.scopes,
    )
    output.parent.mkdir(parents=True, exist_ok=True)
    with output.open("w", encoding="utf-8") as file:
        json.dump(merged, file, indent=2, ensure_ascii=False)
        file.write("\n")

    print(f"Wrote {summary['repositories']} repositories from {summary['files']} files to {output}")
    for source in summary["sources"]:
        print(
            f"- {source['file']}: {source['repositories']} repositories "
            f"({source['source_shape']})"
        )
    print(f"Completed at {datetime.now().isoformat(timespec='seconds')}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
