from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import shutil
from typing import Any, Sequence


DEFAULT_FAILED_STATUSES = {"blocked_preparation_error", "execution_error"}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Remove failed repositories from an attack result JSON, backing up the "
            "original file first."
        )
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Path to attack result JSON file.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report changes without writing backup or overwriting the JSON file.",
    )
    parser.add_argument(
        "--failed-status",
        action="append",
        default=None,
        help=(
            "Risk-level attack_result.status value to treat as failed. "
            "Repeat to add more values."
        ),
    )
    return parser


def _format_backup_timestamp() -> str:
    return datetime.now().strftime("%Y%m%dT%H%M%S")


def _normalize_failed_statuses(failed_statuses: Sequence[str] | None) -> set[str]:
    if not failed_statuses:
        return set(DEFAULT_FAILED_STATUSES)
    normalized = {status.strip() for status in failed_statuses if status.strip()}
    return normalized or set(DEFAULT_FAILED_STATUSES)


def _iter_attack_statuses(repository: dict[str, Any]) -> list[str]:
    risks = repository.get("risks")
    if not isinstance(risks, list):
        return []
    statuses: list[str] = []
    for risk in risks:
        if not isinstance(risk, dict):
            continue
        attack_result = risk.get("attack_result")
        if not isinstance(attack_result, dict):
            continue
        status = attack_result.get("status")
        if isinstance(status, str) and status.strip():
            statuses.append(status.strip())
    return statuses


def repository_is_failed(repository: dict[str, Any], failed_statuses: set[str]) -> bool:
    error_value = repository.get("error")
    if isinstance(error_value, str) and error_value.strip():
        return True
    return any(status in failed_statuses for status in _iter_attack_statuses(repository))


def filter_failed_repositories(
    repositories: Sequence[dict[str, Any]],
    failed_statuses: set[str],
) -> tuple[list[dict[str, Any]], int]:
    kept: list[dict[str, Any]] = []
    removed = 0
    for repository in repositories:
        if repository_is_failed(repository, failed_statuses):
            removed += 1
            continue
        kept.append(repository)
    return kept, removed


def _build_backup_path(file_path: Path, timestamp: str) -> Path:
    suffix = file_path.suffix
    backup_name_base = (
        f"{file_path.stem}.{timestamp}{suffix}"
        if suffix
        else f"{file_path.name}.{timestamp}"
    )
    backup_path = file_path.with_name(backup_name_base)
    counter = 1
    while backup_path.exists():
        backup_name = (
            f"{file_path.stem}.{timestamp}.{counter}{suffix}"
            if suffix
            else f"{file_path.name}.{timestamp}.{counter}"
        )
        backup_path = file_path.with_name(backup_name)
        counter += 1
    return backup_path


def create_backup_copy(file_path: Path, *, timestamp: str | None = None) -> Path:
    backup_timestamp = timestamp or _format_backup_timestamp()
    backup_path = _build_backup_path(file_path, backup_timestamp)
    shutil.copy2(file_path, backup_path)
    return backup_path


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    file_path = Path(args.file)
    if not file_path.exists() or not file_path.is_file():
        parser.error(f"--file must point to an existing file: {file_path}")

    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"Unable to read or parse JSON file {file_path}: {exc}")

    if not isinstance(payload, dict):
        parser.error("JSON payload must be an object.")

    repositories = payload.get("ai_enumeration")
    if not isinstance(repositories, list):
        parser.error("JSON payload must contain an 'ai_enumeration' list.")

    failed_statuses = _normalize_failed_statuses(args.failed_status)
    kept_repositories, removed_count = filter_failed_repositories(
        repositories, failed_statuses
    )
    original_count = len(repositories)
    kept_count = len(kept_repositories)

    backup_path: Path | None = None
    if not args.dry_run:
        backup_path = create_backup_copy(file_path)
        payload["ai_enumeration"] = kept_repositories
        file_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

    print(f"Original repositories: {original_count}")
    print(f"Removed failed repositories: {removed_count}")
    print(f"Kept repositories: {kept_count}")
    print(f"Backup path: {backup_path if backup_path is not None else 'N/A (dry-run)'}")
    print(f"Output path: {file_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
