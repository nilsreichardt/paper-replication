from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import shutil
from typing import Any, Sequence


BLOCKED_PREPARATION_STATUS = "blocked_preparation_error"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Back up an attack result JSON and remove repositories that contain "
            "a blocked_preparation_error attack result."
        )
    )
    parser.add_argument(
        "file",
        help="Path to the attack result JSON file to update in place.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Report how many repositories would be removed without writing changes.",
    )
    return parser


def _format_backup_timestamp() -> str:
    return datetime.now().strftime("%Y%m%dT%H%M%S")


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


def _repository_has_blocked_preparation_error(repository: dict[str, Any]) -> bool:
    risks = repository.get("risks")
    if not isinstance(risks, list):
        return False
    for risk in risks:
        if not isinstance(risk, dict):
            continue
        attack_result = risk.get("attack_result")
        if not isinstance(attack_result, dict):
            continue
        status = attack_result.get("status")
        if status == BLOCKED_PREPARATION_STATUS:
            return True
    return False


def filter_repositories(
    repositories: Sequence[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[str]]:
    kept: list[dict[str, Any]] = []
    removed_names: list[str] = []
    for repository in repositories:
        if _repository_has_blocked_preparation_error(repository):
            repository_name = repository.get("name")
            removed_names.append(
                repository_name if isinstance(repository_name, str) else "<unknown>"
            )
            continue
        kept.append(repository)
    return kept, removed_names


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    file_path = Path(args.file)
    if not file_path.exists() or not file_path.is_file():
        parser.error(f"file must point to an existing file: {file_path}")

    try:
        payload = json.loads(file_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        parser.error(f"Unable to read or parse JSON file {file_path}: {exc}")

    if not isinstance(payload, dict):
        parser.error("JSON payload must be an object.")

    repositories = payload.get("ai_enumeration")
    if not isinstance(repositories, list):
        parser.error("JSON payload must contain an 'ai_enumeration' list.")

    kept_repositories, removed_names = filter_repositories(repositories)

    backup_path: Path | None = None
    if not args.dry_run:
        backup_path = create_backup_copy(file_path)
        payload["ai_enumeration"] = kept_repositories
        file_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )

    print(f"Original repositories: {len(repositories)}")
    print(f"Removed repositories: {len(removed_names)}")
    if removed_names:
        print("Removed repository names:")
        for repository_name in removed_names:
            print(repository_name)
    print(f"Kept repositories: {len(kept_repositories)}")
    print(f"Backup path: {backup_path if backup_path is not None else 'N/A (dry-run)'}")
    print(f"Output path: {file_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
