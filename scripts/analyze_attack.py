#!/usr/bin/env python3
"""Analyze attack output, including vulnerability and mismatch breakdowns."""

from __future__ import annotations

import argparse
from datetime import datetime
import json
import re
from pathlib import Path
import shutil
from typing import Any


def _increment_counter(counter: dict[str, int], key: str | None) -> None:
    normalized = str(key or "missing").strip() or "missing"
    counter[normalized] = counter.get(normalized, 0) + 1


def _to_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
        return None
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1"}:
            return True
        if normalized in {"false", "no", "n", "0"}:
            return False
    return None


def _hookbin_has_github_token_write(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()

    if "github_token permissions" in lowered and "write" in lowered:
        return True
    if "github token permissions" in lowered and "write" in lowered:
        return True

    return bool(
        re.search(
            r"github[_\-\s]*token\s*permissions[\s\S]{0,200}\bwrite\b",
            lowered,
        )
    )


def _hookbin_has_secret(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()

    # Hookbin payloads are often a concatenated sequence of JSON-like objects:
    # "SECRET_NAME":{"value":"...","isSecret":true}
    # Parse object blocks with brace + string awareness so braces inside quoted
    # values (for example flag{...}) do not break extraction.
    secret_name_matches: list[str] = []
    key_pattern = re.compile(r'"([^"]+)"\s*:\s*\{')
    for match in key_pattern.finditer(value):
        secret_name = match.group(1)
        obj_start = match.end() - 1  # points to "{"
        depth = 0
        in_string = False
        escape = False
        obj_end: int | None = None

        for idx in range(obj_start, len(value)):
            ch = value[idx]
            if in_string:
                if escape:
                    escape = False
                elif ch == "\\":
                    escape = True
                elif ch == '"':
                    in_string = False
                continue

            if ch == '"':
                in_string = True
                continue
            if ch == "{":
                depth += 1
                continue
            if ch == "}":
                depth -= 1
                if depth == 0:
                    obj_end = idx
                    break

        if obj_end is None:
            continue
        obj_text = value[obj_start : obj_end + 1]
        if re.search(r'"isSecret"\s*:\s*true', obj_text, flags=re.IGNORECASE):
            secret_name_matches.append(secret_name)

    ignored_names = {"github_token", "system.github.token"}
    for secret_name in secret_name_matches:
        if secret_name.strip().lower() not in ignored_names:
            return True

    # Fallback for odd payloads where secret names are not parseable.
    if "flag{" in lowered and not secret_name_matches:
        return True

    return False


def _has_clear_exploit_job_github_token_permissions(risk: Any) -> bool:
    if not isinstance(risk, dict):
        return False
    attack_result = risk.get("attack_result")
    if not isinstance(attack_result, dict):
        return False
    permissions = attack_result.get("exploit_job_github_token_permissions")
    if not isinstance(permissions, dict):
        return False
    status = permissions.get("status")
    if not isinstance(status, str):
        return False
    return status.strip().lower() in {"write", "read", "non-write"}


def _repo_matches_vulnerable_with_secret_or_write_gh_token(
    entry: dict[str, Any],
) -> bool:
    repo_vulnerable = _to_bool(entry.get("repo_vulnerable"))
    act_repo_vulnerable = _to_bool(entry.get("act_repo_vulnerable"))
    if repo_vulnerable is not True and act_repo_vulnerable is not True:
        return False

    risks = entry.get("risks")
    hookbin_values: list[Any] = []
    repo_has_clear_exploit_job_permissions = False

    # Primary location in this dataset: risks[*].attack_result.execution_result.hookbin_logs
    if isinstance(risks, list):
        for risk in risks:
            if not isinstance(risk, dict):
                continue
            if _has_clear_exploit_job_github_token_permissions(risk):
                repo_has_clear_exploit_job_permissions = True
            attack_result = risk.get("attack_result")
            if not isinstance(attack_result, dict):
                continue
            execution_result = attack_result.get("execution_result")
            if isinstance(execution_result, dict) and "hookbin_logs" in execution_result:
                hookbin_values.append(execution_result.get("hookbin_logs"))

    # Backward-compatible fallback location.
    execution_result = entry.get("execution_result")
    if isinstance(execution_result, dict) and "hookbin_logs" in execution_result:
        hookbin_values.append(execution_result.get("hookbin_logs"))

    if not hookbin_values or not any(value != "" for value in hookbin_values):
        return False

    has_token_write_or_secret = any(
        _hookbin_has_github_token_write(value) or _hookbin_has_secret(value)
        for value in hookbin_values
    )
    return repo_has_clear_exploit_job_permissions or has_token_write_or_secret


def annotate_vulnerable_with_secret_or_write_gh_token(
    entries: list[dict[str, Any]],
) -> int:
    true_count = 0
    for entry in entries:
        matches = _repo_matches_vulnerable_with_secret_or_write_gh_token(entry)
        entry["vulnerable_with_secret_or_write_gh_token"] = matches
        if matches:
            true_count += 1
    return true_count


def _extract_ai_enumeration_objects(
    raw_text: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    marker = '"ai_enumeration"'
    key_idx = raw_text.find(marker)
    if key_idx == -1:
        raise ValueError("Could not find 'ai_enumeration' key in input file.")

    array_start = raw_text.find("[", key_idx)
    if array_start == -1:
        raise ValueError("Could not find start of ai_enumeration array.")

    objects: list[dict[str, Any]] = []
    parse_errors = 0
    in_string = False
    escape = False
    depth = 0
    obj_start: int | None = None
    incomplete_trailing_object = False

    for idx in range(array_start + 1, len(raw_text)):
        ch = raw_text[idx]

        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue

        if ch == '"':
            in_string = True
            continue

        if ch == "{":
            if depth == 0:
                obj_start = idx
            depth += 1
            continue

        if ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0 and obj_start is not None:
                    candidate = raw_text[obj_start : idx + 1]
                    try:
                        parsed = json.loads(candidate)
                    except json.JSONDecodeError:
                        parse_errors += 1
                    else:
                        if isinstance(parsed, dict):
                            objects.append(parsed)
                    obj_start = None
            continue

        if ch == "]" and depth == 0:
            break
    else:
        if depth > 0:
            incomplete_trailing_object = True

    meta = {
        "recovered_from_truncated_json": True,
        "object_parse_errors": parse_errors,
        "incomplete_trailing_object": incomplete_trailing_object,
    }
    return objects, meta


def _coerce_entries_from_payload(
    payload: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    entries = payload.get("ai_enumeration")
    if isinstance(entries, list):
        return [entry for entry in entries if isinstance(entry, dict)], {
            "payload_kind": "ai_enumeration",
            "normalized_from": None,
        }

    enumeration = payload.get("enumeration")
    if isinstance(enumeration, dict):
        repositories = enumeration.get("repositories")
        if isinstance(repositories, list):
            return [entry for entry in repositories if isinstance(entry, dict)], {
                "payload_kind": "enumeration_repositories",
                "normalized_from": "enumeration.repositories",
            }

    raise ValueError(
        "Input JSON has no supported repository list. Expected 'ai_enumeration' "
        "or 'enumeration.repositories'."
    )


def _load_entries(path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    raw_text = path.read_text(encoding="utf-8")

    try:
        payload = json.loads(raw_text)
    except json.JSONDecodeError:
        entries, meta = _extract_ai_enumeration_objects(raw_text)
        meta.update(
            {
                "payload_kind": "ai_enumeration_truncated",
                "normalized_from": None,
            }
        )
        return entries, meta

    if isinstance(payload, dict):
        entries, kind_meta = _coerce_entries_from_payload(payload)
        return entries, {
            "recovered_from_truncated_json": False,
            "object_parse_errors": 0,
            "incomplete_trailing_object": False,
            **kind_meta,
        }

    if isinstance(payload, list):
        return [entry for entry in payload if isinstance(entry, dict)], {
            "recovered_from_truncated_json": False,
            "object_parse_errors": 0,
            "incomplete_trailing_object": False,
            "payload_kind": "top_level_list",
            "normalized_from": None,
        }

    raise ValueError("Unsupported JSON shape: expected object or list.")


def _load_annotatable_payload(path: Path) -> tuple[Any, list[dict[str, Any]], dict[str, Any]]:
    raw_text = path.read_text(encoding="utf-8")
    payload = json.loads(raw_text)

    if isinstance(payload, dict):
        entries, kind_meta = _coerce_entries_from_payload(payload)
        return payload, entries, {
            "recovered_from_truncated_json": False,
            "object_parse_errors": 0,
            "incomplete_trailing_object": False,
            **kind_meta,
        }

    if isinstance(payload, list):
        return payload, [entry for entry in payload if isinstance(entry, dict)], {
            "recovered_from_truncated_json": False,
            "object_parse_errors": 0,
            "incomplete_trailing_object": False,
            "payload_kind": "top_level_list",
            "normalized_from": None,
        }

    raise ValueError("Unsupported JSON shape: expected object or list.")


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


def analyze(entries: list[dict[str, Any]]) -> dict[str, Any]:
    true_false_repos: list[str] = []
    false_true_repos: list[str] = []
    true_true_repos: list[str] = []
    vulnerable_repos: list[str] = []
    github_hosted_vulnerable_repos: list[str] = []
    act_vulnerable_repos: list[str] = []
    hookbin_empty_repos: list[str] = []
    hookbin_not_empty_repos: list[str] = []
    hookbin_missing_repos: list[str] = []
    hookbin_not_empty_and_token_write_or_has_secret_repos: list[str] = []
    hookbin_not_empty_and_token_write_or_has_secret_or_clear_permissions_repos: list[
        str
    ] = []
    skipped_non_boolean = 0
    status_counts: dict[str, int] = {}
    error_stage_counts: dict[str, int] = {}
    failure_fingerprint_counts: dict[str, int] = {}
    secret_seed_failure_class_counts: dict[str, int] = {}
    vulnerable_repo_first_attempt: dict[str, int] = {}
    last_processed_repo_name: str | None = None
    last_processed_repo_date: str | None = None

    for entry in entries:
        repo_name = str(entry.get("name") or "<unknown>")
        last_processed_repo_name = repo_name
        repo_vulnerable = _to_bool(entry.get("repo_vulnerable"))
        act_repo_vulnerable = _to_bool(entry.get("act_repo_vulnerable"))
        risks = entry.get("risks")
        entry_last_processed_time: str | None = None
        if isinstance(risks, list):
            for risk in risks:
                if not isinstance(risk, dict):
                    continue
                risk_processed_time = risk.get("attack_processed_time")
                if isinstance(risk_processed_time, str) and risk_processed_time.strip():
                    entry_last_processed_time = risk_processed_time.strip()
                attack_result = risk.get("attack_result")
                if not isinstance(attack_result, dict):
                    continue
                _increment_counter(status_counts, attack_result.get("status"))
                _increment_counter(error_stage_counts, attack_result.get("error_stage"))
                _increment_counter(
                    failure_fingerprint_counts,
                    attack_result.get("failure_fingerprint"),
                )
                execution_result = attack_result.get("execution_result")
                if isinstance(execution_result, dict):
                    execution_vulnerable = _to_bool(execution_result.get("vulnerable"))
                    if execution_vulnerable is True:
                        attempt_value = execution_result.get("attempt")
                        if not isinstance(attempt_value, int) or attempt_value <= 0:
                            attempt_count_value = execution_result.get("attempt_count")
                            if (
                                isinstance(attempt_count_value, int)
                                and attempt_count_value > 0
                            ):
                                attempt_value = attempt_count_value
                        if isinstance(attempt_value, int) and attempt_value > 0:
                            previous = vulnerable_repo_first_attempt.get(repo_name)
                            if previous is None or attempt_value < previous:
                                vulnerable_repo_first_attempt[repo_name] = attempt_value
                seed_failures = attack_result.get("secret_seed_failures")
                if isinstance(seed_failures, list):
                    for failure in seed_failures:
                        if not isinstance(failure, dict):
                            continue
                        _increment_counter(
                            secret_seed_failure_class_counts,
                            failure.get("failure_class"),
                        )
        if entry_last_processed_time is None:
            entry_processed_time = entry.get("attack_processed_time")
            if isinstance(entry_processed_time, str) and entry_processed_time.strip():
                entry_last_processed_time = entry_processed_time.strip()
        if entry_last_processed_time is None:
            enum_time = entry.get("enum_time")
            if isinstance(enum_time, str) and enum_time.strip():
                entry_last_processed_time = enum_time.strip()
        if entry_last_processed_time is not None:
            last_processed_repo_date = entry_last_processed_time

        # Include only repos where either side is explicitly true.
        if repo_vulnerable is True or act_repo_vulnerable is True:
            vulnerable_repos.append(repo_name)
            hookbin_values: list[Any] = []

            # Primary location in this dataset: risks[*].attack_result.execution_result.hookbin_logs
            if isinstance(risks, list):
                for risk in risks:
                    if not isinstance(risk, dict):
                        continue
                    attack_result = risk.get("attack_result")
                    if not isinstance(attack_result, dict):
                        continue
                    execution_result = attack_result.get("execution_result")
                    if (
                        isinstance(execution_result, dict)
                        and "hookbin_logs" in execution_result
                    ):
                        hookbin_values.append(execution_result.get("hookbin_logs"))

            # Backward-compatible fallback location.
            execution_result = entry.get("execution_result")
            if (
                isinstance(execution_result, dict)
                and "hookbin_logs" in execution_result
            ):
                hookbin_values.append(execution_result.get("hookbin_logs"))

            if not hookbin_values:
                hookbin_missing_repos.append(repo_name)
            elif any(value != "" for value in hookbin_values):
                hookbin_not_empty_repos.append(repo_name)
                if any(
                    _hookbin_has_github_token_write(value) or _hookbin_has_secret(value)
                    for value in hookbin_values
                ):
                    hookbin_not_empty_and_token_write_or_has_secret_repos.append(
                        repo_name
                    )
                if _repo_matches_vulnerable_with_secret_or_write_gh_token(entry):
                    hookbin_not_empty_and_token_write_or_has_secret_or_clear_permissions_repos.append(
                        repo_name
                    )
            else:
                hookbin_empty_repos.append(repo_name)

        if repo_vulnerable:
            github_hosted_vulnerable_repos.append(repo_name)
        if act_repo_vulnerable:
            act_vulnerable_repos.append(repo_name)

        if repo_vulnerable is None or act_repo_vulnerable is None:
            skipped_non_boolean += 1
            continue

        if repo_vulnerable and not act_repo_vulnerable:
            true_false_repos.append(repo_name)
        elif (not repo_vulnerable) and act_repo_vulnerable:
            false_true_repos.append(repo_name)
        elif repo_vulnerable and act_repo_vulnerable:
            true_true_repos.append(repo_name)

    true_false_repos = sorted(set(true_false_repos))
    false_true_repos = sorted(set(false_true_repos))
    true_true_repos = sorted(set(true_true_repos))
    vulnerable_repos = sorted(set(vulnerable_repos))
    github_hosted_vulnerable_repos = sorted(set(github_hosted_vulnerable_repos))
    act_vulnerable_repos = sorted(set(act_vulnerable_repos))
    hookbin_empty_repos = sorted(set(hookbin_empty_repos))
    hookbin_not_empty_repos = sorted(set(hookbin_not_empty_repos))
    hookbin_missing_repos = sorted(set(hookbin_missing_repos))
    hookbin_not_empty_and_token_write_or_has_secret_repos = sorted(
        set(hookbin_not_empty_and_token_write_or_has_secret_repos)
    )
    hookbin_not_empty_and_token_write_or_has_secret_or_clear_permissions_repos = sorted(
        set(hookbin_not_empty_and_token_write_or_has_secret_or_clear_permissions_repos)
    )
    vulnerable_by_attempt: dict[int, int] = {}
    for first_attempt in vulnerable_repo_first_attempt.values():
        vulnerable_by_attempt[first_attempt] = vulnerable_by_attempt.get(first_attempt, 0) + 1

    return {
        "total_entries_processed": len(entries),
        "entries_skipped_non_boolean_or_missing_flags": skipped_non_boolean,
        "mismatch_total": len(true_false_repos) + len(false_true_repos),
        "vulnerable_repositories": {
            "count": len(vulnerable_repos),
            "repos": vulnerable_repos,
        },
        "github_hosted_vulnerable_repositories": {
            "count": len(github_hosted_vulnerable_repos),
            "repos": github_hosted_vulnerable_repos,
        },
        "act_vulnerable_repositories": {
            "count": len(act_vulnerable_repos),
            "repos": act_vulnerable_repos,
        },
        "repo_vulnerable_true_act_repo_vulnerable_false": {
            "count": len(true_false_repos),
            "repos": true_false_repos,
        },
        "repo_vulnerable_false_act_repo_vulnerable_true": {
            "count": len(false_true_repos),
            "repos": false_true_repos,
        },
        "repo_vulnerable_true_act_repo_vulnerable_true": {
            "count": len(true_true_repos),
            "repos": true_true_repos,
        },
        "hookbin_logs_for_repos_with_repo_or_act_true": {
            "total_repos_in_scope": (
                len(hookbin_empty_repos)
                + len(hookbin_not_empty_repos)
                + len(hookbin_missing_repos)
            ),
            "hookbin_logs_empty_string": {
                "count": len(hookbin_empty_repos),
                "repos": hookbin_empty_repos,
            },
            "hookbin_logs_not_empty_string": {
                "count": len(hookbin_not_empty_repos),
                "repos": hookbin_not_empty_repos,
            },
            "hookbin_logs_not_empty_string_and_github_token_write_or_has_secret": {
                "count": len(hookbin_not_empty_and_token_write_or_has_secret_repos),
                "repos": hookbin_not_empty_and_token_write_or_has_secret_repos,
            },
            "hookbin_logs_not_empty_string_and_github_token_write_or_has_secret_or_clear_permissions": {
                "count": len(
                    hookbin_not_empty_and_token_write_or_has_secret_or_clear_permissions_repos
                ),
                "repos": (
                    hookbin_not_empty_and_token_write_or_has_secret_or_clear_permissions_repos
                ),
            },
            "missing_execution_result_or_hookbin_logs": {
                "count": len(hookbin_missing_repos),
                "repos": hookbin_missing_repos,
            },
        },
        "attack_result_breakdown": {
            "status": dict(sorted(status_counts.items())),
            "error_stage": dict(sorted(error_stage_counts.items())),
            "failure_fingerprint": dict(sorted(failure_fingerprint_counts.items())),
            "secret_seed_failure_class": dict(
                sorted(secret_seed_failure_class_counts.items())
            ),
            "vulnerable_repositories_by_first_attempt": {
                str(attempt): count
                for attempt, count in sorted(vulnerable_by_attempt.items())
            },
        },
        "last_processed_repository": {
            "name": last_processed_repo_name,
            "date": last_processed_repo_date,
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze attack result output JSON")
    parser.add_argument(
        "--input",
        "--file",
        required=True,
        help="Path to attack results JSON file (alias: --file)",
        dest="input",
    )
    parser.add_argument(
        "--output",
        required=False,
        help="Optional path to write analysis report JSON",
    )
    parser.add_argument(
        "--add-vulnerable-with-secret-or-write-gh-token",
        action="store_true",
        help=(
            "Add vulnerable_with_secret_or_write_gh_token to each repository. "
            "Writes to --annotated-output, or updates --input in place with a backup."
        ),
    )
    parser.add_argument(
        "--annotated-output",
        required=False,
        help=(
            "Optional path for the annotated attack result JSON. Only used with "
            "--add-vulnerable-with-secret-or-write-gh-token."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    input_path = Path(args.input).expanduser().resolve()
    output_path = Path(args.output).expanduser().resolve() if args.output else None

    annotated_payload: Any | None = None
    annotated_true_count: int | None = None
    annotated_output_path: Path | None = None
    annotation_backup_path: Path | None = None
    if args.add_vulnerable_with_secret_or_write_gh_token:
        annotated_payload, entries, loader_meta = _load_annotatable_payload(input_path)
        annotated_true_count = annotate_vulnerable_with_secret_or_write_gh_token(entries)
        annotated_output_path = (
            Path(args.annotated_output).expanduser().resolve()
            if args.annotated_output
            else input_path
        )
        if annotated_output_path == input_path:
            annotation_backup_path = create_backup_copy(input_path)
        annotated_output_path.parent.mkdir(parents=True, exist_ok=True)
        annotated_output_path.write_text(
            json.dumps(annotated_payload, indent=2, ensure_ascii=True) + "\n",
            encoding="utf-8",
        )
    else:
        entries, loader_meta = _load_entries(input_path)

    report = {
        "input_file": str(input_path),
        "output_file": str(output_path) if output_path else None,
        "annotated_output_file": (
            str(annotated_output_path) if annotated_output_path else None
        ),
        "annotation_backup_file": (
            str(annotation_backup_path) if annotation_backup_path else None
        ),
        "annotated_vulnerable_with_secret_or_write_gh_token_count": (
            annotated_true_count
        ),
        "loader": loader_meta,
        "analysis": analyze(entries),
    }

    analysis = report["analysis"]
    hookbin = analysis["hookbin_logs_for_repos_with_repo_or_act_true"]
    recovered_entries = analysis["total_entries_processed"]

    def fmt_with_pct(value: int) -> str:
        if recovered_entries <= 0:
            pct = "0,00"
        else:
            pct = f"{(value / recovered_entries) * 100:.2f}".replace(".", ",")
        return f"{value} ({pct}%)"

    if output_path:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"Wrote report to {output_path}")
    if annotated_output_path:
        print(f"Wrote annotated attack results to {annotated_output_path}")
        print(
            "Repositories with vulnerable_with_secret_or_write_gh_token=true: "
            f"{annotated_true_count}"
        )
        if annotation_backup_path:
            print(f"Backup path: {annotation_backup_path}")

    print(f"Recovered entries: {fmt_with_pct(recovered_entries)}")
    print(
        "Vulnerable repos total: "
        f"{fmt_with_pct(analysis['vulnerable_repositories']['count'])}"
    )
    print(
        "GitHub Hosted vulnerable: "
        f"{fmt_with_pct(analysis['github_hosted_vulnerable_repositories']['count'])}"
    )
    print(
        "Act vulnerable: "
        f"{fmt_with_pct(analysis['act_vulnerable_repositories']['count'])}"
    )
    print(f"Mismatch total: {fmt_with_pct(analysis['mismatch_total'])}")
    print(
        "True/True total: "
        f"{fmt_with_pct(analysis['repo_vulnerable_true_act_repo_vulnerable_true']['count'])}"
    )
    print(
        "Hookbin empty string total: "
        f"{fmt_with_pct(hookbin['hookbin_logs_empty_string']['count'])}"
    )
    print(
        "Hookbin not empty string total: "
        f"{fmt_with_pct(hookbin['hookbin_logs_not_empty_string']['count'])}"
    )
    print(
        "Hookbin not empty string + (GITHUB_TOKEN write or has secrets) total: "
        f"{fmt_with_pct(hookbin['hookbin_logs_not_empty_string_and_github_token_write_or_has_secret']['count'])}"
    )
    print(
        "Hookbin not empty string + (GITHUB_TOKEN write or has secrets) with solved not-clear permissions total: "
        f"{fmt_with_pct(hookbin['hookbin_logs_not_empty_string_and_github_token_write_or_has_secret_or_clear_permissions']['count'])}"
    )
    print(
        "Hookbin missing field total: "
        f"{fmt_with_pct(hookbin['missing_execution_result_or_hookbin_logs']['count'])}"
    )

    by_attempt = analysis["attack_result_breakdown"][
        "vulnerable_repositories_by_first_attempt"
    ]
    if by_attempt:
        print("Vulnerable repositories by first successful attempt:")
        print("| Attempt | Repositories marked vulnerable |")
        print("| --- | ---: |")
        for attempt_str, count in by_attempt.items():
            print(f"| {attempt_str} | {count} |")

    last_processed = analysis["last_processed_repository"]
    print(
        "Last processed repository: "
        f"{last_processed.get('name') or 'unknown'}"
    )
    print(
        "Last processed repository date: "
        f"{last_processed.get('date') or 'unknown'}"
    )


if __name__ == "__main__":
    main()
