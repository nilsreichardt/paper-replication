from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any

import yaml


_MATRIX_RUNS_ON_PATTERN = re.compile(
    r"^\$\{\{\s*matrix\.([A-Za-z0-9_-]+)\s*\}\}$"
)
_OWNER_GUARD_PATTERN = re.compile(
    r"(github\.repository_owner\s*==\s*)(['\"])([^'\"]+)(\2)"
)

_SUPPORTED_UBUNTU = frozenset({"ubuntu-latest", "ubuntu-24.04", "ubuntu-22.04", "ubuntu-slim"})
_SUPPORTED_MACOS = frozenset(
    {
        "macos-latest",
        "macos-26",
        "macos-26-xlarge",
        "macos-26-intel",
        "macos-26-large",
        "macos-latest-large",
        "macos-15-large",
        "macos-15-intel",
        "macos-15",
        "macos-15-xlarge",
        "macos-14-large",
        "macos-14",
        "macos-14-xlarge",
    }
)
_SUPPORTED_WINDOWS = frozenset(
    {"windows-latest", "windows-2025-vs2026", "windows-2025", "windows-2022"}
)


class _WorkflowLoader(yaml.SafeLoader):
    pass


_WorkflowLoader.yaml_implicit_resolvers = {
    key: list(value) for key, value in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
for key, resolvers in list(_WorkflowLoader.yaml_implicit_resolvers.items()):
    _WorkflowLoader.yaml_implicit_resolvers[key] = [
        entry for entry in resolvers if entry[0] != "tag:yaml.org,2002:bool"
    ]
_WorkflowLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


@dataclass(frozen=True, slots=True)
class WorkflowPreprocessResult:
    content: str
    changed: bool


def preprocess_workflow_content(
    *,
    workflow_content: str,
    source_repo_owner: str,
    user_a_login: str,
) -> WorkflowPreprocessResult:
    if not isinstance(workflow_content, str) or not workflow_content.strip():
        return WorkflowPreprocessResult(content=workflow_content, changed=False)

    try:
        parsed = yaml.load(workflow_content, Loader=_WorkflowLoader)
    except yaml.YAMLError:
        return WorkflowPreprocessResult(content=workflow_content, changed=False)
    if not isinstance(parsed, dict):
        return WorkflowPreprocessResult(content=workflow_content, changed=False)

    changed = _rewrite_workflow_mapping(
        parsed,
        source_repo_owner=source_repo_owner,
        user_a_login=user_a_login,
    )
    if not changed:
        return WorkflowPreprocessResult(content=workflow_content, changed=False)

    dumped = yaml.safe_dump(parsed, sort_keys=False, allow_unicode=False)
    if not dumped.endswith("\n"):
        dumped += "\n"
    return WorkflowPreprocessResult(content=dumped, changed=True)


def workflow_has_schedule_trigger(workflow_content: str) -> bool:
    if not isinstance(workflow_content, str) or not workflow_content.strip():
        return False

    try:
        parsed = yaml.load(workflow_content, Loader=_WorkflowLoader)
    except yaml.YAMLError:
        return False
    if not isinstance(parsed, dict):
        return False

    return _event_mapping_has_schedule(parsed.get("on"))


def _rewrite_workflow_mapping(
    node: dict[str, Any],
    *,
    source_repo_owner: str,
    user_a_login: str,
) -> bool:
    changed = _rewrite_if_guards(
        node,
        source_repo_owner=source_repo_owner,
        user_a_login=user_a_login,
    )
    jobs = node.get("jobs")
    if not isinstance(jobs, dict):
        return changed

    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        changed = _rewrite_job_runs_on(job) or changed
        changed = (
            _rewrite_if_guards(
                job,
                source_repo_owner=source_repo_owner,
                user_a_login=user_a_login,
            )
            or changed
        )
    return changed


def _rewrite_if_guards(
    mapping: dict[str, Any],
    *,
    source_repo_owner: str,
    user_a_login: str,
) -> bool:
    changed = False
    value = mapping.get("if")
    if isinstance(value, str):
        updated = _replace_owner_guard(
            expression=value,
            source_repo_owner=source_repo_owner,
            user_a_login=user_a_login,
        )
        if updated != value:
            mapping["if"] = updated
            changed = True
    return changed


def _replace_owner_guard(
    *,
    expression: str,
    source_repo_owner: str,
    user_a_login: str,
) -> str:
    source_owner_normalized = source_repo_owner.strip().lower()
    if not source_owner_normalized:
        return expression

    def repl(match: re.Match[str]) -> str:
        owner = match.group(3).strip().lower()
        if owner != source_owner_normalized:
            return match.group(0)
        return f"{match.group(1)}{match.group(2)}{user_a_login}{match.group(4)}"

    return _OWNER_GUARD_PATTERN.sub(repl, expression)


def _rewrite_job_runs_on(job: dict[str, Any]) -> bool:
    changed = False
    runs_on_value = job.get("runs-on")
    normalized_runs_on, runs_on_changed = _normalize_runs_on_value(runs_on_value)
    if runs_on_changed:
        job["runs-on"] = normalized_runs_on
        changed = True

    matrix_keys = _extract_matrix_keys_from_runs_on(runs_on_value)
    if not matrix_keys:
        return changed

    strategy = job.get("strategy")
    if not isinstance(strategy, dict):
        return changed
    matrix = strategy.get("matrix")
    if not isinstance(matrix, dict):
        return changed

    for matrix_key in matrix_keys:
        changed = _normalize_matrix_key_values(matrix, matrix_key) or changed
    return changed


def _extract_matrix_keys_from_runs_on(runs_on_value: Any) -> set[str]:
    labels = _extract_runs_on_labels(runs_on_value)
    keys: set[str] = set()
    for label in labels:
        match = _MATRIX_RUNS_ON_PATTERN.fullmatch(label.strip())
        if match is not None:
            keys.add(match.group(1))
    return keys


def _normalize_matrix_key_values(node: Any, matrix_key: str) -> bool:
    changed = False
    if isinstance(node, dict):
        for key, value in list(node.items()):
            if key == matrix_key:
                normalized, did_change = _normalize_runs_on_value(value)
                if did_change:
                    node[key] = normalized
                    changed = True
                continue
            changed = _normalize_matrix_key_values(value, matrix_key) or changed
        return changed
    if isinstance(node, list):
        for item in node:
            changed = _normalize_matrix_key_values(item, matrix_key) or changed
    return changed


def _normalize_runs_on_value(value: Any) -> tuple[Any, bool]:
    labels = _extract_runs_on_labels(value)
    if labels and _has_self_hosted(labels):
        fallback = _self_hosted_fallback(labels)
        return fallback, True

    if isinstance(value, str):
        normalized = _normalize_runner_label(value)
        if normalized != value:
            return normalized, True
        return value, False

    if isinstance(value, list):
        changed = False
        normalized_entries: list[Any] = []
        for entry in value:
            if not isinstance(entry, str):
                normalized_entries.append(entry)
                continue
            normalized = _normalize_runner_label(entry)
            if normalized != entry:
                changed = True
            normalized_entries.append(normalized)
        return normalized_entries, changed

    if isinstance(value, dict):
        labels_value = value.get("labels")
        normalized_labels, labels_changed = _normalize_runs_on_value(labels_value)
        if labels_changed:
            updated = dict(value)
            updated["labels"] = normalized_labels
            return updated, True
        return value, False

    return value, False


def _extract_runs_on_labels(value: Any) -> list[str]:
    labels: list[str] = []
    if isinstance(value, str):
        stripped = value.strip()
        if stripped:
            labels.append(stripped)
        return labels
    if isinstance(value, list):
        for entry in value:
            if isinstance(entry, str):
                stripped = entry.strip()
                if stripped:
                    labels.append(stripped)
        return labels
    if isinstance(value, dict):
        return _extract_runs_on_labels(value.get("labels"))
    return labels


def _has_self_hosted(labels: list[str]) -> bool:
    for label in labels:
        if "self-hosted" in label.strip().lower():
            return True
    return False


def _self_hosted_fallback(labels: list[str]) -> str:
    joined = " ".join(labels).lower()
    if "windows" in joined:
        return "windows-latest"
    if "macos" in joined or "mac" in joined or "darwin" in joined:
        return "macos-latest"
    return "ubuntu-latest"


def _normalize_runner_label(label: str) -> str:
    stripped = label.strip()
    lowered = stripped.lower()
    if lowered.startswith("ubuntu"):
        if lowered in _SUPPORTED_UBUNTU:
            return stripped
        return "ubuntu-latest"
    if lowered.startswith("macos"):
        if lowered in _SUPPORTED_MACOS:
            return stripped
        return "macos-latest"
    if lowered.startswith("windows"):
        if lowered in _SUPPORTED_WINDOWS:
            return stripped
        return "windows-latest"
    return stripped


def _event_mapping_has_schedule(events: Any) -> bool:
    if isinstance(events, str):
        return events.strip().lower() == "schedule"
    if isinstance(events, list):
        return any(
            isinstance(event, str) and event.strip().lower() == "schedule"
            for event in events
        )
    if isinstance(events, dict):
        return "schedule" in events
    return False
