from __future__ import annotations

import io
import logging
import re
from typing import Any
import zipfile

import yaml

from pwn_hunter_ai.github_client import GitHubApiError, GitHubClient


LOGGER = logging.getLogger(__name__)

_PERMISSIONS_KEY_PATTERN = re.compile(r"^\s*permissions\s*:", re.MULTILINE)
_TIMESTAMP_PREFIX_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T[^\s]+\s+")
_PERMISSION_ENTRY_PATTERN = re.compile(
    r"^\s*([A-Za-z][A-Za-z0-9]*):\s*(read|write|none)\s*$", re.IGNORECASE
)
_HEX_SHA_PATTERN = re.compile(r"^[0-9a-fA-F]{7,40}$")
_NON_ALNUM_PATTERN = re.compile(r"[^a-z0-9]")
_EXPECTED_PERMISSION_CATEGORIES = {
    "actions",
    "artifactmetadata",
    "attestations",
    "checks",
    "contents",
    "deployments",
    "discussions",
    "issues",
    "metadata",
    "models",
    "packages",
    "pages",
    "pullrequests",
    "repositoryprojects",
    "securityevents",
    "statuses",
}


def detect_default_github_token_permissions(
    github_client: GitHubClient,
    *,
    repo_name: str,
    ref: str,
    max_run_pages: int = 5,
) -> dict[str, Any]:
    try:
        workflow_items = github_client.list_directory(repo_name, ".github/workflows", ref)
    except GitHubApiError as exc:
        LOGGER.debug("Failed to list workflow directory for %s: %s", repo_name, exc)
        return _unknown(reason="workflows_directory_unavailable")

    workflow_paths = [
        item.get("path", "")
        for item in workflow_items
        if item.get("type") == "file"
        and str(item.get("path", "")).startswith(".github/workflows/")
        and str(item.get("path", "")).lower().endswith((".yml", ".yaml"))
    ]
    candidate_paths: list[str] = []
    for workflow_path in workflow_paths:
        try:
            content = github_client.get_file_content(repo_name, workflow_path, ref)
        except GitHubApiError as exc:
            LOGGER.debug(
                "Failed to fetch workflow file %s in %s: %s", workflow_path, repo_name, exc
            )
            continue
        if (
            not _has_permissions_key(content)
            and _has_pull_request_target_trigger(content)
        ):
            candidate_paths.append(workflow_path)

    if not candidate_paths:
        return _unknown(reason="no_pull_request_target_workflows_without_permissions")

    target_head_sha = _resolve_head_sha_for_ref(
        github_client=github_client,
        repo_name=repo_name,
        ref=ref,
    )
    if not target_head_sha:
        return _unknown(reason="ref_resolution_failed")

    candidate_set = set(candidate_paths)
    matching_runs: list[dict[str, Any]] = []
    fallback_runs: list[dict[str, Any]] = []
    for page in range(1, max_run_pages + 1):
        runs_payload = github_client.get_workflow_runs(repo_name, per_page=100, page=page)
        runs = runs_payload.get("workflow_runs")
        if not isinstance(runs, list) or not runs:
            break

        for run in runs:
            if not isinstance(run, dict):
                continue
            run_path = run.get("path")
            run_event = str(run.get("event") or "").strip().lower()
            run_head_sha = str(run.get("head_sha") or "").strip().lower()
            if (
                isinstance(run_path, str)
                and run_path in candidate_set
            ):
                if run_event and run_event != "pull_request_target":
                    continue
                fallback_runs.append(run)
                if run_head_sha == target_head_sha:
                    matching_runs.append(run)

        if len(runs) < 100:
            break

    if not matching_runs and fallback_runs:
        matching_runs = fallback_runs

    if not matching_runs:
        return _unknown(reason="no_matching_workflow_runs")

    saw_forbidden_logs = False
    saw_any_logs = False

    for run in matching_runs:
        run_id = run.get("id")
        if not isinstance(run_id, int):
            continue

        html_url = run.get("html_url")
        evidence_log_url = (
            html_url
            if isinstance(html_url, str) and html_url
            else f"https://github.com/{repo_name}/actions/runs/{run_id}"
        )
        try:
            logs_content = github_client.download_workflow_run_logs(repo_name, run_id)
        except GitHubApiError as exc:
            if "Must have admin rights to Repository" in str(exc):
                saw_forbidden_logs = True
            LOGGER.debug("Unable to download logs for %s run %s: %s", repo_name, run_id, exc)
            continue

        if not logs_content:
            continue

        saw_any_logs = True
        permissions = parse_github_token_permissions_from_logs(logs_content)
        if not permissions:
            continue

        if any(value.lower() == "write" for value in permissions.values()):
            return {
                "status": "write",
                "evidence_log_url": evidence_log_url,
                "reason": "write_permission_found_in_setup_job",
                "permissions": permissions,
            }
        return {
            "status": "non-write",
            "evidence_log_url": evidence_log_url,
            "reason": "permissions_block_found_without_write",
            "permissions": permissions,
        }

    if saw_forbidden_logs:
        return _unknown(reason="logs_unavailable_or_forbidden")
    if saw_any_logs:
        return _unknown(reason="no_permissions_block_in_logs")
    return _unknown(reason="no_usable_logs_within_retention")


def parse_github_token_permissions_from_logs(logs_content: bytes) -> dict[str, str]:
    try:
        with zipfile.ZipFile(io.BytesIO(logs_content)) as zf:
            names = [name for name in zf.namelist() if not name.endswith("/")]
            preferred_names = [name for name in names if "set up job" in name.lower()]
            fallback_names = [name for name in names if name not in preferred_names]

            for name in [*preferred_names, *fallback_names]:
                try:
                    with zf.open(name) as handle:
                        text = handle.read().decode("utf-8", errors="ignore")
                except Exception:
                    continue

                parsed = _parse_permissions_from_log_text(text)
                if parsed:
                    return parsed
    except Exception:
        return {}
    return {}


def has_complete_permissions_catalog(permissions: dict[str, str]) -> bool:
    if not isinstance(permissions, dict) or not permissions:
        return False
    normalized_keys = {
        _NON_ALNUM_PATTERN.sub("", str(key).strip().lower()) for key in permissions
    }
    return _EXPECTED_PERMISSION_CATEGORIES.issubset(normalized_keys)


def _parse_permissions_from_log_text(log_text: str) -> dict[str, str]:
    permissions: dict[str, str] = {}
    in_permissions_block = False
    saw_permission_entry = False

    for raw_line in log_text.splitlines():
        line = _sanitize_log_line(raw_line)
        if "GITHUB_TOKEN Permissions" in line:
            in_permissions_block = True
            saw_permission_entry = False
            continue
        if not in_permissions_block:
            continue

        match = _PERMISSION_ENTRY_PATTERN.match(line)
        if match:
            key = match.group(1)
            value = match.group(2).lower()
            permissions[key] = value
            saw_permission_entry = True
            continue

        if saw_permission_entry:
            break

    return permissions


def _sanitize_log_line(raw_line: str) -> str:
    line = _TIMESTAMP_PREFIX_PATTERN.sub("", raw_line)
    return line.strip()


def _has_permissions_key(workflow_content: str) -> bool:
    return _PERMISSIONS_KEY_PATTERN.search(workflow_content) is not None


def _has_pull_request_target_trigger(workflow_content: str) -> bool:
    try:
        parsed = yaml.safe_load(workflow_content)
    except Exception:
        return False
    if not isinstance(parsed, dict):
        return False

    # PyYAML may parse bare "on" as True (YAML 1.1 compatibility).
    on_block = parsed.get("on")
    if on_block is None and True in parsed:
        on_block = parsed.get(True)

    if isinstance(on_block, str):
        return on_block.strip() == "pull_request_target"
    if isinstance(on_block, list):
        return any(
            isinstance(entry, str) and entry.strip() == "pull_request_target"
            for entry in on_block
        )
    if isinstance(on_block, dict):
        return "pull_request_target" in on_block
    return False


def _resolve_head_sha_for_ref(
    *,
    github_client: GitHubClient,
    repo_name: str,
    ref: str,
) -> str | None:
    normalized_ref = str(ref).strip()
    if not normalized_ref:
        return None
    if _HEX_SHA_PATTERN.fullmatch(normalized_ref):
        return normalized_ref.lower()
    try:
        commit = github_client.get_commit(repo_name, normalized_ref)
    except GitHubApiError:
        return None
    sha = (commit or {}).get("sha")
    if not isinstance(sha, str) or not sha.strip():
        return None
    return sha.strip().lower()


def _unknown(*, reason: str) -> dict[str, Any]:
    return {
        "status": "unknown",
        "evidence_log_url": None,
        "reason": reason,
    }
