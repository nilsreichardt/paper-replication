from __future__ import annotations

from copy import deepcopy
import re
from typing import Any

import yaml

from pwn_hunter_ai.ai_enumerate.prompting import extract_referenced_files


WORKFLOW_PATH_PATTERN = re.compile(r"\.github/workflows/[^:#'\s]+")


def _build_attack_result(
    *,
    risk: dict[str, Any],
    prepared: Any,
    artifact_bundle: Any,
    agent_launch: Any,
    github_token_probe: dict[str, Any] | None = None,
    github_token_probe_timing: str = "not_needed",
) -> dict[str, Any]:
    focused_workflow = _resolve_focused_workflow(risk)
    focused_workflows = _resolve_focused_workflows(risk)
    focused_workflow_refs = _resolve_focused_workflow_refs(risk)
    focused_workflow_secrets = prepared.workflow_secret_map.get(focused_workflow or "", [])
    token_permissions = _extract_github_token_permissions(risk)
    return {
        "status": "prepared_for_manual_validation",
        "reason": "Owned forks and workflow scan are complete. PR execution remains manual.",
        "agent_provider": prepared.agent_provider,
        "focused_workflow": focused_workflow,
        "focused_workflows": focused_workflows,
        "focused_workflow_refs": focused_workflow_refs,
        "source_default_branch": prepared.source_default_branch,
        "focused_workflow_has_secrets": bool(focused_workflow_secrets),
        "focused_workflow_secrets": focused_workflow_secrets,
        "user_a_fork": prepared.user_a_fork,
        "user_b_fork": prepared.user_b_fork,
        "seeded_secrets": prepared.seeded_secrets,
        "secret_seed_summary": prepared.secret_seed_summary,
        "secret_seed_failures": prepared.secret_seed_failures,
        "scanned_workflows": prepared.scanned_workflows,
        "flagged_for_human_review": False,
        "attempt_count": 0,
        "attempts": [],
        "max_retries": prepared.max_retries,
        "artifact_root": str(artifact_bundle.artifact_root),
        "workspace_path": str(artifact_bundle.workspace_path),
        "agent_prompt_path": str(artifact_bundle.agent_prompt_path),
        "context_path": str(artifact_bundle.context_path),
        "agent_output_path": str(artifact_bundle.agent_output_path),
        "attempt_state_path": str(artifact_bundle.attempt_state_path),
        "shared_secrets_state_path": str(artifact_bundle.shared_secrets_state_path),
        "github_token_permissions": token_permissions,
        "github_token_permissions_classification": _github_token_permission_status(
            token_permissions
        ),
        "github_token_probe": github_token_probe,
        "github_token_probe_timing": github_token_probe_timing,
        "agent_runtime_path": str(artifact_bundle.agent_metadata_path),
        "agent_runtime": (
            {
                "status": agent_launch.status,
                "base_url": getattr(agent_launch, "base_url", None),
                "pid": agent_launch.pid,
                "tracing": getattr(agent_launch, "tracing", None),
            }
            if agent_launch is not None
            else None
        ),
    }


def _risk_is_vulnerable(risk: dict[str, Any]) -> bool:
    if risk.get("vulnerable") is True:
        return True
    for key in ("pwn_request_result", "ai-analysis"):
        result = risk.get(key)
        if isinstance(result, dict) and result.get("vulnerable") is True:
            return True
    return False


def _risk_is_confirmed_vulnerable(risk: dict[str, Any]) -> bool:
    attack_result = risk.get("attack_result")
    if not isinstance(attack_result, dict):
        return False
    if attack_result.get("vulnerable") is True:
        return True
    status = str(attack_result.get("status") or "").strip().lower()
    if status == "vulnerable_confirmed":
        return True
    execution_result = attack_result.get("execution_result")
    if isinstance(execution_result, dict) and execution_result.get("vulnerable") is True:
        return True
    return False


def _risk_needs_human_review(risk: dict[str, Any]) -> bool:
    attack_result = risk.get("attack_result")
    if not isinstance(attack_result, dict):
        if risk.get("vulnerable") is True:
            return True
        for key in ("pwn_request_result", "ai-analysis"):
            result = risk.get(key)
            if isinstance(result, dict) and result.get("vulnerable") is True:
                return True
        return False
    if attack_result.get("flagged_for_human_review") is True:
        return True
    status = str(attack_result.get("status") or "").strip().lower()
    return status in {
        "human_review_required",
        "needs_human_review",
        "prepared_for_manual_validation",
        "blocked_preparation_error",
        "execution_error",
        "skipped_node_runtime_unavailable",
    }


def _derive_repo_vulnerable(repository: dict[str, Any]) -> str:
    risks = repository.get("risks", [])
    if not isinstance(risks, list):
        return "false"
    if any(
        _risk_is_confirmed_vulnerable(risk)
        for risk in risks
        if isinstance(risk, dict)
    ):
        return "true"
    if any(
        _risk_needs_human_review(risk) for risk in risks if isinstance(risk, dict)
    ):
        return "unknown"
    return "false"


def _derive_act_repo_vulnerable(repository: dict[str, Any]) -> bool:
    risks = repository.get("risks", [])
    if not isinstance(risks, list):
        return False
    for risk in risks:
        if not isinstance(risk, dict):
            continue
        attack_result = risk.get("attack_result")
        if not isinstance(attack_result, dict):
            continue
        attempts = attack_result.get("attempts")
        if not isinstance(attempts, list):
            continue
        for attempt in attempts:
            if _attempt_has_successful_local_test(attempt):
                return True
    return False


def _attempt_has_successful_local_test(attempt: Any) -> bool:
    if not isinstance(attempt, dict):
        return False

    local_test_result = str(attempt.get("local_test_result") or "").strip().lower()
    if local_test_result == "success":
        return True

    agent_output = attempt.get("agent_output")
    if isinstance(agent_output, dict):
        nested_result = str(agent_output.get("local_test_result") or "").strip().lower()
        if nested_result == "success":
            return True
    return False


def _resolve_focused_workflow(risk: dict[str, Any]) -> str | None:
    workflow_refs = _resolve_focused_workflow_refs(risk)
    if workflow_refs:
        first_path = workflow_refs[0].get("path")
        if isinstance(first_path, str) and first_path.strip():
            return first_path.strip()
    return None


def _resolve_focused_workflows(risk: dict[str, Any]) -> list[str]:
    return [
        str(ref["path"]).strip()
        for ref in _resolve_focused_workflow_refs(risk)
        if isinstance(ref, dict)
        and isinstance(ref.get("path"), str)
        and str(ref.get("path")).strip()
    ]


def _resolve_focused_workflow_refs(risk: dict[str, Any]) -> list[dict[str, str | None]]:
    workflow_refs = _extract_workflow_refs_from_gato_x_path(risk)
    if workflow_refs:
        return workflow_refs

    workflow_paths = _extract_workflow_paths_from_gato_x_path(risk)
    if workflow_paths:
        repository_name = risk.get("repository_name")
        repo_value = (
            repository_name.strip()
            if isinstance(repository_name, str) and repository_name.strip()
            else None
        )
        return [
            {"repo_name": repo_value, "path": path, "ref": None}
            for path in workflow_paths
        ]

    referenced_files = extract_referenced_files(
        risk,
        fallback_repo_name=risk.get("repository_name", ""),
        fallback_ref=None,
    )
    if referenced_files:
        refs = [
            {
                "repo_name": file.repo_name,
                "path": file.path,
                "ref": file.ref,
            }
            for file in referenced_files
            if isinstance(file.path, str) and file.path.strip()
        ]
        return _dedupe_workflow_refs(refs)

    workflow_name = risk.get("initial_workflow")
    repository_name = risk.get("repository_name")
    repo_value = (
        repository_name.strip()
        if isinstance(repository_name, str) and repository_name.strip()
        else None
    )
    if not isinstance(workflow_name, str) or not workflow_name:
        return []
    if workflow_name.startswith(".github/workflows/"):
        return [{"repo_name": repo_value, "path": workflow_name, "ref": None}]
    return [
        {
            "repo_name": repo_value,
            "path": f".github/workflows/{workflow_name}",
            "ref": None,
        }
    ]


def _extract_workflow_paths_from_gato_x_path(risk: dict[str, Any]) -> list[str]:
    path_entries = risk.get("gato-x-path")
    if not isinstance(path_entries, list):
        return []

    paths: list[str] = []
    seen: set[str] = set()
    for entry in path_entries:
        if not isinstance(entry, dict):
            continue
        node_value = entry.get("node")
        if not isinstance(node_value, str):
            continue
        for match in WORKFLOW_PATH_PATTERN.finditer(node_value):
            workflow_path = match.group(0)
            if workflow_path in seen:
                continue
            seen.add(workflow_path)
            paths.append(workflow_path)
    return paths


def _extract_workflow_refs_from_gato_x_path(
    risk: dict[str, Any],
) -> list[dict[str, str | None]]:
    path_entries = risk.get("gato-x-path")
    if not isinstance(path_entries, list):
        return []

    refs: list[dict[str, str | None]] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in path_entries:
        if not isinstance(entry, dict):
            continue
        node_value = entry.get("node")
        if not isinstance(node_value, str):
            continue
        descriptor = _extract_node_descriptor(node_value)
        if descriptor is None:
            continue
        repo_name, ref, remainder = descriptor
        for match in WORKFLOW_PATH_PATTERN.finditer(remainder):
            path = match.group(0).strip()
            key = (repo_name.lower(), path, (ref or "").lower())
            if key in seen:
                continue
            seen.add(key)
            refs.append({"repo_name": repo_name, "path": path, "ref": ref})
    return refs


def _extract_node_descriptor(node_value: str) -> tuple[str, str | None, str] | None:
    if "('" not in node_value or not node_value.endswith("')"):
        return None
    payload = node_value.split("('", 1)[1][:-2]
    parts = payload.split(":", 2)
    if len(parts) != 3:
        return None
    repo_name, ref, remainder = parts
    if not repo_name:
        return None
    normalized_ref = ref.strip() if isinstance(ref, str) else ""
    return repo_name, (normalized_ref or None), remainder


def _dedupe_workflow_refs(
    refs: list[dict[str, str | None]]
) -> list[dict[str, str | None]]:
    deduped: list[dict[str, str | None]] = []
    seen: set[tuple[str, str, str]] = set()
    for ref in refs:
        path = ref.get("path")
        if not isinstance(path, str):
            continue
        normalized_path = path.strip()
        if not normalized_path:
            continue
        repo_name = ref.get("repo_name")
        normalized_repo = (
            repo_name.strip() if isinstance(repo_name, str) and repo_name.strip() else ""
        )
        ref_value = ref.get("ref")
        normalized_ref = (
            ref_value.strip() if isinstance(ref_value, str) and ref_value.strip() else ""
        )
        key = (normalized_repo.lower(), normalized_path, normalized_ref.lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(
            {
                "repo_name": normalized_repo or None,
                "path": normalized_path,
                "ref": normalized_ref or None,
            }
        )
    return deduped


def _with_attack_result(
    risk: dict[str, Any], attack_result: dict[str, Any]
) -> dict[str, Any]:
    output_risk = deepcopy(risk)
    output_risk["attack_result"] = attack_result
    return output_risk


def _extract_github_token_permissions(risk: dict[str, Any]) -> dict[str, Any] | None:
    permissions = risk.get("github_token_permissions")
    if isinstance(permissions, dict):
        return permissions
    return None


def _github_token_permission_status(permissions: dict[str, Any] | None) -> str | None:
    if not isinstance(permissions, dict):
        return None
    status = permissions.get("status")
    if not isinstance(status, str):
        return None
    normalized = status.strip().lower()
    if not normalized:
        return None
    return normalized


def _extract_explicit_workflow_github_token_permissions(
    workflow_content: str,
) -> dict[str, Any] | None:
    if not isinstance(workflow_content, str) or not workflow_content.strip():
        return None
    try:
        parsed = yaml.safe_load(workflow_content)
    except Exception:
        return None
    if not isinstance(parsed, dict):
        return None

    jobs = parsed.get("jobs")
    job_permission_blocks: list[Any] = []
    if isinstance(jobs, dict) and jobs:
        job_permission_blocks = [
            job.get("permissions")
            for job in jobs.values()
            if isinstance(job, dict) and "permissions" in job
        ]

    top_level_permissions = parsed.get("permissions")
    if len(job_permission_blocks) > 0 and isinstance(jobs, dict) and len(jobs) > 1:
        top_level_status = _permission_block_status(top_level_permissions)
        job_statuses = [_permission_block_status(block) for block in job_permission_blocks]
        if top_level_status == "non-write" and job_statuses and all(
            status == "non-write" for status in job_statuses
        ):
            return {
                "status": "non-write",
                "evidence_log_url": None,
                "reason": "explicit_top_level_permissions_without_write",
                "source": "explicit_top_level",
                "permissions": _permission_block_details(top_level_permissions),
            }
        return {
            "status": "not-clear",
            "evidence_log_url": None,
            "reason": "multi_job_with_job_level_permissions_not_clear",
            "source": "explicit_job_level",
            "permissions": None,
        }

    if top_level_permissions is not None:
        status = _permission_block_status(top_level_permissions)
        if status is None:
            return None
        reason = (
            "explicit_top_level_permissions_include_write"
            if status == "write"
            else "explicit_top_level_permissions_without_write"
        )
        return {
            "status": status,
            "evidence_log_url": None,
            "reason": reason,
            "source": "explicit_top_level",
            "permissions": _permission_block_details(top_level_permissions),
        }

    if len(job_permission_blocks) == 1:
        status = _permission_block_status(job_permission_blocks[0])
        if status is None:
            return None
        reason = (
            "explicit_single_job_permissions_include_write"
            if status == "write"
            else "explicit_single_job_permissions_without_write"
        )
        return {
            "status": status,
            "evidence_log_url": None,
            "reason": reason,
            "source": "explicit_single_job",
            "permissions": _permission_block_details(job_permission_blocks[0]),
        }

    return None


def _permission_block_status(block: Any) -> str | None:
    if isinstance(block, str):
        normalized = block.strip().lower()
        if normalized == "write-all":
            return "write"
        if normalized in {"read-all", "none"}:
            return "non-write"
        return None
    if isinstance(block, dict):
        if not block:
            return "non-write"
        values = [
            str(value).strip().lower()
            for value in block.values()
            if isinstance(value, str)
        ]
        if any(value == "write" for value in values):
            return "write"
        if values:
            return "non-write"
    return None


def _permission_block_details(block: Any) -> dict[str, str] | None:
    if isinstance(block, str):
        normalized = block.strip().lower()
        if normalized == "write-all":
            return {"all": "write"}
        if normalized == "read-all":
            return {"all": "read"}
        if normalized == "none":
            return {"all": "none"}
        return None
    if isinstance(block, dict):
        if not block:
            return {"all": "none"}
        details: dict[str, str] = {}
        for key, value in block.items():
            if not isinstance(value, str):
                continue
            normalized_value = value.strip().lower()
            if normalized_value not in {"read", "write", "none"}:
                continue
            normalized_key = str(key).strip()
            if not normalized_key:
                continue
            details[normalized_key] = normalized_value
        return details or None
    return None


def _format_permission_summary_for_comment(
    permissions_payload: dict[str, Any] | None,
) -> str:
    if not isinstance(permissions_payload, dict):
        return ""
    permissions = permissions_payload.get("permissions")
    if not isinstance(permissions, dict) or not permissions:
        return ""
    ordered_items = sorted(
        (
            (str(key).strip(), str(value).strip().lower())
            for key, value in permissions.items()
        ),
        key=lambda item: item[0].lower(),
    )
    return ", ".join(f"{key}={value}" for key, value in ordered_items if key and value)
