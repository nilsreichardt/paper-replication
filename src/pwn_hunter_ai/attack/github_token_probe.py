from __future__ import annotations

import logging
from pathlib import Path
import shutil
import time
import uuid
from typing import Any

from pwn_hunter_ai.ai_enumerate.token_permissions import (
    parse_github_token_permissions_from_logs,
)
from pwn_hunter_ai.attack.github_token_probe_helpers import (
    _select_base_branch,
    build_probe_file_change_plan,
    _commit_and_push_probe_change,
    _prepare_probe_workspace,
    _write_probe_file,
    build_probe_file_path,
    parse_pull_request_target_filters,
    select_pull_request_target_base_branch as _select_pull_request_target_base_branch,
)
from pwn_hunter_ai.attack.git_identity import build_git_identity_from_github_user
from pwn_hunter_ai.attack.sandbox_manager import build_workspace_git_env
from pwn_hunter_ai.github_client import GitHubClient


LOGGER = logging.getLogger(__name__)
_TOKEN_URL_PATTERN = "https://x-access-token:"


def select_pull_request_target_base_branch(
    *,
    source_default_branch: str,
    workflow_content: str,
) -> str:
    return _select_pull_request_target_base_branch(
        source_default_branch=source_default_branch,
        workflow_content=workflow_content,
    )


class GitHubTokenProbeService:
    def __init__(
        self,
        github_client_factory,
        *,
        workflow_timeout: int = 120,
        poll_interval: float = 2.0,
    ) -> None:
        self._github_client_factory = github_client_factory
        self._workflow_timeout = workflow_timeout
        self._poll_interval = poll_interval

    def resolve_unknown_status(
        self,
        *,
        repo_name: str,
        source_default_branch: str,
        vulnerable_commit_hash: str,
        focused_workflow: str | None,
        workspace_path: Path,
        user_a_token: str,
        user_a_fork: str,
        user_b_token: str,
        user_b_fork: str,
    ) -> dict[str, Any]:
        if not focused_workflow:
            return {
                "resolved_permissions": None,
                "probe": {
                    "status": "skipped",
                    "reason": "focused_workflow_missing",
                },
            }

        source_client = self._github_client_factory(user_a_token)

        try:
            workflow_content = source_client.get_file_content(
                repo_name, focused_workflow, vulnerable_commit_hash
            )
        except Exception as exc:
            return {
                "resolved_permissions": None,
                "probe": {
                    "status": "failed",
                    "reason": f"workflow_fetch_failed: {exc}",
                    "focused_workflow": focused_workflow,
                },
            }

        filters = parse_pull_request_target_filters(workflow_content)
        base_branch = _select_base_branch(
            source_default_branch=source_default_branch,
            branch_filters=filters.get("branches") or [],
        )

        probe_uuid = uuid.uuid4().hex
        file_path: str | None = None
        pr_number: int | None = None
        pr_url: str | None = None
        run_id: int | None = None
        actor_used: str | None = None
        probe_actor_client: GitHubClient | None = None
        artifact_root = (
            workspace_path.parent
            if workspace_path.name == "workspace"
            else workspace_path
        )
        probe_root = artifact_root / ".pwnhunter-token-probe" / probe_uuid

        try:
            create_pr_errors: list[str] = []
            for actor_token, actor_fork, actor_label in (
                (user_b_token, user_b_fork, "user_b"),
                (user_a_token, user_a_fork, "user_a"),
            ):
                try:
                    actor_client = self._github_client_factory(actor_token)
                    actor_owner = actor_fork.split("/", 1)[0]
                    branch_name = "readme-update"
                    actor_identity = None
                    if hasattr(actor_client, "get_authenticated_user"):
                        actor_identity = actor_client.get_authenticated_user()
                    git_user_name, git_user_email = (
                        build_git_identity_from_github_user(actor_identity)
                    )
                    push_clone_url = (
                        f"https://x-access-token:{actor_token}@github.com/{actor_fork}.git"
                    )
                    base_clone_url = (
                        f"https://x-access-token:{user_a_token}@github.com/{repo_name}.git"
                    )
                    actor_workspace = probe_root / actor_label
                    probe_env = build_workspace_git_env(actor_workspace)

                    _prepare_probe_workspace(
                        workspace_path=actor_workspace,
                        base_clone_url=base_clone_url,
                        push_clone_url=push_clone_url,
                        base_branch=base_branch,
                        branch_name=branch_name,
                        env=probe_env,
                        git_user_name=git_user_name,
                        git_user_email=git_user_email,
                    )
                    change_plan = build_probe_file_change_plan(
                        workspace_path=actor_workspace,
                        path_filters=filters.get("paths") or [],
                    )
                    file_path = change_plan["file_path"]
                    _write_probe_file(
                        workspace_path=actor_workspace,
                        file_path=change_plan["file_path"],
                        content=change_plan["content"],
                        append=change_plan["append"],
                    )
                    _commit_and_push_probe_change(
                        workspace_path=actor_workspace,
                        branch_name=branch_name,
                        file_path=change_plan["file_path"],
                        env=probe_env,
                    )

                    pr: dict[str, Any] | None = None
                    create_error: str | None = None
                    for _ in range(3):
                        try:
                            pr = actor_client.create_pull_request(
                                repo_name=repo_name,
                                title="Update README.md",
                                body="",
                                head=f"{actor_owner}:{branch_name}",
                                base=base_branch,
                                draft=True,
                            )
                            create_error = None
                            break
                        except Exception as exc:
                            create_error = str(exc)
                            time.sleep(2.0)

                    if pr is None:
                        create_pr_errors.append(f"{actor_label}: {create_error}")
                        continue
                except Exception as exc:
                    create_pr_errors.append(
                        f"{actor_label}: {_sanitize_error_text(str(exc))}"
                    )
                    continue

                pr_number = pr.get("number") if isinstance(pr, dict) else None
                pr_url = pr.get("html_url") if isinstance(pr, dict) else None
                if not isinstance(pr_number, int):
                    create_pr_errors.append(
                        f"{actor_label}: missing pull request number in response"
                    )
                    continue
                actor_used = actor_label
                probe_actor_client = actor_client
                break

            if not isinstance(pr_number, int):
                joined = "; ".join(create_pr_errors) or "all actor attempts failed"
                raise RuntimeError(f"probe_pull_request_creation_failed: {joined}")

            pr_payload = source_client.get_pull_request(repo_name, pr_number)
            head_sha = ((pr_payload.get("head") or {}).get("sha") or "").strip()
            if not head_sha:
                raise RuntimeError("missing probe pull request head sha")

            run = _wait_for_probe_workflow_run(
                client=source_client,
                repo_name=repo_name,
                head_sha=head_sha,
                workflow_path=focused_workflow,
                timeout_seconds=self._workflow_timeout,
                poll_interval=self._poll_interval,
            )

            if run is None:
                return {
                    "resolved_permissions": {
                        "status": "unknown",
                        "evidence_log_url": None,
                        "reason": "probe_workflow_run_not_found",
                    },
                    "probe": {
                        "status": "completed_unknown",
                        "reason": "probe_workflow_run_not_found",
                        "pr_number": pr_number,
                        "pr_url": pr_url,
                        "run_id": None,
                        "focused_workflow": focused_workflow,
                        "actor_used": actor_used,
                        "base_branch": base_branch,
                        "file_path": file_path
                        or build_probe_file_path(
                            path_filters=filters.get("paths") or [],
                        ),
                        "matched_filters": filters,
                    },
                }

            run_id = run["id"]
            run_html_url = run.get("html_url") or f"https://github.com/{repo_name}/actions/runs/{run_id}"

            logs_content = _download_probe_workflow_logs_with_retry(
                client=source_client,
                repo_name=repo_name,
                run_id=run_id,
                max_attempts=5,
                poll_interval=self._poll_interval,
            )
            parsed = parse_github_token_permissions_from_logs(logs_content)
            if not parsed:
                return {
                    "resolved_permissions": {
                        "status": "unknown",
                        "evidence_log_url": run_html_url,
                        "reason": "probe_no_permissions_block_in_logs",
                        "permissions": None,
                    },
                    "probe": {
                        "status": "completed_unknown",
                        "reason": "probe_no_permissions_block_in_logs",
                        "pr_number": pr_number,
                        "pr_url": pr_url,
                        "run_id": run_id,
                        "focused_workflow": focused_workflow,
                        "actor_used": actor_used,
                        "base_branch": base_branch,
                        "file_path": file_path
                        or build_probe_file_path(
                            path_filters=filters.get("paths") or [],
                        ),
                        "matched_filters": filters,
                    },
                }
            # Unlike historical default-permission detection, this probe observes a
            # dedicated run triggered for this PR, so a partial permissions block is
            # still sufficient evidence to classify write vs read.
            status = (
                "write"
                if any(value.lower() == "write" for value in parsed.values())
                else "read"
            )
            reason = (
                "probe_write_permission_found_in_setup_job"
                if status == "write"
                else "probe_permissions_block_found_without_write"
            )
            return {
                "resolved_permissions": {
                    "status": status,
                    "evidence_log_url": run_html_url,
                    "reason": reason,
                    "permissions": parsed,
                },
                "probe": {
                    "status": f"completed_{status}",
                    "reason": reason,
                    "pr_number": pr_number,
                    "pr_url": pr_url,
                    "run_id": run_id,
                    "focused_workflow": focused_workflow,
                "actor_used": actor_used,
                "base_branch": base_branch,
                "file_path": file_path
                or build_probe_file_path(
                    path_filters=filters.get("paths") or [],
                ),
                "matched_filters": filters,
            },
        }
        except Exception as exc:
            LOGGER.warning(
                "Token permission probe failed for %s: %s",
                repo_name,
                _sanitize_error_text(str(exc)),
            )
            return {
                "resolved_permissions": {
                    "status": "unknown",
                    "evidence_log_url": None,
                    "reason": f"probe_failed: {type(exc).__name__}",
                    "permissions": None,
                },
                "probe": {
                    "status": "failed",
                    "reason": _sanitize_error_text(str(exc)),
                    "pr_number": pr_number,
                    "pr_url": pr_url,
                    "run_id": run_id,
                    "focused_workflow": focused_workflow,
                    "actor_used": actor_used,
                    "base_branch": base_branch,
                    "file_path": file_path,
                    "matched_filters": filters,
                },
            }
        finally:
            shutil.rmtree(probe_root, ignore_errors=True)
            if pr_number is not None:
                closed = False
                comment_posted = False
                close_error: str | None = None
                comment_error: str | None = None
                cleanup_client = probe_actor_client or source_client
                try:
                    cleanup_client.create_pull_request_comment(
                        repo_name, pr_number, "Never mind"
                    )
                    comment_posted = True
                except Exception as exc:
                    comment_error = str(exc)

                try:
                    cleanup_client.close_pull_request(repo_name, pr_number)
                    closed = True
                except Exception as exc:
                    close_error = str(exc)

                if comment_posted and closed:
                    LOGGER.info(
                        "Closed temporary probe PR #%s in %s with comment",
                        pr_number,
                        repo_name,
                    )
                elif closed:
                    LOGGER.warning(
                        "Closed temporary probe PR #%s in %s but failed to post comment: %s",
                        pr_number,
                        repo_name,
                        comment_error,
                    )
                else:
                    LOGGER.warning(
                        "Failed to close temporary probe PR #%s in %s: %s (comment error: %s)",
                        pr_number,
                        repo_name,
                        close_error,
                        comment_error,
                    )


def _wait_for_probe_workflow_run(
    *,
    client: GitHubClient,
    repo_name: str,
    head_sha: str,
    workflow_path: str,
    timeout_seconds: int,
    poll_interval: float,
) -> dict[str, Any] | None:
    deadline = time.time() + timeout_seconds

    while time.time() < deadline:
        runs_payload = client.get_workflow_runs(repo_name, per_page=100, page=1)
        workflow_runs = runs_payload.get("workflow_runs") or []
        matched_run: dict[str, Any] | None = None

        for run in workflow_runs:
            if not isinstance(run, dict):
                continue
            if run.get("head_sha") != head_sha:
                continue
            run_path = str(run.get("path") or "")
            run_workflow_path = run_path.split("@", 1)[0] if run_path else ""
            if run_workflow_path != workflow_path:
                continue
            matched_run = run
            break

        if matched_run is None:
            time.sleep(poll_interval)
            continue

        run_id = matched_run.get("id")
        if not isinstance(run_id, int):
            return None

        run_status = client.get_workflow_run(repo_name, run_id)
        if run_status.get("conclusion") is not None:
            return run_status

        time.sleep(poll_interval)

    return None


def _sanitize_error_text(value: str) -> str:
    if _TOKEN_URL_PATTERN not in value:
        return value
    prefix, _, suffix = value.partition(_TOKEN_URL_PATTERN)
    if "@github.com/" not in suffix:
        return value
    _, _, tail = suffix.partition("@github.com/")
    return f"{prefix}{_TOKEN_URL_PATTERN}***@github.com/{tail}"


def _download_probe_workflow_logs_with_retry(
    *,
    client: GitHubClient,
    repo_name: str,
    run_id: int,
    max_attempts: int,
    poll_interval: float,
) -> bytes:
    last_error: Exception | None = None
    for attempt in range(1, max_attempts + 1):
        try:
            return client.download_workflow_run_logs(repo_name, run_id)
        except Exception as exc:
            last_error = exc
            message = str(exc).lower()
            is_not_found = " 404 " in message or "404 not found" in message
            if not is_not_found or attempt >= max_attempts:
                raise
            LOGGER.debug(
                "Probe workflow logs not ready for run %s in %s (attempt %s/%s): %s",
                run_id,
                repo_name,
                attempt,
                max_attempts,
                exc,
            )
            time.sleep(poll_interval)
    if last_error is not None:
        raise last_error
    raise RuntimeError("Unable to download probe workflow logs.")
