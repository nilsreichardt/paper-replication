from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime
import inspect
import json
import logging
from pathlib import Path
import random
import re
from threading import Lock
import time
from typing import Any, Callable, Union

from pwn_hunter_ai.ai_enumerate.prompting import extract_referenced_files
from pwn_hunter_ai.ai_enumerate.token_permissions import (
    detect_default_github_token_permissions,
)
from pwn_hunter_ai.attack.artifacts import (
    AttackArtifactsManager,
    RepositoryArtifactBundle,
)
from pwn_hunter_ai.attack.tokens import AttackTokenBroker
from pwn_hunter_ai.attack.github_token_probe import GitHubTokenProbeService
from pwn_hunter_ai.github_client import GitHubApiError, GitHubClient
from pwn_hunter_ai.attack.agent_runtime import (
    AttackAgentRuntime,
    AttackAgentProvider,
    AttackAgentLaunchResult,
    AttackAgentHeadlessResult,
)
from pwn_hunter_ai.attack.workflow_preprocessing import (
    preprocess_workflow_content,
    workflow_has_schedule_trigger,
)
from pwn_hunter_ai.attack.workflow_secrets import (
    build_dummy_secret_value,
    collect_workflow_secrets,
)
from pwn_hunter_ai.attack.service_helpers.forks import (
    build_fork_name_candidates as _build_fork_name_candidates,
    _repo_exists,
)
from pwn_hunter_ai.attack.service_helpers.risk import (
    _build_attack_result,
    _derive_act_repo_vulnerable,
    _derive_repo_vulnerable,
    _extract_explicit_workflow_github_token_permissions,
    _format_permission_summary_for_comment,
    _github_token_permission_status,
    _resolve_focused_workflow,
    _resolve_focused_workflow_refs,
    _resolve_focused_workflows,
    _risk_is_vulnerable,
    _with_attack_result,
)
from pwn_hunter_ai.attack.service_helpers.selection import (
    _extract_attack_repositories,
    _normalize_repository_full_name,
)


LOGGER = logging.getLogger(__name__)
LOCAL_SECRETS_FILENAME = ".secrets"
LOCAL_SECRETS_PATH = Path(__file__).resolve().parents[3] / LOCAL_SECRETS_FILENAME
_LOCAL_SECRETS_LINE_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")

GitHubClientFactory = Callable[[str], GitHubClient]
FORK_PARENT_VALIDATION_MAX_ATTEMPTS = 8
FORK_PARENT_VALIDATION_RETRY_DELAY_SECONDS = 0.25
FORK_PARENT_VALIDATION_MAX_ELAPSED_SECONDS = 25.0
FORK_PARENT_VALIDATION_RETRY_MAX_SECONDS = 2.0
SECRET_PREFLIGHT_MAX_ATTEMPTS = 5
SECRET_SEED_MAX_ATTEMPTS = 3
SECRET_SEED_RETRY_BASE_SECONDS = 1.5
_HTTP_STATUS_PATTERN = re.compile(r":\s*(\d{3})\s")
_REQUEST_ID_PATTERN = re.compile(r"(?:request[_ -]?id|X-GitHub-Request-Id)[=: ]+([A-Za-z0-9_-]+)")


def _format_now_timestamp() -> str:
    return datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Y")


def _parse_local_seed_secret_values(content: str) -> dict[str, str]:
    parsed_values: dict[str, str] = {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = _LOCAL_SECRETS_LINE_PATTERN.match(raw_line)
        if match is None:
            continue
        key, value = match.groups()
        normalized_key = key.strip()
        if not normalized_key or normalized_key.upper().startswith("GITHUB_"):
            continue
        parsed_values[normalized_key] = value.strip()
    return parsed_values


def _load_local_seed_secret_values(path: Path | None = None) -> dict[str, str]:
    if path is None:
        path = LOCAL_SECRETS_PATH
    if not path.exists():
        return {}
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    return _parse_local_seed_secret_values(content)


def _resolve_seed_secret_values(
    *,
    required_secret_names: set[str],
    base_values: dict[str, str] | None = None,
) -> dict[str, str]:
    resolved_values = dict(base_values or {})
    normalized_required = sorted(
        {
            name.strip()
            for name in required_secret_names
            if isinstance(name, str)
            and name.strip()
                and not name.strip().upper().startswith("GITHUB_")
        }
    )
    for secret_name in normalized_required:
        if resolved_values.get(secret_name, "").strip():
            continue
        resolved_values[secret_name] = build_dummy_secret_value(secret_name)
    return resolved_values


@dataclass(frozen=True, slots=True)
class PreparedRepository:
    vulnerable_commit_hash: str
    source_last_commit_timestamp: str | None
    source_default_branch: str
    repository_name: str
    user_a_login: str
    user_b_login: str
    user_a_fork: str
    user_b_fork: str
    seeded_secrets: list[str]
    workflow_secret_map: dict[str, list[str]]
    workflow_contents: dict[str, str]
    scanned_workflows: list[str]
    shared_secrets_state_path: Path
    agent_provider: str
    max_retries: int
    secret_seed_summary: dict[str, int]
    secret_seed_failures: list[dict[str, Any]]


@dataclass(frozen=True, slots=True)
class PreparationError(RuntimeError):
    reason: str
    error_stage: str
    error_class: str
    failure_fingerprint: str
    secret_seed_summary: dict[str, int] | None = None
    secret_seed_failures: list[dict[str, Any]] | None = None

    def __str__(self) -> str:
        return self.reason


class AttackPreparationService:
    def __init__(
        self,
        *,
        token_broker: AttackTokenBroker,
        github_client_factory: GitHubClientFactory,
        reset_forks: bool,
        artifacts_dir: Path | None = None,
        artifacts_manager: AttackArtifactsManager | None = None,
        max_retries: int = 3,
        dry_run: bool = False,
        launch_agent: bool = False,
        agent_headless: bool = False,
        agent_timeout: int = 900,
        agent_runtime: AttackAgentRuntime | None = None,
        agent_provider: str = AttackAgentProvider.OPENHANDS.value,
        openhands_manager: AttackAgentRuntime | None = None,
        openhands_headless: bool | None = None,
        openhands_timeout: int | None = None,
        github_token_probe_service: GitHubTokenProbeService | None = None,
        skip_default_permission_log_read: bool = False,
    ) -> None:
        if agent_runtime is None and openhands_manager is not None:
            agent_runtime = openhands_manager
        if openhands_headless is not None:
            agent_headless = openhands_headless
        if openhands_timeout is not None:
            agent_timeout = openhands_timeout

        self._token_broker = token_broker
        self._github_client_factory = github_client_factory
        self._reset_forks = reset_forks
        self._artifacts = artifacts_manager or AttackArtifactsManager(
            artifacts_dir or Path("attack-artifacts")
        )
        self._max_retries = max_retries
        self._dry_run = dry_run
        self._launch_agent = launch_agent
        self._agent_headless = agent_headless
        self._agent_timeout = agent_timeout
        self._agent_runtime = agent_runtime
        if agent_runtime is not None:
            provider_name = getattr(
                agent_runtime, "provider_name", AttackAgentProvider.OPENHANDS
            )
            if isinstance(provider_name, AttackAgentProvider):
                self._agent_provider = provider_name.value
            else:
                try:
                    self._agent_provider = AttackAgentProvider(
                        str(provider_name).strip().lower()
                    ).value
                except ValueError:
                    self._agent_provider = AttackAgentProvider.OPENHANDS.value
        else:
            self._agent_provider = AttackAgentProvider(
                (agent_provider or AttackAgentProvider.OPENHANDS.value)
                .strip()
                .lower()
            ).value
        self._skip_default_permission_log_read = skip_default_permission_log_read
        self._fork_name_locks: dict[tuple[str, str], Lock] = {}
        self._fork_name_locks_guard = Lock()
        _ = github_token_probe_service

    def _report_token_failure(
        self,
        *,
        token: str,
        token_role: str,
        repo_name: str,
        stage: str,
        reason: str,
    ) -> None:
        reporter = getattr(self._token_broker, "report_preparation_token_failure", None)
        if not callable(reporter):
            return
        reporter(
            token=token,
            token_role=token_role,
            repository_name=repo_name,
            stage=stage,
            reason=reason,
        )

    def run(
        self,
        input_payload: dict[str, Any],
        *,
        parallel_jobs: int,
        skip_repositories: set[str] | None = None,
    ) -> dict[str, Any]:
        normalized_skip_repositories = {
            normalized_name
            for repository_name in (skip_repositories or set())
            if (normalized_name := _normalize_repository_full_name(repository_name))
            is not None
        }
        repositories = _extract_attack_repositories(
            input_payload,
            skip_repositories=normalized_skip_repositories,
        )
        results: list[dict[str, Any] | None] = [None] * len(repositories)

        max_workers = max(1, min(parallel_jobs, self._token_broker.user_b_capacity))
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {
                executor.submit(self._process_repository, repository): index
                for index, repository in enumerate(repositories)
            }
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                results[index] = future.result()

        output_payload = deepcopy(input_payload)
        output_payload["timestamp"] = _format_now_timestamp()
        output_payload["ai_enumeration"] = [
            result for result in results if result is not None
        ]
        if "enumeration" in output_payload and isinstance(
            output_payload.get("enumeration"), dict
        ):
            output_payload["enumeration"]["repositories"] = [
                repository
                for repository in output_payload["enumeration"].get("repositories", [])
                if _normalize_repository_full_name(repository.get("name"))
                not in normalized_skip_repositories
            ]
        return output_payload

    def _process_repository(self, repository: dict[str, Any]) -> dict[str, Any]:
        repo_name = repository["name"]
        vulnerable_risks = [
            risk for risk in repository.get("risks", []) if _risk_is_vulnerable(risk)
        ]
        primary_risk = vulnerable_risks[0] if vulnerable_risks else None

        output_repository = deepcopy(repository)
        output_repository["vulnerable_commit_hash"] = None
        output_repository["source_last_commit_timestamp"] = None

        if not vulnerable_risks:
            output_repository["risks"] = []
            output_repository["repo_vulnerable"] = _derive_repo_vulnerable(
                output_repository
            )
            output_repository["act_repo_vulnerable"] = _derive_act_repo_vulnerable(
                output_repository
            )
            return output_repository

        lease = self._token_broker.reserve(repo_name)
        try:
            try:
                self._log_stage_event(
                    "preparation_start",
                    repo_name=repo_name,
                    stage="preparation",
                )
                prepared = self._prepare_repository(
                    repo_name=repo_name,
                    primary_risk=primary_risk,
                    user_a_token=lease.user_a_token,
                    user_b_token=lease.user_b_token,
                )
                self._log_stage_event(
                    "preparation_end",
                    repo_name=repo_name,
                    stage="preparation",
                    status="success",
                )
            except PreparationError as exc:
                output_repository["risks"] = []
                for risk in vulnerable_risks:
                    failed_risk = _with_attack_result(
                        risk,
                        {
                            "status": "blocked_preparation_error",
                            "reason": str(exc),
                            "error_stage": exc.error_stage,
                            "error_class": exc.error_class,
                            "failure_fingerprint": exc.failure_fingerprint,
                            "secret_seed_summary": exc.secret_seed_summary,
                            "secret_seed_failures": exc.secret_seed_failures or [],
                        },
                    )
                    failed_risk["attack_processed_time"] = _format_now_timestamp()
                    output_repository["risks"].append(failed_risk)
                self._log_stage_event(
                    "preparation_end",
                    repo_name=repo_name,
                    stage="preparation",
                    status="failed",
                    error_class=exc.error_class,
                    failure_fingerprint=exc.failure_fingerprint,
                )
                return output_repository
            except RuntimeError as exc:
                self._log_stage_event(
                    "preparation_end",
                    repo_name=repo_name,
                    stage="preparation",
                    status="failed",
                    error_class="unknown_preparation_error",
                    failure_fingerprint="preparation_runtime_error",
                )
                output_repository["risks"] = []
                for risk in vulnerable_risks:
                    failed_risk = _with_attack_result(
                        risk,
                        {
                            "status": "blocked_preparation_error",
                            "reason": str(exc),
                            "error_stage": "preparation",
                            "error_class": "unknown_preparation_error",
                            "failure_fingerprint": "preparation_runtime_error",
                        },
                    )
                    failed_risk["attack_processed_time"] = _format_now_timestamp()
                    output_repository["risks"].append(failed_risk)
                return output_repository

            output_repository["vulnerable_commit_hash"] = prepared.vulnerable_commit_hash
            output_repository["source_last_commit_timestamp"] = (
                prepared.source_last_commit_timestamp
            )
            output_repository["repository_creation_date"] = repository.get(
                "repository_creation_date"
            )
            output_risks: list[dict[str, Any]] = []
            source_client = self._github_client_factory(lease.user_a_token)
            default_permissions: dict[str, Any] | None = None
            default_permissions_loaded = False
            for risk_index, risk in enumerate(vulnerable_risks):
                updated_risk = deepcopy(risk)
                focused_workflow = _resolve_focused_workflow(updated_risk)
                focused_workflow_secrets = prepared.workflow_secret_map.get(
                    focused_workflow or "", []
                )
                explicit_permissions = _extract_explicit_workflow_github_token_permissions(
                    prepared.workflow_contents.get(focused_workflow or "")
                )
                if explicit_permissions is not None:
                    resolved_permissions = explicit_permissions
                else:
                    if not default_permissions_loaded:
                        if self._skip_default_permission_log_read:
                            default_permissions = {
                                "status": "unknown",
                                "evidence_log_url": None,
                                "reason": "default_permission_log_read_skipped",
                            }
                        else:
                            default_permissions = (
                                detect_default_github_token_permissions(
                                    source_client,
                                    repo_name=repo_name,
                                    ref=prepared.vulnerable_commit_hash,
                                )
                            )
                        default_permissions_loaded = True
                    resolved_permissions = default_permissions

                if isinstance(resolved_permissions, dict):
                    updated_risk["github_token_permissions"] = resolved_permissions

                status = _github_token_permission_status(resolved_permissions)
                if not focused_workflow_secrets and status in {"non-write", "read"}:
                    permission_summary = _format_permission_summary_for_comment(
                        resolved_permissions
                    )
                    reason = (
                        "GITHUB_TOKEN is read-only and no workflow secrets were found; "
                        "skipping agentic execution."
                    )
                    if permission_summary:
                        reason = f"{reason} Detected permissions: {permission_summary}."
                    updated_risk["attack_result"] = {
                        "status": "skipped_read_only_token_without_secrets",
                        "reason": reason,
                        "focused_workflow": focused_workflow,
                        "focused_workflow_has_secrets": False,
                        "focused_workflow_secrets": [],
                        "github_token_permissions": resolved_permissions,
                        "github_token_permissions_classification": _github_token_permission_status(
                            resolved_permissions
                        ),
                        "github_token_probe": None,
                        "github_token_probe_timing": "not_needed",
                    }
                    updated_risk["attack_processed_time"] = _format_now_timestamp()
                    output_risks.append(updated_risk)
                    continue

                risk_artifacts = self._prepare_risk_artifacts(
                    prepared=prepared,
                    risk=updated_risk,
                    risk_index=risk_index,
                    source_client=source_client,
                    user_b_token=lease.user_b_token,
                )
                updated_risk["attack_result"] = _build_attack_result(
                    risk=updated_risk,
                    prepared=prepared,
                    artifact_bundle=risk_artifacts["artifact_bundle"],
                    agent_launch=risk_artifacts["agent_launch"],
                    github_token_probe=None,
                    github_token_probe_timing=(
                        "after_agentic" if status == "unknown" else "not_needed"
                    ),
                )
                updated_risk["attack_processed_time"] = _format_now_timestamp()
                output_risks.append(updated_risk)

            output_repository["risks"] = output_risks
            output_repository["repo_vulnerable"] = _derive_repo_vulnerable(
                output_repository
            )
            output_repository["act_repo_vulnerable"] = _derive_act_repo_vulnerable(
                output_repository
            )
            return output_repository
        finally:
            self._token_broker.release(lease)

    def _prepare_repository(
        self,
        *,
        repo_name: str,
        primary_risk: dict[str, Any] | None,
        user_a_token: str,
        user_b_token: str,
    ) -> PreparedRepository:
        user_a_client = self._github_client_factory(user_a_token)
        user_b_client = self._github_client_factory(user_b_token)

        try:
            source_metadata = user_a_client.get_repo_metadata(repo_name)
        except GitHubApiError as exc:
            self._report_token_failure(
                token=user_a_token,
                token_role="user_a",
                repo_name=repo_name,
                stage="get_repo_metadata",
                reason=str(exc),
            )
            if self._is_not_found_error(exc):
                raise PreparationError(
                    reason=f"Source repository `{repo_name}` was not found.",
                    error_stage="preparation",
                    error_class="source_repo_not_found",
                    failure_fingerprint="source_repo_not_found",
                ) from exc
            raise
        vulnerable_commit_hash = user_a_client.get_branch_head_sha(
            repo_name,
            source_metadata["default_branch"],
        )
        source_last_commit_timestamp = self._extract_commit_timestamp(
            user_a_client.get_commit(repo_name, vulnerable_commit_hash)
        )
        try:
            user_a_login = user_a_client.get_authenticated_user()["login"]
        except Exception as exc:
            self._report_token_failure(
                token=user_a_token,
                token_role="user_a",
                repo_name=repo_name,
                stage="get_authenticated_user",
                reason=str(exc),
            )
            raise
        try:
            user_b_login = user_b_client.get_authenticated_user()["login"]
        except Exception as exc:
            self._report_token_failure(
                token=user_b_token,
                token_role="user_b",
                repo_name=repo_name,
                stage="get_authenticated_user",
                reason=str(exc),
            )
            raise

        try:
            user_a_fork = self._ensure_fork(
                client=user_a_client,
                source_repo=repo_name,
                fork_owner=user_a_login,
            )
        except RuntimeError as exc:
            self._report_token_failure(
                token=user_a_token,
                token_role="user_a",
                repo_name=repo_name,
                stage="ensure_user_a_fork",
                reason=str(exc),
            )
            raise self._classify_fork_preparation_error(
                exc=exc,
                source_repo=repo_name,
                fork_owner=user_a_login,
            ) from exc
        user_a_client.enable_actions(user_a_fork, enabled=True)

        workflows = self._load_workflows(
            client=user_a_client,
            repo_name=repo_name,
            ref=vulnerable_commit_hash,
        )
        workflows = sorted(workflows, key=lambda item: item[0])
        source_repo_owner = repo_name.split("/", 1)[0].strip()
        default_branch = source_metadata["default_branch"]
        updated_workflows: list[tuple[str, str]] = []
        for path, content in workflows:
            preprocess_result = preprocess_workflow_content(
                workflow_content=content,
                source_repo_owner=source_repo_owner,
                user_a_login=user_a_login,
            )
            normalized_content = (
                preprocess_result.content if preprocess_result.changed else content
            )
            updated_workflows.append((path, normalized_content))
            if not preprocess_result.changed:
                continue
            try:
                file_sha = user_a_client.get_file_sha(
                    user_a_fork,
                    path,
                    default_branch,
                )
                user_a_client.create_or_update_file(
                    user_a_fork,
                    path,
                    normalized_content,
                    "Normalize workflow compatibility for attack preparation.",
                    default_branch,
                    sha=file_sha,
                )
            except Exception as exc:
                raise RuntimeError(
                    f"Failed to update User A workflow `{path}` during preprocessing: {exc}"
                ) from exc
        workflows = updated_workflows
        workflow_contents = {path: content for path, content in workflows}
        focused_workflow = (
            _resolve_focused_workflow(primary_risk) if primary_risk else None
        )
        focused_workflow_content = (
            workflow_contents.get(focused_workflow or "") if focused_workflow else ""
        )
        if focused_workflow and workflow_has_schedule_trigger(focused_workflow_content):
            workflow_identifier = Path(focused_workflow).name
            try:
                user_a_client.enable_workflow(user_a_fork, workflow_identifier)
            except Exception as exc:
                raise RuntimeError(
                    "Failed to enable scheduled focused workflow "
                    f"`{focused_workflow}` on `{user_a_fork}`: {exc}"
                ) from exc

        workflow_secret_map = collect_workflow_secrets(workflows)
        workflow_secret_map_list = {
            path: sorted(names) for path, names in workflow_secret_map.items()
        }
        workflow_secret_names = {
            name for names in workflow_secret_map.values() for name in names
        }
        local_seed_secret_values = _load_local_seed_secret_values()
        seeded_secret_values = _resolve_seed_secret_values(
            required_secret_names=workflow_secret_names,
            base_values=local_seed_secret_values,
        )
        (
            seeded_secrets,
            secret_seed_summary,
            secret_seed_failures,
        ) = self._seed_actions_secrets(
            client=user_a_client,
            repo_name=repo_name,
            user_a_fork=user_a_fork,
            seeded_secret_values=seeded_secret_values,
        )

        try:
            user_b_fork = self._ensure_fork(
                client=user_b_client,
                source_repo=user_a_fork,
                fork_owner=user_b_login,
            )
        except RuntimeError as exc:
            self._report_token_failure(
                token=user_b_token,
                token_role="user_b",
                repo_name=repo_name,
                stage="ensure_user_b_fork",
                reason=str(exc),
            )
            raise self._classify_fork_preparation_error(
                exc=exc,
                source_repo=user_a_fork,
                fork_owner=user_b_login,
            ) from exc

        shared_secrets_state_path = self._artifacts.prepare_repository_shared_state(
            repository_name=repo_name
        )

        return PreparedRepository(
            vulnerable_commit_hash=vulnerable_commit_hash,
            source_last_commit_timestamp=source_last_commit_timestamp,
            source_default_branch=source_metadata["default_branch"],
            repository_name=repo_name,
            user_a_login=user_a_login,
            user_b_login=user_b_login,
            user_a_fork=user_a_fork,
            user_b_fork=user_b_fork,
            seeded_secrets=seeded_secrets,
            workflow_secret_map=workflow_secret_map_list,
            workflow_contents=workflow_contents,
            scanned_workflows=sorted(path for path, _ in workflows),
            shared_secrets_state_path=shared_secrets_state_path,
            agent_provider=self._agent_provider,
            max_retries=self._max_retries,
            secret_seed_summary=secret_seed_summary,
            secret_seed_failures=secret_seed_failures,
        )

    @staticmethod
    def _extract_commit_timestamp(commit_payload: Any) -> str | None:
        if not isinstance(commit_payload, dict):
            return None
        commit = commit_payload.get("commit")
        if not isinstance(commit, dict):
            return None
        committer = commit.get("committer")
        if isinstance(committer, dict):
            timestamp = str(committer.get("date") or "").strip()
            if timestamp:
                return timestamp
        author = commit.get("author")
        if isinstance(author, dict):
            timestamp = str(author.get("date") or "").strip()
            if timestamp:
                return timestamp
        return None

    def _prepare_risk_artifacts(
        self,
        *,
        prepared: PreparedRepository,
        risk: dict[str, Any],
        risk_index: int,
        source_client: GitHubClient,
        user_b_token: str,
    ) -> dict[str, Any]:
        focused_workflow = _resolve_focused_workflow(risk)
        focused_workflows = _resolve_focused_workflows(risk)
        focused_workflow_refs = _resolve_focused_workflow_refs(risk)
        focused_workflow_secrets = prepared.workflow_secret_map.get(
            focused_workflow or "", []
        )
        placeholder_attack_result = {
            "focused_workflow": focused_workflow,
            "focused_workflows": focused_workflows,
            "focused_workflow_refs": focused_workflow_refs,
            "focused_workflow_has_secrets": bool(focused_workflow_secrets),
            "focused_workflow_secrets": focused_workflow_secrets,
            "user_a_fork": prepared.user_a_fork,
            "user_b_fork": prepared.user_b_fork,
            "seeded_secrets": prepared.seeded_secrets,
            "secret_seed_summary": prepared.secret_seed_summary,
            "secret_seed_failures": prepared.secret_seed_failures,
            "scanned_workflows": prepared.scanned_workflows,
        }
        context_payload = {
            "repository_name": prepared.repository_name,
            "vulnerable_commit_hash": prepared.vulnerable_commit_hash,
            "attack_input_source": str(risk.get("attack_input_source") or "ai-enumerate"),
            "attack_result": placeholder_attack_result,
            "risk": risk,
            "referenced_files": self._load_referenced_files(
                client=source_client,
                repo_name=prepared.repository_name,
                ref=prepared.vulnerable_commit_hash,
                risk=risk,
            ),
        }
        artifact_bundle = self._artifacts.prepare_risk_bundle(
            repository_name=prepared.repository_name,
            risk_key=self._build_risk_artifact_key(risk=risk, risk_index=risk_index),
            vulnerable_commit_hash=prepared.vulnerable_commit_hash,
            user_b_fork=prepared.user_b_fork,
            agent_provider=self._agent_provider,
            context_payload=context_payload,
            reset_workspace=self._reset_forks,
            max_retries=self._max_retries,
            bin_id=None,
        )
        agent_launch = (
            self._maybe_launch_agent(
                artifact_bundle,
                use_headless=self._agent_headless,
                timeout=self._agent_timeout,
                git_token=user_b_token,
            )
            if self._launch_agent
            else None
        )
        return {
            "artifact_bundle": artifact_bundle,
            "agent_launch": agent_launch,
        }

    @staticmethod
    def _build_risk_artifact_key(*, risk: dict[str, Any], risk_index: int) -> str:
        issue_type = str(risk.get("issue_type") or "risk").strip().lower()
        normalized_issue_type = re.sub(r"[^a-z0-9]+", "-", issue_type).strip("-")
        if not normalized_issue_type:
            normalized_issue_type = "risk"
        return f"risk-{risk_index:03d}-{normalized_issue_type}"

    def _seed_actions_secrets(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        user_a_fork: str,
        seeded_secret_values: dict[str, str],
    ) -> tuple[list[str], dict[str, int], list[dict[str, Any]]]:
        planned_secret_names = sorted(
            name
            for name, value in seeded_secret_values.items()
            if isinstance(name, str) and name.strip() and isinstance(value, str)
        )
        summary = {
            "attempted": len(planned_secret_names),
            "succeeded": 0,
            "failed": 0,
            "skipped": 0,
        }
        failures: list[dict[str, Any]] = []
        seeded_successfully: list[str] = []

        self._log_stage_event(
            "secret_preflight_start",
            repo_name=repo_name,
            stage="preparation",
            user_a_fork=user_a_fork,
            secret_count=len(planned_secret_names),
        )
        get_public_key = getattr(client, "get_actions_secret_public_key", None)
        preflight_error: Exception | None = None
        preflight_key_id: str | None = None
        if callable(get_public_key):
            for attempt in range(1, SECRET_PREFLIGHT_MAX_ATTEMPTS + 1):
                try:
                    key_payload = get_public_key(user_a_fork)
                    preflight_key_id = str(key_payload.get("key_id") or "").strip() or None
                    preflight_error = None
                    break
                except Exception as exc:  # pragma: no cover - covered through service integration behavior
                    preflight_error = exc
                    if attempt >= SECRET_PREFLIGHT_MAX_ATTEMPTS:
                        break
                    self._sleep_secret_retry(attempt)
        if preflight_error is not None:
            failure = self._build_secret_seed_failure(
                secret_name="__preflight__",
                exception=preflight_error,
                key_id=preflight_key_id,
            )
            failures.append(failure)
            self._log_stage_event(
                "secret_preflight_end",
                repo_name=repo_name,
                stage="preparation",
                status="failed",
                failure_class=failure.get("failure_class"),
                github_request_id=failure.get("github_request_id"),
            )
            raise PreparationError(
                reason=(
                    f"Failed Actions secret preflight for `{user_a_fork}`: "
                    f"{failure.get('message') or 'unknown error'}"
                ),
                error_stage="preparation",
                error_class="repo_not_ready",
                failure_fingerprint="seed_secret_repo_not_ready",
                secret_seed_summary=summary,
                secret_seed_failures=failures,
            ) from preflight_error
        self._log_stage_event(
            "secret_preflight_end",
            repo_name=repo_name,
            stage="preparation",
            status="success",
            key_id=preflight_key_id,
        )

        for secret_name in planned_secret_names:
            secret_value = seeded_secret_values.get(secret_name, "")
            if not secret_value:
                summary["skipped"] += 1
                continue
            self._log_stage_event(
                "secret_seed_start",
                repo_name=repo_name,
                stage="preparation",
                secret_name=secret_name,
            )
            terminal_failure: dict[str, Any] | None = None
            for attempt in range(1, SECRET_SEED_MAX_ATTEMPTS + 1):
                key_id: str | None = None
                key_request_id: str | None = None
                write_request_id: str | None = None
                try:
                    if callable(get_public_key):
                        key_payload = get_public_key(user_a_fork)
                        key_id = str(key_payload.get("key_id") or "").strip() or None
                        key_request_id = (
                            str(key_payload.get("github_request_id") or "").strip() or None
                        )
                    seed_result = client.set_actions_secret(
                        user_a_fork,
                        secret_name,
                        secret_value,
                    )
                    if isinstance(seed_result, dict):
                        write_request_id = (
                            str(seed_result.get("github_request_id") or "").strip()
                            or None
                        )
                        key_id = str(seed_result.get("key_id") or key_id or "").strip() or None
                    summary["succeeded"] += 1
                    seeded_successfully.append(secret_name)
                    self._log_stage_event(
                        "secret_seed_end",
                        repo_name=repo_name,
                        stage="preparation",
                        status="success",
                        secret_name=secret_name,
                        key_id=key_id,
                        github_request_id=write_request_id or key_request_id,
                    )
                    terminal_failure = None
                    break
                except Exception as exc:
                    terminal_failure = self._build_secret_seed_failure(
                        secret_name=secret_name,
                        exception=exc,
                        key_id=key_id,
                    )
                    if not terminal_failure.get("github_request_id"):
                        terminal_failure["github_request_id"] = key_request_id
                    retryable = (
                        terminal_failure.get("failure_class")
                        in {"repo_not_ready", "rate_limited", "unknown_400"}
                    )
                    if retryable and attempt < SECRET_SEED_MAX_ATTEMPTS:
                        self._sleep_secret_retry(attempt)
                        continue
                    break
            if terminal_failure is not None:
                summary["failed"] += 1
                failures.append(terminal_failure)
                self._log_stage_event(
                    "secret_seed_end",
                    repo_name=repo_name,
                    stage="preparation",
                    status="failed",
                    secret_name=secret_name,
                    failure_class=terminal_failure.get("failure_class"),
                    github_request_id=terminal_failure.get("github_request_id"),
                )

        if (
            summary["attempted"] > 0
            and summary["succeeded"] == 0
            and failures
            and all(
                str(item.get("failure_class") or "") == "repo_not_ready"
                for item in failures
            )
        ):
            raise PreparationError(
                reason=(
                    f"Systemic Actions secret seeding readiness failure for `{user_a_fork}` "
                    f"({summary['failed']} failures)."
                ),
                error_stage="preparation",
                error_class="repo_not_ready",
                failure_fingerprint="seed_secret_repo_not_ready",
                secret_seed_summary=summary,
                secret_seed_failures=failures,
            )

        return sorted(set(seeded_successfully)), summary, failures

    def _build_secret_seed_failure(
        self,
        *,
        secret_name: str,
        exception: Exception,
        key_id: str | None,
    ) -> dict[str, Any]:
        message = str(exception)
        http_status = self._extract_http_status(message)
        failure_class = self._classify_secret_seed_failure(
            message=message,
            http_status=http_status,
        )
        return {
            "secret_name": secret_name,
            "http_status": http_status,
            "failure_class": failure_class,
            "key_id": key_id,
            "github_request_id": self._extract_request_id(message),
            "message": message,
        }

    @staticmethod
    def _extract_http_status(message: str) -> int | None:
        match = _HTTP_STATUS_PATTERN.search(message)
        if match is None:
            return None
        try:
            return int(match.group(1))
        except ValueError:
            return None

    @staticmethod
    def _extract_request_id(message: str) -> str | None:
        match = _REQUEST_ID_PATTERN.search(message)
        if match is None:
            return None
        request_id = match.group(1).strip()
        return request_id or None

    @staticmethod
    def _classify_secret_seed_failure(*, message: str, http_status: int | None) -> str:
        lowered = message.lower()
        if http_status == 422 and "secret" in lowered and "name" in lowered:
            return "invalid_secret_name"
        if http_status == 403 or "resource not accessible" in lowered or "forbidden" in lowered:
            return "permission_denied"
        if http_status == 429 or "rate limit" in lowered or "secondary rate limit" in lowered:
            return "rate_limited"
        if (
            http_status in {400, 404, 409}
            and (
                "public-key" in lowered
                or "public key" in lowered
                or "key_id" in lowered
                or "not ready" in lowered
                or "disabled" in lowered
                or "empty repository" in lowered
            )
        ):
            return "repo_not_ready"
        if http_status == 400:
            return "unknown_400"
        return "repo_not_ready"

    @staticmethod
    def _sleep_secret_retry(attempt: int) -> None:
        backoff = SECRET_SEED_RETRY_BASE_SECONDS * (2 ** max(0, attempt - 1))
        jitter = random.uniform(0.0, 0.35 * backoff)
        time.sleep(backoff + jitter)

    def _log_stage_event(self, event: str, **payload: Any) -> None:
        event_payload = {
            "event": event,
            "run_id": self._artifacts.run_root.name if self._artifacts else None,
            **payload,
        }
        LOGGER.info("attack.lifecycle %s", json.dumps(event_payload, sort_keys=True))

    @staticmethod
    def _is_not_found_error(exc: Exception) -> bool:
        return " 404 " in str(exc) or "404 Not Found" in str(exc)

    def _classify_fork_preparation_error(
        self,
        *,
        exc: RuntimeError,
        source_repo: str,
        fork_owner: str,
    ) -> PreparationError:
        message = str(exc)
        lowered = message.lower()
        if "source_repo_not_found" in lowered:
            return PreparationError(
                reason=f"Source repository `{source_repo}` was not found.",
                error_stage="preparation",
                error_class="source_repo_not_found",
                failure_fingerprint="source_repo_not_found",
            )
        if "fork_parent_validation_timeout" in lowered:
            return PreparationError(
                reason=(
                    f"Fork parent validation timed out for `{source_repo}` under `{fork_owner}`."
                ),
                error_stage="preparation",
                error_class="fork_parent_validation_timeout",
                failure_fingerprint="fork_parent_validation_timeout",
            )
        if "fork_visibility_timeout" in lowered:
            return PreparationError(
                reason=(
                    f"Fork visibility timed out for `{source_repo}` under `{fork_owner}`."
                ),
                error_stage="preparation",
                error_class="fork_visibility_timeout",
                failure_fingerprint="fork_visibility_timeout",
            )
        if "fork_name_not_honored" in lowered:
            return PreparationError(
                reason=(
                    f"GitHub did not honor requested fork name while preparing `{source_repo}` under `{fork_owner}`."
                ),
                error_stage="preparation",
                error_class="fork_name_not_honored",
                failure_fingerprint="fork_name_not_honored",
            )
        return PreparationError(
            reason=message,
            error_stage="preparation",
            error_class="unknown_preparation_error",
            failure_fingerprint="preparation_runtime_error",
        )

    def _ensure_fork(
        self,
        *,
        client: GitHubClient,
        source_repo: str,
        fork_owner: str,
    ) -> str:
        source_owner = source_repo.split("/", 1)[0]
        if source_owner.lower() == fork_owner.lower():
            raise RuntimeError(
                f"Invalid fork chain: `{fork_owner}` cannot fork `{source_repo}` into itself. "
                "Use a distinct User A account from the source owner."
            )

        repo_basename = source_repo.split("/", 1)[1]
        lock = self._resolve_fork_name_lock(fork_owner=fork_owner, repo_basename=repo_basename)
        with lock:
            return self._ensure_fork_with_locked_basename(
                client=client,
                source_repo=source_repo,
                fork_owner=fork_owner,
                source_owner=source_owner,
                repo_basename=repo_basename,
            )

    def _ensure_fork_with_locked_basename(
        self,
        *,
        client: GitHubClient,
        source_repo: str,
        fork_owner: str,
        source_owner: str,
        repo_basename: str,
    ) -> str:
        candidate_repo_names = _build_fork_name_candidates(
            source_owner=source_owner,
            repo_basename=repo_basename,
        )
        attempted_candidates: list[str] = []
        source_repo_lower = source_repo.lower()

        for candidate_repo_name in candidate_repo_names:
            fork_name = f"{fork_owner}/{candidate_repo_name}"
            attempted_candidates.append(fork_name)
            if _repo_exists(client, fork_name):
                metadata = client.get_repo_metadata(fork_name)
                parent_full_name = (
                    str(metadata.get("parent_full_name") or "").strip() or None
                )
                if parent_full_name and parent_full_name.lower() == source_repo_lower:
                    if self._reset_forks:
                        LOGGER.info("Deleting existing fork %s before recreation.", fork_name)
                        client.delete_repo(fork_name)
                        self._create_fork_with_name(
                            client=client,
                            source_repo=source_repo,
                            fork_name=fork_name,
                        )
                        self._validate_fork_parent(
                            client=client,
                            fork_name=fork_name,
                            source_repo=source_repo,
                        )
                    return fork_name

                if self._can_delete_conflicting_wrong_parent_fork(
                    metadata=metadata,
                    expected_owner=fork_owner,
                    source_repo=source_repo,
                ):
                    LOGGER.info(
                        "Deleting conflicting wrong-parent fork %s (observed_parent=%s) before recreation from %s.",
                        fork_name,
                        parent_full_name,
                        source_repo,
                    )
                    client.delete_repo(fork_name)
                    self._create_fork_with_name(
                        client=client,
                        source_repo=source_repo,
                        fork_name=fork_name,
                    )
                    self._validate_fork_parent(
                        client=client,
                        fork_name=fork_name,
                        source_repo=source_repo,
                    )
                    return fork_name

                LOGGER.info(
                    "Repository %s already exists and is not a fork of %s. Trying alternate fork name.",
                    fork_name,
                    source_repo,
                )
                continue

            self._create_fork_with_name(
                client=client,
                source_repo=source_repo,
                fork_name=fork_name,
            )
            self._validate_fork_parent(
                client=client,
                fork_name=fork_name,
                source_repo=source_repo,
            )
            return fork_name

        raise RuntimeError(
            "Unable to allocate fork name for "
            f"`{source_repo}` under `{fork_owner}`. Tried: {', '.join(attempted_candidates)}."
        )

    def _resolve_fork_name_lock(self, *, fork_owner: str, repo_basename: str) -> Lock:
        key = (fork_owner.lower(), repo_basename.lower())
        with self._fork_name_locks_guard:
            existing_lock = self._fork_name_locks.get(key)
            if existing_lock is not None:
                return existing_lock
            created = Lock()
            self._fork_name_locks[key] = created
            return created

    def _create_fork_with_name(
        self,
        *,
        client: GitHubClient,
        source_repo: str,
        fork_name: str,
    ) -> None:
        requested_name = fork_name.split("/", 1)[1]
        LOGGER.info("Creating fork %s from %s.", fork_name, source_repo)
        self._log_stage_event(
            "fork_create",
            stage="preparation",
            source_repo=source_repo,
            fork_name=fork_name,
            status="start",
        )
        try:
            response = client.create_fork(source_repo, name=requested_name)
            created_full_name = (
                str((response or {}).get("full_name") or "").strip().lower()
                if isinstance(response, dict)
                else ""
            )
            requested_full_name = fork_name.strip().lower()
            if created_full_name and created_full_name != requested_full_name:
                raise RuntimeError(
                    "fork_name_not_honored: GitHub create_fork returned "
                    f"`{created_full_name}` instead of requested `{requested_full_name}`."
                )
            self._log_stage_event(
                "fork_create",
                stage="preparation",
                source_repo=source_repo,
                fork_name=fork_name,
                status="success",
            )
            return
        except GitHubApiError as exc:
            self._log_stage_event(
                "fork_create",
                stage="preparation",
                source_repo=source_repo,
                fork_name=fork_name,
                status="failed",
                reason=str(exc),
            )
            if self._is_not_found_error(exc):
                raise RuntimeError(
                    f"source_repo_not_found: unable to fork `{source_repo}` into `{fork_name}`"
                ) from exc
            raise
        except TypeError:
            if requested_name != source_repo.split("/", 1)[1]:
                raise RuntimeError(
                    "Configured GitHub client does not support custom fork names, "
                    f"but `{fork_name}` is required to avoid a naming collision."
                ) from None
            client.create_fork(source_repo)

    @staticmethod
    def _can_delete_conflicting_wrong_parent_fork(
        *,
        metadata: dict[str, Any],
        expected_owner: str,
        source_repo: str,
    ) -> bool:
        full_name = str(metadata.get("name") or metadata.get("full_name") or "").strip()
        if "/" not in full_name:
            return False
        owner = full_name.split("/", 1)[0].strip().lower()
        if owner != expected_owner.strip().lower():
            return False
        parent = str(metadata.get("parent_full_name") or "").strip().lower()
        if not parent:
            return False
        return parent != source_repo.strip().lower()

    def _validate_fork_parent(
        self,
        *,
        client: GitHubClient,
        fork_name: str,
        source_repo: str,
    ) -> None:
        observed_parent: str | None = None
        started_at = time.monotonic()
        attempt = 0
        while True:
            attempt += 1
            elapsed = time.monotonic() - started_at
            elapsed_ms = int(elapsed * 1000)
            timed_out = (
                elapsed >= FORK_PARENT_VALIDATION_MAX_ELAPSED_SECONDS
                or attempt > FORK_PARENT_VALIDATION_MAX_ATTEMPTS
            )
            self._log_stage_event(
                "fork_visibility_check",
                stage="preparation",
                fork_name=fork_name,
                source_repo=source_repo,
                attempt=attempt,
                elapsed_ms=elapsed_ms,
            )
            try:
                metadata = self._get_repo_metadata(
                    client=client,
                    repo_name=fork_name,
                    force_refresh=True,
                )
                parent_full_name = metadata.get("parent_full_name")
            except GitHubApiError as exc:
                if self._is_not_found_error(exc) and not timed_out:
                    LOGGER.info(
                        "Fork %s metadata not visible yet (attempt %s, elapsed %.2fs). Retrying.",
                        fork_name,
                        attempt,
                        elapsed,
                    )
                    sleep_seconds = min(
                        FORK_PARENT_VALIDATION_RETRY_MAX_SECONDS,
                        FORK_PARENT_VALIDATION_RETRY_DELAY_SECONDS
                        * (2 ** max(0, attempt - 1)),
                    )
                    sleep_seconds += random.uniform(0.0, 0.3 * sleep_seconds)
                    time.sleep(sleep_seconds)
                    continue
                if self._is_not_found_error(exc):
                    raise RuntimeError(
                        f"fork_visibility_timeout: `{fork_name}` metadata remained unavailable "
                        f"after {elapsed:.1f}s"
                    ) from exc
                raise

            observed_parent = (
                parent_full_name.strip()
                if isinstance(parent_full_name, str) and parent_full_name.strip()
                else None
            )
            if observed_parent and observed_parent.lower() == source_repo.lower():
                if attempt > 1 or elapsed_ms > 0:
                    LOGGER.info(
                        "Validated fork parent for %s after %s attempt(s).",
                        fork_name,
                        attempt,
                    )
                return

            if not timed_out:
                LOGGER.info(
                    "Fork %s parent not resolved yet (attempt %s, elapsed %.2fs, observed_parent=%r). Retrying.",
                    fork_name,
                    attempt,
                    elapsed,
                    observed_parent,
                )
                sleep_seconds = min(
                    FORK_PARENT_VALIDATION_RETRY_MAX_SECONDS,
                    FORK_PARENT_VALIDATION_RETRY_DELAY_SECONDS
                    * (2 ** max(0, attempt - 1)),
                )
                sleep_seconds += random.uniform(0.0, 0.3 * sleep_seconds)
                time.sleep(sleep_seconds)
                continue

            # Final fallback check: one extra metadata read before classifying timeout.
            try:
                fallback_metadata = self._get_repo_metadata(
                    client=client,
                    repo_name=fork_name,
                    force_refresh=True,
                )
            except GitHubApiError as fallback_exc:
                if self._is_not_found_error(fallback_exc):
                    raise RuntimeError(
                        f"fork_visibility_timeout: `{fork_name}` metadata remained unavailable "
                        f"after {elapsed:.1f}s"
                    ) from fallback_exc
                raise
            fallback_parent = str(
                fallback_metadata.get("parent_full_name") or ""
            ).strip() or None
            if fallback_parent and fallback_parent.lower() == source_repo.lower():
                return
            raise RuntimeError(
                "fork_parent_validation_timeout: invalid fork chain after creation "
                f"for `{fork_name}` expected parent `{source_repo}` "
                f"(observed_parent={fallback_parent!r})."
            )

    @staticmethod
    def _get_repo_metadata(
        *, client: GitHubClient, repo_name: str, force_refresh: bool = False
    ) -> dict[str, Any]:
        if force_refresh:
            try:
                parameters = inspect.signature(client.get_repo_metadata).parameters
            except (TypeError, ValueError):
                parameters = {}
            if "force_refresh" in parameters:
                return client.get_repo_metadata(repo_name, force_refresh=True)
        return client.get_repo_metadata(repo_name)

    def _load_workflows(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        ref: str,
    ) -> list[tuple[str, str]]:
        try:
            items = client.list_directory(repo_name, ".github/workflows", ref)
        except GitHubApiError as exc:
            if "404" in str(exc):
                return []
            raise

        workflows: list[tuple[str, str]] = []
        for item in items:
            item_type = item.get("type")
            path = item.get("path")
            if item_type != "file" or not isinstance(path, str):
                continue
            if not path.endswith((".yml", ".yaml")):
                continue
            workflows.append((path, client.get_file_content(repo_name, path, ref)))
        return workflows

    def _load_referenced_files(
        self,
        *,
        client: GitHubClient,
        repo_name: str,
        ref: str,
        risk: dict[str, Any] | None,
    ) -> list[dict[str, str]]:
        if risk is None:
            return []

        referenced_files = extract_referenced_files(
            risk,
            fallback_repo_name=repo_name,
            fallback_ref=ref,
        )
        results: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for referenced in referenced_files:
            if referenced.repo_name.lower() != repo_name.lower():
                continue
            key = (referenced.repo_name.lower(), referenced.path)
            if key in seen:
                continue
            seen.add(key)
            results.append(
                {
                    "path": referenced.path,
                    "content": client.get_file_content(repo_name, referenced.path, ref),
                }
            )
        return results

    def _maybe_launch_agent(
        self,
        artifact_bundle: RepositoryArtifactBundle,
        use_headless: bool = False,
        timeout: int = 900,
        git_token: str | None = None,
    ) -> Union[AttackAgentLaunchResult, AttackAgentHeadlessResult, None]:
        if not self._launch_agent:
            return None

        if self._agent_runtime is None:
            return _unavailable_agent_launch_result(
                metadata_path=artifact_bundle.agent_metadata_path,
                reason="Agent runtime is not configured.",
            )

        if self._dry_run:
            return _unavailable_agent_launch_result(
                metadata_path=artifact_bundle.agent_metadata_path,
                reason="Dry-run mode does not launch the configured agent provider.",
            )

        if use_headless:
            return self._agent_runtime.run_headless(
                workspace_path=artifact_bundle.workspace_path,
                prompt_path=artifact_bundle.agent_prompt_path,
                metadata_path=artifact_bundle.agent_metadata_path,
                timeout=timeout,
                git_token=git_token,
            )

        return self._agent_runtime.launch(
            workspace_path=artifact_bundle.workspace_path,
            prompt_path=artifact_bundle.agent_prompt_path,
            metadata_path=artifact_bundle.agent_metadata_path,
        )


def _unavailable_agent_launch_result(
    *,
    metadata_path: Path,
    reason: str,
) -> AttackAgentLaunchResult:
    payload = {
        "status": "unavailable",
        "reason": reason,
        "base_url": None,
        "pid": None,
        "command": [],
        "tracing": {
            "enabled": False,
            "service_name": "pwnhunter-attack-agent",
            "endpoint": None,
        },
    }
    metadata_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    return AttackAgentLaunchResult(
        status="unavailable",
        base_url=None,
        pid=None,
        command=[],
        metadata_path=metadata_path,
        tracing=payload["tracing"],
    )
