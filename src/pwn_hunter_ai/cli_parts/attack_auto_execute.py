from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable

from pwn_hunter_ai.config import AttackCLIConfig, split_csv_tokens

LOGGER = logging.getLogger(__name__)


def run_auto_execute(
    output_payload: dict[str, Any],
    config: AttackCLIConfig,
    token_broker: Any,
    *,
    resolve_symbol: Callable[[str], Any],
    build_agent_runtime: Callable[[AttackCLIConfig], Any],
    reserve_attack_lease: Callable[..., Any],
    extract_repo_owner: Callable[[Any], str | None],
    build_risk_trace_id: Callable[..., str],
    build_human_review_precheck_runner: Callable[[AttackCLIConfig], Any],
    format_now_timestamp: Callable[[], str],
    refresh_repo_vulnerable_fields: Callable[[dict[str, Any]], None],
    instantiate_with_supported_kwargs: Callable[[Any, dict[str, Any]], Any],
    token_probe_timeout_seconds: int,
) -> dict[str, Any]:
    from pwn_hunter_ai.attack.execution_service import AttackExecutionService
    from pwn_hunter_ai.attack.github_token_probe import GitHubTokenProbeService
    from pwn_hunter_ai.attack.hookbin_client import HookbinClient
    from pwn_hunter_ai.attack.sandbox_manager import SandboxManager

    sandbox_manager = SandboxManager(use_host=True)
    tracer_factory = resolve_symbol("build_tracer")
    tracer = tracer_factory(
        public_key=config.langfuse_public_key,
        secret_key=config.langfuse_secret_key,
        host=config.langfuse_host,
    )

    github_client_class = resolve_symbol("GitHubClient")
    execution_service_kwargs: dict[str, Any] = {
        "use_host_agent_directly": True,
        "use_host_openhands_directly": True,
    }

    runtime_manager = build_agent_runtime(config)
    security_reports_dir: Path | None = None
    if config.generate_security_report:
        security_reports_dir = config.output_path.parent / "security-reports"
        security_reports_dir.mkdir(parents=True, exist_ok=True)

    execution_service = instantiate_with_supported_kwargs(
        AttackExecutionService,
        {
            "github_client_factory": lambda token: github_client_class(tokens=[token]),
            "hookbin_client": HookbinClient(),
            "sandbox_manager": sandbox_manager,
            "agent_runtime": runtime_manager,
            "agent_provider": config.agent_provider,
            "security_reports_dir": security_reports_dir,
            "generate_security_report": config.generate_security_report,
            # Legacy compatibility kwarg for older tests and integrations.
            "openhands_manager": runtime_manager,
            **execution_service_kwargs,
        },
    )
    token_probe_service = GitHubTokenProbeService(
        github_client_factory=lambda token: github_client_class(tokens=[token]),
        workflow_timeout=token_probe_timeout_seconds,
    )
    repo_probe_cache: dict[str, dict[str, Any]] = {}
    repositories = output_payload.get("ai_enumeration", [])
    LOGGER.info(
        "Starting attack auto-execute pass for %s repositories (max_retries=%s, workflow_timeout=%s, agent_timeout=%s).",
        len(repositories) if isinstance(repositories, list) else 0,
        config.max_retries,
        config.workflow_timeout,
        config.agent_timeout,
    )

    try:
        for repo in repositories:
            repo_name = repo.get("name", "")
            risks = repo.get("risks", [])
            LOGGER.info(
                "Auto-execute repository %s with %s risk(s).",
                repo_name or "unknown-repository",
                len(risks) if isinstance(risks, list) else 0,
            )
            for risk_index, risk in enumerate(risks):
                attack_result = risk.get("attack_result", {})
                if attack_result.get("status") not in ("prepared_for_manual_validation",):
                    LOGGER.debug(
                        "Skipping repo=%s risk_index=%s because status is %r.",
                        repo_name or "unknown-repository",
                        risk_index,
                        attack_result.get("status"),
                    )
                    continue

                user_a_fork = attack_result.get("user_a_fork")
                user_b_fork = attack_result.get("user_b_fork")
                workspace_path = attack_result.get("workspace_path")
                default_branch = str(
                    attack_result.get("source_default_branch") or "main"
                )
                focused_workflow = attack_result.get("focused_workflow")
                focused_workflows = attack_result.get("focused_workflows")
                focused_workflow_refs = attack_result.get("focused_workflow_refs")
                seeded_secrets = (
                    [
                        str(secret_name).strip()
                        for secret_name in attack_result.get("seeded_secrets")
                        if isinstance(secret_name, str) and str(secret_name).strip()
                    ]
                    if isinstance(attack_result.get("seeded_secrets"), list)
                    else None
                )
                shared_secrets_state_path = str(
                    attack_result.get("shared_secrets_state_path") or ""
                ).strip()

                if not all([user_a_fork, user_b_fork, workspace_path]):
                    LOGGER.warning(
                        "Skipping repo=%s risk_index=%s due to missing execution prerequisites (user_a_fork=%s, user_b_fork=%s, workspace_path=%s).",
                        repo_name or "unknown-repository",
                        risk_index,
                        bool(user_a_fork),
                        bool(user_b_fork),
                        bool(workspace_path),
                    )
                    continue
                expected_user_a_owner = extract_repo_owner(user_a_fork)
                expected_user_b_owner = extract_repo_owner(user_b_fork)

                agent_runtime = attack_result.get("agent_runtime") or {}
                agent_runtime_base_url = (
                    agent_runtime.get("base_url")
                    if isinstance(agent_runtime, dict)
                    else None
                )
                human_review_precheck_metadata = {
                    "repository_name": repo_name,
                    "initial_workflow": risk.get("initial_workflow"),
                    "trace_id": build_risk_trace_id(repo_name=repo_name, risk=risk),
                }

                LOGGER.info(
                    "Executing attack for repo=%s risk_index=%s workflow=%s default_branch=%s.",
                    repo_name or "unknown-repository",
                    risk_index,
                    focused_workflow if isinstance(focused_workflow, str) else "",
                    default_branch,
                )
                list_user_b_tokens = getattr(token_broker, "list_user_b_tokens", None)
                if callable(list_user_b_tokens):
                    reviewer_tokens = list_user_b_tokens()
                else:
                    reviewer_tokens = split_csv_tokens(config.github_tokens_user_b)
                lease = reserve_attack_lease(
                    token_broker=token_broker,
                    repository_name=repo["name"],
                    expected_user_a_owner=expected_user_a_owner,
                    expected_user_b_owner=expected_user_b_owner,
                )
                try:
                    LOGGER.debug(
                        "Lease acquired for repo=%s risk_index=%s (expected_user_a_owner=%s, expected_user_b_owner=%s).",
                        repo_name or "unknown-repository",
                        risk_index,
                        expected_user_a_owner,
                        expected_user_b_owner,
                    )
                    result = execution_service.execute_attack(
                        user_a_token=lease.user_a_token,
                        user_b_token=lease.user_b_token,
                        user_a_fork=user_a_fork,
                        user_b_fork=user_b_fork,
                        workspace_path=Path(workspace_path),
                        default_branch=default_branch,
                        max_retries=config.max_retries,
                        agent_runtime_base_url=agent_runtime_base_url,
                        agent_timeout=config.agent_timeout,
                        workflow_timeout=config.workflow_timeout,
                        repo_name=repo_name,
                        focused_workflow=(
                            str(focused_workflow)
                            if isinstance(focused_workflow, str)
                            else None
                        ),
                        focused_workflows=(
                            [
                                str(path)
                                for path in focused_workflows
                                if isinstance(path, str) and path.strip()
                            ]
                            if isinstance(focused_workflows, list)
                            else None
                        ),
                        focused_workflow_refs=(
                            [
                                {
                                    "repo_name": (
                                        str(ref.get("repo_name"))
                                        if isinstance(ref.get("repo_name"), str)
                                        and str(ref.get("repo_name")).strip()
                                        else None
                                    ),
                                    "path": str(ref.get("path")).strip(),
                                    "ref": (
                                        str(ref.get("ref"))
                                        if isinstance(ref.get("ref"), str)
                                        and str(ref.get("ref")).strip()
                                        else None
                                    ),
                                }
                                for ref in focused_workflow_refs
                                if isinstance(ref, dict)
                                and isinstance(ref.get("path"), str)
                                and str(ref.get("path")).strip()
                            ]
                            if isinstance(focused_workflow_refs, list)
                            else None
                        ),
                        seeded_secrets=seeded_secrets,
                        user_b_reviewer_tokens=reviewer_tokens,
                        ai_analysis=risk.get("ai-analysis"),
                        github_token_permissions=(
                            risk.get("github_token_permissions")
                            if isinstance(risk.get("github_token_permissions"), dict)
                            else None
                        ),
                        human_review_precheck=build_human_review_precheck_runner(config),
                        human_review_precheck_metadata=human_review_precheck_metadata,
                        risk_index=risk_index,
                        shared_secrets_state_path=(
                            Path(shared_secrets_state_path)
                            if shared_secrets_state_path
                            else None
                        ),
                    )
                finally:
                    token_broker.release(lease)
                    LOGGER.debug(
                        "Lease released for repo=%s risk_index=%s.",
                        repo_name or "unknown-repository",
                        risk_index,
                    )

                risk["attack_result"]["execution_result"] = result
                risk["attack_processed_time"] = format_now_timestamp()
                result_attempt_count = result.get("attempt_count")
                if not isinstance(result_attempt_count, int) or result_attempt_count < 0:
                    if isinstance(result.get("attempt"), int) and result["attempt"] >= 0:
                        result_attempt_count = result["attempt"]
                    elif isinstance(result.get("attempts"), list):
                        result_attempt_count = len(result["attempts"])
                    else:
                        result_attempt_count = None
                if isinstance(result_attempt_count, int):
                    risk["attack_result"]["attempt_count"] = result_attempt_count
                result_attempts = result.get("attempts")
                if isinstance(result_attempts, list):
                    risk["attack_result"]["attempts"] = result_attempts
                pull_request_url = result.get("pull_request_url")
                if isinstance(pull_request_url, str) and pull_request_url.strip():
                    risk["attack_result"]["pull_request_url"] = pull_request_url.strip()
                security_report = result.get("security_report")
                if isinstance(security_report, dict):
                    report_status = str(security_report.get("status") or "").strip()
                    persisted_path = str(
                        security_report.get("persisted_path") or ""
                    ).strip()
                    verification_sources = security_report.get("verification_sources")
                    if report_status:
                        risk["attack_result"]["security_report_status"] = report_status
                    if persisted_path:
                        risk["attack_result"]["security_report_path"] = persisted_path
                    if isinstance(verification_sources, list):
                        risk["attack_result"][
                            "security_report_verification_sources"
                        ] = [
                            str(source).strip()
                            for source in verification_sources
                            if isinstance(source, str) and str(source).strip()
                        ]
                result_status = str(result.get("status") or "").strip()
                result_status_normalized = result_status.lower()
                result_reason = str(result.get("reason") or "").strip()
                controller_signal = result.get("controller_signal")
                controller_status = (
                    str(controller_signal.get("status") or "").strip()
                    if isinstance(controller_signal, dict)
                    else ""
                )
                LOGGER.info(
                    "Execution result for repo=%s risk_index=%s: status=%s vulnerable=%s needs_human_review=%s attempts=%s.",
                    repo_name or "unknown-repository",
                    risk_index,
                    result_status or "unknown",
                    result.get("vulnerable"),
                    result.get("needs_human_review"),
                    result_attempt_count if isinstance(result_attempt_count, int) else "unknown",
                )
                if result_status_normalized == "skipped_node_runtime_unavailable":
                    risk["attack_result"]["status"] = "skipped_node_runtime_unavailable"
                    risk["attack_result"]["reason"] = result_reason or (
                        "Auto execution skipped because Gemini CLI requires Node.js >= 20 "
                        "and nvm could not activate node 24, 22, or 20."
                    )
                    LOGGER.info(
                        "Marked repo=%s risk_index=%s as skipped_node_runtime_unavailable.",
                        repo_name or "unknown-repository",
                        risk_index,
                    )
                    continue
                if result_status_normalized == "execution_error":
                    risk["attack_result"]["status"] = "execution_error"
                    risk["attack_result"]["reason"] = result_reason or (
                        "Runtime execution failed after preparation."
                    )
                    for field in (
                        "error_stage",
                        "error_class",
                        "failure_fingerprint",
                    ):
                        value = result.get(field)
                        if isinstance(value, str) and value.strip():
                            risk["attack_result"][field] = value.strip()
                    LOGGER.info(
                        "Marked repo=%s risk_index=%s as execution_error (error_class=%s).",
                        repo_name or "unknown-repository",
                        risk_index,
                        risk["attack_result"].get("error_class") or "unknown",
                    )
                    continue
                needs_human_review = (
                    result.get("needs_human_review") is True
                    or result_status_normalized
                    in {"needs_human_review", "human_review_required"}
                    or controller_status
                    in {"needs_human_review", "human_review_required"}
                    or result_reason
                    == "Repository changed, but controller could not commit any eligible files after retries."
                )
                if needs_human_review:
                    risk["attack_result"]["flagged_for_human_review"] = True
                    risk["attack_result"]["status"] = "human_review_required"
                    if result.get("reason"):
                        risk["attack_result"]["reason"] = result["reason"]
                    LOGGER.info(
                        "Marked repo=%s risk_index=%s as human_review_required.",
                        repo_name or "unknown-repository",
                        risk_index,
                    )
                    continue

                vulnerable = result.get("vulnerable")
                if vulnerable is True:
                    risk["attack_result"]["status"] = "vulnerable_confirmed"
                    risk["attack_result"]["reason"] = (
                        "Auto execution confirmed the repository is vulnerable."
                    )
                    timing = risk.get("attack_result", {}).get("github_token_probe_timing")
                    permissions = risk.get("github_token_permissions")
                    if (
                        timing == "after_agentic"
                        and isinstance(permissions, dict)
                        and str(permissions.get("status") or "").strip().lower()
                        == "unknown"
                    ):
                        probe_result = repo_probe_cache.get(repo_name)
                        if probe_result is None:
                            LOGGER.info(
                                "Running post-execution token probe for repo=%s risk_index=%s.",
                                repo_name or "unknown-repository",
                                risk_index,
                            )
                            lease = reserve_attack_lease(
                                token_broker=token_broker,
                                repository_name=repo["name"],
                                expected_user_a_owner=expected_user_a_owner,
                                expected_user_b_owner=expected_user_b_owner,
                            )
                            try:
                                probe_result = token_probe_service.resolve_unknown_status(
                                    repo_name=repo_name,
                                    source_default_branch=str(
                                        risk["attack_result"].get("source_default_branch")
                                        or "main"
                                    ),
                                    vulnerable_commit_hash=repo.get(
                                        "vulnerable_commit_hash", ""
                                    ),
                                    focused_workflow=risk["attack_result"].get(
                                        "focused_workflow"
                                    ),
                                    workspace_path=Path(workspace_path),
                                    user_a_token=lease.user_a_token,
                                    user_a_fork=user_a_fork,
                                    user_b_token=lease.user_b_token,
                                    user_b_fork=user_b_fork,
                                )
                            finally:
                                token_broker.release(lease)
                            if not isinstance(probe_result, dict):
                                probe_result = {}
                            repo_probe_cache[repo_name] = probe_result
                        else:
                            LOGGER.debug(
                                "Reusing cached token probe result for repo=%s.",
                                repo_name or "unknown-repository",
                            )

                        resolved_permissions = probe_result.get("resolved_permissions")
                        if isinstance(resolved_permissions, dict):
                            risk["github_token_permissions"] = resolved_permissions
                            risk["attack_result"][
                                "github_token_permissions"
                            ] = resolved_permissions
                            status = resolved_permissions.get("status")
                            if isinstance(status, str) and status.strip():
                                risk["attack_result"][
                                    "github_token_permissions_classification"
                                ] = status.strip().lower()
                        probe_payload = probe_result.get("probe")
                        if isinstance(probe_payload, dict):
                            risk["attack_result"]["github_token_probe"] = probe_payload
                    LOGGER.info(
                        "Marked repo=%s risk_index=%s as vulnerable_confirmed.",
                        repo_name or "unknown-repository",
                        risk_index,
                    )
                elif vulnerable is False:
                    risk["attack_result"]["status"] = "not_vulnerable_after_execution"
                    if result.get("reason"):
                        risk["attack_result"]["reason"] = result["reason"]
                    else:
                        risk["attack_result"]["reason"] = (
                            "Auto execution did not confirm vulnerability."
                        )
                    LOGGER.info(
                        "Marked repo=%s risk_index=%s as not_vulnerable_after_execution.",
                        repo_name or "unknown-repository",
                        risk_index,
                    )
    finally:
        LOGGER.debug("Flushing tracer for attack auto-execute pass.")
        tracer.flush()

    refresh_repo_vulnerable_fields(output_payload)
    LOGGER.info("Attack auto-execute pass completed.")
    return output_payload
