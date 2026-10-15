from __future__ import annotations

from contextlib import nullcontext
import hashlib
import json
import logging
import random
from typing import Any, Callable

from pwn_hunter_ai.config import AttackCLIConfig


HUMAN_REVIEW_PRECHECK_MODEL = "gemini-3.1-flash-lite-preview"


def extract_repo_owner(repo_name: Any) -> str | None:
    if not isinstance(repo_name, str):
        return None
    owner, sep, _ = repo_name.partition("/")
    if not sep:
        return None
    owner = owner.strip()
    if not owner:
        return None
    return owner


def reserve_attack_lease(
    *,
    token_broker: Any,
    repository_name: str,
    expected_user_a_owner: str | None,
    expected_user_b_owner: str | None,
) -> Any:
    reserve_for_owners = getattr(token_broker, "reserve_for_owners", None)
    if callable(reserve_for_owners):
        return reserve_for_owners(
            repository_name,
            user_a_owner=expected_user_a_owner,
            user_b_owner=expected_user_b_owner,
            require_owner_match=True,
        )
    return token_broker.reserve(repository_name)


def refresh_repo_vulnerable_fields(payload: dict[str, Any]) -> None:
    repositories = payload.get("ai_enumeration")
    if not isinstance(repositories, list):
        return
    for repository in repositories:
        if not isinstance(repository, dict):
            continue
        repository["repo_vulnerable"] = derive_repo_vulnerable(repository)
        repository["act_repo_vulnerable"] = derive_act_repo_vulnerable(repository)


def derive_repo_vulnerable(repository: dict[str, Any]) -> str:
    risks = repository.get("risks", [])
    if not isinstance(risks, list):
        return "false"
    if any(risk_is_vulnerable(risk) for risk in risks if isinstance(risk, dict)):
        return "true"
    if any(
        risk_needs_human_review(risk) for risk in risks if isinstance(risk, dict)
    ):
        return "unknown"
    return "false"


def derive_act_repo_vulnerable(repository: dict[str, Any]) -> bool:
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
            if attempt_has_successful_local_test(attempt):
                return True
    return False


def attempt_has_successful_local_test(attempt: Any) -> bool:
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


def risk_is_vulnerable(risk: dict[str, Any]) -> bool:
    attack_result = risk.get("attack_result")
    if isinstance(attack_result, dict):
        if attack_result.get("vulnerable") is True:
            return True
        status = str(attack_result.get("status") or "").strip().lower()
        if status == "vulnerable_confirmed":
            return True
        execution_result = attack_result.get("execution_result")
        if (
            isinstance(execution_result, dict)
            and execution_result.get("vulnerable") is True
        ):
            return True
        return False
    return False


def risk_needs_human_review(risk: dict[str, Any]) -> bool:
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
    if status in {
        "human_review_required",
        "needs_human_review",
        "prepared_for_manual_validation",
        "blocked_preparation_error",
        "execution_error",
        "skipped_node_runtime_unavailable",
    }:
        return True
    execution_result = attack_result.get("execution_result")
    if not isinstance(execution_result, dict):
        return False
    if execution_result.get("needs_human_review") is True:
        return True
    execution_status = str(execution_result.get("status") or "").strip().lower()
    return execution_status in {"human_review_required", "needs_human_review"}


def run_human_review_precheck(
    *,
    ai_analysis: Any,
    gemini_api_key: str | None,
    resolve_symbol: Callable[[str], Any],
    billing: str = "oauth",
    metadata: dict[str, Any] | None = None,
    logger: logging.Logger | None = None,
    model: str = HUMAN_REVIEW_PRECHECK_MODEL,
) -> dict[str, Any]:
    if str(billing).strip().lower() != "api":
        return {
            "needs_human_review": False,
            "reason": "Human review pre-check skipped for oauth billing mode.",
        }
    if not gemini_api_key:
        return {"needs_human_review": False, "reason": "Gemini API key missing."}
    if not isinstance(ai_analysis, dict):
        return {"needs_human_review": False, "reason": "ai-analysis missing."}

    logger = logger or logging.getLogger(__name__)
    gemini_analyzer_class = resolve_symbol("GeminiAnalyzer")
    analyzer = gemini_analyzer_class(
        api_key=gemini_api_key,
        model=model,
    )
    trace_id = str((metadata or {}).get("trace_id") or "")
    span_context = start_human_review_precheck_trace(trace_id)
    try:
        with span_context:
            result = analyzer.analyze_human_review_precheck(
                ai_analysis, metadata=metadata
            )
    except Exception as exc:  # pragma: no cover - behavior validated in cli tests
        logger.warning("Gemini human review pre-check failed: %s", exc)
        return {
            "needs_human_review": False,
            "reason": "Gemini human review pre-check failed; continuing with configured agent provider.",
            "error": f"{type(exc).__name__}: {exc}",
        }
    return (
        result
        if isinstance(result, dict)
        else {"needs_human_review": False, "reason": ""}
    )


def build_human_review_precheck_runner(
    *,
    config: AttackCLIConfig,
    resolve_symbol: Callable[[str], Any],
    logger: logging.Logger | None = None,
    model: str = HUMAN_REVIEW_PRECHECK_MODEL,
):
    def _runner(*, ai_analysis: Any, metadata: dict[str, Any] | None = None):
        return run_human_review_precheck(
            ai_analysis=ai_analysis,
            gemini_api_key=config.gemini_api_key,
            billing=config.billing,
            resolve_symbol=resolve_symbol,
            metadata=metadata,
            logger=logger,
            model=model,
        )

    return _runner


def build_risk_trace_id(*, repo_name: str, risk: dict[str, Any]) -> str:
    workflow = str(risk.get("initial_workflow") or "unknown-workflow")
    issue_type = str(risk.get("issue_type") or "unknown-issue")
    path = risk.get("gato-x-path")
    if path is None:
        path = risk.get("path")
    path_repr = json.dumps(path if isinstance(path, list) else [], sort_keys=True)
    digest_source = "|".join([repo_name, workflow, issue_type, path_repr])
    return f"risk-{hashlib.sha256(digest_source.encode('utf-8')).hexdigest()[:32]}"


def start_human_review_precheck_trace(trace_id: str):
    normalized = trace_id.strip()
    if not normalized.startswith("risk-"):
        return nullcontext()
    hex_trace_id = normalized.removeprefix("risk-")
    if len(hex_trace_id) != 32:
        return nullcontext()
    try:
        from opentelemetry import trace as ot_trace
    except Exception:  # pragma: no cover - optional dependency path
        return nullcontext()

    try:
        parent_context = ot_trace.set_span_in_context(
            ot_trace.NonRecordingSpan(
                ot_trace.SpanContext(
                    trace_id=int(hex_trace_id, 16),
                    span_id=random.getrandbits(64),
                    is_remote=False,
                    trace_flags=ot_trace.TraceFlags(0x01),
                    trace_state=ot_trace.TraceState(),
                )
            )
        )
        tracer = ot_trace.get_tracer("pwn_hunter_ai.attack")
        return tracer.start_as_current_span(
            "human-review-precheck",
            context=parent_context,
        )
    except Exception:  # pragma: no cover - tracing should never block execution
        return nullcontext()


def build_agent_runtime(config: AttackCLIConfig):
    provider = (config.agent_provider or "openhands").strip().lower()
    if provider == "gemini-cli":
        from pwn_hunter_ai.attack.gemini_cli_manager import (
            GeminiCliConfig,
            GeminiCliRuntimeManager,
        )

        return GeminiCliRuntimeManager(
            config=GeminiCliConfig(model=config.agent_model, billing=config.billing)
        )

    from pwn_hunter_ai.attack.openhands_manager import (
        OpenHandsLaunchManager,
        OpenHandsTracingConfig,
    )

    return OpenHandsLaunchManager(
        host=config.openhands_host,
        start_port=config.openhands_start_port,
        tracing=OpenHandsTracingConfig(
            public_key=config.langfuse_public_key,
            secret_key=config.langfuse_secret_key,
            host=config.langfuse_host,
        ),
    )
