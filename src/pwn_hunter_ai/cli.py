from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from copy import deepcopy
from datetime import datetime
import inspect
import json
import logging
import os
from pathlib import Path
import shutil
import subprocess
import sys
import threading
from urllib import error as urllib_error
from urllib import request as urllib_request
from typing import Any, Sequence, TYPE_CHECKING

from pwn_hunter_ai.cli_parts.attack_auto_execute import (
    run_auto_execute as _run_auto_execute_impl,
)
from pwn_hunter_ai.cli_parts.attack_helpers import (
    build_agent_runtime as _build_agent_runtime_impl,
    build_human_review_precheck_runner as _build_human_review_precheck_runner_impl,
    build_risk_trace_id as _build_risk_trace_id_impl,
    derive_repo_vulnerable as _derive_repo_vulnerable_impl,
    extract_repo_owner as _extract_repo_owner_impl,
    refresh_repo_vulnerable_fields as _refresh_repo_vulnerable_fields_impl,
    reserve_attack_lease as _reserve_attack_lease_impl,
    risk_is_vulnerable as _risk_is_vulnerable_impl,
    risk_needs_human_review as _risk_needs_human_review_impl,
    run_human_review_precheck as _run_human_review_precheck_impl,
    start_human_review_precheck_trace as _start_human_review_precheck_trace_impl,
)
from pwn_hunter_ai.cli_parts.parser import build_parser as _build_parser_impl
from pwn_hunter_ai.config import (
    AttackCLIConfig,
    CLIConfig,
    env_value,
    load_env_file,
    split_csv_tokens,
)
from pwn_hunter_ai.attack.service_helpers.selection import (
    _extract_attack_repositories,
    _normalize_repository_full_name,
)
from pwn_hunter_ai.logging_utils import (
    AttackParallelLogManager,
    configure_logging,
    format_command_for_logging,
)
from pwn_hunter_ai.slack_notifications import send_slack_message
from pwn_hunter_ai.review_app import run_review_server

if TYPE_CHECKING:
    from pwn_hunter_ai.attack.cleanup import AttackCleanupService as _AttackCleanupService
    from pwn_hunter_ai.attack.service import (
        AttackPreparationService as _AttackPreparationService,
    )
    from pwn_hunter_ai.attack.tokens import AttackTokenBroker as _AttackTokenBroker
    from pwn_hunter_ai.ai_enumerate.service import (
        AIEnumerationService as _AIEnumerationService,
    )
    from pwn_hunter_ai.gemini_client import GeminiAnalyzer as _GeminiAnalyzer
    from pwn_hunter_ai.github_client import GitHubClient as _GitHubClient
    from pwn_hunter_ai.pr_target_history import (
        PullRequestTargetHistoryService as _PullRequestTargetHistoryService,
    )
    from pwn_hunter_ai.search.service import (
        GitHubCodeSearchService as _GitHubCodeSearchService,
    )

# Cache lazily loaded classes/functions to avoid importing heavyweight modules for
# unrelated commands.
AttackCleanupService: type[Any] | None = None
AttackPreparationService: type[Any] | None = None
AttackTokenBroker: type[Any] | None = None
AIEnumerationService: type[Any] | None = None
GeminiAnalyzer: type[Any] | None = None
GitHubClient: type[Any] | None = None
PullRequestTargetHistoryService: type[Any] | None = None
GitHubCodeSearchService: type[Any] | None = None
build_tracer: Any | None = None
load_repositories_from_text_file: Any | None = None
write_scan_results: Any | None = None
LOGGER = logging.getLogger(__name__)
MAX_ATTACK_RISKS_PER_REPOSITORY = 15
TOKEN_PROBE_TIMEOUT_SECONDS = 90


class AttackRepositoryStageError(RuntimeError):
    def __init__(self, stage: str, cause: Exception) -> None:
        self.stage = stage
        self.cause = cause
        super().__init__(f"{type(cause).__name__}: {cause}")


class AttackResumeOutputError(RuntimeError):
    """Raised when an existing attack output file cannot be resumed."""


def _format_now_timestamp() -> str:
    return datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Y")


def _format_backup_timestamp() -> str:
    return datetime.now().astimezone().strftime("%Y%m%dT%H%M%S%z")


def _resolve_learning_file_path(raw_value: str | None) -> Path | None:
    if raw_value:
        return Path(raw_value)
    default_learning_path = Path.cwd() / "LEARNING.md"
    if default_learning_path.is_file():
        return default_learning_path
    return None


def _parse_attack_skip_repositories(raw_value: str | None) -> tuple[str, ...]:
    normalized_repositories: list[str] = []
    seen_repositories: set[str] = set()
    for repository_name in split_csv_tokens(raw_value):
        normalized_repository_name = _normalize_repository_full_name(repository_name)
        if normalized_repository_name is None:
            raise ValueError(
                "Invalid repository in --skip. Expected OWNER/REPO or OWNER/* entries separated by commas."
            )
        if normalized_repository_name in seen_repositories:
            continue
        seen_repositories.add(normalized_repository_name)
        normalized_repositories.append(normalized_repository_name)
    return tuple(normalized_repositories)


def _resolve_cli_env_source(
    raw_value: str | None,
    *,
    env_name: str,
    env_file_values: dict[str, str],
) -> tuple[str | None, str]:
    if raw_value is not None:
        return raw_value, "cli"
    env_raw_value = os.environ.get(env_name)
    if env_raw_value is not None:
        return env_raw_value, "env"
    env_file_value = env_file_values.get(env_name)
    if env_file_value is not None:
        return env_file_value, "env_file"
    return None, "missing"


def _attack_token_refresh_enabled(config: AttackCLIConfig) -> bool:
    return (
        config.github_tokens_user_a_source == "env_file"
        or config.github_tokens_user_b_source == "env_file"
    )


def _load_attack_token_snapshot(config: AttackCLIConfig) -> tuple[list[str], list[str]]:
    env_file_path = config.env_file_path or (Path.cwd() / ".env")
    env_file_values = load_env_file(env_file_path)
    user_a_raw = config.github_tokens_user_a
    user_b_raw = config.github_tokens_user_b
    if config.github_tokens_user_a_source == "env_file":
        user_a_raw = env_file_values.get("GITHUB_TOKENS_USER_A")
    elif config.github_tokens_user_a_source == "env":
        user_a_raw = os.environ.get("GITHUB_TOKENS_USER_A")
    if config.github_tokens_user_b_source == "env_file":
        user_b_raw = env_file_values.get("GITHUB_TOKENS_USER_B")
    elif config.github_tokens_user_b_source == "env":
        user_b_raw = os.environ.get("GITHUB_TOKENS_USER_B")
    return split_csv_tokens(user_a_raw), split_csv_tokens(user_b_raw)


def _resolve_symbol(name: str) -> Any:
    global AttackCleanupService
    global AttackPreparationService
    global AttackTokenBroker
    global AIEnumerationService
    global GeminiAnalyzer
    global GitHubClient
    global PullRequestTargetHistoryService
    global GitHubCodeSearchService
    global build_tracer
    global load_repositories_from_text_file
    global write_scan_results

    if name == "AttackCleanupService" and AttackCleanupService is None:
        from pwn_hunter_ai.attack.cleanup import AttackCleanupService as _symbol

        AttackCleanupService = _symbol
    elif name == "AttackPreparationService" and AttackPreparationService is None:
        from pwn_hunter_ai.attack.service import AttackPreparationService as _symbol

        AttackPreparationService = _symbol
    elif name == "AttackTokenBroker" and AttackTokenBroker is None:
        from pwn_hunter_ai.attack.tokens import AttackTokenBroker as _symbol

        AttackTokenBroker = _symbol
    elif name == "AIEnumerationService" and AIEnumerationService is None:
        from pwn_hunter_ai.ai_enumerate.service import AIEnumerationService as _symbol

        AIEnumerationService = _symbol
    elif name == "GeminiAnalyzer" and GeminiAnalyzer is None:
        from pwn_hunter_ai.gemini_client import GeminiAnalyzer as _symbol

        GeminiAnalyzer = _symbol
    elif name == "GitHubClient" and GitHubClient is None:
        from pwn_hunter_ai.github_client import GitHubClient as _symbol

        GitHubClient = _symbol
    elif (
        name == "PullRequestTargetHistoryService"
        and PullRequestTargetHistoryService is None
    ):
        from pwn_hunter_ai.pr_target_history import (
            PullRequestTargetHistoryService as _symbol,
        )

        PullRequestTargetHistoryService = _symbol
    elif name == "GitHubCodeSearchService" and GitHubCodeSearchService is None:
        from pwn_hunter_ai.search.service import GitHubCodeSearchService as _symbol

        GitHubCodeSearchService = _symbol
    elif name == "build_tracer" and build_tracer is None:
        from pwn_hunter_ai.tracing import build_tracer as _symbol

        build_tracer = _symbol
    elif name == "load_repositories_from_text_file" and load_repositories_from_text_file is None:
        from pwn_hunter_ai.pr_target_history import (
            load_repositories_from_text_file as _symbol,
        )

        load_repositories_from_text_file = _symbol
    elif name == "write_scan_results" and write_scan_results is None:
        from pwn_hunter_ai.pr_target_history import write_scan_results as _symbol

        write_scan_results = _symbol

    return globals()[name]


def build_parser():
    return _build_parser_impl()


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = list(argv) if argv is not None else sys.argv[1:]
    args = parser.parse_args(raw_argv)

    env_file_values = load_env_file(Path.cwd() / ".env")
    configure_logging(Path(args.log_file), args.log_level.upper(), args.verbose)
    LOGGER.info("Command: %s", format_command_for_logging(parser.prog, raw_argv))

    if args.command == "ai-enumerate":
        config = CLIConfig(
            input_path=Path(args.input),
            output_path=Path(args.output),
            failure_output_path=_resolve_failure_output_path(
                output_path=Path(args.output),
                raw_value=args.failure_output,
            ),
            parallel_jobs=args.parallel_jobs,
            github_token=args.github_token
            or env_value("GITHUB_TOKEN", env_file_values),
            gemini_api_key=args.gemini_api_key
            or env_value("GEMINI_API_KEY", env_file_values),
            gemini_batch=args.gemini_batch,
            langfuse_public_key=env_value("LANGFUSE_PUBLIC_KEY", env_file_values),
            langfuse_secret_key=env_value("LANGFUSE_SECRET_KEY", env_file_values),
            langfuse_host=env_value("LANGFUSE_HOST", env_file_values),
            output_only_vulnerable=args.output_only_vulnerable,
            log_file=Path(args.log_file),
            log_level=args.log_level.upper(),
            verbose=args.verbose,
        )

        if config.parallel_jobs < 1:
            parser.error("--parallel-jobs must be at least 1.")
        if not config.gemini_api_key:
            parser.error(
                "Gemini API key is required via --gemini-api-key or GEMINI_API_KEY."
            )

        run_cli(config)
        return 0

    if args.command == "search":
        github_token = args.github_token or env_value("GITHUB_TOKEN", env_file_values)
        if not github_token:
            parser.error("GitHub token is required via --github-token or GITHUB_TOKEN.")
        if args.parallel_jobs < 1:
            parser.error("--parallel-jobs must be at least 1.")
        if args.min_file_size < 0:
            parser.error("--min-file-size must be at least 0.")
        if args.max_file_size < args.min_file_size:
            parser.error(
                "--max-file-size must be greater than or equal to --min-file-size."
            )
        if args.max_results_per_shard < 1:
            parser.error("--max-results-per-shard must be at least 1.")
        if args.query is None and not args.resume_snapshot:
            parser.error("A query is required unless --resume-snapshot is provided.")
        run_search(
            query=args.query,
            output_path=Path(args.output),
            github_token=github_token,
            parallel_jobs=args.parallel_jobs,
            min_file_size=args.min_file_size,
            max_file_size=args.max_file_size,
            max_results_per_shard=args.max_results_per_shard,
            brute_force=args.brute_force,
            snapshot_path=Path(args.snapshot_file) if args.snapshot_file else None,
            resume_snapshot_path=Path(args.resume_snapshot)
            if args.resume_snapshot
            else None,
        )
        return 0

    if args.command == "attack":
        github_tokens_user_a, github_tokens_user_a_source = _resolve_cli_env_source(
            args.github_tokens_user_a,
            env_name="GITHUB_TOKENS_USER_A",
            env_file_values=env_file_values,
        )
        github_tokens_user_b, github_tokens_user_b_source = _resolve_cli_env_source(
            args.github_tokens_user_b,
            env_name="GITHUB_TOKENS_USER_B",
            env_file_values=env_file_values,
        )
        try:
            config = AttackCLIConfig(
                input_path=Path(args.input),
                output_path=Path(args.output),
                artifacts_dir=Path(args.artifacts_dir),
                skip_repositories=_parse_attack_skip_repositories(args.skip),
                parallel_jobs=args.parallel_jobs,
                max_retries=args.max_retries,
                github_tokens_user_a=github_tokens_user_a,
                github_tokens_user_b=github_tokens_user_b,
                reset_forks=args.reset_forks,
                dry_run=args.dry_run,
                launch_agent=args.launch_agent,
                agent_provider=args.agent_provider,
                agent_model=args.agent_model,
                auto_execute=args.auto_execute,
                no_sandbox=args.no_sandbox,
                agent_timeout=args.agent_timeout,
                workflow_timeout=args.workflow_timeout,
                openhands_host=args.openhands_host,
                openhands_start_port=args.openhands_start_port,
                langfuse_public_key=env_value("LANGFUSE_PUBLIC_KEY", env_file_values),
                langfuse_secret_key=env_value("LANGFUSE_SECRET_KEY", env_file_values),
                langfuse_host=env_value("LANGFUSE_HOST", env_file_values),
                log_file=Path(args.log_file),
                log_level=args.log_level.upper(),
                verbose=args.verbose,
                skip_permission_log_read=args.skip_permission_log_read,
                gemini_api_key=args.gemini_api_key
                or env_value("GEMINI_API_KEY", env_file_values),
                delete_workspace_after_processing=args.delete_workspace_after_processing,
                user_b_token_concurrency=args.user_b_token_concurrency,
                learning_file_path=_resolve_learning_file_path(args.learning_file),
                slack_webhook_url=env_value("SLACK_WEBHOOK_URL", env_file_values),
                billing=args.billing,
                generate_security_report=args.generate_security_report,
                github_tokens_user_a_source=github_tokens_user_a_source,
                github_tokens_user_b_source=github_tokens_user_b_source,
                env_file_path=Path.cwd() / ".env",
            )
        except ValueError as exc:
            parser.error(str(exc))
        if config.parallel_jobs < 1:
            parser.error("--parallel-jobs must be at least 1.")
        if config.max_retries < 1:
            parser.error("--max-retries must be at least 1.")
        if config.user_b_token_concurrency < 1:
            parser.error("--user-b-token-concurrency must be at least 1.")
        if config.openhands_start_port < 1:
            parser.error("--openhands-start-port must be at least 1.")
        if (
            config.auto_execute
            and config.billing == "api"
            and not config.gemini_api_key
        ):
            parser.error(
                "Auto execution with --billing api requires Gemini API key via --gemini-api-key or GEMINI_API_KEY."
            )
        if (
            config.learning_file_path is not None
            and not config.learning_file_path.is_file()
        ):
            parser.error(
                "--learning-file must point to an existing file."
            )
        if not config.github_tokens_user_a:
            parser.error(
                "User A GitHub token(s) are required via --github-tokens-user-a or GITHUB_TOKENS_USER_A."
            )
        if not config.github_tokens_user_b:
            parser.error(
                "User B GitHub token(s) are required via --github-tokens-user-b or GITHUB_TOKENS_USER_B."
            )
        if config.no_sandbox:
            LOGGER.warning(
                "--no-sandbox is kept for compatibility; host-only mode is always enabled."
            )

        try:
            output_payload = run_attack_prepare(config)
        except Exception as exc:
            _send_attack_completion_slack_notification(
                config=config,
                output_payload=None,
                success=False,
                error_message=f"{type(exc).__name__}: {exc}",
            )
            raise
        _send_attack_completion_slack_notification(
            config=config,
            output_payload=output_payload,
            success=True,
        )
        return 0

    if args.command == "attack-cleanup":
        github_token = args.github_token
        if not github_token:
            token_pool = env_value("GITHUB_TOKENS_USER_A", env_file_values)
            github_token = split_csv_tokens(token_pool)[0] if token_pool else None
        if not github_token:
            parser.error("Cleanup requires --github-token or GITHUB_TOKENS_USER_A.")
        if not args.delete_forks and not args.delete_artifacts:
            parser.error(
                "At least one of --delete-forks or --delete-artifacts is required."
            )
        run_attack_cleanup(
            input_path=Path(args.input),
            github_token=github_token,
            delete_forks=args.delete_forks,
            delete_artifacts=args.delete_artifacts,
        )
        return 0

    if args.command == "pr-target-history":
        github_token = args.github_token or env_value("GITHUB_TOKEN", env_file_values)
        if not github_token:
            parser.error("GitHub token is required via --github-token or GITHUB_TOKEN.")
        if args.days < 1:
            parser.error("--days must be at least 1.")
        if args.parallel_jobs < 1:
            parser.error("--parallel-jobs must be at least 1.")
        run_pr_target_history(
            input_path=Path(args.input),
            output_path=Path(args.output),
            days=args.days,
            parallel_jobs=args.parallel_jobs,
            github_token=github_token,
        )
        return 0

    if args.command == "review":
        github_token = args.github_token or env_value("GITHUB_TOKEN", env_file_values)
        if not github_token:
            parser.error("GitHub token is required via --github-token or GITHUB_TOKEN.")
        if args.port < 1 or args.port > 65535:
            parser.error("--port must be between 1 and 65535.")
        run_review(
            input_path=Path(args.input),
            github_token=github_token,
            host=args.host,
            port=args.port,
        )
        return 0

    parser.error(f"Unknown command: {args.command}")


def run_cli(config: CLIConfig) -> dict:
    input_payload = json.loads(config.input_path.read_text(encoding="utf-8"))

    github_client_class = _resolve_symbol("GitHubClient")
    tracer_factory = _resolve_symbol("build_tracer")
    gemini_analyzer_class = _resolve_symbol("GeminiAnalyzer")
    ai_enumeration_service_class = _resolve_symbol("AIEnumerationService")

    github_client = github_client_class(tokens=split_csv_tokens(config.github_token))
    tracer = tracer_factory(
        public_key=config.langfuse_public_key,
        secret_key=config.langfuse_secret_key,
        host=config.langfuse_host,
    )
    analyzer = gemini_analyzer_class(api_key=config.gemini_api_key or "")
    service = ai_enumeration_service_class(github_client, analyzer)
    try:
        output_payload = service.run(
            input_payload,
            parallel_jobs=config.parallel_jobs,
            gemini_batch=config.gemini_batch,
            output_only_vulnerable=False,
        )
    finally:
        tracer.flush()

    failure_payload = _build_failure_input_payload(input_payload, output_payload)
    if config.output_only_vulnerable:
        for repository in output_payload["ai_enumeration"]:
            repository["risks"] = [
                risk
                for risk in repository["risks"]
                if risk["ai-analysis"]["vulnerable"]
            ]
        output_payload["ai_enumeration"] = [
            repository
            for repository in output_payload["ai_enumeration"]
            if repository["risks"]
        ]

    config.output_path.parent.mkdir(parents=True, exist_ok=True)
    config.output_path.write_text(
        json.dumps(output_payload, indent=2) + "\n",
        encoding="utf-8",
    )
    config.failure_output_path.parent.mkdir(parents=True, exist_ok=True)
    config.failure_output_path.write_text(
        json.dumps(failure_payload, indent=2) + "\n",
        encoding="utf-8",
    )
    return output_payload


def _resolve_failure_output_path(*, output_path: Path, raw_value: str | None) -> Path:
    if raw_value:
        return Path(raw_value)
    suffix = output_path.suffix or ".json"
    return output_path.with_name(f"{output_path.stem}.failures{suffix}")


def _build_failure_input_payload(
    input_payload: dict,
    output_payload: dict,
) -> dict:
    failure_names = {
        repository["name"]
        for repository in output_payload.get("ai_enumeration", [])
        if _repository_has_failures(repository)
    }
    failure_payload = deepcopy(input_payload)
    enumeration = failure_payload.setdefault("enumeration", {})
    repositories = enumeration.get("repositories", [])
    enumeration["repositories"] = [
        repository
        for repository in repositories
        if repository.get("name") in failure_names
    ]
    return failure_payload


def _repository_has_failures(repository: dict) -> bool:
    if repository.get("error"):
        return True
    return any(
        risk.get("ai-analysis-error")
        for risk in repository.get("risks", [])
    )


def run_search(
    *,
    query: str | None,
    output_path: Path,
    github_token: str,
    parallel_jobs: int,
    min_file_size: int,
    max_file_size: int,
    max_results_per_shard: int,
    brute_force: bool,
    snapshot_path: Path | None = None,
    resume_snapshot_path: Path | None = None,
) -> list[str]:
    github_client_class = _resolve_symbol("GitHubClient")
    search_service_class = _resolve_symbol("GitHubCodeSearchService")
    github_client = github_client_class(tokens=split_csv_tokens(github_token))
    service = search_service_class(
        github_client,
        min_file_size=min_file_size,
        max_file_size=max_file_size,
        max_results_per_shard=max_results_per_shard,
        brute_force=brute_force,
    )
    effective_snapshot_path = snapshot_path or resume_snapshot_path
    repositories = service.collect_repositories(
        query,
        parallel_jobs=parallel_jobs,
        snapshot_path=effective_snapshot_path,
        resume_snapshot_path=resume_snapshot_path,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        "".join(f"{repository}\n" for repository in repositories), encoding="utf-8"
    )
    return repositories


def run_review(*, input_path: Path, github_token: str, host: str, port: int) -> None:
    raw_payload = json.loads(input_path.read_text(encoding="utf-8"))
    review_payload, payload_kind = _coerce_review_payload(raw_payload)
    LOGGER.info(
        "Detected review input kind '%s' for %s.",
        payload_kind,
        input_path,
    )
    github_client_class = _resolve_symbol("GitHubClient")
    github_client = github_client_class(tokens=split_csv_tokens(github_token))
    run_review_server(
        payload=review_payload,
        input_path=input_path,
        github_client=github_client,
        host=host,
        port=port,
    )


def _coerce_review_payload(
    payload: dict[str, Any],
) -> tuple[dict[str, Any], str]:
    kind = _detect_review_payload_kind(payload)
    if kind in {"ai_enumerate_output", "attack_output"}:
        return payload, kind
    if kind == "enumeration_input":
        enumeration = payload.get("enumeration")
        repositories = (
            enumeration.get("repositories", [])
            if isinstance(enumeration, dict)
            else []
        )
        return {"ai_enumeration": deepcopy(repositories)}, kind
    raise ValueError(
        "Unsupported review input JSON. Expected ai-enumeration output, attack output, or enumeration input with enumeration.repositories."
    )


def _detect_review_payload_kind(payload: dict[str, Any]) -> str:
    repositories = payload.get("ai_enumeration")
    if isinstance(repositories, list):
        if _payload_contains_attack_results(repositories):
            return "attack_output"
        return "ai_enumerate_output"

    enumeration = payload.get("enumeration")
    if isinstance(enumeration, dict) and isinstance(
        enumeration.get("repositories"), list
    ):
        return "enumeration_input"
    return "unknown"


def _payload_contains_attack_results(repositories: list[Any]) -> bool:
    for repository in repositories:
        if not isinstance(repository, dict):
            continue
        risks = repository.get("risks")
        if not isinstance(risks, list):
            continue
        for risk in risks:
            if not isinstance(risk, dict):
                continue
            if isinstance(risk.get("attack_result"), dict):
                return True
    return False


def _normalize_attack_input_payload(payload: dict[str, Any]) -> dict[str, Any]:
    normalized_payload = deepcopy(payload)
    repositories = normalized_payload.get("ai_enumeration")
    if isinstance(repositories, list):
        normalized_payload.setdefault("_attack_input_source", "ai-enumerate")
        return normalized_payload

    enumeration = normalized_payload.get("enumeration")
    if not isinstance(enumeration, dict):
        return normalized_payload

    raw_repositories = enumeration.get("repositories")
    if not isinstance(raw_repositories, list):
        return normalized_payload

    normalized_payload["_attack_input_source"] = "gato-x"
    normalized_payload["ai_enumeration"] = [
        _normalize_attack_repository(repository)
        for repository in raw_repositories
        if isinstance(repository, dict)
    ]
    return normalized_payload


def _normalize_attack_repository(repository: dict[str, Any]) -> dict[str, Any]:
    normalized_repository = deepcopy(repository)
    risks = normalized_repository.get("risks")
    if not isinstance(risks, list):
        return normalized_repository
    normalized_repository["risks"] = [
        _normalize_attack_risk(risk) if isinstance(risk, dict) else risk
        for risk in risks
    ]
    return normalized_repository


def _normalize_attack_risk(risk: dict[str, Any]) -> dict[str, Any]:
    normalized_risk = deepcopy(risk)
    if "ai-analysis" in normalized_risk:
        return normalized_risk

    # Raw gato-x attack inputs do not always include an explicit vulnerability flag.
    # For the attack command, each supplied risk should be treated as an attack candidate
    # unless the source explicitly marked it otherwise.
    normalized_risk.setdefault("vulnerable", True)
    normalized_risk["attack_input_source"] = "gato-x"
    _copy_attack_risk_field(
        normalized_risk,
        source_key="confidence",
        destination_key="gato-x-confidence",
    )
    _copy_attack_risk_field(
        normalized_risk,
        source_key="attack_complexity",
        destination_key="gato-x-attack_complexity",
    )
    _copy_attack_risk_field(
        normalized_risk,
        source_key="explanation",
        destination_key="gato-x-explanation",
    )
    _copy_attack_risk_field(
        normalized_risk,
        source_key="path",
        destination_key="gato-x-path",
    )
    _copy_attack_risk_field(
        normalized_risk,
        source_key="sink",
        destination_key="gato-x-sink",
    )
    return normalized_risk


def _copy_attack_risk_field(
    risk: dict[str, Any], *, source_key: str, destination_key: str
) -> None:
    if destination_key in risk:
        return
    if source_key not in risk:
        return
    risk[destination_key] = deepcopy(risk[source_key])


def run_attack_prepare(config: AttackCLIConfig) -> dict:
    token_broker_class = _resolve_symbol("AttackTokenBroker")
    attack_preparation_service_class = _resolve_symbol("AttackPreparationService")
    github_client_class = _resolve_symbol("GitHubClient")

    LOGGER.info(
        "Starting attack command run: input=%s output=%s auto_execute=%s parallel_jobs=%s max_retries=%s dry_run=%s reset_forks=%s delete_workspace_after_processing=%s generate_security_report=%s skipped_repositories=%s.",
        config.input_path,
        config.output_path,
        config.auto_execute,
        config.parallel_jobs,
        config.max_retries,
        config.dry_run,
        config.reset_forks,
        config.delete_workspace_after_processing,
        config.generate_security_report,
        len(config.skip_repositories),
    )
    input_payload = _normalize_attack_input_payload(
        json.loads(config.input_path.read_text(encoding="utf-8"))
    )
    existing_repository_results = _load_existing_attack_repository_results(
        output_path=config.output_path
    )
    backup_path = _backup_existing_attack_output(output_path=config.output_path)
    if backup_path is not None:
        LOGGER.info(
            "Existing attack output detected at %s. Created backup copy at %s.",
            config.output_path,
            backup_path,
        )
    user_a_tokens = split_csv_tokens(config.github_tokens_user_a)
    user_b_tokens = split_csv_tokens(config.github_tokens_user_b)
    LOGGER.info(
        "Attack token configuration: user_a_tokens=%s user_b_tokens=%s user_b_token_concurrency=%s.",
        len(user_a_tokens),
        len(user_b_tokens),
        config.user_b_token_concurrency,
    )
    token_broker = _instantiate_with_supported_kwargs(
        token_broker_class,
        {
            "user_a_tokens": user_a_tokens,
            "user_b_tokens": user_b_tokens,
            "user_b_max_parallel_per_token": config.user_b_token_concurrency,
            "token_login_resolver": lambda token: (
                github_client_class(tokens=[token]).get_authenticated_user().get("login")
            ),
            "on_token_quarantined": lambda event: _send_attack_token_quarantine_slack_notification(
                config=config,
                event=event,
            ),
            "on_token_availability_changed": lambda event: _send_attack_token_waiting_slack_notification(
                config=config,
                event=event,
            ),
        },
    )
    refresh_lock = threading.Lock()

    def refresh_attack_tokens(*, trigger: str) -> None:
        if not _attack_token_refresh_enabled(config):
            return
        refresh_tokens = getattr(token_broker, "refresh_tokens", None)
        if not callable(refresh_tokens):
            return
        with refresh_lock:
            refreshed_user_a_tokens, refreshed_user_b_tokens = _load_attack_token_snapshot(
                config
            )
            LOGGER.info(
                "Refreshing attack GitHub tokens from %s (user_a_tokens=%s, user_b_tokens=%s).",
                trigger,
                len(refreshed_user_a_tokens),
                len(refreshed_user_b_tokens),
            )
            refresh_tokens(
                user_a_tokens=refreshed_user_a_tokens,
                user_b_tokens=refreshed_user_b_tokens,
                trigger=trigger,
            )

    refresh_stop_event = threading.Event()
    refresh_thread: threading.Thread | None = None
    if _attack_token_refresh_enabled(config):
        refresh_attack_tokens(trigger="startup")

        def _periodic_refresh_loop() -> None:
            interval_seconds = max(1, int(config.token_refresh_interval_seconds))
            while not refresh_stop_event.wait(interval_seconds):
                try:
                    refresh_attack_tokens(trigger="periodic_refresh")
                except Exception:
                    LOGGER.exception("Periodic attack token refresh failed.")

        refresh_thread = threading.Thread(
            target=_periodic_refresh_loop,
            name="attack-token-refresh",
            daemon=True,
        )
        refresh_thread.start()
    launch_runtime = (
        None
        if not (config.launch_agent and not config.auto_execute)
        else __build_agent_runtime(config)
    )
    service = _instantiate_with_supported_kwargs(
        attack_preparation_service_class,
        {
            "token_broker": token_broker,
            "github_client_factory": lambda token: github_client_class(tokens=[token]),
            "reset_forks": config.reset_forks,
            "artifacts_dir": config.artifacts_dir,
            "max_retries": config.max_retries,
            "dry_run": config.dry_run,
            "launch_agent": config.launch_agent and not config.auto_execute,
            "agent_headless": False,
            "agent_timeout": config.agent_timeout,
            "agent_runtime": launch_runtime,
            "agent_provider": config.agent_provider,
            "skip_default_permission_log_read": config.skip_permission_log_read,
            # Legacy compatibility kwargs for old call sites/test doubles.
            "openhands_manager": launch_runtime,
            "openhands_headless": False,
            "openhands_timeout": config.agent_timeout,
        },
    )
    _seed_run_level_learnings(
        service=service,
        learning_file_path=config.learning_file_path,
    )
    repositories = _extract_attack_repositories(
        input_payload,
        skip_repositories=set(config.skip_repositories),
    )
    results: list[dict[str, Any] | None] = [None] * len(repositories)

    resumed_count = 0
    for index, repository in enumerate(repositories):
        repository_name = repository.get("name")
        if not isinstance(repository_name, str) or not repository_name.strip():
            continue
        existing_result = existing_repository_results.get(repository_name)
        if existing_result is None:
            continue
        results[index] = existing_result
        resumed_count += 1
    if resumed_count:
        LOGGER.info(
            "Resuming attack output from %s. Skipping %s/%s already processed repositories.",
            config.output_path,
            resumed_count,
            len(repositories),
        )

    risk_limit_skipped_count = 0
    for index, repository in enumerate(repositories):
        if results[index] is not None:
            continue
        risk_count = _count_attack_repository_risks(repository)
        if risk_count <= MAX_ATTACK_RISKS_PER_REPOSITORY:
            continue
        results[index] = _build_attack_repository_risk_limit_skip_result(
            repository=repository,
            risk_count=risk_count,
            max_risks=MAX_ATTACK_RISKS_PER_REPOSITORY,
        )
        risk_limit_skipped_count += 1
    if risk_limit_skipped_count:
        LOGGER.info(
            "Skipping %s repositories with more than %s risks and marking them for manual review.",
            risk_limit_skipped_count,
            MAX_ATTACK_RISKS_PER_REPOSITORY,
        )

    pending_indices = [index for index, result in enumerate(results) if result is None]
    if not repositories:
        LOGGER.info("Attack input contains no repositories. Writing empty output snapshot.")
        output_payload = _write_attack_snapshot(
            output_path=config.output_path,
            input_payload=input_payload,
            repository_results=results,
        )
        return output_payload
    if risk_limit_skipped_count:
        output_payload = _write_attack_snapshot(
            output_path=config.output_path,
            input_payload=input_payload,
            repository_results=results,
        )
        LOGGER.info(
            "Snapshot updated at %s after marking risk-limit skips.",
            config.output_path,
        )
    if not pending_indices:
        LOGGER.info(
            "All repositories are already processed in %s. Writing refreshed snapshot and exiting.",
            config.output_path,
        )
        output_payload = _write_attack_snapshot(
            output_path=config.output_path,
            input_payload=input_payload,
            repository_results=results,
        )
        return output_payload

    max_workers = max(1, config.parallel_jobs)
    LOGGER.info(
        "Attack run will process %s pending repositories out of %s total with %s worker(s) (requested_parallel_jobs=%s, dynamic_user_b_capacity=%s).",
        len(pending_indices),
        len(repositories),
        max_workers,
        config.parallel_jobs,
        token_broker.user_b_capacity,
    )
    repository_worker = (
        _prepare_and_execute_single_repository
        if config.auto_execute
        else _prepare_single_repository
    )

    output_payload = _build_attack_output_payload(
        input_payload=input_payload,
        repository_results=results,
    )
    try:
        with AttackParallelLogManager(
            base_log_file=config.log_file,
            log_level=config.log_level,
            worker_count=max_workers,
        ) as parallel_log_manager:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_index = {
                    executor.submit(
                        _run_attack_repository_with_worker_logging,
                        repository_worker=repository_worker,
                        repository=repositories[index],
                        service=service,
                        config=config,
                        token_broker=token_broker,
                        parallel_log_manager=parallel_log_manager,
                        refresh_attack_tokens=refresh_attack_tokens,
                    ): index
                    for index in pending_indices
                }
                for future in as_completed(future_to_index):
                    index = future_to_index[future]
                    repository = repositories[index]
                    repo_name = str(repository.get("name") or f"index:{index}")
                    try:
                        repository_result = future.result()
                    except Exception as exc:  # pragma: no cover - exercised via tests
                        LOGGER.exception(
                            "Attack processing failed for repository %s. Persisting failure and continuing.",
                            repo_name,
                        )
                        error_stage = (
                            exc.stage
                            if isinstance(exc, AttackRepositoryStageError)
                            else "preparation"
                        )
                        formatted_error = (
                            f"{type(exc.cause).__name__}: {exc.cause}"
                            if isinstance(exc, AttackRepositoryStageError)
                            else f"{type(exc).__name__}: {exc}"
                        )
                        repository_result = _build_attack_repository_error_result(
                            repository=repository,
                            error=formatted_error,
                            error_stage=error_stage,
                        )
                    if (
                        repository_result is not None
                        and config.delete_workspace_after_processing
                    ):
                        try:
                            _delete_repository_workspaces(repository_result)
                        except Exception as exc:
                            LOGGER.exception(
                                "Workspace cleanup failed for repository %s. Continuing without cleanup. Error: %s",
                                repo_name,
                                exc,
                            )
                    results[index] = repository_result
                    output_payload = _write_attack_snapshot(
                        output_path=config.output_path,
                        input_payload=input_payload,
                        repository_results=results,
                    )
                    LOGGER.info(
                        "Repository %s completed (%s/%s): %s. Snapshot updated at %s.",
                        repo_name,
                        sum(result is not None for result in results),
                        len(results),
                        _summarize_repository_attack_statuses(repository_result),
                        config.output_path,
                    )
    finally:
        refresh_stop_event.set()
        if refresh_thread is not None:
            refresh_thread.join(timeout=1.0)

    LOGGER.info(
        "Attack command run complete. Processed %s repositories. Output written to %s.",
        len(_extract_attack_repositories_for_cli(output_payload)),
        config.output_path,
    )
    return output_payload


def _send_attack_completion_slack_notification(
    *,
    config: AttackCLIConfig,
    output_payload: dict[str, Any] | None,
    success: bool,
    error_message: str | None = None,
) -> None:
    if success:
        repository_count = (
            len(_extract_attack_repositories_for_cli(output_payload))
            if isinstance(output_payload, dict)
            else 0
        )
        message = (
            "pwnhunter attack command completed successfully.\n"
            f"Repositories processed: {repository_count}\n"
            f"Output: {config.output_path}"
        )
    else:
        message = (
            "pwnhunter attack command failed.\n"
            f"Output: {config.output_path}\n"
            f"Error: {error_message or 'unknown error'}"
        )
    send_slack_message(
        webhook_url=config.slack_webhook_url,
        message=message,
        logger=LOGGER,
    )


def _send_attack_token_quarantine_slack_notification(
    *,
    config: AttackCLIConfig,
    event: Any,
) -> None:
    token_owner = getattr(event, "token_owner", None) or "unknown-owner"
    token_role = getattr(event, "token_role", "unknown-role")
    token_display = getattr(event, "token_display", "unknown-token")
    reason_code = getattr(event, "reason_code", "unknown-reason")
    repository_name = getattr(event, "repository_name", "unknown-repository")
    stage = getattr(event, "stage", "unknown-stage")
    failure_count = getattr(event, "failure_count", 0)
    reason = getattr(event, "reason", "unknown reason")
    message = (
        "pwnhunter quarantined a GitHub token during attack preparation.\n"
        f"Owner: {token_owner}\n"
        f"Role: {token_role}\n"
        f"Token: {token_display}\n"
        f"Reason code: {reason_code}\n"
        f"Failure count: {failure_count}\n"
        f"Repository: {repository_name}\n"
        f"Stage: {stage}\n"
        f"Reason: {reason}"
    )
    send_slack_message(
        webhook_url=config.slack_webhook_url,
        message=message,
        logger=LOGGER,
    )


def _send_attack_token_waiting_slack_notification(
    *,
    config: AttackCLIConfig,
    event: Any,
) -> None:
    status = str(getattr(event, "status", "") or "").strip().lower()
    if status != "waiting":
        return
    missing_roles = getattr(event, "missing_roles", ()) or ()
    if not isinstance(missing_roles, tuple):
        missing_roles = tuple(missing_roles)
    message = (
        "pwnhunter attack command is waiting for refreshed GitHub tokens.\n"
        f"Missing roles: {', '.join(missing_roles) or 'unknown'}\n"
        f"Available User A tokens: {getattr(event, 'user_a_count', 0)}\n"
        f"Available User B tokens: {getattr(event, 'user_b_count', 0)}\n"
        f"Trigger: {getattr(event, 'trigger', 'unknown')}\n"
        f"Output: {config.output_path}"
    )
    send_slack_message(
        webhook_url=config.slack_webhook_url,
        message=message,
        logger=LOGGER,
    )


def _load_existing_attack_repository_results(
    *, output_path: Path
) -> dict[str, dict[str, Any]]:
    if not output_path.exists() or not output_path.is_file():
        return {}
    try:
        existing_payload = _normalize_attack_input_payload(
            json.loads(output_path.read_text(encoding="utf-8"))
        )
    except OSError as exc:
        raise AttackResumeOutputError(
            f"Unable to read existing attack output at {output_path}: {exc}"
        ) from exc
    except json.JSONDecodeError as exc:
        raise AttackResumeOutputError(
            f"Existing attack output at {output_path} is invalid JSON and cannot be resumed: {exc}"
        ) from exc

    existing_repositories = _extract_attack_repositories_for_cli(existing_payload)
    existing_results: dict[str, dict[str, Any]] = {}
    for repository in existing_repositories:
        if not isinstance(repository, dict):
            continue
        repository_name = repository.get("name")
        if not isinstance(repository_name, str) or not repository_name.strip():
            continue
        existing_results[repository_name] = repository
    return existing_results


def _count_attack_repository_risks(repository: dict[str, Any]) -> int:
    risks = repository.get("risks")
    if not isinstance(risks, list):
        return 0
    return len(risks)


def _build_attack_repository_risk_limit_skip_result(
    *,
    repository: dict[str, Any],
    risk_count: int,
    max_risks: int,
) -> dict[str, Any]:
    output_repository = deepcopy(repository)
    note = (
        f"Skipped automatic attack execution because this repository has {risk_count} "
        f"risks, exceeding the per-repository limit of {max_risks}. Manual review is required."
    )
    output_repository["attack_skipped"] = True
    output_repository["attack_skip_reason"] = "too_many_risks_for_auto_execution"
    output_repository["manual_review_note"] = note
    output_repository["risk_count"] = risk_count

    risks = output_repository.get("risks")
    if not isinstance(risks, list):
        return output_repository
    for risk in risks:
        if not isinstance(risk, dict):
            continue
        attack_result = risk.get("attack_result")
        if not isinstance(attack_result, dict):
            attack_result = {}
        attack_result["status"] = "skipped_too_many_risks_for_manual_review"
        attack_result["reason"] = note
        attack_result["flagged_for_human_review"] = True
        attack_result["error_stage"] = "pre_execution_skip"
        attack_result["error_class"] = "too_many_risks_for_auto_execution"
        attack_result["failure_fingerprint"] = "too_many_risks_for_auto_execution"
        attack_result["risk_count"] = risk_count
        attack_result["max_auto_attack_risks"] = max_risks
        risk["attack_result"] = attack_result
        risk["attack_processed_time"] = _format_now_timestamp()
    return output_repository


def _backup_existing_attack_output(*, output_path: Path) -> Path | None:
    if not output_path.exists() or not output_path.is_file():
        return None
    timestamp = _format_backup_timestamp()
    suffix = output_path.suffix
    backup_name_base = (
        f"{output_path.stem}.{timestamp}{suffix}"
        if suffix
        else f"{output_path.name}.{timestamp}"
    )
    backup_path = output_path.with_name(backup_name_base)
    counter = 1
    while backup_path.exists():
        backup_name = (
            f"{output_path.stem}.{timestamp}.{counter}{suffix}"
            if suffix
            else f"{output_path.name}.{timestamp}.{counter}"
        )
        backup_path = output_path.with_name(backup_name)
        counter += 1
    shutil.copy2(output_path, backup_path)
    return backup_path


def _seed_run_level_learnings(*, service: Any, learning_file_path: Path | None) -> None:
    if learning_file_path is None:
        return
    artifacts_manager = getattr(service, "_artifacts", None)
    run_root = getattr(artifacts_manager, "run_root", None)
    if not isinstance(run_root, Path):
        LOGGER.warning(
            "Unable to seed learnings from %s because attack service run root is unavailable.",
            learning_file_path,
        )
        return
    seeded_path = run_root / "LEARNINGS.md"
    seeded_content = learning_file_path.read_text(encoding="utf-8")
    seeded_path.write_text(seeded_content, encoding="utf-8")
    LOGGER.info(
        "Seeded run-level learnings from %s to %s.",
        learning_file_path,
        seeded_path,
    )


def _run_attack_repository_with_worker_logging(
    *,
    repository_worker: Any,
    repository: dict[str, Any],
    service: Any,
    config: AttackCLIConfig,
    token_broker: Any,
    parallel_log_manager: AttackParallelLogManager,
    refresh_attack_tokens: Any,
) -> dict[str, Any] | None:
    repository_name = str(repository.get("name") or "unknown-repository")
    with parallel_log_manager.worker_scope(repository_name) as worker_id:
        if worker_id is not None:
            LOGGER.info(
                "Starting attack worker %s for repository %s.",
                worker_id,
                repository_name,
            )
        result = repository_worker(
            repository=repository,
            service=service,
            config=config,
            token_broker=token_broker,
            refresh_attack_tokens=refresh_attack_tokens,
        )
        if worker_id is not None:
            LOGGER.info(
                "Finished attack worker %s for repository %s (%s).",
                worker_id,
                repository_name,
                _summarize_repository_attack_statuses(result),
            )
        else:
            LOGGER.info(
                "Finished attack processing for repository %s (%s).",
                repository_name,
                _summarize_repository_attack_statuses(result),
            )
        return result


def _consume_repository_restart_request(
    *,
    token_broker: Any,
    repository_name: str,
) -> bool:
    consume_restart_request = getattr(
        token_broker, "consume_repository_restart_request", None
    )
    if not callable(consume_restart_request):
        return False
    return bool(consume_restart_request(repository_name))


def _extract_attack_repositories_for_cli(payload: dict[str, Any]) -> list[dict[str, Any]]:
    normalized_payload = _normalize_attack_input_payload(payload)
    return _extract_attack_repositories(normalized_payload)


def _build_attack_repository_error_result(
    *,
    repository: dict[str, Any],
    error: str,
    error_stage: str = "preparation",
) -> dict[str, Any]:
    output_repository = deepcopy(repository)
    output_repository["error"] = error
    status = (
        "execution_error"
        if error_stage == "execution"
        else "blocked_preparation_error"
    )
    error_class = (
        "runtime_execution_error"
        if error_stage == "execution"
        else "unknown_preparation_error"
    )
    failure_fingerprint = (
        "execution_runtime_error"
        if error_stage == "execution"
        else "preparation_runtime_error"
    )
    lowered_error = error.lower()
    if "argument list too long" in lowered_error and "gemini" in lowered_error:
        failure_fingerprint = "gemini_arg_too_long"
    risks = output_repository.get("risks")
    if not isinstance(risks, list):
        return output_repository
    for risk in risks:
        if not isinstance(risk, dict):
            continue
        attack_result = risk.get("attack_result")
        if not isinstance(attack_result, dict):
            attack_result = {}
        attack_result.setdefault("status", status)
        attack_result.setdefault("reason", f"Attack processing failed: {error}")
        attack_result.setdefault("error_stage", error_stage)
        attack_result.setdefault("error_class", error_class)
        attack_result.setdefault("failure_fingerprint", failure_fingerprint)
        risk["attack_result"] = attack_result
        risk["attack_processed_time"] = _format_now_timestamp()
    return output_repository


def _summarize_repository_attack_statuses(repository_result: dict[str, Any] | None) -> str:
    if not isinstance(repository_result, dict):
        return "no_repository_result"
    risks = repository_result.get("risks")
    if not isinstance(risks, list):
        return "no_risks"
    statuses: list[str] = []
    for risk in risks:
        if not isinstance(risk, dict):
            continue
        attack_result = risk.get("attack_result")
        status = (
            attack_result.get("status")
            if isinstance(attack_result, dict)
            else None
        )
        if isinstance(status, str) and status.strip():
            statuses.append(status.strip())
    if not statuses:
        return "risk_count=%s statuses=none" % len(risks)
    unique_statuses = sorted(set(statuses))
    return "risk_count=%s statuses=%s" % (len(risks), ",".join(unique_statuses))


def _prepare_and_execute_single_repository(
    *,
    repository: dict[str, Any],
    service: Any,
    config: AttackCLIConfig,
    token_broker: Any,
    refresh_attack_tokens: Any,
) -> dict[str, Any] | None:
    repository_name = str(repository.get("name") or "unknown-repository")
    attempt = 0
    while True:
        attempt += 1
        refresh_attack_tokens(trigger=f"repository_start:{repository_name}:attempt_{attempt}")
        LOGGER.info(
            "Preparing repository %s for attack execution (attempt=%s).",
            repository_name,
            attempt,
        )
        try:
            prepared_payload = service.run(
                {"ai_enumeration": [repository]},
                parallel_jobs=1,
            )
        except Exception as exc:
            if _consume_repository_restart_request(
                token_broker=token_broker,
                repository_name=repository_name,
            ):
                LOGGER.warning(
                    "Restarting repository %s after preparation failure because its leased token set changed.",
                    repository_name,
                )
                continue
            raise AttackRepositoryStageError("preparation", exc) from exc
        if _consume_repository_restart_request(
            token_broker=token_broker,
            repository_name=repository_name,
        ):
            LOGGER.warning(
                "Restarting repository %s because its preparation lease became invalid.",
                repository_name,
            )
            continue

        prepared_repositories = prepared_payload.get("ai_enumeration", [])
        if not prepared_repositories:
            LOGGER.warning(
                "Preparation produced no repository output for %s; skipping execution.",
                repository_name,
            )
            return None

        prepared_repository = prepared_repositories[0]
        LOGGER.info(
            "Preparation complete for %s (%s). Starting auto execution.",
            repository_name,
            _summarize_repository_attack_statuses(prepared_repository),
        )
        try:
            executed_payload = _run_auto_execute(
                {"ai_enumeration": [prepared_repository]},
                config,
                token_broker,
            )
        except Exception as exc:
            if _consume_repository_restart_request(
                token_broker=token_broker,
                repository_name=repository_name,
            ):
                LOGGER.warning(
                    "Restarting repository %s after execution failure because its leased token set changed.",
                    repository_name,
                )
                continue
            raise AttackRepositoryStageError("execution", exc) from exc
        if _consume_repository_restart_request(
            token_broker=token_broker,
            repository_name=repository_name,
        ):
            LOGGER.warning(
                "Restarting repository %s because its execution lease became invalid.",
                repository_name,
            )
            continue

        executed_repositories = executed_payload.get("ai_enumeration", [])
        if not executed_repositories:
            LOGGER.warning(
                "Auto execution produced no repository output for %s; keeping prepared repository result.",
                repository_name,
            )
            return prepared_repository
        LOGGER.info(
            "Auto execution complete for %s (%s).",
            repository_name,
            _summarize_repository_attack_statuses(executed_repositories[0]),
        )
        return executed_repositories[0]


def _prepare_single_repository(
    *,
    repository: dict[str, Any],
    service: Any,
    config: AttackCLIConfig,
    token_broker: Any,
    refresh_attack_tokens: Any,
) -> dict[str, Any] | None:
    _ = config
    repository_name = str(repository.get("name") or "unknown-repository")
    attempt = 0
    while True:
        attempt += 1
        refresh_attack_tokens(trigger=f"repository_start:{repository_name}:attempt_{attempt}")
        LOGGER.info(
            "Preparing repository %s for manual validation (attempt=%s).",
            repository_name,
            attempt,
        )
        try:
            prepared_payload = service.run(
                {"ai_enumeration": [repository]},
                parallel_jobs=1,
            )
        except Exception as exc:
            if _consume_repository_restart_request(
                token_broker=token_broker,
                repository_name=repository_name,
            ):
                LOGGER.warning(
                    "Restarting repository %s after preparation failure because its leased token set changed.",
                    repository_name,
                )
                continue
            raise AttackRepositoryStageError("preparation", exc) from exc
        if _consume_repository_restart_request(
            token_broker=token_broker,
            repository_name=repository_name,
        ):
            LOGGER.warning(
                "Restarting repository %s because its preparation lease became invalid.",
                repository_name,
            )
            continue
        prepared_repositories = prepared_payload.get("ai_enumeration", [])
        if not prepared_repositories:
            LOGGER.warning(
                "Preparation produced no repository output for %s.",
                repository_name,
            )
            return None
        LOGGER.info(
            "Preparation complete for %s (%s).",
            repository_name,
            _summarize_repository_attack_statuses(prepared_repositories[0]),
        )
        return prepared_repositories[0]


def _build_attack_output_payload(
    *,
    input_payload: dict[str, Any],
    repository_results: list[dict[str, Any] | None],
) -> dict[str, Any]:
    output_payload = deepcopy(input_payload)
    output_payload["timestamp"] = _format_now_timestamp()
    completed_repositories = [
        result for result in repository_results if result is not None
    ]
    refresh_payload = {"ai_enumeration": completed_repositories}
    _refresh_repo_vulnerable_fields(refresh_payload)
    completed_repositories = refresh_payload["ai_enumeration"]
    attack_input_source = str(output_payload.get("_attack_input_source") or "").strip()
    if attack_input_source == "gato-x":
        enumeration = output_payload.get("enumeration")
        if isinstance(enumeration, dict):
            enumeration["repositories"] = completed_repositories
        output_payload.pop("ai_enumeration", None)
    else:
        output_payload["ai_enumeration"] = completed_repositories
    output_payload.pop("_attack_input_source", None)
    return output_payload


def _write_attack_snapshot(
    *,
    output_path: Path,
    input_payload: dict[str, Any],
    repository_results: list[dict[str, Any] | None],
) -> dict[str, Any]:
    output_payload = _build_attack_output_payload(
        input_payload=input_payload,
        repository_results=repository_results,
    )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(output_payload, indent=2) + "\n",
        encoding="utf-8",
    )
    return output_payload


def _delete_repository_workspaces(repository_result: dict[str, Any]) -> None:
    seen_paths: set[Path] = set()
    for risk in repository_result.get("risks", []):
        attack_result = risk.get("attack_result") or {}
        workspace_path = attack_result.get("workspace_path")
        if not isinstance(workspace_path, str) or not workspace_path.strip():
            continue
        candidate = Path(workspace_path)
        if candidate in seen_paths:
            continue
        seen_paths.add(candidate)
        _delete_workspace_path(candidate)


def _delete_workspace_path(workspace_path: Path) -> None:
    if workspace_path.name != "workspace":
        LOGGER.warning(
            "Skipping workspace cleanup for unexpected path %s.", workspace_path
        )
        return
    if not workspace_path.exists():
        return
    if not workspace_path.is_dir():
        LOGGER.warning(
            "Skipping workspace cleanup because path is not a directory: %s.",
            workspace_path,
        )
        return
    delete_command = ["sudo", "-n", "rm", "-rf", str(workspace_path)]
    completed = subprocess.run(
        delete_command,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.returncode == 0:
        return
    stderr = completed.stderr.strip()
    stdout = completed.stdout.strip()
    details = stderr or stdout or f"exit_code={completed.returncode}"
    LOGGER.warning(
        "Failed to delete workspace path %s via `%s`: %s",
        workspace_path,
        " ".join(delete_command),
        details,
    )
    if workspace_path.exists():
        LOGGER.warning(
            "Workspace path still exists after cleanup attempt: %s.",
            workspace_path,
        )


def _run_auto_execute(
    output_payload: dict,
    config: AttackCLIConfig,
    token_broker,
) -> dict:
    return _run_auto_execute_impl(
        output_payload,
        config,
        token_broker,
        resolve_symbol=_resolve_symbol,
        build_agent_runtime=__build_agent_runtime,
        reserve_attack_lease=_reserve_attack_lease,
        extract_repo_owner=_extract_repo_owner,
        build_risk_trace_id=_build_risk_trace_id,
        build_human_review_precheck_runner=_build_human_review_precheck_runner,
        format_now_timestamp=_format_now_timestamp,
        refresh_repo_vulnerable_fields=_refresh_repo_vulnerable_fields,
        instantiate_with_supported_kwargs=_instantiate_with_supported_kwargs,
        token_probe_timeout_seconds=TOKEN_PROBE_TIMEOUT_SECONDS,
    )


def _extract_repo_owner(repo_name: Any) -> str | None:
    return _extract_repo_owner_impl(repo_name)


def _reserve_attack_lease(
    *,
    token_broker: Any,
    repository_name: str,
    expected_user_a_owner: str | None,
    expected_user_b_owner: str | None,
) -> Any:
    return _reserve_attack_lease_impl(
        token_broker=token_broker,
        repository_name=repository_name,
        expected_user_a_owner=expected_user_a_owner,
        expected_user_b_owner=expected_user_b_owner,
    )


def _refresh_repo_vulnerable_fields(payload: dict[str, Any]) -> None:
    _refresh_repo_vulnerable_fields_impl(payload)


def _derive_repo_vulnerable(repository: dict[str, Any]) -> str:
    return _derive_repo_vulnerable_impl(repository)


def _risk_is_vulnerable(risk: dict[str, Any]) -> bool:
    return _risk_is_vulnerable_impl(risk)


def _risk_needs_human_review(risk: dict[str, Any]) -> bool:
    return _risk_needs_human_review_impl(risk)


def _run_human_review_precheck(
    *,
    ai_analysis: Any,
    gemini_api_key: str | None,
    billing: str = "oauth",
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return _run_human_review_precheck_impl(
        ai_analysis=ai_analysis,
        gemini_api_key=gemini_api_key,
        billing=billing,
        metadata=metadata,
        resolve_symbol=_resolve_symbol,
        logger=LOGGER,
    )


def _build_human_review_precheck_runner(config: AttackCLIConfig):
    return _build_human_review_precheck_runner_impl(
        config=config,
        resolve_symbol=_resolve_symbol,
        logger=LOGGER,
    )


def _build_risk_trace_id(*, repo_name: str, risk: dict[str, Any]) -> str:
    return _build_risk_trace_id_impl(repo_name=repo_name, risk=risk)


def _start_human_review_precheck_trace(trace_id: str):
    return _start_human_review_precheck_trace_impl(trace_id)


def run_attack_cleanup(
    *,
    input_path: Path,
    github_token: str,
    delete_forks: bool,
    delete_artifacts: bool,
) -> dict:
    attack_cleanup_service_class = _resolve_symbol("AttackCleanupService")
    github_client_class = _resolve_symbol("GitHubClient")
    input_payload = json.loads(input_path.read_text(encoding="utf-8"))
    service = attack_cleanup_service_class(
        github_client_factory=lambda token: github_client_class(tokens=[token])
    )
    return service.run(
        input_payload,
        github_token=github_token,
        delete_forks=delete_forks,
        delete_artifacts=delete_artifacts,
    )


def run_pr_target_history(
    *,
    input_path: Path,
    output_path: Path,
    days: int,
    parallel_jobs: int,
    github_token: str,
) -> dict:
    load_repositories = _resolve_symbol("load_repositories_from_text_file")
    github_client_class = _resolve_symbol("GitHubClient")
    history_service_class = _resolve_symbol("PullRequestTargetHistoryService")
    write_results = _resolve_symbol("write_scan_results")

    repositories = load_repositories(input_path)
    github_client = github_client_class(tokens=split_csv_tokens(github_token))
    service = history_service_class(github_client)
    payload = service.scan_repositories(
        repositories, days=days, parallel_jobs=parallel_jobs
    )
    write_results(output_path, payload)
    return payload


def __build_agent_runtime(config: AttackCLIConfig):
    return _build_agent_runtime_impl(config)


def _instantiate_with_supported_kwargs(factory: Any, kwargs: dict[str, Any]) -> Any:
    try:
        signature = inspect.signature(factory)
    except (TypeError, ValueError):
        return factory(**kwargs)

    parameters = signature.parameters
    if any(
        parameter.kind == inspect.Parameter.VAR_KEYWORD
        for parameter in parameters.values()
    ):
        return factory(**kwargs)

    filtered_kwargs = {key: value for key, value in kwargs.items() if key in parameters}
    return factory(**filtered_kwargs)


if __name__ == "__main__":
    raise SystemExit(main())
