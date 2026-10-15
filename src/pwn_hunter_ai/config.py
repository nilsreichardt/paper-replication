from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import os


@dataclass(slots=True)
class CLIConfig:
    input_path: Path
    output_path: Path
    failure_output_path: Path
    parallel_jobs: int
    github_token: str | None
    gemini_api_key: str | None
    gemini_batch: bool
    langfuse_public_key: str | None
    langfuse_secret_key: str | None
    langfuse_host: str | None
    output_only_vulnerable: bool
    log_file: Path
    log_level: str
    verbose: bool


@dataclass(slots=True)
class AttackCLIConfig:
    input_path: Path
    output_path: Path
    artifacts_dir: Path
    parallel_jobs: int
    max_retries: int
    github_tokens_user_a: str | None
    github_tokens_user_b: str | None
    reset_forks: bool
    dry_run: bool
    launch_agent: bool
    auto_execute: bool
    agent_timeout: int
    workflow_timeout: int
    openhands_host: str
    openhands_start_port: int
    langfuse_public_key: str | None
    langfuse_secret_key: str | None
    langfuse_host: str | None
    log_file: Path
    log_level: str
    verbose: bool
    skip_repositories: tuple[str, ...] = ()
    skip_permission_log_read: bool = False
    gemini_api_key: str | None = None
    no_sandbox: bool = False
    delete_workspace_after_processing: bool = False
    agent_provider: str = "gemini-cli"
    agent_model: str | None = "gemini-3-flash-preview"
    user_b_token_concurrency: int = 1
    learning_file_path: Path | None = None
    slack_webhook_url: str | None = None
    billing: str = "oauth"
    generate_security_report: bool = False
    github_tokens_user_a_source: str = "static"
    github_tokens_user_b_source: str = "static"
    env_file_path: Path | None = None
    token_refresh_interval_seconds: int = 600


def load_env_file(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}

    result: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        result[key.strip()] = value.strip().strip('"').strip("'")
    return result


def env_value(name: str, env_file_values: dict[str, str]) -> str | None:
    return os.environ.get(name) or env_file_values.get(name)


def split_csv_tokens(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []
    return [token.strip() for token in raw_value.split(",") if token.strip()]
