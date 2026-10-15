from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any, Protocol


class AttackAgentProvider(str, Enum):
    OPENHANDS = "openhands"
    GEMINI_CLI = "gemini-cli"


@dataclass(frozen=True, slots=True)
class AttackAgentLaunchResult:
    status: str
    base_url: str | None
    pid: int | None
    command: list[str]
    metadata_path: Path
    tracing: dict[str, Any] | None = None


@dataclass(frozen=True, slots=True)
class AttackAgentHeadlessResult:
    status: str
    pid: int | None
    exit_code: int | None
    stdout_path: Path
    stderr_path: Path
    tracing: dict[str, Any] | None = None


class AttackAgentRuntime(Protocol):
    @property
    def provider_name(self) -> AttackAgentProvider:
        ...

    def launch(
        self,
        *,
        workspace_path: Path,
        prompt_path: Path,
        metadata_path: Path,
    ) -> AttackAgentLaunchResult:
        ...

    def run_headless(
        self,
        *,
        workspace_path: Path,
        prompt_path: Path,
        metadata_path: Path,
        timeout: int = 900,
        git_token: str | None = None,
        git_user_name: str | None = None,
        git_user_email: str | None = None,
    ) -> AttackAgentHeadlessResult:
        ...
