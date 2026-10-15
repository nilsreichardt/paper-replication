from __future__ import annotations

from importlib import import_module
from typing import Any

__all__ = [
    "AttackArtifactsManager",
    "AttackCleanupService",
    "AttackExecutionService",
    "AttackPreparationService",
    "AttackTokenBroker",
    "AttackTokenLease",
    "HookbinClient",
    "OpenHandsHeadlessResult",
    "OpenHandsLaunchManager",
    "OpenHandsLaunchResult",
    "OpenHandsTracingConfig",
    "RepositorySandbox",
    "RepositoryArtifactBundle",
    "SandboxManager",
    "build_dummy_secret_value",
    "collect_workflow_secrets",
    "extract_secret_names",
    "GitHubTokenProbeService",
]

_EXPORT_MAP = {
    "AttackArtifactsManager": "pwn_hunter_ai.attack.artifacts",
    "RepositoryArtifactBundle": "pwn_hunter_ai.attack.artifacts",
    "AttackCleanupService": "pwn_hunter_ai.attack.cleanup",
    "AttackExecutionService": "pwn_hunter_ai.attack.execution_service",
    "HookbinClient": "pwn_hunter_ai.attack.hookbin_client",
    "OpenHandsHeadlessResult": "pwn_hunter_ai.attack.openhands_manager",
    "OpenHandsLaunchManager": "pwn_hunter_ai.attack.openhands_manager",
    "OpenHandsLaunchResult": "pwn_hunter_ai.attack.openhands_manager",
    "OpenHandsTracingConfig": "pwn_hunter_ai.attack.openhands_manager",
    "RepositorySandbox": "pwn_hunter_ai.attack.sandbox_manager",
    "SandboxManager": "pwn_hunter_ai.attack.sandbox_manager",
    "AttackPreparationService": "pwn_hunter_ai.attack.service",
    "AttackTokenBroker": "pwn_hunter_ai.attack.tokens",
    "AttackTokenLease": "pwn_hunter_ai.attack.tokens",
    "GitHubTokenProbeService": "pwn_hunter_ai.attack.github_token_probe",
    "build_dummy_secret_value": "pwn_hunter_ai.attack.workflow_secrets",
    "collect_workflow_secrets": "pwn_hunter_ai.attack.workflow_secrets",
    "extract_secret_names": "pwn_hunter_ai.attack.workflow_secrets",
}


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MAP.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")

    module = import_module(module_name)
    value = getattr(module, name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(list(globals().keys()) + __all__)
