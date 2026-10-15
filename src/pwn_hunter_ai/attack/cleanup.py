from __future__ import annotations

from pathlib import Path
import shutil
from typing import Any, Callable

from pwn_hunter_ai.github_client import GitHubApiError, GitHubClient


GitHubClientFactory = Callable[[str], GitHubClient]


class AttackCleanupService:
    def __init__(self, *, github_client_factory: GitHubClientFactory) -> None:
        self._github_client_factory = github_client_factory

    def run(
        self,
        input_payload: dict[str, Any],
        *,
        github_token: str,
        delete_forks: bool,
        delete_artifacts: bool,
    ) -> dict[str, Any]:
        client = self._github_client_factory(github_token)
        deleted_forks: list[str] = []
        deleted_artifacts: list[str] = []

        for repository in input_payload.get("ai_enumeration", []):
            for risk in repository.get("risks", []):
                attack_result = risk.get("attack_result") or {}
                if delete_forks:
                    for key in ("user_b_fork", "user_a_fork"):
                        repo_name = attack_result.get(key)
                        if isinstance(repo_name, str) and repo_name and _repo_exists(client, repo_name):
                            client.delete_repo(repo_name)
                            deleted_forks.append(repo_name)
                if delete_artifacts:
                    artifact_root = attack_result.get("artifact_root")
                    if isinstance(artifact_root, str) and artifact_root:
                        path = Path(artifact_root)
                        if path.exists():
                            shutil.rmtree(path)
                            deleted_artifacts.append(str(path))

        return {
            "deleted_forks": deleted_forks,
            "deleted_artifacts": deleted_artifacts,
        }


def _repo_exists(client: GitHubClient, repo_name: str) -> bool:
    try:
        client.get_repo_metadata(repo_name)
    except GitHubApiError as exc:
        if "404" in str(exc):
            return False
        raise
    return True
