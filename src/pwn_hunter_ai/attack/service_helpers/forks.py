from __future__ import annotations

import re

from pwn_hunter_ai.github_client import GitHubApiError, GitHubClient


def build_fork_name_candidates(*, source_owner: str, repo_basename: str) -> list[str]:
    normalized_owner = re.sub(r"[^a-z0-9-]+", "-", source_owner.lower()).strip("-")
    if not normalized_owner:
        normalized_owner = "source"

    primary = repo_basename
    secondary = f"{repo_basename}-from-{normalized_owner}"
    candidates = [primary]
    if secondary != primary:
        candidates.append(secondary)
    for suffix in range(2, 101):
        candidates.append(f"{secondary}-{suffix}")
    return candidates


def _repo_exists(client: GitHubClient, repo_name: str) -> bool:
    try:
        client.get_repo_metadata(repo_name)
    except GitHubApiError as exc:
        if "404" in str(exc):
            return False
        raise
    return True


def _repo_parent_full_name(client: GitHubClient, repo_name: str) -> str | None:
    metadata = client.get_repo_metadata(repo_name)
    parent_full_name = metadata.get("parent_full_name")
    if not isinstance(parent_full_name, str) or not parent_full_name:
        return None
    return parent_full_name


__all__ = [
    "build_fork_name_candidates",
    "_repo_exists",
    "_repo_parent_full_name",
]
