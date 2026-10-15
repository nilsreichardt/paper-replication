from __future__ import annotations

from typing import Any, Collection


def _normalize_repository_full_name(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    normalized = value.strip()
    if not normalized or "/" not in normalized:
        return None
    owner, repo = normalized.split("/", 1)
    owner = owner.strip()
    repo = repo.strip()
    if not owner or not repo:
        return None
    return f"{owner}/{repo}".casefold()


def _is_repository_skipped(
    repository_name: Any,
    *,
    skip_repositories: Collection[str],
) -> bool:
    normalized_repository_name = _normalize_repository_full_name(repository_name)
    if normalized_repository_name is None:
        return False
    if normalized_repository_name in skip_repositories:
        return True
    owner, _repo = normalized_repository_name.split("/", 1)
    return f"{owner}/*" in skip_repositories


def _extract_attack_repositories(
    payload: dict[str, Any],
    *,
    skip_repositories: Collection[str] | None = None,
) -> list[dict[str, Any]]:
    normalized_skip_repositories = {
        normalized_name
        for repository_name in (skip_repositories or ())
        if (normalized_name := _normalize_repository_full_name(repository_name))
        is not None
    }
    if "ai_enumeration" in payload:
        repositories = payload.get("ai_enumeration", [])
        if isinstance(repositories, list):
            return [
                repository
                for repository in repositories
                if not _is_repository_skipped(
                    repository.get("name"),
                    skip_repositories=normalized_skip_repositories,
                )
            ]
    if "enumeration" in payload:
        repositories = payload.get("enumeration", {}).get("repositories", [])
        if isinstance(repositories, list):
            return [
                repository
                for repository in repositories
                if not _is_repository_skipped(
                    repository.get("name"),
                    skip_repositories=normalized_skip_repositories,
                )
            ]
    return []
