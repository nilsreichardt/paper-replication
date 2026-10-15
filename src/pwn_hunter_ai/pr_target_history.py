from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
import json
import logging
from pathlib import Path
from typing import Any

from pwn_hunter_ai.github_client import GitHubApiError, GitHubClient


LOGGER = logging.getLogger(__name__)
PULL_REQUEST_TARGET = "pull_request_target"
WORKFLOW_DIRECTORY = ".github/workflows/"


@dataclass(slots=True)
class RemovalCommit:
    sha: str
    url: str
    committed_at: str | None
    workflow_file: str
    change_type: str


@dataclass(slots=True)
class RepoScanResult:
    repository: str
    commits_scanned: int
    removal_commits: list[RemovalCommit]
    error: str | None = None


class PullRequestTargetHistoryService:
    def __init__(self, github_client: GitHubClient) -> None:
        self._github_client = github_client

    def scan_repositories(
        self,
        repositories: list[str],
        *,
        days: int,
        parallel_jobs: int = 1,
        until: datetime | None = None,
    ) -> dict[str, Any]:
        effective_until = until or datetime.now(timezone.utc)
        since = effective_until - timedelta(days=days)

        if parallel_jobs < 1:
            raise ValueError("parallel_jobs must be at least 1.")

        if parallel_jobs == 1:
            results = [
                self.scan_repository(
                    repository,
                    since=since,
                    until=effective_until,
                )
                for repository in repositories
            ]
        else:
            with ThreadPoolExecutor(max_workers=parallel_jobs) as executor:
                results = list(
                    executor.map(
                        lambda repository: self.scan_repository(
                            repository,
                            since=since,
                            until=effective_until,
                        ),
                        repositories,
                    )
                )

        return {
            "generated_at": effective_until.isoformat(),
            "days": days,
            "since": since.isoformat(),
            "until": effective_until.isoformat(),
            "repositories_scanned": len(repositories),
            "repositories_with_removals": sum(
                1 for result in results if result.removal_commits
            ),
            "results": [
                {
                    **asdict(result),
                    "removal_commits": [
                        asdict(removal_commit)
                        for removal_commit in result.removal_commits
                    ],
                }
                for result in results
            ],
        }

    def scan_repository(
        self,
        repository: str,
        *,
        since: datetime,
        until: datetime,
    ) -> RepoScanResult:
        LOGGER.info(
            "Scanning %s for workflow changes between %s and %s.",
            repository,
            since.isoformat(),
            until.isoformat(),
        )

        try:
            commits = self._list_all_commits(
                repository,
                since=since.isoformat(),
                until=until.isoformat(),
            )
            removals: list[RemovalCommit] = []
            for commit_summary in commits:
                commit_sha = commit_summary.get("sha")
                if not isinstance(commit_sha, str) or not commit_sha:
                    continue
                commit_details = self._github_client.get_commit(repository, commit_sha)
                removals.extend(
                    self._find_removals_in_commit(repository, commit_details)
                )

            return RepoScanResult(
                repository=repository,
                commits_scanned=len(commits),
                removal_commits=removals,
            )
        except GitHubApiError as exc:
            LOGGER.error("GitHub API error while scanning %s: %s", repository, exc)
            return RepoScanResult(
                repository=repository,
                commits_scanned=0,
                removal_commits=[],
                error=str(exc),
            )

    def _list_all_commits(
        self,
        repository: str,
        *,
        since: str,
        until: str,
    ) -> list[dict[str, Any]]:
        commits: list[dict[str, Any]] = []
        page = 1
        while True:
            page_items = self._github_client.list_commits(
                repository,
                since=since,
                until=until,
                page=page,
                per_page=100,
            )
            if not page_items:
                return commits
            commits.extend(page_items)
            if len(page_items) < 100:
                return commits
            page += 1

    def _find_removals_in_commit(
        self,
        repository: str,
        commit_details: dict[str, Any],
    ) -> list[RemovalCommit]:
        sha = commit_details.get("sha")
        if not isinstance(sha, str) or not sha:
            return []

        html_url = commit_details.get("html_url")
        committed_at = (
            ((commit_details.get("commit") or {}).get("committer") or {}).get("date")
        )
        parents = commit_details.get("parents") or []
        parent_sha = parents[0].get("sha") if parents else None
        files = commit_details.get("files") or []

        removals: list[RemovalCommit] = []
        for file_entry in files:
            path = file_entry.get("filename")
            if not self._is_workflow_path(path):
                continue
            if self._pull_request_target_removed(repository, file_entry, sha, parent_sha):
                removals.append(
                    RemovalCommit(
                        sha=sha,
                        url=html_url if isinstance(html_url, str) else "",
                        committed_at=committed_at
                        if isinstance(committed_at, str)
                        else None,
                        workflow_file=path,
                        change_type=str(file_entry.get("status") or "modified"),
                    )
                )

        return removals

    def _pull_request_target_removed(
        self,
        repository: str,
        file_entry: dict[str, Any],
        current_sha: str,
        parent_sha: str | None,
    ) -> bool:
        current_path = file_entry.get("filename")
        if not isinstance(current_path, str) or not current_path:
            return False

        patch = file_entry.get("patch")
        if isinstance(patch, str) and _patch_removes_pull_request_target(patch):
            return True

        if not parent_sha:
            return False

        previous_path = current_path
        if file_entry.get("status") == "renamed":
            rename_source = file_entry.get("previous_filename")
            if isinstance(rename_source, str) and rename_source:
                previous_path = rename_source

        before = self._read_file_if_present(repository, previous_path, parent_sha)
        if PULL_REQUEST_TARGET not in before:
            return False

        status = file_entry.get("status")
        if status == "removed":
            return True

        after = self._read_file_if_present(repository, current_path, current_sha)
        return PULL_REQUEST_TARGET in before and PULL_REQUEST_TARGET not in after

    def _read_file_if_present(self, repository: str, path: str, ref: str) -> str:
        try:
            return self._github_client.get_file_content(repository, path, ref)
        except GitHubApiError:
            return ""

    @staticmethod
    def _is_workflow_path(path: Any) -> bool:
        return isinstance(path, str) and path.startswith(WORKFLOW_DIRECTORY)


def load_repositories_from_text_file(path: Path) -> list[str]:
    repositories: list[str] = []
    seen: set[str] = set()
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        repository = raw_line.strip()
        if not repository or repository.startswith("#"):
            continue
        if repository in seen:
            continue
        seen.add(repository)
        repositories.append(repository)
    return repositories


def write_scan_results(output_path: Path, payload: dict[str, Any]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _patch_removes_pull_request_target(patch: str) -> bool:
    return any(
        line.startswith("-") and not line.startswith("---") and PULL_REQUEST_TARGET in line
        for line in patch.splitlines()
    )
