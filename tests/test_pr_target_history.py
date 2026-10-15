from __future__ import annotations

from pathlib import Path

import pytest

from pwn_hunter_ai.pr_target_history import (
    PullRequestTargetHistoryService,
    load_repositories_from_text_file,
)


class FakeHistoryGitHubClient:
    def __init__(self) -> None:
        self.contents = {
            ("owner/repo", ".github/workflows/test.yml", "parent-1"): (
                "on:\n  pull_request_target:\n"
            ),
            ("owner/repo", ".github/workflows/test.yml", "commit-1"): (
                "on:\n  pull_request:\n"
            ),
            ("owner/repo", ".github/workflows/deleted.yml", "parent-2"): (
                "on:\n  pull_request_target:\n"
            ),
        }

    def list_commits(
        self,
        repo_name: str,
        *,
        since: str | None = None,
        until: str | None = None,
        page: int = 1,
        per_page: int = 100,
    ) -> list[dict]:
        if page > 1:
            return []
        return [{"sha": "commit-1"}, {"sha": "commit-2"}]

    def get_commit(self, repo_name: str, ref: str) -> dict:
        if ref == "commit-1":
            return {
                "sha": "commit-1",
                "html_url": "https://github.com/owner/repo/commit/commit-1",
                "commit": {"committer": {"date": "2026-03-07T10:00:00Z"}},
                "parents": [{"sha": "parent-1"}],
                "files": [
                    {
                        "filename": ".github/workflows/test.yml",
                        "status": "modified",
                        "patch": "@@ -1 +1 @@\n-  pull_request_target:\n+  pull_request:\n",
                    }
                ],
            }
        return {
            "sha": "commit-2",
            "html_url": "https://github.com/owner/repo/commit/commit-2",
            "commit": {"committer": {"date": "2026-03-07T11:00:00Z"}},
            "parents": [{"sha": "parent-2"}],
            "files": [
                {
                    "filename": ".github/workflows/deleted.yml",
                    "status": "removed",
                }
            ],
        }

    def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
        return self.contents.get((repo_name, path, ref), "")


def test_history_service_reports_removal_commits() -> None:
    service = PullRequestTargetHistoryService(FakeHistoryGitHubClient())

    payload = service.scan_repositories(["owner/repo"], days=7)

    results = payload["results"]
    assert len(results) == 1
    assert results[0]["commits_scanned"] == 2
    assert [item["sha"] for item in results[0]["removal_commits"]] == [
        "commit-1",
        "commit-2",
    ]
    assert results[0]["removal_commits"][0]["url"].endswith("/commit/commit-1")
    assert results[0]["removal_commits"][1]["workflow_file"] == (
        ".github/workflows/deleted.yml"
    )


def test_load_repositories_from_text_file_deduplicates_and_skips_comments(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "repos.txt"
    input_path.write_text(
        "\n".join(
            [
                "# comment",
                "owner/repo",
                "",
                "owner/repo",
                "other/repo",
            ]
        ),
        encoding="utf-8",
    )

    repositories = load_repositories_from_text_file(input_path)

    assert repositories == ["owner/repo", "other/repo"]


def test_history_service_rejects_invalid_parallel_jobs() -> None:
    service = PullRequestTargetHistoryService(FakeHistoryGitHubClient())

    with pytest.raises(ValueError, match="parallel_jobs must be at least 1"):
        service.scan_repositories(["owner/repo"], days=7, parallel_jobs=0)
