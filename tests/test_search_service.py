from __future__ import annotations

import json
from pathlib import Path
from threading import Event
from threading import Lock
import time

import pytest

from pwn_hunter_ai.search.service import GitHubCodeSearchService


class FakeGitHubClient:
    def __init__(self) -> None:
        self.count_calls: list[str] = []
        self.search_calls: list[tuple[str, int]] = []

    def search_code_count(self, query: str) -> int:
        self.count_calls.append(query)
        counts = {
            "growing-results path:.github/workflows": 1_200,
            "growing-results path:.github/workflows size:0..5": 1_000,
            "growing-results path:.github/workflows size:6..10": 200,
            "growing-results path:.github/workflows size:0..2": 400,
            "growing-results path:.github/workflows size:3..5": 601,
            "growing-results path:.github/workflows size:3..4": 300,
            "growing-results path:.github/workflows size:5..5": 300,
        }
        return counts[query]

    def search_code(self, query: str, *, page: int, per_page: int = 100) -> dict[str, object]:
        del per_page
        self.search_calls.append((query, page))
        responses = {
            ("growing-results path:.github/workflows size:0..5", 1): (1_000, ["repo/root-a"] * 100),
            ("growing-results path:.github/workflows size:0..5", 2): (1_001, ["repo/root-b"] * 100),
            ("growing-results path:.github/workflows size:0..2", 1): (400, ["repo/left"] * 100),
            ("growing-results path:.github/workflows size:0..2", 2): (400, []),
            ("growing-results path:.github/workflows size:3..5", 1): (1_002, ["repo/mid-root"] * 100),
            ("growing-results path:.github/workflows size:3..4", 1): (300, ["repo/mid-left"] * 100),
            ("growing-results path:.github/workflows size:3..4", 2): (300, []),
            ("growing-results path:.github/workflows size:5..5", 1): (300, ["repo/mid-right"] * 100),
            ("growing-results path:.github/workflows size:5..5", 2): (300, []),
            ("growing-results path:.github/workflows size:6..10", 1): (200, ["repo/right"] * 100),
            ("growing-results path:.github/workflows size:6..10", 2): (200, []),
        }
        total_count, repositories = responses[(query, page)]
        return {
            "total_count": total_count,
            "items": [
                {
                    "repository": {
                        "full_name": repository,
                    }
                }
                for repository in repositories
            ],
        }


def test_collect_repositories_resplits_shards_when_total_count_grows_mid_pagination() -> None:
    github_client = FakeGitHubClient()
    service = GitHubCodeSearchService(github_client, max_file_size=10)

    repositories = service.collect_repositories("growing-results path:.github/workflows")

    assert repositories == [
        "repo/left",
        "repo/mid-left",
        "repo/mid-right",
        "repo/right",
        "repo/root-a",
    ]
    assert github_client.count_calls == [
        "growing-results path:.github/workflows",
        "growing-results path:.github/workflows size:0..5",
        "growing-results path:.github/workflows size:6..10",
        "growing-results path:.github/workflows size:0..2",
        "growing-results path:.github/workflows size:3..5",
        "growing-results path:.github/workflows size:3..4",
        "growing-results path:.github/workflows size:5..5",
    ]
    assert github_client.search_calls == [
        ("growing-results path:.github/workflows size:0..5", 1),
        ("growing-results path:.github/workflows size:0..5", 2),
        ("growing-results path:.github/workflows size:0..2", 1),
        ("growing-results path:.github/workflows size:0..2", 2),
        ("growing-results path:.github/workflows size:3..5", 1),
        ("growing-results path:.github/workflows size:3..4", 1),
        ("growing-results path:.github/workflows size:3..4", 2),
        ("growing-results path:.github/workflows size:5..5", 1),
        ("growing-results path:.github/workflows size:5..5", 2),
        ("growing-results path:.github/workflows size:6..10", 1),
        ("growing-results path:.github/workflows size:6..10", 2),
    ]


class FakeExactSizeGitHubClient:
    def __init__(self) -> None:
        self.search_calls: list[tuple[str, int]] = []

    def search_code_count(self, query: str) -> int:
        counts = {
            "exact-split path:.github/workflows": 1_200,
            "exact-split path:.github/workflows size:0..0": 1_200,
        }
        return counts[query]

    def search_code(self, query: str, *, page: int, per_page: int = 100) -> dict[str, object]:
        del per_page
        self.search_calls.append((query, page))
        responses = {
            ("exact-split path:.github/workflows size:0..0", 1): (1_200, ["repo/exact"] * 100),
            ("exact-split path:.github/workflows size:0..0", 2): (1_200, []),
        }
        total_count, repositories = responses[(query, page)]
        return {
            "total_count": total_count,
            "items": [
                {
                    "repository": {
                        "full_name": repository,
                    }
                }
                for repository in repositories
            ],
        }


def test_collect_repositories_accepts_exact_size_shard_above_limit() -> None:
    github_client = FakeExactSizeGitHubClient()
    service = GitHubCodeSearchService(github_client, max_file_size=0)

    repositories = service.collect_repositories("exact-split path:.github/workflows")

    assert repositories == [
        "repo/exact",
    ]
    assert github_client.search_calls == [
        ("exact-split path:.github/workflows size:0..0", 1),
        ("exact-split path:.github/workflows size:0..0", 2),
    ]


class FakeBruteForceGitHubClient:
    def __init__(self) -> None:
        self.search_calls: list[tuple[str, int]] = []

    def search_code_count(self, query: str) -> int:
        raise AssertionError(f"search_code_count should not be called in brute-force mode: {query}")

    def search_code(self, query: str, *, page: int, per_page: int = 100) -> dict[str, object]:
        del per_page
        self.search_calls.append((query, page))
        responses = {
            ("brute-force path:.github/workflows size:2..2", 1): (1, ["repo/two"]),
            ("brute-force path:.github/workflows size:3..3", 1): (0, []),
            ("brute-force path:.github/workflows size:4..4", 1): (2, ["repo/four-a", "repo/four-b"]),
        }
        total_count, repositories = responses[(query, page)]
        return {
            "total_count": total_count,
            "items": [
                {
                    "repository": {
                        "full_name": repository,
                    }
                }
                for repository in repositories
            ],
        }


def test_collect_repositories_can_bruteforce_file_sizes() -> None:
    github_client = FakeBruteForceGitHubClient()
    service = GitHubCodeSearchService(
        github_client,
        min_file_size=2,
        max_file_size=4,
        brute_force=True,
    )

    repositories = service.collect_repositories("brute-force path:.github/workflows")

    assert repositories == [
        "repo/four-a",
        "repo/four-b",
        "repo/two",
    ]
    assert github_client.search_calls == [
        ("brute-force path:.github/workflows size:2..2", 1),
        ("brute-force path:.github/workflows size:3..3", 1),
        ("brute-force path:.github/workflows size:4..4", 1),
    ]


class CrashOnceGitHubClient:
    def __init__(self) -> None:
        self.count_calls: list[str] = []
        self.search_calls: list[tuple[str, int]] = []
        self._crashed = False

    def search_code_count(self, query: str) -> int:
        self.count_calls.append(query)
        counts = {
            "resume-me path:.github/workflows": 1_200,
            "resume-me path:.github/workflows size:0..5": 600,
            "resume-me path:.github/workflows size:6..10": 600,
        }
        return counts[query]

    def search_code(self, query: str, *, page: int, per_page: int = 100) -> dict[str, object]:
        del per_page
        self.search_calls.append((query, page))
        if query == "resume-me path:.github/workflows size:0..5" and page == 2 and not self._crashed:
            self._crashed = True
            raise RuntimeError("boom")

        responses = {
            ("resume-me path:.github/workflows size:0..5", 1): (600, ["repo/alpha"] * 100),
            ("resume-me path:.github/workflows size:0..5", 2): (600, []),
            ("resume-me path:.github/workflows size:6..10", 1): (600, ["repo/beta"] * 100),
            ("resume-me path:.github/workflows size:6..10", 2): (600, []),
        }
        total_count, repositories = responses[(query, page)]
        return {
            "total_count": total_count,
            "items": [
                {
                    "repository": {
                        "full_name": repository,
                    }
                }
                for repository in repositories
            ],
        }


def test_collect_repositories_can_resume_from_snapshot_after_crash(tmp_path: Path) -> None:
    snapshot_path = tmp_path / "search.snapshot.json"
    github_client = CrashOnceGitHubClient()
    service = GitHubCodeSearchService(github_client, max_file_size=10)

    with pytest.raises(RuntimeError, match="boom"):
        service.collect_repositories(
            "resume-me path:.github/workflows",
            snapshot_path=snapshot_path,
        )

    snapshot_payload = json.loads(snapshot_path.read_text(encoding="utf-8"))
    assert snapshot_payload["query"] == "resume-me path:.github/workflows"
    assert snapshot_payload["min_file_size"] == 0
    assert snapshot_payload["repositories"] == ["repo/alpha"]
    assert snapshot_payload["max_results_per_shard"] == 1000
    assert snapshot_payload["brute_force"] is False
    assert snapshot_payload["current_shard"]["lower"] == 0
    assert snapshot_payload["current_shard"]["upper"] == 5
    assert snapshot_payload["next_page"] == 2

    resumed_service = GitHubCodeSearchService(github_client, max_file_size=10)
    repositories = resumed_service.collect_repositories(
        None,
        snapshot_path=snapshot_path,
        resume_snapshot_path=snapshot_path,
    )

    assert repositories == [
        "repo/alpha",
        "repo/beta",
    ]
    assert not snapshot_path.exists()
    assert github_client.count_calls == [
        "resume-me path:.github/workflows",
        "resume-me path:.github/workflows size:0..5",
        "resume-me path:.github/workflows size:6..10",
    ]
    assert github_client.search_calls == [
        ("resume-me path:.github/workflows size:0..5", 1),
        ("resume-me path:.github/workflows size:0..5", 2),
        ("resume-me path:.github/workflows size:0..5", 2),
        ("resume-me path:.github/workflows size:6..10", 1),
        ("resume-me path:.github/workflows size:6..10", 2),
    ]


class ParallelShardGitHubClient:
    def __init__(self) -> None:
        self._active_searches = 0
        self._active_lock = Lock()
        self.max_concurrent_searches = 0

    def search_code_count(self, query: str) -> int:
        counts = {
            "parallel-test path:.github/workflows": 1_200,
            "parallel-test path:.github/workflows size:0..5": 600,
            "parallel-test path:.github/workflows size:6..10": 600,
        }
        return counts[query]

    def search_code(self, query: str, *, page: int, per_page: int = 100) -> dict[str, object]:
        del per_page
        with self._active_lock:
            self._active_searches += 1
            self.max_concurrent_searches = max(self.max_concurrent_searches, self._active_searches)
        try:
            time.sleep(0.05)
            responses = {
                ("parallel-test path:.github/workflows size:0..5", 1): (600, ["repo/alpha"] * 100),
                ("parallel-test path:.github/workflows size:0..5", 2): (600, []),
                ("parallel-test path:.github/workflows size:6..10", 1): (600, ["repo/beta"] * 100),
                ("parallel-test path:.github/workflows size:6..10", 2): (600, []),
            }
            total_count, repositories = responses[(query, page)]
            return {
                "total_count": total_count,
                "items": [
                    {
                        "repository": {
                            "full_name": repository,
                        }
                    }
                    for repository in repositories
                ],
            }
        finally:
            with self._active_lock:
                self._active_searches -= 1


def test_collect_repositories_can_fetch_shards_in_parallel() -> None:
    github_client = ParallelShardGitHubClient()
    service = GitHubCodeSearchService(github_client, max_file_size=10)

    repositories = service.collect_repositories(
        "parallel-test path:.github/workflows",
        parallel_jobs=2,
    )

    assert repositories == [
        "repo/alpha",
        "repo/beta",
    ]
    assert github_client.max_concurrent_searches >= 2


class CoordinatedParallelShardGitHubClient:
    def __init__(self) -> None:
        self._lock = Lock()
        self.started_queries: list[str] = []
        self.max_concurrent_searches = 0
        self._active_searches = 0
        self._release = Event()

    def search_code_count(self, query: str) -> int:
        counts = {
            "parallel-coordinated path:.github/workflows": 1_200,
            "parallel-coordinated path:.github/workflows size:0..5": 600,
            "parallel-coordinated path:.github/workflows size:6..10": 600,
        }
        return counts[query]

    def search_code(self, query: str, *, page: int, per_page: int = 100) -> dict[str, object]:
        del per_page
        with self._lock:
            self.started_queries.append(f"{query}#{page}")
            self._active_searches += 1
            self.max_concurrent_searches = max(self.max_concurrent_searches, self._active_searches)
            if len(self.started_queries) >= 2:
                self._release.set()
        self._release.wait(timeout=1.0)
        try:
            responses = {
                ("parallel-coordinated path:.github/workflows size:0..5", 1): (600, ["repo/alpha"] * 100),
                ("parallel-coordinated path:.github/workflows size:0..5", 2): (600, []),
                ("parallel-coordinated path:.github/workflows size:6..10", 1): (600, ["repo/beta"] * 100),
                ("parallel-coordinated path:.github/workflows size:6..10", 2): (600, []),
            }
            total_count, repositories = responses[(query, page)]
            return {
                "total_count": total_count,
                "items": [
                    {
                        "repository": {
                            "full_name": repository,
                        }
                    }
                    for repository in repositories
                ],
            }
        finally:
            with self._lock:
                self._active_searches -= 1


def test_collect_repositories_starts_multiple_workers_before_first_completion() -> None:
    github_client = CoordinatedParallelShardGitHubClient()
    service = GitHubCodeSearchService(github_client, max_file_size=10)

    repositories = service.collect_repositories(
        "parallel-coordinated path:.github/workflows",
        parallel_jobs=2,
    )

    assert repositories == [
        "repo/alpha",
        "repo/beta",
    ]
    assert github_client.started_queries[:2] == [
        "parallel-coordinated path:.github/workflows size:0..5#1",
        "parallel-coordinated path:.github/workflows size:6..10#1",
    ]
    assert github_client.max_concurrent_searches >= 2
