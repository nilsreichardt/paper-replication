from __future__ import annotations

import json
from pathlib import Path
import subprocess
from typing import Any

import pytest

import pwn_hunter_ai.cli as cli_module
from pwn_hunter_ai.attack.artifacts import AttackArtifactsManager
from pwn_hunter_ai.attack.tokens import AttackTokenQuarantineEvent
from pwn_hunter_ai.cli import _delete_repository_workspaces, _run_auto_execute, main
from pwn_hunter_ai.config import AttackCLIConfig
from pwn_hunter_ai.github_client import GitHubApiError
from pwn_hunter_ai.models import AiAnalysis
import pwn_hunter_ai.slack_notifications as slack_notifications


class FakeGitHubClient:
    def __init__(self, tokens: list[str] | None = None) -> None:
        self.tokens = tokens or []

    def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
        return {
            "name": repo_name,
            "created_at": "2022-01-01T00:00:00Z",
            "default_branch": "main",
        }

    def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
        return f"name: CI\n# {repo_name}@{ref}:{path}\n"

    def list_directory(self, repo_name: str, path: str, ref: str) -> list[dict[str, str]]:
        return []

    def search_code_count(self, query: str) -> int:
        counts = {
            "pull_request_target path:.github/workflows language:yaml": 3,
            "many-results path:.github/workflows": 1200,
            "many-results path:.github/workflows size:0..5": 700,
            "many-results path:.github/workflows size:6..10": 500,
            "many-results path:.github/workflows size:2..2": 1,
            "many-results path:.github/workflows size:3..3": 0,
            "many-results path:.github/workflows size:4..4": 2,
            "already-sized size:1..10": 1201,
            "exact-sized size:7..7": 1201,
        }
        return counts[query]

    def search_code(self, query: str, *, page: int, per_page: int = 100) -> dict[str, object]:
        responses = {
            ("pull_request_target path:.github/workflows language:yaml", 1): [
                "Grow-with-Open-Source/Python-Projects",
                "AstroNvim/astrocore",
                "Grow-with-Open-Source/Python-Projects",
            ],
            ("many-results path:.github/workflows", 1): [],
            ("many-results path:.github/workflows size:0..5", 1): [
                "repo/alpha",
                "repo/beta",
            ],
            ("many-results path:.github/workflows size:0..5", 2): [],
            ("many-results path:.github/workflows size:0..5", 3): [],
            ("many-results path:.github/workflows size:0..5", 4): [],
            ("many-results path:.github/workflows size:0..5", 5): [],
            ("many-results path:.github/workflows size:0..5", 6): [],
            ("many-results path:.github/workflows size:0..5", 7): [],
            ("many-results path:.github/workflows size:6..10", 1): [
                "repo/beta",
                "repo/gamma",
            ],
            ("many-results path:.github/workflows size:6..10", 2): [],
            ("many-results path:.github/workflows size:6..10", 3): [],
            ("many-results path:.github/workflows size:6..10", 4): [],
            ("many-results path:.github/workflows size:6..10", 5): [],
            ("many-results path:.github/workflows size:2..2", 1): [
                "repo/min-two",
            ],
            ("many-results path:.github/workflows size:3..3", 1): [],
            ("many-results path:.github/workflows size:4..4", 1): [
                "repo/min-four-a",
                "repo/min-four-b",
            ],
            ("exact-sized size:7..7", 1): [
                "repo/exact",
            ],
            ("exact-sized size:7..7", 2): [],
        }
        repositories = responses[(query, page)]
        return {
            "total_count": 1201 if query == "exact-sized size:7..7" else len(repositories),
            "items": [
                {
                    "repository": {
                        "full_name": repository,
                    }
                }
                for repository in repositories
            ]
        }


class FakeGeminiAnalyzer:
    def __init__(self, api_key: str, **kwargs) -> None:
        self.api_key = api_key

    def analyze_prompt(self, prompt: str, *, metadata=None) -> AiAnalysis:
        vulnerable = "true-risk" in prompt
        return AiAnalysis(
            vulnerable=vulnerable,
            confidence="high",
            explanation="vulnerable" if vulnerable else "safe",
            impact="impact" if vulnerable else "none",
            poc="poc" if vulnerable else "",
        )

    def analyze_prompts_batch(self, requests: list) -> list[AiAnalysis]:
        return [
            self.analyze_prompt(request.prompt, metadata=request.metadata)
            for request in requests
        ]


class FakeFailingGeminiAnalyzer(FakeGeminiAnalyzer):
    def analyze_prompt(self, prompt: str, *, metadata=None) -> AiAnalysis:
        if "bad-risk" in prompt:
            raise ValueError("invalid structured output")
        return super().analyze_prompt(prompt, metadata=metadata)


class FakeMissingRepoGitHubClient(FakeGitHubClient):
    def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
        if repo_name == "repo/missing":
            raise GitHubApiError(
                f"GitHub API request failed for /repos/{repo_name}: 404 Not Found"
            )
        return super().get_repo_metadata(repo_name)


class FakeTracer:
    def flush(self) -> None:
        return None


class FakeAttackGitHubClient:
    repos = {
        "owner/repo": {
            "name": "owner/repo",
            "created_at": "2024-01-01T00:00:00Z",
            "default_branch": "main",
            "parent_full_name": "",
        }
    }

    def __init__(self, tokens: list[str] | None = None) -> None:
        token = (tokens or [""])[0]
        self.login = "user-a" if token == "token-a" else "user-b"

    def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
        if repo_name not in self.repos:
            raise GitHubApiError(f"GitHub API request failed for /repos/{repo_name}: 404 Not Found")
        return self.repos[repo_name]

    def get_branch_head_sha(self, repo_name: str, branch: str) -> str:
        return "cafebabe"

    def get_commit(self, repo_name: str, ref: str) -> dict[str, object]:
        _ = (repo_name, ref)
        return {
            "sha": "cafebabe",
            "commit": {"committer": {"date": "2024-01-03T04:05:06Z"}},
        }

    def get_authenticated_user(self) -> dict[str, str]:
        return {"login": self.login}

    def create_fork(self, repo_name: str, name: str | None = None) -> dict[str, str]:
        repo_name_part = name.strip() if isinstance(name, str) and name.strip() else repo_name.split("/", 1)[1]
        fork_name = f"{self.login}/{repo_name_part}"
        self.repos[fork_name] = {
            "name": fork_name,
            "created_at": "2024-01-01T00:00:00Z",
            "default_branch": "main",
            "parent_full_name": repo_name,
        }
        return {"full_name": fork_name}

    def delete_repo(self, repo_name: str) -> None:
        self.repos.pop(repo_name, None)

    def enable_actions(self, repo_name: str, *, enabled: bool = True) -> None:
        return None

    def list_directory(self, repo_name: str, path: str, ref: str) -> list[dict[str, str]]:
        return [{"type": "file", "path": ".github/workflows/pull_request.yml"}]

    def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
        return "steps:\n  - run: echo ${{ secrets.TEST_SECRET }}\n"

    def set_actions_secret(self, repo_name: str, name: str, value: str) -> None:
        return None

    def get_workflow_runs(self, repo_name: str, per_page: int = 100, page: int = 1) -> dict:
        _ = (repo_name, per_page, page)
        return {"workflow_runs": []}

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        _ = (repo_name, run_id)
        return b""


class FakeHistoryCliGitHubClient:
    def __init__(self, tokens: list[str] | None = None) -> None:
        self.tokens = tokens or []

    def list_commits(
        self,
        repo_name: str,
        *,
        since: str | None = None,
        until: str | None = None,
        page: int = 1,
        per_page: int = 100,
    ) -> list[dict]:
        return [{"sha": "abc123"}] if page == 1 else []

    def get_commit(self, repo_name: str, ref: str) -> dict:
        return {
            "sha": ref,
            "html_url": f"https://github.com/{repo_name}/commit/{ref}",
            "commit": {"committer": {"date": "2026-03-07T12:00:00Z"}},
            "parents": [{"sha": "parent-sha"}],
            "files": [
                {
                    "filename": ".github/workflows/test.yml",
                    "status": "modified",
                    "patch": "@@ -1 +1 @@\n-  pull_request_target:\n+  pull_request:\n",
                }
            ],
        }

    def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
        if ref == "parent-sha":
            return "on:\n  pull_request_target:\n"
        return "on:\n  pull_request:\n"


def fake_clone_runner(clone_url: str, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / ".git-clone-url").write_text(clone_url, encoding="utf-8")


@pytest.fixture(autouse=True)
def _disable_slack_notifications_for_cli_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("SLACK_WEBHOOK_URL", raising=False)
    original_load_env_file = cli_module.load_env_file

    def _load_env_file_without_slack(path: Path) -> dict[str, str]:
        values = original_load_env_file(path)
        values.pop("SLACK_WEBHOOK_URL", None)
        return values

    monkeypatch.setattr(cli_module, "load_env_file", _load_env_file_without_slack)


def test_cli_writes_only_vulnerable_repositories(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    input_payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "repo/one",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 1,
                    "risks": [
                        {
                            "repository_name": "repo/one",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "true-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        }
                    ],
                },
                {
                    "name": "repo/two",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 2,
                    "risks": [
                        {
                            "repository_name": "repo/two",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "false-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        }
                    ],
                },
            ]
        }
    }
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(json.dumps(input_payload), encoding="utf-8")

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeGitHubClient)
    monkeypatch.setattr("pwn_hunter_ai.cli.GeminiAnalyzer", FakeGeminiAnalyzer)
    monkeypatch.setattr("pwn_hunter_ai.cli.build_tracer", lambda **kwargs: FakeTracer())

    exit_code = main(
        [
            "ai-enumerate",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--gemini-api-key",
            "test-key",
            "--output-only-vulnerable",
        ]
    )

    assert exit_code == 0
    output_payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert [repo["name"] for repo in output_payload["ai_enumeration"]] == ["repo/one"]
    assert output_payload["ai_enumeration"][0]["risks"][0]["ai-analysis"]["vulnerable"] is True


def test_cli_requires_gemini_api_key(tmp_path: Path) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text('{"enumeration": {"repositories": []}}', encoding="utf-8")

    monkeypatch = pytest.MonkeyPatch()
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    with pytest.raises(SystemExit):
        main(["ai-enumerate", "--input", str(input_path), "--output", str(output_path)])

    monkeypatch.undo()


def test_cli_pr_target_history_writes_json_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "repos.txt"
    output_path = tmp_path / "report.json"
    log_path = tmp_path / "history.log"
    input_path.write_text("owner/repo\n", encoding="utf-8")

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeHistoryCliGitHubClient)

    exit_code = main(
        [
            "pr-target-history",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--days",
            "7",
            "--parallel-jobs",
            "2",
            "--github-token",
            "token-1,token-2",
            "--log-file",
            str(log_path),
        ]
    )

    assert exit_code == 0
    output_payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert output_payload["repositories_scanned"] == 1
    assert output_payload["repositories_with_removals"] == 1
    assert output_payload["results"][0]["removal_commits"][0]["url"].endswith(
        "/commit/abc123"
    )


def test_cli_accepts_gemini_batch_flag(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    input_payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "repo/one",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 1,
                    "risks": [
                        {
                            "repository_name": "repo/one",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "true-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        }
                    ],
                }
            ]
        }
    }
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(json.dumps(input_payload), encoding="utf-8")

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeGitHubClient)
    monkeypatch.setattr("pwn_hunter_ai.cli.GeminiAnalyzer", FakeGeminiAnalyzer)
    monkeypatch.setattr("pwn_hunter_ai.cli.build_tracer", lambda **kwargs: FakeTracer())

    exit_code = main(
        [
            "ai-enumerate",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--gemini-api-key",
            "test-key",
            "--gemini-batch",
        ]
    )

    assert exit_code == 0
    output_payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert output_payload["ai_enumeration"][0]["risks"][0]["ai-analysis"]["vulnerable"] is True


def test_cli_writes_failure_restart_file_for_failed_repositories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "repo/failed",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 1,
                    "risks": [
                        {
                            "repository_name": "repo/failed",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "bad-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        }
                    ],
                },
                {
                    "name": "repo/ok",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 2,
                    "risks": [
                        {
                            "repository_name": "repo/ok",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "true-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        }
                    ],
                },
            ]
        }
    }
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    failure_output_path = tmp_path / "output.failures.json"
    input_path.write_text(json.dumps(input_payload), encoding="utf-8")

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeGitHubClient)
    monkeypatch.setattr("pwn_hunter_ai.cli.GeminiAnalyzer", FakeFailingGeminiAnalyzer)
    monkeypatch.setattr("pwn_hunter_ai.cli.build_tracer", lambda **kwargs: FakeTracer())

    exit_code = main(
        [
            "ai-enumerate",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--gemini-api-key",
            "test-key",
            "--output-only-vulnerable",
        ]
    )

    assert exit_code == 0
    output_payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert [repo["name"] for repo in output_payload["ai_enumeration"]] == ["repo/ok"]
    failure_payload = json.loads(failure_output_path.read_text(encoding="utf-8"))
    assert [repo["name"] for repo in failure_payload["enumeration"]["repositories"]] == [
        "repo/failed"
    ]


def test_cli_skips_missing_repository_and_excludes_it_from_failure_restart_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "repo/missing",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 1,
                    "risks": [],
                },
                {
                    "name": "repo/ok",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 2,
                    "risks": [
                        {
                            "repository_name": "repo/ok",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "true-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        }
                    ],
                },
            ]
        }
    }
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    failure_output_path = tmp_path / "output.failures.json"
    log_path = tmp_path / "ai-enumerate.log"
    input_path.write_text(json.dumps(input_payload), encoding="utf-8")

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeMissingRepoGitHubClient)
    monkeypatch.setattr("pwn_hunter_ai.cli.GeminiAnalyzer", FakeGeminiAnalyzer)
    monkeypatch.setattr("pwn_hunter_ai.cli.build_tracer", lambda **kwargs: FakeTracer())

    exit_code = main(
        [
            "ai-enumerate",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--gemini-api-key",
            "test-key",
            "--log-file",
            str(log_path),
        ]
    )

    assert exit_code == 0
    output_payload = json.loads(output_path.read_text(encoding="utf-8"))
    assert [repo["name"] for repo in output_payload["ai_enumeration"]] == ["repo/ok"]
    failure_payload = json.loads(failure_output_path.read_text(encoding="utf-8"))
    assert failure_payload["enumeration"]["repositories"] == []
    log_content = log_path.read_text(encoding="utf-8")
    assert "Skipping repository repo/missing because it is no longer accessible on GitHub" in log_content
    assert "Command: pwnhunter ai-enumerate" in log_content
    assert "--gemini-api-key '<redacted>'" in log_content
    assert "test-key" not in log_content


def test_search_command_writes_unique_repositories_and_normalizes_lang(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "repositories.txt"

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeGitHubClient)

    exit_code = main(
        [
            "search",
            "pull_request_target path:.github/workflows lang:yaml",
            "--output",
            str(output_path),
            "--github-token",
            "test-token",
        ]
    )

    assert exit_code == 0
    assert output_path.read_text(encoding="utf-8").splitlines() == [
        "AstroNvim/astrocore",
        "Grow-with-Open-Source/Python-Projects",
    ]


def test_search_command_shards_beyond_thousand_results(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "repositories.txt"

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeGitHubClient)

    exit_code = main(
        [
            "search",
            "many-results path:.github/workflows",
            "--output",
            str(output_path),
            "--github-token",
            "test-token",
            "--parallel-jobs",
            "2",
            "--max-file-size",
            "10",
        ]
    )

    assert exit_code == 0
    assert output_path.read_text(encoding="utf-8").splitlines() == [
        "repo/alpha",
        "repo/beta",
        "repo/gamma",
    ]


def test_search_command_rejects_oversized_explicit_size_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "repositories.txt"

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeGitHubClient)

    with pytest.raises(RuntimeError, match="explicit size"):
        main(
            [
                "search",
                "already-sized size:1..10",
                "--output",
                str(output_path),
                "--github-token",
                "test-token",
            ]
        )


def test_search_command_can_bruteforce_byte_by_byte(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "repositories.txt"

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeGitHubClient)

    exit_code = main(
        [
            "search",
            "many-results path:.github/workflows",
            "--output",
            str(output_path),
            "--github-token",
            "test-token",
            "--min-file-size",
            "2",
            "--max-file-size",
            "4",
            "--brute-force",
        ]
    )

    assert exit_code == 0
    assert output_path.read_text(encoding="utf-8").splitlines() == [
        "repo/min-four-a",
        "repo/min-four-b",
        "repo/min-two",
    ]


def test_search_command_rejects_min_file_size_above_max_file_size(tmp_path: Path) -> None:
    output_path = tmp_path / "repositories.txt"

    with pytest.raises(SystemExit):
        main(
            [
                "search",
                "many-results path:.github/workflows",
                "--output",
                str(output_path),
                "--github-token",
                "test-token",
                "--min-file-size",
                "5",
                "--max-file-size",
                "4",
            ]
        )


def test_search_command_rejects_parallel_jobs_below_one(tmp_path: Path) -> None:
    output_path = tmp_path / "repositories.txt"

    with pytest.raises(SystemExit):
        main(
            [
                "search",
                "many-results path:.github/workflows",
                "--output",
                str(output_path),
                "--github-token",
                "test-token",
                "--parallel-jobs",
                "0",
            ]
        )


def test_search_command_accepts_oversized_explicit_exact_size_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "repositories.txt"

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeGitHubClient)

    exit_code = main(
        [
            "search",
            "exact-sized size:7..7",
            "--output",
            str(output_path),
            "--github-token",
            "test-token",
        ]
    )

    assert exit_code == 0
    assert output_path.read_text(encoding="utf-8").splitlines() == [
        "repo/exact",
    ]


def test_search_command_can_resume_from_snapshot_without_query(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "repositories.txt"
    snapshot_path = tmp_path / "search.snapshot.json"
    snapshot_path.write_text(
        json.dumps(
            {
                "query": "many-results path:.github/workflows",
                "min_file_size": 0,
                "max_file_size": 10,
                "max_results_per_shard": 1000,
                "brute_force": False,
                "count_cache": {
                    "many-results path:.github/workflows": 1200,
                    "many-results path:.github/workflows size:0..5": 700,
                    "many-results path:.github/workflows size:6..10": 500,
                },
                "repositories": ["repo/alpha", "repo/beta"],
                "pending_shards": [
                    {
                        "base_query": "many-results path:.github/workflows",
                        "count": 500,
                        "lower": 6,
                        "upper": 10,
                    }
                ],
                "current_shard": None,
                "next_page": 1,
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeGitHubClient)

    exit_code = main(
        [
            "search",
            "--output",
            str(output_path),
            "--github-token",
            "test-token",
            "--max-file-size",
            "10",
            "--resume-snapshot",
            str(snapshot_path),
        ]
    )

    assert exit_code == 0
    assert output_path.read_text(encoding="utf-8").splitlines() == [
        "repo/alpha",
        "repo/beta",
        "repo/gamma",
    ]
    assert not snapshot_path.exists()


def test_search_command_accepts_custom_max_results_per_shard(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "repositories.txt"

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeGitHubClient)

    exit_code = main(
        [
            "search",
            "many-results path:.github/workflows",
            "--output",
            str(output_path),
            "--github-token",
            "test-token",
            "--max-file-size",
            "10",
            "--max-results-per-shard",
            "1200",
        ]
    )

    assert exit_code == 0
    assert output_path.read_text(encoding="utf-8").splitlines() == []


def test_attack_command_writes_preparation_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {
                        "name": "owner/repo",
                        "enum_time": "Sat Feb 28 12:30:10 2026",
                        "can_fork": True,
                        "stars": 1,
                        "repository_creation_date": "2024-01-01T00:00:00Z",
                        "risks": [
                            {
                                "repository_name": "owner/repo",
                                "issue_type": "PwnRequestResult",
                                "triggers": ["pull_request_target"],
                                "initial_workflow": "pull_request.yml",
                                "pwn_request_result": {
                                    "vulnerable": True,
                                    "explanation": "vulnerable",
                                    "impact": "impact",
                                    "poc": "poc",
                                },
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.service.AttackArtifactsManager",
        lambda base_dir: AttackArtifactsManager(base_dir, clone_runner=fake_clone_runner),
    )

    exit_code = main(
        [
            "attack",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
            "--github-tokens-user-a",
            "token-a",
            "--github-tokens-user-b",
            "token-b",
        ]
    )

    assert exit_code == 0
    output_payload = json.loads(output_path.read_text(encoding="utf-8"))
    repository = output_payload["ai_enumeration"][0]
    risk = repository["risks"][0]
    assert repository["vulnerable_commit_hash"] == "cafebabe"
    assert repository["repo_vulnerable"] == "unknown"
    assert repository["act_repo_vulnerable"] is False
    assert isinstance(risk["attack_processed_time"], str)
    assert risk["attack_processed_time"]
    assert risk["attack_result"]["status"] == "prepared_for_manual_validation"
    assert Path(risk["attack_result"]["workspace_path"]).exists()


def test_attack_command_can_delete_workspace_after_processing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {
                        "name": "owner/repo",
                        "enum_time": "Sat Feb 28 12:30:10 2026",
                        "can_fork": True,
                        "stars": 1,
                        "repository_creation_date": "2024-01-01T00:00:00Z",
                        "risks": [
                            {
                                "repository_name": "owner/repo",
                                "issue_type": "PwnRequestResult",
                                "triggers": ["pull_request_target"],
                                "initial_workflow": "pull_request.yml",
                                "pwn_request_result": {
                                    "vulnerable": True,
                                    "explanation": "vulnerable",
                                    "impact": "impact",
                                    "poc": "poc",
                                },
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.service.AttackArtifactsManager",
        lambda base_dir: AttackArtifactsManager(base_dir, clone_runner=fake_clone_runner),
    )
    delete_commands: list[list[str]] = []

    def _fake_run(
        cmd: list[str],
        *,
        capture_output: bool,
        text: bool,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        _ = (capture_output, text, check)
        delete_commands.append(cmd)
        assert cmd[:4] == ["sudo", "-n", "rm", "-rf"]
        workspace_path = Path(cmd[4])
        if workspace_path.exists():
            for child in sorted(workspace_path.rglob("*"), reverse=True):
                if child.is_file():
                    child.unlink()
                else:
                    child.rmdir()
            workspace_path.rmdir()
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("pwn_hunter_ai.cli.subprocess.run", _fake_run)

    exit_code = main(
        [
            "attack",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
            "--github-tokens-user-a",
            "token-a",
            "--github-tokens-user-b",
            "token-b",
            "--delete-workspace-after-processing",
        ]
    )

    assert exit_code == 0
    output_payload = json.loads(output_path.read_text(encoding="utf-8"))
    repository = output_payload["ai_enumeration"][0]
    risk = repository["risks"][0]
    assert repository["vulnerable_commit_hash"] == "cafebabe"
    assert repository["repo_vulnerable"] == "unknown"
    assert repository["act_repo_vulnerable"] is False
    assert risk["attack_result"]["status"] == "prepared_for_manual_validation"
    assert not Path(risk["attack_result"]["workspace_path"]).exists()
    assert Path(risk["attack_result"]["artifact_root"]).exists()
    assert Path(risk["attack_result"]["context_path"]).exists()
    assert Path(risk["attack_result"]["agent_prompt_path"]).exists()
    assert len(delete_commands) == 1


def test_delete_repository_workspaces_keeps_persisted_security_report(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace_path = tmp_path / "attack-artifacts" / "run" / "owner__repo" / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    (workspace_path / "temp.txt").write_text("x", encoding="utf-8")
    report_path = (
        tmp_path / "security-reports" / "owner-repo-risk-1-github-workflows-ci.yml.md"
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text("# Security Report\n", encoding="utf-8")

    def _fake_run(
        cmd: list[str],
        *,
        capture_output: bool,
        text: bool,
        check: bool,
    ) -> subprocess.CompletedProcess[str]:
        _ = (capture_output, text, check)
        workspace = Path(cmd[4])
        if workspace.exists():
            for child in sorted(workspace.rglob("*"), reverse=True):
                if child.is_file():
                    child.unlink()
                else:
                    child.rmdir()
            workspace.rmdir()
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("pwn_hunter_ai.cli.subprocess.run", _fake_run)

    _delete_repository_workspaces(
        {
            "risks": [
                {
                    "attack_result": {
                        "workspace_path": str(workspace_path),
                        "security_report_path": str(report_path),
                    }
                }
            ]
        }
    )

    assert not workspace_path.exists()
    assert report_path.exists()


def test_attack_command_seeds_run_level_learnings_from_learning_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    learning_path = tmp_path / "LEARNING.md"
    learning_content = "# Learnings\n\n- [seed/repo] keep branch names deterministic\n"
    learning_path.write_text(learning_content, encoding="utf-8")
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {
                        "name": "owner/repo",
                        "enum_time": "Sat Feb 28 12:30:10 2026",
                        "can_fork": True,
                        "stars": 1,
                        "repository_creation_date": "2024-01-01T00:00:00Z",
                        "risks": [
                            {
                                "repository_name": "owner/repo",
                                "issue_type": "PwnRequestResult",
                                "triggers": ["pull_request_target"],
                                "initial_workflow": "pull_request.yml",
                                "pwn_request_result": {
                                    "vulnerable": True,
                                    "explanation": "vulnerable",
                                    "impact": "impact",
                                    "poc": "poc",
                                },
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.service.AttackArtifactsManager",
        lambda base_dir: AttackArtifactsManager(base_dir, clone_runner=fake_clone_runner),
    )

    exit_code = main(
        [
            "attack",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
            "--github-tokens-user-a",
            "token-a",
            "--github-tokens-user-b",
            "token-b",
            "--learning-file",
            str(learning_path),
        ]
    )

    assert exit_code == 0
    output_payload = json.loads(output_path.read_text(encoding="utf-8"))
    repository = output_payload["ai_enumeration"][0]
    risk = repository["risks"][0]
    workspace_path = Path(risk["attack_result"]["workspace_path"])
    assert workspace_path.exists()
    run_level_learnings_path = workspace_path.parents[3] / "LEARNINGS.md"
    assert run_level_learnings_path.read_text(encoding="utf-8") == learning_content


def test_attack_command_defaults_learning_file_to_repo_root_learning_md(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    learning_path = tmp_path / "LEARNING.md"
    learning_content = "# Learnings\n\n- [default/path] loaded from repo root\n"
    learning_path.write_text(learning_content, encoding="utf-8")
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {
                        "name": "owner/repo",
                        "enum_time": "Sat Feb 28 12:30:10 2026",
                        "can_fork": True,
                        "stars": 1,
                        "repository_creation_date": "2024-01-01T00:00:00Z",
                        "risks": [
                            {
                                "repository_name": "owner/repo",
                                "issue_type": "PwnRequestResult",
                                "triggers": ["pull_request_target"],
                                "initial_workflow": "pull_request.yml",
                                "pwn_request_result": {
                                    "vulnerable": True,
                                    "explanation": "vulnerable",
                                    "impact": "impact",
                                    "poc": "poc",
                                },
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.service.AttackArtifactsManager",
        lambda base_dir: AttackArtifactsManager(base_dir, clone_runner=fake_clone_runner),
    )

    exit_code = main(
        [
            "attack",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
            "--github-tokens-user-a",
            "token-a",
            "--github-tokens-user-b",
            "token-b",
        ]
    )

    assert exit_code == 0
    output_payload = json.loads(output_path.read_text(encoding="utf-8"))
    repository = output_payload["ai_enumeration"][0]
    risk = repository["risks"][0]
    workspace_path = Path(risk["attack_result"]["workspace_path"])
    assert workspace_path.exists()
    run_level_learnings_path = workspace_path.parents[3] / "LEARNINGS.md"
    assert run_level_learnings_path.read_text(encoding="utf-8") == learning_content


def test_run_attack_prepare_auto_execute_processes_one_repository_per_execution_step(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {"name": "owner/repo-a", "risks": [{"pwn_request_result": {"vulnerable": True}}]},
                    {"name": "owner/repo-b", "risks": [{"pwn_request_result": {"vulnerable": True}}]},
                ]
            }
        ),
        encoding="utf-8",
    )

    prepared_calls: list[tuple[str, int]] = []
    auto_execute_calls: list[list[str]] = []

    class FakeTokenBroker:
        def __init__(self, *, user_a_tokens: list[str], user_b_tokens: list[str]) -> None:
            _ = user_a_tokens
            self.user_b_capacity = len(user_b_tokens)

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            repo_name = input_payload["ai_enumeration"][0]["name"]
            prepared_calls.append((repo_name, parallel_jobs))
            return {
                "ai_enumeration": [
                    {
                        "name": repo_name,
                        "risks": [{"attack_result": {"status": "prepared_for_manual_validation"}}],
                    }
                ]
            }

    def fake_auto_execute(output_payload: dict, config: AttackCLIConfig, token_broker) -> dict:
        _ = (config, token_broker)
        repo_names = [repo["name"] for repo in output_payload.get("ai_enumeration", [])]
        auto_execute_calls.append(repo_names)
        return output_payload

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "GitHubClient", FakeAttackGitHubClient)
    monkeypatch.setattr(cli_module, "_run_auto_execute", fake_auto_execute)

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=2,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b,token-c",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        generate_security_report=True,
    )

    result = cli_module.run_attack_prepare(config)

    assert sorted(name for name, jobs in prepared_calls) == [
        "owner/repo-a",
        "owner/repo-b",
    ]
    assert all(jobs == 1 for _, jobs in prepared_calls)
    assert sorted(tuple(call) for call in auto_execute_calls) == [
        ("owner/repo-a",),
        ("owner/repo-b",),
    ]
    assert [repo["name"] for repo in result["ai_enumeration"]] == [
        "owner/repo-a",
        "owner/repo-b",
    ]


def test_run_attack_prepare_normalizes_raw_gato_x_enumeration_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "username": "anonymous-author",
                "enumeration": {
                    "repositories": [
                        {
                            "name": "owner/repo-a",
                            "commit": "abc123",
                            "risks": [
                                {
                                    "repository_name": "owner/repo-a",
                                    "issue_type": "PwnRequestResult",
                                    "triggers": ["pull_request_target"],
                                    "initial_workflow": "ci.yml",
                                    "confidence": "high",
                                    "attack_complexity": "No Interaction",
                                    "explanation": "Untrusted PR code is executed.",
                                    "path": [
                                        {
                                            "node": (
                                                "WorkflowNode('owner/repo-a:main:.github/workflows/ci.yml')"
                                            )
                                        }
                                    ],
                                    "sink": "make test",
                                }
                            ],
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    prepared_inputs: list[dict[str, Any]] = []

    class FakeTokenBroker:
        def __init__(self, *, user_a_tokens: list[str], user_b_tokens: list[str]) -> None:
            _ = user_a_tokens
            self.user_b_capacity = len(user_b_tokens)

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            _ = parallel_jobs
            prepared_inputs.append(input_payload)
            repository = input_payload["ai_enumeration"][0]
            risk = repository["risks"][0]
            assert repository["name"] == "owner/repo-a"
            assert risk["vulnerable"] is True
            assert risk["attack_input_source"] == "gato-x"
            assert risk["gato-x-confidence"] == "high"
            assert risk["gato-x-attack_complexity"] == "No Interaction"
            assert risk["gato-x-explanation"] == "Untrusted PR code is executed."
            assert risk["gato-x-path"] == risk["path"]
            assert risk["gato-x-sink"] == "make test"
            assert "ai-analysis" not in risk
            return {
                "ai_enumeration": [
                    {
                        "name": repository["name"],
                        "risks": [
                            {
                                **risk,
                                "attack_result": {
                                    "status": "prepared_for_manual_validation"
                                },
                            }
                        ],
                    }
                ]
            }

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = cli_module.run_attack_prepare(config)

    assert len(prepared_inputs) == 1
    assert result["enumeration"]["repositories"][0]["name"] == "owner/repo-a"
    assert "ai_enumeration" not in result
    assert [repo["name"] for repo in result["enumeration"]["repositories"]] == [
        "owner/repo-a"
    ]
    assert (
        result["enumeration"]["repositories"][0]["risks"][0]["attack_result"]["status"]
        == "prepared_for_manual_validation"
    )


def test_run_attack_prepare_uses_gato_x_single_fixture_without_explicit_vulnerable_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = Path("test_e2e/attack/gato-x-attack-e2e-single.json")
    output_path = tmp_path / "output.json"

    prepared_repo_names: list[str] = []

    class FakeTokenBroker:
        def __init__(self, *, user_a_tokens: list[str], user_b_tokens: list[str]) -> None:
            _ = user_a_tokens
            self.user_b_capacity = len(user_b_tokens)

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            _ = parallel_jobs
            repository = input_payload["ai_enumeration"][0]
            risk = repository["risks"][0]
            prepared_repo_names.append(repository["name"])
            assert repository["name"] == "synthetic-owner/demo"
            assert risk["vulnerable"] is True
            assert risk["attack_input_source"] == "gato-x"
            return {
                "ai_enumeration": [
                    {
                        "name": repository["name"],
                        "risks": [
                            {
                                **risk,
                                "attack_result": {
                                    "status": "prepared_for_manual_validation"
                                },
                            }
                        ],
                    }
                ]
            }

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = cli_module.run_attack_prepare(config)

    assert prepared_repo_names == ["synthetic-owner/demo"]
    assert "ai_enumeration" not in result
    assert [repo["name"] for repo in result["enumeration"]["repositories"]] == [
        "synthetic-owner/demo"
    ]
    assert (
        result["enumeration"]["repositories"][0]["risks"][0]["attack_result"]["status"]
        == "prepared_for_manual_validation"
    )


def test_run_attack_prepare_passes_user_b_token_concurrency_to_token_broker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {"name": "owner/repo-a", "risks": [{"pwn_request_result": {"vulnerable": True}}]},
                ]
            }
        ),
        encoding="utf-8",
    )

    captured_concurrency: dict[str, int] = {}

    class FakeTokenBroker:
        def __init__(
            self,
            *,
            user_a_tokens: list[str],
            user_b_tokens: list[str],
            user_b_max_parallel_per_token: int,
        ) -> None:
            _ = (user_a_tokens, user_b_tokens)
            captured_concurrency["value"] = user_b_max_parallel_per_token
            self.user_b_capacity = user_b_max_parallel_per_token

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            _ = parallel_jobs
            repo_name = input_payload["ai_enumeration"][0]["name"]
            return {
                "ai_enumeration": [
                    {
                        "name": repo_name,
                        "risks": [{"attack_result": {"status": "prepared_for_manual_validation"}}],
                    }
                ]
            }

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        user_b_token_concurrency=3,
    )

    cli_module.run_attack_prepare(config)

    assert captured_concurrency == {"value": 3}


def test_run_attack_prepare_auto_execute_writes_snapshot_after_each_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {"name": "owner/repo-a", "risks": [{"pwn_request_result": {"vulnerable": True}}]},
                    {"name": "owner/repo-b", "risks": [{"pwn_request_result": {"vulnerable": True}}]},
                ]
            }
        ),
        encoding="utf-8",
    )

    snapshot_progress: list[list[str]] = []

    class FakeTokenBroker:
        def __init__(self, *, user_a_tokens: list[str], user_b_tokens: list[str]) -> None:
            _ = user_a_tokens
            self.user_b_capacity = len(user_b_tokens)

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            _ = parallel_jobs
            repo_name = input_payload["ai_enumeration"][0]["name"]
            return {
                "ai_enumeration": [
                    {
                        "name": repo_name,
                        "risks": [{"attack_result": {"status": "prepared_for_manual_validation"}}],
                    }
                ]
            }

    def fake_auto_execute(output_payload: dict, config: AttackCLIConfig, token_broker) -> dict:
        _ = (config, token_broker)
        return output_payload

    def fake_write_snapshot(*, output_path: Path, input_payload: dict, repository_results: list):
        _ = (output_path, input_payload)
        repo_names = [repo["name"] for repo in repository_results if repo is not None]
        snapshot_progress.append(repo_names)
        return {
            "ai_enumeration": [repo for repo in repository_results if repo is not None]
        }

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "GitHubClient", FakeAttackGitHubClient)
    monkeypatch.setattr(cli_module, "_run_auto_execute", fake_auto_execute)
    monkeypatch.setattr(cli_module, "_write_attack_snapshot", fake_write_snapshot)

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        generate_security_report=True,
    )

    result = cli_module.run_attack_prepare(config)

    assert snapshot_progress == [
        ["owner/repo-a"],
        ["owner/repo-a", "owner/repo-b"],
    ]
    assert [repo["name"] for repo in result["ai_enumeration"]] == [
        "owner/repo-a",
        "owner/repo-b",
    ]


def test_run_attack_prepare_skips_repositories_with_more_than_fifteen_risks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    many_risks = [{"pwn_request_result": {"vulnerable": True}} for _ in range(16)]
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {"name": "owner/repo-big", "risks": many_risks},
                    {
                        "name": "owner/repo-small",
                        "risks": [{"pwn_request_result": {"vulnerable": True}}],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    prepared_calls: list[str] = []

    class FakeTokenBroker:
        def __init__(self, *, user_a_tokens: list[str], user_b_tokens: list[str]) -> None:
            _ = user_a_tokens
            self.user_b_capacity = len(user_b_tokens)

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            _ = parallel_jobs
            repo_name = input_payload["ai_enumeration"][0]["name"]
            prepared_calls.append(repo_name)
            return {
                "ai_enumeration": [
                    {
                        "name": repo_name,
                        "risks": [
                            {
                                "attack_result": {
                                    "status": "prepared_for_manual_validation"
                                }
                            }
                        ],
                    }
                ]
            }

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        generate_security_report=True,
    )

    result = cli_module.run_attack_prepare(config)

    assert prepared_calls == ["owner/repo-small"]
    big_repo = result["ai_enumeration"][0]
    small_repo = result["ai_enumeration"][1]
    assert big_repo["name"] == "owner/repo-big"
    assert big_repo["attack_skipped"] is True
    assert big_repo["attack_skip_reason"] == "too_many_risks_for_auto_execution"
    assert "Manual review is required" in big_repo["manual_review_note"]
    assert big_repo["risk_count"] == 16
    assert big_repo["repo_vulnerable"] == "unknown"
    assert small_repo["name"] == "owner/repo-small"
    assert (
        small_repo["risks"][0]["attack_result"]["status"]
        == "prepared_for_manual_validation"
    )
    assert all(
        risk["attack_result"]["status"] == "skipped_too_many_risks_for_manual_review"
        for risk in big_repo["risks"]
    )
    assert all(
        risk["attack_result"]["flagged_for_human_review"] is True
        for risk in big_repo["risks"]
    )
    assert json.loads(output_path.read_text(encoding="utf-8")) == result


def test_run_attack_prepare_resumes_existing_output_skips_processed_repositories_and_creates_backup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {"name": "owner/repo-a", "risks": [{"pwn_request_result": {"vulnerable": True}}]},
                    {"name": "owner/repo-b", "risks": [{"pwn_request_result": {"vulnerable": True}}]},
                    {"name": "owner/repo-c", "risks": [{"pwn_request_result": {"vulnerable": True}}]},
                ]
            }
        ),
        encoding="utf-8",
    )
    existing_output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-a",
                "risks": [{"attack_result": {"status": "already_processed_a"}}],
            },
            {
                "name": "owner/repo-c",
                "risks": [{"attack_result": {"status": "already_processed_c"}}],
            },
        ]
    }
    output_path.write_text(
        json.dumps(existing_output_payload, indent=2) + "\n",
        encoding="utf-8",
    )

    prepared_calls: list[str] = []

    class FakeTokenBroker:
        def __init__(self, *, user_a_tokens: list[str], user_b_tokens: list[str]) -> None:
            _ = user_a_tokens
            self.user_b_capacity = len(user_b_tokens)

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            _ = parallel_jobs
            repo_name = input_payload["ai_enumeration"][0]["name"]
            prepared_calls.append(repo_name)
            return {
                "ai_enumeration": [
                    {
                        "name": repo_name,
                        "risks": [{"attack_result": {"status": "prepared_for_manual_validation"}}],
                    }
                ]
            }

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "GitHubClient", FakeAttackGitHubClient)
    monkeypatch.setattr(cli_module, "_format_backup_timestamp", lambda: "20260329T120000+0100")

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=2,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b,token-c",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        generate_security_report=True,
    )

    result = cli_module.run_attack_prepare(config)

    assert prepared_calls == ["owner/repo-b"]
    assert [repo["name"] for repo in result["ai_enumeration"]] == [
        "owner/repo-a",
        "owner/repo-b",
        "owner/repo-c",
    ]
    assert result["ai_enumeration"][0]["risks"][0]["attack_result"]["status"] == "already_processed_a"
    assert (
        result["ai_enumeration"][1]["risks"][0]["attack_result"]["status"]
        == "prepared_for_manual_validation"
    )
    assert result["ai_enumeration"][2]["risks"][0]["attack_result"]["status"] == "already_processed_c"

    backup_path = output_path.with_name("output.20260329T120000+0100.json")
    assert backup_path.exists()
    assert json.loads(backup_path.read_text(encoding="utf-8")) == existing_output_payload


def test_run_attack_prepare_resumes_existing_output_for_raw_gato_x_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "enumeration": {
                    "repositories": [
                        {
                            "name": "owner/repo-a",
                            "risks": [{"vulnerable": True, "path": [], "sink": "a"}],
                        },
                        {
                            "name": "owner/repo-b",
                            "risks": [{"vulnerable": True, "path": [], "sink": "b"}],
                        },
                    ]
                }
            }
        ),
        encoding="utf-8",
    )
    output_path.write_text(
        json.dumps(
            {
                "enumeration": {"repositories": [{"name": "owner/repo-a"}]},
                "ai_enumeration": [
                    {
                        "name": "owner/repo-a",
                        "risks": [{"attack_result": {"status": "already_processed"}}],
                    }
                ],
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    prepared_calls: list[str] = []

    class FakeTokenBroker:
        def __init__(self, *, user_a_tokens: list[str], user_b_tokens: list[str]) -> None:
            _ = user_a_tokens
            self.user_b_capacity = len(user_b_tokens)

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            _ = parallel_jobs
            repo_name = input_payload["ai_enumeration"][0]["name"]
            prepared_calls.append(repo_name)
            return {
                "ai_enumeration": [
                    {
                        "name": repo_name,
                        "risks": [{"attack_result": {"status": "prepared_for_manual_validation"}}],
                    }
                ]
            }

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "GitHubClient", FakeAttackGitHubClient)
    monkeypatch.setattr(cli_module, "_format_backup_timestamp", lambda: "20260329T120000+0100")

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=2,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b,token-c",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = cli_module.run_attack_prepare(config)

    assert prepared_calls == ["owner/repo-b"]
    assert "ai_enumeration" not in result
    assert [repo["name"] for repo in result["enumeration"]["repositories"]] == [
        "owner/repo-a",
        "owner/repo-b",
    ]
    assert result["enumeration"]["repositories"][0]["name"] == "owner/repo-a"
    assert (
        result["enumeration"]["repositories"][0]["risks"][0]["attack_result"]["status"]
        == "already_processed"
    )
    assert (
        result["enumeration"]["repositories"][1]["risks"][0]["attack_result"]["status"]
        == "prepared_for_manual_validation"
    )


def test_run_attack_prepare_stops_when_existing_output_is_invalid_json(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {"name": "owner/repo-a", "risks": [{"pwn_request_result": {"vulnerable": True}}]}
                ]
            }
        ),
        encoding="utf-8",
    )
    output_path.write_text("not-json\n", encoding="utf-8")

    token_broker_called = False
    service_called = False

    class FakeTokenBroker:
        def __init__(self, **kwargs) -> None:
            nonlocal token_broker_called
            token_broker_called = True
            _ = kwargs

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            nonlocal service_called
            service_called = True
            _ = kwargs

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        generate_security_report=True,
    )

    with pytest.raises(
        cli_module.AttackResumeOutputError,
        match="invalid JSON and cannot be resumed",
    ):
        cli_module.run_attack_prepare(config)

    assert token_broker_called is False
    assert service_called is False


def test_run_attack_prepare_persists_failure_and_continues_after_worker_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {"name": "owner/repo-a", "risks": [{"pwn_request_result": {"vulnerable": True}}]},
                    {"name": "owner/repo-b", "risks": [{"pwn_request_result": {"vulnerable": True}}]},
                ]
            }
        ),
        encoding="utf-8",
    )

    snapshot_progress: list[list[str]] = []

    class FakeTokenBroker:
        def __init__(self, *, user_a_tokens: list[str], user_b_tokens: list[str]) -> None:
            _ = user_a_tokens
            self.user_b_capacity = len(user_b_tokens)

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            _ = parallel_jobs
            repo_name = input_payload["ai_enumeration"][0]["name"]
            if repo_name == "owner/repo-a":
                raise RuntimeError("simulated repository failure")
            return {
                "ai_enumeration": [
                    {
                        "name": repo_name,
                        "risks": [{"attack_result": {"status": "prepared_for_manual_validation"}}],
                    }
                ]
            }

    def fake_write_snapshot(*, output_path: Path, input_payload: dict, repository_results: list):
        _ = (output_path, input_payload)
        repo_names = [repo["name"] for repo in repository_results if repo is not None]
        snapshot_progress.append(repo_names)
        return {
            "ai_enumeration": [repo for repo in repository_results if repo is not None]
        }

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "GitHubClient", FakeAttackGitHubClient)
    monkeypatch.setattr(cli_module, "_write_attack_snapshot", fake_write_snapshot)

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = cli_module.run_attack_prepare(config)

    assert snapshot_progress == [
        ["owner/repo-a"],
        ["owner/repo-a", "owner/repo-b"],
    ]
    failed_repo = result["ai_enumeration"][0]
    assert failed_repo["name"] == "owner/repo-a"
    assert failed_repo["error"] == "RuntimeError: simulated repository failure"
    failed_risk = failed_repo["risks"][0]["attack_result"]
    assert failed_risk["status"] == "blocked_preparation_error"
    assert (
        failed_risk["reason"]
        == "Attack processing failed: RuntimeError: simulated repository failure"
    )
    assert result["ai_enumeration"][1]["name"] == "owner/repo-b"
    assert (
        result["ai_enumeration"][1]["risks"][0]["attack_result"]["status"]
        == "prepared_for_manual_validation"
    )


def test_run_attack_prepare_marks_execution_error_when_auto_execute_raises(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {
                        "name": "owner/repo-a",
                        "risks": [{"pwn_request_result": {"vulnerable": True}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    class FakeTokenBroker:
        def __init__(self, *, user_a_tokens: list[str], user_b_tokens: list[str]) -> None:
            _ = user_a_tokens
            self.user_b_capacity = len(user_b_tokens)

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            _ = (input_payload, parallel_jobs)
            return {
                "ai_enumeration": [
                    {
                        "name": "owner/repo-a",
                        "risks": [{"attack_result": {"status": "prepared_for_manual_validation"}}],
                    }
                ]
            }

    def fake_run_auto_execute(*_args, **_kwargs):
        raise RuntimeError("simulated execution failure")

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "GitHubClient", FakeAttackGitHubClient)
    monkeypatch.setattr(cli_module, "_run_auto_execute", fake_run_auto_execute)

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = cli_module.run_attack_prepare(config)
    failed_risk = result["ai_enumeration"][0]["risks"][0]["attack_result"]
    assert failed_risk["status"] == "execution_error"
    assert failed_risk["error_stage"] == "execution"
    assert failed_risk["failure_fingerprint"] == "execution_runtime_error"
    assert (
        failed_risk["reason"]
        == "Attack processing failed: RuntimeError: simulated execution failure"
    )


def test_run_attack_prepare_skips_slack_notification_when_webhook_missing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(json.dumps({"ai_enumeration": []}), encoding="utf-8")

    called = {"urlopen": False}

    def fake_urlopen(*_args, **_kwargs):
        called["urlopen"] = True
        raise AssertionError("urlopen should not be called without webhook")

    monkeypatch.setattr(slack_notifications.urllib_request, "urlopen", fake_urlopen)

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        slack_webhook_url=None,
    )

    cli_module.run_attack_prepare(config)
    assert called["urlopen"] is False


def test_attack_command_sends_success_slack_notification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(json.dumps({"ai_enumeration": []}), encoding="utf-8")

    request_payload: dict[str, str] = {}

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            _ = (exc_type, exc, tb)
            return False

    def fake_urlopen(request, timeout: int):
        request_payload["url"] = request.full_url
        request_payload["body"] = request.data.decode("utf-8")
        request_payload["timeout"] = str(timeout)
        return FakeResponse()

    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setattr(slack_notifications.urllib_request, "urlopen", fake_urlopen)
    monkeypatch.setattr(
        cli_module,
        "run_attack_prepare",
        lambda _config: {"ai_enumeration": []},
    )

    exit_code = main(
        [
            "attack",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
            "--github-tokens-user-a",
            "token-a",
            "--github-tokens-user-b",
            "token-b",
        ]
    )

    assert exit_code == 0
    assert request_payload["url"] == "https://example.com/hook"
    parsed_payload = json.loads(request_payload["body"])
    assert "pwnhunter attack command completed successfully." in parsed_payload["text"]
    assert "Repositories processed: 0" in parsed_payload["text"]
    assert str(output_path) in parsed_payload["text"]


def test_attack_command_sends_failure_slack_notification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(json.dumps({"ai_enumeration": []}), encoding="utf-8")

    request_payload: dict[str, str] = {}

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            _ = (exc_type, exc, tb)
            return False

    def fake_urlopen(request, timeout: int):
        _ = timeout
        request_payload["url"] = request.full_url
        request_payload["body"] = request.data.decode("utf-8")
        return FakeResponse()

    def fake_run_attack_prepare(_config: AttackCLIConfig) -> dict:
        raise RuntimeError("simulated command failure")

    monkeypatch.setenv("SLACK_WEBHOOK_URL", "https://example.com/hook")
    monkeypatch.setattr(slack_notifications.urllib_request, "urlopen", fake_urlopen)
    monkeypatch.setattr(cli_module, "run_attack_prepare", fake_run_attack_prepare)

    with pytest.raises(RuntimeError, match="simulated command failure"):
        main(
            [
                "attack",
                "--input",
                str(input_path),
                "--output",
                str(output_path),
                "--artifacts-dir",
                str(tmp_path / "artifacts"),
                "--github-tokens-user-a",
                "token-a",
                "--github-tokens-user-b",
                "token-b",
            ]
        )

    assert request_payload["url"] == "https://example.com/hook"
    parsed_payload = json.loads(request_payload["body"])
    assert "pwnhunter attack command failed." in parsed_payload["text"]
    assert str(output_path) in parsed_payload["text"]
    assert "RuntimeError: simulated command failure" in parsed_payload["text"]


def test_attack_command_parses_skip_repositories(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(json.dumps({"ai_enumeration": []}), encoding="utf-8")

    captured_skip_repositories: tuple[str, ...] | None = None

    def fake_run_attack_prepare(config: AttackCLIConfig) -> dict:
        nonlocal captured_skip_repositories
        captured_skip_repositories = config.skip_repositories
        return {"ai_enumeration": []}

    monkeypatch.setattr(cli_module, "run_attack_prepare", fake_run_attack_prepare)

    exit_code = main(
        [
            "attack",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--artifacts-dir",
            str(tmp_path / "artifacts"),
            "--github-tokens-user-a",
            "token-a",
            "--github-tokens-user-b",
            "token-b",
            "--skip",
            "Owner-One/Repo-One, owner-two/repo-two ,OWNER-ONE/repo-one, Owner-Three/*, owner-three/*",
        ]
    )

    assert exit_code == 0
    assert captured_skip_repositories == (
        "owner-one/repo-one",
        "owner-two/repo-two",
        "owner-three/*",
    )


def test_attack_command_sends_token_quarantine_slack_notification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_payload: dict[str, str] = {}

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            _ = (exc_type, exc, tb)
            return False

    def fake_urlopen(request, timeout: int):
        request_payload["url"] = request.full_url
        request_payload["body"] = request.data.decode("utf-8")
        request_payload["timeout"] = str(timeout)
        return FakeResponse()

    monkeypatch.setattr(slack_notifications.urllib_request, "urlopen", fake_urlopen)
    config = AttackCLIConfig(
        input_path=tmp_path / "input.json",
        output_path=tmp_path / "output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        slack_webhook_url="https://example.com/hook",
    )

    cli_module._send_attack_token_quarantine_slack_notification(
        config=config,
        event=AttackTokenQuarantineEvent(
            token_role="user_a",
            token_owner="synthetic-target",
            token_display="toke...ken1",
            reason_code="fork_denied",
            reason="GitHub API request failed for /repos/owner/repo/forks: 403 You cannot fork this repository at this time",
            failure_count=3,
            repository_name="owner/repo",
            stage="ensure_user_a_fork",
        ),
    )

    assert request_payload["url"] == "https://example.com/hook"
    parsed_payload = json.loads(request_payload["body"])
    assert "pwnhunter quarantined a GitHub token during attack preparation." in parsed_payload["text"]
    assert "Owner: synthetic-target" in parsed_payload["text"]
    assert "Reason code: fork_denied" in parsed_payload["text"]


def test_attack_command_sends_waiting_for_tokens_slack_notification(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    request_payload: dict[str, str] = {}

    class FakeResponse:
        status = 200

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            _ = (exc_type, exc, tb)
            return False

    def fake_urlopen(request, timeout: int):
        request_payload["url"] = request.full_url
        request_payload["body"] = request.data.decode("utf-8")
        request_payload["timeout"] = str(timeout)
        return FakeResponse()

    class FakeAvailabilityEvent:
        status = "waiting"
        missing_roles = ("user_a", "user_b")
        user_a_count = 0
        user_b_count = 0
        trigger = "periodic_refresh"

    monkeypatch.setattr(slack_notifications.urllib_request, "urlopen", fake_urlopen)
    config = AttackCLIConfig(
        input_path=tmp_path / "input.json",
        output_path=tmp_path / "output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        slack_webhook_url="https://example.com/hook",
    )

    cli_module._send_attack_token_waiting_slack_notification(
        config=config,
        event=FakeAvailabilityEvent(),
    )

    assert request_payload["url"] == "https://example.com/hook"
    parsed_payload = json.loads(request_payload["body"])
    assert "pwnhunter attack command is waiting for refreshed GitHub tokens." in parsed_payload["text"]
    assert "Missing roles: user_a, user_b" in parsed_payload["text"]
    assert str(config.output_path) in parsed_payload["text"]


def test_run_attack_prepare_refreshes_env_sourced_tokens_before_processing_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    env_path = tmp_path / ".env"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {
                        "name": "owner/repo-a",
                        "risks": [{"pwn_request_result": {"vulnerable": True}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    env_path.write_text("", encoding="utf-8")

    refresh_calls: list[tuple[str, list[str], list[str]]] = []

    class FakeTokenBroker:
        def __init__(self, **kwargs) -> None:
            _ = kwargs
            self.user_b_capacity = 1

        def refresh_tokens(
            self,
            *,
            user_a_tokens: list[str],
            user_b_tokens: list[str],
            trigger: str,
        ) -> None:
            refresh_calls.append((trigger, list(user_a_tokens), list(user_b_tokens)))

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            _ = (input_payload, parallel_jobs)
            return {
                "ai_enumeration": [
                    {
                        "name": "owner/repo-a",
                        "risks": [{"attack_result": {"status": "prepared_for_manual_validation"}}],
                    }
                ]
            }

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(
        cli_module,
        "load_env_file",
        lambda _path: {
            "GITHUB_TOKENS_USER_A": "token-a2",
            "GITHUB_TOKENS_USER_B": "token-b2",
        },
    )

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a1",
        github_tokens_user_b="token-b1",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=False,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        github_tokens_user_a_source="env_file",
        github_tokens_user_b_source="env_file",
        env_file_path=env_path,
    )

    cli_module.run_attack_prepare(config)

    assert refresh_calls[0] == ("startup", ["token-a2"], ["token-b2"])
    assert refresh_calls[1][0].startswith("repository_start:owner/repo-a:attempt_1")
    assert refresh_calls[1][1:] == (["token-a2"], ["token-b2"])


def test_run_attack_prepare_restarts_repository_when_broker_requests_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {
                        "name": "owner/repo-a",
                        "risks": [{"pwn_request_result": {"vulnerable": True}}],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    calls = {"prepare": 0, "execute": 0}

    class FakeTokenBroker:
        def __init__(self, **kwargs) -> None:
            _ = kwargs
            self.user_b_capacity = 1
            self._restart_requested = True

        def consume_repository_restart_request(self, repository_name: str) -> bool:
            _ = repository_name
            if not self._restart_requested:
                return False
            self._restart_requested = False
            return True

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            _ = kwargs

        def run(self, input_payload, *, parallel_jobs: int):
            _ = (input_payload, parallel_jobs)
            calls["prepare"] += 1
            return {
                "ai_enumeration": [
                    {
                        "name": "owner/repo-a",
                        "risks": [{"attack_result": {"status": "prepared_for_manual_validation"}}],
                    }
                ]
            }

    def fake_run_auto_execute(output_payload, config, token_broker):
        _ = (config, token_broker)
        calls["execute"] += 1
        return {
            "ai_enumeration": [
                {
                    "name": output_payload["ai_enumeration"][0]["name"],
                    "risks": [{"attack_result": {"status": "vulnerable_confirmed"}}],
                }
            ]
        }

    monkeypatch.setattr(cli_module, "AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(cli_module, "AttackPreparationService", FakeAttackPreparationService)
    monkeypatch.setattr(cli_module, "_run_auto_execute", fake_run_auto_execute)

    config = AttackCLIConfig(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=2,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        no_sandbox=False,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = cli_module.run_attack_prepare(config)

    assert calls == {"prepare": 2, "execute": 1}
    assert result["ai_enumeration"][0]["risks"][0]["attack_result"]["status"] == (
        "vulnerable_confirmed"
    )


def test_run_auto_execute_uses_live_user_b_reviewer_tokens_from_broker(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-a",
                "risks": [
                    {
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-a",
                            "user_b_fork": "attacker/repo-a",
                            "workspace_path": str(tmp_path / "workspace"),
                            "source_default_branch": "main",
                        }
                    }
                ],
            }
        ]
    }
    captured_reviewer_tokens: list[str] = []

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            agent_runtime=None,
            agent_provider=None,
            openhands_manager=None,
            use_host_agent_directly=False,
            use_host_openhands_directly=False,
        ) -> None:
            _ = (
                github_client_factory,
                hookbin_client,
                sandbox_manager,
                agent_runtime,
                agent_provider,
                openhands_manager,
                use_host_agent_directly,
                use_host_openhands_directly,
            )

        def execute_attack(self, **kwargs):
            captured_reviewer_tokens[:] = kwargs["user_b_reviewer_tokens"]
            return {"vulnerable": False, "reason": "not exploitable"}

    class FakeHookbinClient:
        pass

    class FakeSandboxManager:
        def __init__(self, use_host: bool = True) -> None:
            _ = use_host

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

        def list_user_b_tokens(self) -> list[str]:
            return ["token-b-live", "token-c-live"]

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.hookbin_client.HookbinClient",
        FakeHookbinClient,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.sandbox_manager.SandboxManager",
        FakeSandboxManager,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b-static",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    _run_auto_execute(output_payload, config, FakeTokenBroker())

    assert captured_reviewer_tokens == ["token-b-live", "token-c-live"]


def test_auto_execute_marks_human_review_and_continues_to_next_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace_a = tmp_path / "repo-a"
    workspace_b = tmp_path / "repo-b"
    workspace_a.mkdir(parents=True, exist_ok=True)
    workspace_b.mkdir(parents=True, exist_ok=True)

    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-a",
                "risks": [
                    {
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-a",
                            "user_b_fork": "attacker/repo-a",
                            "workspace_path": str(workspace_a),
                            "flagged_for_human_review": False,
                        }
                    }
                ],
            },
            {
                "name": "owner/repo-b",
                "risks": [
                    {
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-b",
                            "user_b_fork": "attacker/repo-b",
                            "workspace_path": str(workspace_b),
                            "flagged_for_human_review": False,
                        }
                    }
                ],
            },
        ]
    }

    executed_repositories: list[str] = []

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            return None

        def execute_attack(self, **kwargs):
            repo_name = kwargs["repo_name"]
            executed_repositories.append(repo_name)
            if repo_name == "owner/repo-a":
                return {
                    "vulnerable": False,
                    "needs_human_review": True,
                    "status": "human_review_required",
                    "reason": "requires paid third-party account",
                    "controller_signal": {"status": "needs_human_review"},
                    "pull_request_url": "https://github.com/playground/repo-a/pull/11",
                }
            return {
                "vulnerable": False,
                "reason": "not exploitable",
                "pull_request_url": "https://github.com/playground/repo-b/pull/12",
            }

    class FakeHookbinClient:
        pass

    class FakeSandboxManager:
        def __init__(self, *args, **kwargs) -> None:
            _ = (args, kwargs)

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.hookbin_client.HookbinClient",
        FakeHookbinClient,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.sandbox_manager.SandboxManager",
        FakeSandboxManager,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())

    assert executed_repositories == ["owner/repo-a", "owner/repo-b"]
    risk_a = result["ai_enumeration"][0]["risks"][0]["attack_result"]
    risk_b = result["ai_enumeration"][1]["risks"][0]["attack_result"]
    assert isinstance(result["ai_enumeration"][0]["risks"][0]["attack_processed_time"], str)
    assert result["ai_enumeration"][0]["risks"][0]["attack_processed_time"]
    assert isinstance(result["ai_enumeration"][1]["risks"][0]["attack_processed_time"], str)
    assert result["ai_enumeration"][1]["risks"][0]["attack_processed_time"]
    assert risk_a["status"] == "human_review_required"
    assert risk_a["flagged_for_human_review"] is True
    assert risk_a["reason"] == "requires paid third-party account"
    assert risk_a["pull_request_url"] == "https://github.com/playground/repo-a/pull/11"
    assert result["ai_enumeration"][0]["repo_vulnerable"] == "unknown"
    assert result["ai_enumeration"][0]["act_repo_vulnerable"] is False
    assert risk_b["execution_result"]["reason"] == "not exploitable"
    assert risk_b["status"] == "not_vulnerable_after_execution"
    assert risk_b["reason"] == "not exploitable"
    assert risk_b["pull_request_url"] == "https://github.com/playground/repo-b/pull/12"
    assert result["ai_enumeration"][1]["repo_vulnerable"] == "false"
    assert result["ai_enumeration"][1]["act_repo_vulnerable"] is False


def test_run_auto_execute_marks_node_runtime_skip_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-a",
                "risks": [
                    {
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-a",
                            "user_b_fork": "attacker/repo-a",
                            "workspace_path": str(tmp_path / "workspace"),
                            "source_default_branch": "main",
                            "agent_runtime": {"base_url": None},
                        }
                    }
                ],
            }
        ]
    }

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            agent_runtime=None,
            agent_provider=None,
            openhands_manager=None,
            use_host_agent_directly=False,
            use_host_openhands_directly=False,
        ) -> None:
            _ = (
                github_client_factory,
                hookbin_client,
                sandbox_manager,
                agent_runtime,
                agent_provider,
                openhands_manager,
                use_host_agent_directly,
                use_host_openhands_directly,
            )

        def execute_attack(self, **kwargs):
            _ = kwargs
            return {
                "vulnerable": False,
                "status": "skipped_node_runtime_unavailable",
                "reason": "Gemini CLI skipped: unable to activate Node.js 24, 22, or 20 via nvm.",
            }

    class FakeHookbinClient:
        pass

    class FakeSandboxManager:
        def __init__(self, *args, **kwargs) -> None:
            _ = (args, kwargs)

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.hookbin_client.HookbinClient",
        FakeHookbinClient,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.sandbox_manager.SandboxManager",
        FakeSandboxManager,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())
    attack_result = result["ai_enumeration"][0]["risks"][0]["attack_result"]
    assert attack_result["status"] == "skipped_node_runtime_unavailable"
    assert "node.js 24, 22, or 20" in attack_result["reason"].lower()
    assert result["ai_enumeration"][0]["repo_vulnerable"] == "unknown"
    assert result["ai_enumeration"][0]["act_repo_vulnerable"] is False


def test_run_auto_execute_preserves_execution_error_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-a",
                "risks": [
                    {
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-a",
                            "user_b_fork": "attacker/repo-a",
                            "workspace_path": str(tmp_path / "workspace"),
                            "source_default_branch": "main",
                            "agent_runtime": {"base_url": None},
                        }
                    }
                ],
            }
        ]
    }

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            agent_runtime=None,
            agent_provider=None,
            openhands_manager=None,
            use_host_agent_directly=False,
            use_host_openhands_directly=False,
        ) -> None:
            _ = (
                github_client_factory,
                hookbin_client,
                sandbox_manager,
                agent_runtime,
                agent_provider,
                openhands_manager,
                use_host_agent_directly,
                use_host_openhands_directly,
            )

        def execute_attack(self, **kwargs):
            _ = kwargs
            return {
                "vulnerable": False,
                "status": "execution_error",
                "reason": "PR never became visible after creation.",
                "error_stage": "execution",
                "error_class": "pr_not_visible_after_create",
                "failure_fingerprint": "pr_fetch_404_after_create",
            }

    class FakeHookbinClient:
        pass

    class FakeSandboxManager:
        def __init__(self, *args, **kwargs) -> None:
            _ = (args, kwargs)

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.hookbin_client.HookbinClient",
        FakeHookbinClient,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.sandbox_manager.SandboxManager",
        FakeSandboxManager,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())
    attack_result = result["ai_enumeration"][0]["risks"][0]["attack_result"]
    assert attack_result["status"] == "execution_error"
    assert attack_result["error_class"] == "pr_not_visible_after_create"
    assert attack_result["failure_fingerprint"] == "pr_fetch_404_after_create"


def test_auto_execute_uses_host_sandbox_when_no_sandbox_enabled(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_payload = {"ai_enumeration": []}
    captured: dict[str, object] = {}

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
            use_host_openhands_directly=False,
        ) -> None:
            _ = (github_client_factory, hookbin_client, sandbox_manager, openhands_manager)
            captured["use_host_openhands_directly"] = use_host_openhands_directly

    class FakeHookbinClient:
        pass

    class FakeSandboxManager:
        def __init__(self, *args, **kwargs) -> None:
            captured["sandbox_manager_kwargs"] = kwargs

    class FakeTokenProbeService:
        def __init__(self, github_client_factory, workflow_timeout: int) -> None:
            _ = (github_client_factory, workflow_timeout)

    class _FakeTracer:
        def flush(self) -> None:
            return None

    class FakeTokenBroker:
        def reserve(self, _repo_name: str):
            raise AssertionError("reserve should not be called for empty payload")

        def release(self, _lease) -> None:
            raise AssertionError("release should not be called for empty payload")

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.hookbin_client.HookbinClient",
        FakeHookbinClient,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.sandbox_manager.SandboxManager",
        FakeSandboxManager,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe.GitHubTokenProbeService",
        FakeTokenProbeService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.build_tracer", lambda **kwargs: _FakeTracer())

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        no_sandbox=True,
    )

    _run_auto_execute(output_payload, config, FakeTokenBroker())

    assert captured["sandbox_manager_kwargs"] == {"use_host": True}
    assert captured["use_host_openhands_directly"] is True


def test_auto_execute_marks_human_review_from_status_without_needs_flag(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo-human-review-status-only"
    workspace.mkdir(parents=True, exist_ok=True)

    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-status-only",
                "risks": [
                    {
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-status-only",
                            "user_b_fork": "attacker/repo-status-only",
                            "workspace_path": str(workspace),
                            "flagged_for_human_review": False,
                        }
                    }
                ],
            }
        ]
    }

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            _ = (github_client_factory, hookbin_client, sandbox_manager, openhands_manager)

        def execute_attack(self, **kwargs):
            _ = kwargs
            return {
                "vulnerable": False,
                "status": "human_review_required",
                "reason": "OpenHands requested human review via status only.",
            }

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())
    attack_result = result["ai_enumeration"][0]["risks"][0]["attack_result"]
    assert attack_result["status"] == "human_review_required"
    assert attack_result["flagged_for_human_review"] is True
    assert attack_result["reason"] == "OpenHands requested human review via status only."


def test_auto_execute_marks_human_review_for_non_committable_retry_exhausted_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo-non-committable-retries"
    workspace.mkdir(parents=True, exist_ok=True)

    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-non-committable-retries",
                "risks": [
                    {
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-non-committable-retries",
                            "user_b_fork": "attacker/repo-non-committable-retries",
                            "workspace_path": str(workspace),
                            "flagged_for_human_review": False,
                        }
                    }
                ],
            }
        ]
    }

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            _ = (github_client_factory, hookbin_client, sandbox_manager, openhands_manager)

        def execute_attack(self, **kwargs):
            _ = kwargs
            return {
                "vulnerable": False,
                "reason": (
                    "Repository changed, but controller could not commit any eligible "
                    "files after retries."
                ),
            }

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())
    attack_result = result["ai_enumeration"][0]["risks"][0]["attack_result"]
    assert attack_result["status"] == "human_review_required"
    assert attack_result["flagged_for_human_review"] is True
    assert (
        attack_result["reason"]
        == "Repository changed, but controller could not commit any eligible files after retries."
    )


def test_auto_execute_precheck_skips_openhands_when_human_review_required(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo-human-review"
    workspace.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-human-review",
                "risks": [
                    {
                        "ai-analysis": {
                            "vulnerable": True,
                            "confidence": "high",
                            "explanation": "The workflow uses a maintainer label trust gate.",
                            "impact": "RCE",
                            "poc": "x",
                        },
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-human-review",
                            "user_b_fork": "attacker/repo-human-review",
                            "workspace_path": str(workspace),
                            "flagged_for_human_review": False,
                        },
                    }
                ],
            }
        ]
    }

    class FakeGeminiAnalyzer:
        def __init__(self, api_key: str, model: str) -> None:
            assert api_key == "gemini-key"
            assert model == "gemini-3.1-flash-lite-preview"

        def analyze_human_review_precheck(self, ai_analysis, metadata=None):
            _ = (ai_analysis, metadata)
            return {
                "needs_human_review": True,
                "reason": "Detected maintainer-label trust gate in ai-analysis.",
            }

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            _ = (github_client_factory, hookbin_client, sandbox_manager, openhands_manager)

        def execute_attack(self, **kwargs):
            precheck = kwargs["human_review_precheck"](
                ai_analysis=kwargs["ai_analysis"],
                metadata=kwargs["human_review_precheck_metadata"],
            )
            assert precheck["needs_human_review"] is True
            return {
                "vulnerable": False,
                "needs_human_review": True,
                "status": "human_review_required",
                "reason": precheck["reason"],
                "controller_signal": {
                    "status": "needs_human_review",
                    "source": "gemini_human_review_precheck",
                },
                "human_review_precheck": precheck,
            }

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr("pwn_hunter_ai.cli.GeminiAnalyzer", FakeGeminiAnalyzer)
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        gemini_api_key="gemini-key",
        billing="api",
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())

    attack_result = result["ai_enumeration"][0]["risks"][0]["attack_result"]
    assert attack_result["status"] == "human_review_required"
    assert attack_result["flagged_for_human_review"] is True
    assert "trust gate" in attack_result["reason"].lower()
    assert (
        attack_result["execution_result"]["controller_signal"]["source"]
        == "gemini_human_review_precheck"
    )


def test_auto_execute_passes_no_ai_analysis_for_gato_x_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo-gato"
    workspace.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-gato",
                "risks": [
                    {
                        "attack_input_source": "gato-x",
                        "gato-x-path": [
                            {
                                "node": (
                                    "WorkflowNode('owner/repo-gato:main:.github/workflows/ci.yml')"
                                )
                            }
                        ],
                        "gato-x-sink": "make test",
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-gato",
                            "user_b_fork": "attacker/repo-gato",
                            "workspace_path": str(workspace),
                            "focused_workflow": ".github/workflows/ci.yml",
                            "focused_workflows": [".github/workflows/ci.yml"],
                            "focused_workflow_refs": [
                                {
                                    "repo_name": "owner/repo-gato",
                                    "path": ".github/workflows/ci.yml",
                                    "ref": "main",
                                }
                            ],
                            "source_default_branch": "main",
                            "agent_runtime": {"base_url": None},
                            "flagged_for_human_review": False,
                        },
                    }
                ],
            }
        ]
    }

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            _ = (github_client_factory, hookbin_client, sandbox_manager, openhands_manager)

        def execute_attack(self, **kwargs):
            assert kwargs["ai_analysis"] is None
            assert kwargs["focused_workflow"] == ".github/workflows/ci.yml"
            assert callable(kwargs["human_review_precheck"])
            return {
                "vulnerable": False,
                "status": "not_vulnerable_after_execution",
                "reason": "No exploit path confirmed.",
            }

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        gemini_api_key="gemini-key",
        billing="api",
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())

    attack_result = result["ai_enumeration"][0]["risks"][0]["attack_result"]
    assert attack_result["status"] == "not_vulnerable_after_execution"
    assert attack_result["flagged_for_human_review"] is False


def test_auto_execute_marks_vulnerable_when_execution_succeeds(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo-v"
    workspace.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-v",
                "risks": [
                    {
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-v",
                            "user_b_fork": "attacker/repo-v",
                            "workspace_path": str(workspace),
                            "flagged_for_human_review": False,
                        }
                    }
                ],
            }
        ]
    }

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            return None

        def execute_attack(self, **kwargs):
            _ = kwargs
            return {
                "vulnerable": True,
                "attempt": 1,
                "run_id": 123,
                "pull_request_url": "https://github.com/playground/repo-v/pull/13",
                "security_report": {
                    "status": "generated",
                    "verification_sources": ["hosted"],
                    "workspace_path": str(workspace / "REPORT.md"),
                    "persisted_path": str(
                        tmp_path
                        / "security-reports"
                        / "owner-repo-v-risk-1-github-workflows-ci.yml.md"
                    ),
                },
            }

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())
    attack_result = result["ai_enumeration"][0]["risks"][0]["attack_result"]
    assert isinstance(result["ai_enumeration"][0]["risks"][0]["attack_processed_time"], str)
    assert result["ai_enumeration"][0]["risks"][0]["attack_processed_time"]
    assert attack_result["status"] == "vulnerable_confirmed"
    assert attack_result["reason"] == "Auto execution confirmed the repository is vulnerable."
    assert attack_result["pull_request_url"] == "https://github.com/playground/repo-v/pull/13"
    assert attack_result["security_report_status"] == "generated"
    assert attack_result["security_report_verification_sources"] == ["hosted"]
    assert attack_result["security_report_path"].endswith(
        "owner-repo-v-risk-1-github-workflows-ci.yml.md"
    )
    assert result["ai_enumeration"][0]["repo_vulnerable"] == "true"
    assert result["ai_enumeration"][0]["act_repo_vulnerable"] is False


def test_auto_execute_sets_attempt_metadata_and_default_reason_for_non_vulnerable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo-nv"
    workspace.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-nv",
                "risks": [
                    {
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "reason": "Owned forks and workflow scan are complete. PR execution remains manual.",
                            "attempt_count": 0,
                            "attempts": [],
                            "user_a_fork": "playground/repo-nv",
                            "user_b_fork": "attacker/repo-nv",
                            "workspace_path": str(workspace),
                            "flagged_for_human_review": False,
                        }
                    }
                ],
            }
        ]
    }

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            return None

        def execute_attack(self, **kwargs):
            _ = kwargs
            return {
                "vulnerable": False,
                "attempt": 2,
                "attempt_count": 2,
                "attempts": [
                    {"attempt": 1, "conclusion": "failure"},
                    {"attempt": 2, "conclusion": "failure"},
                ],
            }

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())
    attack_result = result["ai_enumeration"][0]["risks"][0]["attack_result"]
    assert attack_result["status"] == "not_vulnerable_after_execution"
    assert attack_result["reason"] == "Auto execution did not confirm vulnerability."
    assert attack_result["attempt_count"] == 2
    assert attack_result["attempts"] == [
        {"attempt": 1, "conclusion": "failure"},
        {"attempt": 2, "conclusion": "failure"},
    ]
    assert result["ai_enumeration"][0]["repo_vulnerable"] == "false"
    assert result["ai_enumeration"][0]["act_repo_vulnerable"] is False


def test_auto_execute_sets_act_repo_vulnerable_from_successful_local_test_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo-act-success"
    workspace.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-act-success",
                "risks": [
                    {
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "reason": "Owned forks and workflow scan are complete. PR execution remains manual.",
                            "attempt_count": 0,
                            "attempts": [],
                            "user_a_fork": "playground/repo-act-success",
                            "user_b_fork": "attacker/repo-act-success",
                            "workspace_path": str(workspace),
                            "flagged_for_human_review": False,
                        }
                    }
                ],
            }
        ]
    }

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            return None

        def execute_attack(self, **kwargs):
            _ = kwargs
            return {
                "vulnerable": False,
                "attempt_count": 1,
                "attempts": [
                    {
                        "attempt": 1,
                        "conclusion": "failure",
                        "agent_output": {"local_test_result": "success"},
                    }
                ],
            }

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())
    assert result["ai_enumeration"][0]["act_repo_vulnerable"] is True


def test_auto_execute_passes_source_default_branch_and_focused_workflow(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo-default-branch"
    workspace.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-default-branch",
                "risks": [
                    {
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-default-branch",
                            "user_b_fork": "attacker/repo-default-branch",
                            "workspace_path": str(workspace),
                            "focused_workflow": ".github/workflows/summary.yml",
                            "focused_workflows": [
                                ".github/workflows/summary.yml",
                                ".github/workflows/preview-image.yml",
                            ],
                            "focused_workflow_refs": [
                                {
                                    "repo_name": "owner/repo-default-branch",
                                    "path": ".github/workflows/summary.yml",
                                    "ref": "main",
                                },
                                {
                                    "repo_name": "other/reusable",
                                    "path": ".github/workflows/preview-image.yml",
                                    "ref": "master",
                                },
                            ],
                            "source_default_branch": "master",
                            "seeded_secrets": ["FERN_TOKEN", "CUSTOM_TOKEN"],
                            "shared_secrets_state_path": str(
                                tmp_path / "repo-shared-secrets.json"
                            ),
                            "flagged_for_human_review": False,
                        }
                    }
                ],
            }
        ]
    }
    captured_kwargs: dict[str, object] = {}
    captured_constructor: dict[str, object] = {}

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
            security_reports_dir: Path | None = None,
        ) -> None:
            _ = (github_client_factory, hookbin_client, sandbox_manager, openhands_manager)
            captured_constructor["security_reports_dir"] = security_reports_dir

        def execute_attack(self, **kwargs):
            captured_kwargs.update(kwargs)
            return {"vulnerable": False, "reason": "not exploitable"}

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        generate_security_report=True,
    )

    _run_auto_execute(output_payload, config, FakeTokenBroker())

    assert captured_kwargs["default_branch"] == "master"
    assert captured_kwargs["focused_workflow"] == ".github/workflows/summary.yml"
    assert captured_kwargs["focused_workflows"] == [
        ".github/workflows/summary.yml",
        ".github/workflows/preview-image.yml",
    ]
    assert captured_kwargs["focused_workflow_refs"] == [
        {
            "repo_name": "owner/repo-default-branch",
            "path": ".github/workflows/summary.yml",
            "ref": "main",
        },
        {
            "repo_name": "other/reusable",
            "path": ".github/workflows/preview-image.yml",
            "ref": "master",
        },
    ]
    assert captured_kwargs["seeded_secrets"] == ["FERN_TOKEN", "CUSTOM_TOKEN"]
    assert captured_kwargs["risk_index"] == 0
    assert captured_kwargs["shared_secrets_state_path"] == (
        tmp_path / "repo-shared-secrets.json"
    )
    assert captured_constructor["security_reports_dir"] == (
        tmp_path / "security-reports"
    )
    assert (tmp_path / "security-reports").exists()


def test_auto_execute_runs_token_probe_after_agentic_when_needed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo-v2"
    workspace.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-v2",
                "vulnerable_commit_hash": "deadbeef",
                "risks": [
                    {
                        "github_token_permissions": {"status": "unknown"},
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-v2",
                            "user_b_fork": "attacker/repo-v2",
                            "workspace_path": str(workspace),
                            "flagged_for_human_review": False,
                            "focused_workflow": ".github/workflows/pull_request.yml",
                            "github_token_probe_timing": "after_agentic",
                            "source_default_branch": "main",
                        },
                    }
                ],
            }
        ]
    }

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            return None

        def execute_attack(self, **kwargs):
            _ = kwargs
            return {"vulnerable": True, "attempt": 1, "run_id": 123}

    observed_probe_timeout: int | None = None

    class FakeProbeService:
        def __init__(self, github_client_factory, workflow_timeout=120) -> None:
            _ = github_client_factory
            nonlocal observed_probe_timeout
            observed_probe_timeout = workflow_timeout

        def resolve_unknown_status(self, **kwargs):
            _ = kwargs
            return {
                "resolved_permissions": {
                    "status": "write",
                    "reason": "probe_write_permission_found_in_setup_job",
                    "evidence_log_url": "https://example/actions/runs/1",
                },
                "probe": {"status": "completed", "pr_number": 1},
            }

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe.GitHubTokenProbeService",
        FakeProbeService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())
    risk = result["ai_enumeration"][0]["risks"][0]
    assert risk["attack_result"]["status"] == "vulnerable_confirmed"
    assert risk["github_token_permissions"]["status"] == "write"
    assert risk["attack_result"]["github_token_permissions"]["status"] == "write"
    assert risk["attack_result"]["github_token_permissions_classification"] == "write"
    assert risk["attack_result"]["github_token_probe"]["pr_number"] == 1
    assert observed_probe_timeout == 90


def test_auto_execute_does_not_pass_skip_permission_log_read_to_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo-v2-skip-logs"
    workspace.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-v2-skip-logs",
                "vulnerable_commit_hash": "deadbeef",
                "risks": [
                    {
                        "github_token_permissions": {"status": "unknown"},
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-v2-skip-logs",
                            "user_b_fork": "attacker/repo-v2-skip-logs",
                            "workspace_path": str(workspace),
                            "flagged_for_human_review": False,
                            "focused_workflow": ".github/workflows/pull_request.yml",
                            "github_token_probe_timing": "after_agentic",
                            "source_default_branch": "main",
                        },
                    }
                ],
            }
        ]
    }
    captured_probe_kwargs: dict[str, object] = {}

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            _ = (github_client_factory, hookbin_client, sandbox_manager, openhands_manager)

        def execute_attack(self, **kwargs):
            _ = kwargs
            return {"vulnerable": True, "attempt": 1, "run_id": 123}

    class FakeProbeService:
        def __init__(self, github_client_factory, workflow_timeout=120) -> None:
            _ = (github_client_factory, workflow_timeout)

        def resolve_unknown_status(self, **kwargs):
            captured_probe_kwargs.update(kwargs)
            return {
                "resolved_permissions": {
                    "status": "write",
                    "reason": "probe_write_permission_found_in_setup_job",
                    "evidence_log_url": "https://example/actions/runs/7",
                },
                "probe": {"status": "completed", "pr_number": 7},
            }

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe.GitHubTokenProbeService",
        FakeProbeService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        skip_permission_log_read=True,
    )

    _run_auto_execute(output_payload, config, FakeTokenBroker())
    assert "skip_permission_log_read" not in captured_probe_kwargs


def test_auto_execute_reuses_token_probe_per_repository(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace_a = tmp_path / "repo-v3-a"
    workspace_b = tmp_path / "repo-v3-b"
    workspace_a.mkdir(parents=True, exist_ok=True)
    workspace_b.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-v3",
                "vulnerable_commit_hash": "deadbeef",
                "risks": [
                    {
                        "github_token_permissions": {"status": "unknown"},
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-v3",
                            "user_b_fork": "attacker/repo-v3",
                            "workspace_path": str(workspace_a),
                            "flagged_for_human_review": False,
                            "focused_workflow": ".github/workflows/pull_request.yml",
                            "github_token_probe_timing": "after_agentic",
                            "source_default_branch": "main",
                        },
                    },
                    {
                        "github_token_permissions": {"status": "unknown"},
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-v3",
                            "user_b_fork": "attacker/repo-v3",
                            "workspace_path": str(workspace_b),
                            "flagged_for_human_review": False,
                            "focused_workflow": ".github/workflows/pull_request.yml",
                            "github_token_probe_timing": "after_agentic",
                            "source_default_branch": "main",
                        },
                    },
                ],
            }
        ]
    }
    probe_calls: list[str] = []

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            return None

        def execute_attack(self, **kwargs):
            _ = kwargs
            return {"vulnerable": True, "attempt": 1, "run_id": 123}

    class FakeProbeService:
        def __init__(self, github_client_factory, workflow_timeout=120) -> None:
            _ = (github_client_factory, workflow_timeout)

        def resolve_unknown_status(self, **kwargs):
            probe_calls.append(kwargs["repo_name"])
            return {
                "resolved_permissions": {
                    "status": "write",
                    "reason": "probe_write_permission_found_in_setup_job",
                    "evidence_log_url": "https://example/actions/runs/2",
                },
                "probe": {"status": "completed", "pr_number": 2},
            }

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe.GitHubTokenProbeService",
        FakeProbeService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())
    assert probe_calls == ["owner/repo-v3"]
    first_risk = result["ai_enumeration"][0]["risks"][0]
    second_risk = result["ai_enumeration"][0]["risks"][1]
    assert first_risk["github_token_permissions"]["status"] == "write"
    assert second_risk["github_token_permissions"]["status"] == "write"
    assert first_risk["attack_result"]["github_token_permissions"]["status"] == "write"
    assert second_risk["attack_result"]["github_token_permissions"]["status"] == "write"
    assert first_risk["attack_result"]["github_token_permissions_classification"] == "write"
    assert second_risk["attack_result"]["github_token_permissions_classification"] == "write"
    assert first_risk["attack_result"]["github_token_probe"]["pr_number"] == 2
    assert second_risk["attack_result"]["github_token_probe"]["pr_number"] == 2


def test_auto_execute_does_not_probe_when_permissions_not_clear(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "repo-not-clear"
    workspace.mkdir(parents=True, exist_ok=True)
    output_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-not-clear",
                "vulnerable_commit_hash": "deadbeef",
                "risks": [
                    {
                        "github_token_permissions": {"status": "not-clear"},
                        "attack_result": {
                            "status": "prepared_for_manual_validation",
                            "user_a_fork": "playground/repo-not-clear",
                            "user_b_fork": "attacker/repo-not-clear",
                            "workspace_path": str(workspace),
                            "flagged_for_human_review": False,
                            "focused_workflow": ".github/workflows/pull_request.yml",
                            "github_token_probe_timing": "not_needed",
                            "github_token_permissions_classification": "not-clear",
                            "source_default_branch": "main",
                        },
                    }
                ],
            }
        ]
    }
    probe_calls: list[str] = []

    class FakeExecutionService:
        def __init__(
            self,
            github_client_factory,
            hookbin_client,
            sandbox_manager,
            openhands_manager=None,
        ) -> None:
            _ = (github_client_factory, hookbin_client, sandbox_manager, openhands_manager)

        def execute_attack(self, **kwargs):
            _ = kwargs
            return {"vulnerable": True, "attempt": 1, "run_id": 321}

    class FakeProbeService:
        def __init__(self, github_client_factory, workflow_timeout=120) -> None:
            _ = (github_client_factory, workflow_timeout)

        def resolve_unknown_status(self, **kwargs):
            probe_calls.append(kwargs["repo_name"])
            return {
                "resolved_permissions": {"status": "write"},
                "probe": {"status": "completed", "pr_number": 9},
            }

    class FakeTokenLease:
        def __init__(self) -> None:
            self.user_a_token = "token-a"
            self.user_b_token = "token-b"

    class FakeTokenBroker:
        def reserve(self, _repo_name: str) -> FakeTokenLease:
            return FakeTokenLease()

        def release(self, _lease: FakeTokenLease) -> None:
            return None

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe.GitHubTokenProbeService",
        FakeProbeService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FakeAttackGitHubClient)

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
    )

    result = _run_auto_execute(output_payload, config, FakeTokenBroker())
    risk = result["ai_enumeration"][0]["risks"][0]
    assert risk["attack_result"]["status"] == "vulnerable_confirmed"
    assert probe_calls == []
    assert risk["attack_result"].get("github_token_probe") is None
    assert risk["attack_result"]["github_token_permissions_classification"] == "not-clear"


def test_attack_cleanup_command_accepts_artifact_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_root = tmp_path / "artifact-root"
    artifact_root.mkdir()
    input_path = tmp_path / "prepared.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {
                        "risks": [
                            {
                                "attack_result": {
                                    "artifact_root": str(artifact_root),
                                    "user_a_fork": "user-a/repo",
                                    "user_b_fork": "user-b/repo",
                                }
                            }
                        ]
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    called = {}

    class FakeCleanupService:
        def __init__(self, github_client_factory) -> None:
            return None

        def run(self, input_payload, *, github_token: str, delete_forks: bool, delete_artifacts: bool):
            called["github_token"] = github_token
            called["delete_forks"] = delete_forks
            called["delete_artifacts"] = delete_artifacts
            return {"deleted_forks": [], "deleted_artifacts": [str(artifact_root)]}

    monkeypatch.setattr("pwn_hunter_ai.cli.AttackCleanupService", FakeCleanupService)

    exit_code = main(
        [
            "attack-cleanup",
            "--input",
            str(input_path),
            "--github-token",
            "token-a",
            "--delete-artifacts",
        ]
    )

    assert exit_code == 0
    assert called == {
        "github_token": "token-a",
        "delete_forks": False,
        "delete_artifacts": True,
    }


def test_attack_command_builds_openhands_manager_with_langfuse_from_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(json.dumps({"ai_enumeration": []}), encoding="utf-8")

    captured: dict[str, object] = {}

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            captured["openhands_manager"] = kwargs.get("openhands_manager")

        def run(self, input_payload, *, parallel_jobs: int):
            return {"ai_enumeration": []}

    monkeypatch.setattr(
        "pwn_hunter_ai.cli.AttackPreparationService", FakeAttackPreparationService
    )
    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-lf-test")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-lf-test")
    monkeypatch.setenv("LANGFUSE_HOST", "https://us.cloud.langfuse.com")

    exit_code = main(
        [
            "attack",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--github-tokens-user-a",
            "token-a",
            "--github-tokens-user-b",
            "token-b",
            "--agent-provider",
            "openhands",
            "--launch-agent",
        ]
    )

    assert exit_code == 0
    manager = captured["openhands_manager"]
    assert manager is not None
    assert manager._tracing is not None
    assert manager._tracing.metadata() == {
        "enabled": True,
        "service_name": "pwnhunter-attack-openhands",
        "endpoint": "https://us.cloud.langfuse.com/api/public/otel",
    }


def test_attack_command_builds_gemini_runtime_with_provider_and_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from pwn_hunter_ai.attack.gemini_cli_manager import GeminiCliRuntimeManager

    input_path = tmp_path / "input.json"
    output_path = tmp_path / "output.json"
    input_path.write_text(json.dumps({"ai_enumeration": []}), encoding="utf-8")

    captured: dict[str, object] = {}

    class FakeTokenBroker:
        def __init__(self, **kwargs) -> None:
            _ = kwargs
            self.user_b_capacity = 1

    class FakeAttackPreparationService:
        def __init__(self, **kwargs) -> None:
            captured["agent_provider"] = kwargs.get("agent_provider")
            captured["agent_runtime"] = kwargs.get("agent_runtime")

        def run(self, input_payload, *, parallel_jobs: int):
            _ = (input_payload, parallel_jobs)
            return {"ai_enumeration": []}

    monkeypatch.setattr("pwn_hunter_ai.cli.AttackTokenBroker", FakeTokenBroker)
    monkeypatch.setattr(
        "pwn_hunter_ai.cli.AttackPreparationService", FakeAttackPreparationService
    )

    exit_code = main(
        [
            "attack",
            "--input",
            str(input_path),
            "--output",
            str(output_path),
            "--github-tokens-user-a",
            "token-a",
            "--github-tokens-user-b",
            "token-b",
            "--launch-agent",
            "--agent-provider",
            "gemini-cli",
            "--agent-model",
            "gemini-2.5-pro",
        ]
    )

    assert exit_code == 0
    assert captured["agent_provider"] == "gemini-cli"
    runtime = captured["agent_runtime"]
    assert isinstance(runtime, GeminiCliRuntimeManager)
    assert runtime.provider_name.value == "gemini-cli"
    assert runtime._config.model == "gemini-2.5-pro"


def test_auto_execute_builds_gemini_runtime_for_execution_service(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    captured: dict[str, object] = {}

    class FakeExecutionService:
        def __init__(self, **kwargs) -> None:
            captured.update(kwargs)

    class FakeHookbinClient:
        pass

    class FakeSandboxManager:
        def __init__(self, *args, **kwargs) -> None:
            _ = (args, kwargs)

    class FakeTokenProbeService:
        def __init__(self, github_client_factory, workflow_timeout: int) -> None:
            _ = (github_client_factory, workflow_timeout)

    class _FakeTracer:
        def flush(self) -> None:
            return None

    class FakeTokenBroker:
        def reserve(self, _repo_name: str):
            raise AssertionError("reserve should not be called for empty payload")

        def release(self, _lease) -> None:
            raise AssertionError("release should not be called for empty payload")

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.AttackExecutionService",
        FakeExecutionService,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.hookbin_client.HookbinClient",
        FakeHookbinClient,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.sandbox_manager.SandboxManager",
        FakeSandboxManager,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe.GitHubTokenProbeService",
        FakeTokenProbeService,
    )
    monkeypatch.setattr("pwn_hunter_ai.cli.build_tracer", lambda **kwargs: _FakeTracer())

    config = AttackCLIConfig(
        input_path=tmp_path / "unused-input.json",
        output_path=tmp_path / "unused-output.json",
        artifacts_dir=tmp_path / "artifacts",
        parallel_jobs=1,
        max_retries=3,
        github_tokens_user_a="token-a",
        github_tokens_user_b="token-b",
        reset_forks=False,
        dry_run=False,
        launch_agent=False,
        auto_execute=True,
        agent_timeout=900,
        workflow_timeout=60,
        openhands_host="127.0.0.1",
        openhands_start_port=3000,
        langfuse_public_key=None,
        langfuse_secret_key=None,
        langfuse_host=None,
        log_file=tmp_path / "attack.log",
        log_level="INFO",
        verbose=False,
        agent_provider="gemini-cli",
        agent_model="gemini-2.5-flash",
    )

    _run_auto_execute({"ai_enumeration": []}, config, FakeTokenBroker())

    runtime = captured["agent_runtime"]
    assert captured["agent_provider"] == "gemini-cli"
    assert runtime.provider_name.value == "gemini-cli"
    assert runtime._config.model == "gemini-2.5-flash"


def test_review_command_dispatches_with_env_token(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "review.json"
    input_path.write_text(json.dumps({"ai_enumeration": []}), encoding="utf-8")
    monkeypatch.setenv("GITHUB_TOKEN", "token-from-env")

    captured: dict[str, object] = {}

    def fake_run_review(*, input_path: Path, github_token: str, host: str, port: int) -> None:
        captured["input_path"] = input_path
        captured["github_token"] = github_token
        captured["host"] = host
        captured["port"] = port

    monkeypatch.setattr("pwn_hunter_ai.cli.run_review", fake_run_review)

    exit_code = main(
        [
            "review",
            "--input",
            str(input_path),
            "--host",
            "0.0.0.0",
            "--port",
            "9000",
        ]
    )

    assert exit_code == 0
    assert captured == {
        "input_path": input_path,
        "github_token": "token-from-env",
        "host": "0.0.0.0",
        "port": 9000,
    }


def test_run_review_detects_attack_output_payload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "attack-results.json"
    input_path.write_text(
        json.dumps(
            {
                "ai_enumeration": [
                    {
                        "name": "owner/repo",
                        "risks": [
                            {
                                "issue_type": "pull_request_target",
                                "attack_result": {"status": "vulnerable_confirmed"},
                            }
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    captured: dict[str, object] = {}

    class _FakeReviewGitHubClient:
        def __init__(self, tokens: list[str]) -> None:
            captured["tokens"] = tokens

    def _fake_resolve_symbol(name: str):
        if name == "GitHubClient":
            return _FakeReviewGitHubClient
        raise AssertionError(f"Unexpected symbol: {name}")

    def _fake_run_review_server(**kwargs) -> None:
        captured["payload"] = kwargs["payload"]
        captured["input_path"] = kwargs["input_path"]
        captured["host"] = kwargs["host"]
        captured["port"] = kwargs["port"]

    monkeypatch.setattr(cli_module, "_resolve_symbol", _fake_resolve_symbol)
    monkeypatch.setattr(cli_module, "run_review_server", _fake_run_review_server)

    cli_module.run_review(
        input_path=input_path,
        github_token="token-1",
        host="127.0.0.1",
        port=8765,
    )

    assert captured["tokens"] == ["token-1"]
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["ai_enumeration"][0]["name"] == "owner/repo"
    assert captured["input_path"] == input_path
    assert captured["host"] == "127.0.0.1"
    assert captured["port"] == 8765


def test_run_review_raises_for_unknown_input_shape(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    input_path = tmp_path / "unsupported.json"
    input_path.write_text(json.dumps({"unexpected": []}), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported review input JSON"):
        cli_module.run_review(
            input_path=input_path,
            github_token="token-1",
            host="127.0.0.1",
            port=8765,
        )


def test_review_command_requires_token(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    input_path = tmp_path / "review.json"
    input_path.write_text(json.dumps({"ai_enumeration": []}), encoding="utf-8")
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.chdir(tmp_path)

    with pytest.raises(SystemExit):
        main(["review", "--input", str(input_path)])


def test_reserve_attack_lease_prefers_owner_aware_reservation() -> None:
    captured: dict[str, object] = {}

    class FakeBroker:
        def reserve_for_owners(self, repository_name: str, **kwargs):
            captured["repository_name"] = repository_name
            captured["kwargs"] = kwargs
            return "owner-aware-lease"

    lease = cli_module._reserve_attack_lease(
        token_broker=FakeBroker(),
        repository_name="owner/repo",
        expected_user_a_owner="user-a",
        expected_user_b_owner="user-b",
    )

    assert lease == "owner-aware-lease"
    assert captured["repository_name"] == "owner/repo"
    assert captured["kwargs"] == {
        "user_a_owner": "user-a",
        "user_b_owner": "user-b",
        "require_owner_match": True,
    }


def test_reserve_attack_lease_falls_back_to_plain_reserve() -> None:
    class FakeBroker:
        def reserve(self, repository_name: str):
            return {"repository_name": repository_name}

    lease = cli_module._reserve_attack_lease(
        token_broker=FakeBroker(),
        repository_name="owner/repo",
        expected_user_a_owner="user-a",
        expected_user_b_owner="user-b",
    )

    assert lease == {"repository_name": "owner/repo"}
