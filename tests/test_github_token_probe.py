from __future__ import annotations

from pathlib import Path

from pwn_hunter_ai.attack.github_token_probe import (
    GitHubTokenProbeService,
    build_probe_file_change_plan,
    _write_probe_file,
    build_probe_file_path,
    parse_pull_request_target_filters,
)
from pwn_hunter_ai.github_client import GitHubApiError


def test_parse_pull_request_target_filters_reads_branches_and_paths() -> None:
    workflow = """
on:
  pull_request_target:
    branches:
      - main
      - release/*
    paths:
      - mkdocs.yaml
      - "**/*.md"
"""

    parsed = parse_pull_request_target_filters(workflow)

    assert parsed["branches"] == ["main", "release/*"]
    assert parsed["paths"] == ["mkdocs.yaml", "**/*.md"]
    assert parsed["types"] == []
    assert parsed["types_explicit"] is False


def test_parse_pull_request_target_filters_returns_empty_without_filters() -> None:
    workflow = """
on:
  push:
    branches: [main]
  pull_request_target:
"""

    parsed = parse_pull_request_target_filters(workflow)

    assert parsed["branches"] == []
    assert parsed["paths"] == []
    assert parsed["types"] == []
    assert parsed["types_explicit"] is False


def test_parse_pull_request_target_filters_supports_singular_branch_key() -> None:
    workflow = """
on:
  pull_request_target:
    branch:
      - master
      - release/*
"""

    parsed = parse_pull_request_target_filters(workflow)

    assert parsed["branches"] == ["master", "release/*"]
    assert parsed["paths"] == []
    assert parsed["types"] == []
    assert parsed["types_explicit"] is False


def test_parse_pull_request_target_filters_supports_string_branch_value() -> None:
    workflow = """
on:
  pull_request_target:
    branch: master
"""

    parsed = parse_pull_request_target_filters(workflow)

    assert parsed["branches"] == ["master"]
    assert parsed["paths"] == []
    assert parsed["types"] == []
    assert parsed["types_explicit"] is False


def test_parse_pull_request_target_filters_uses_branches_over_branch() -> None:
    workflow = """
on:
  pull_request_target:
    branches:
      - main
    branch:
      - master
"""

    parsed = parse_pull_request_target_filters(workflow)

    assert parsed["branches"] == ["main"]
    assert parsed["types"] == []
    assert parsed["types_explicit"] is False


def test_parse_pull_request_target_filters_reads_explicit_types() -> None:
    workflow = """
on:
  pull_request_target:
    types:
      - OPENED
      - synchronize
      - opened
"""

    parsed = parse_pull_request_target_filters(workflow)

    assert parsed["types_explicit"] is True
    assert parsed["types"] == ["opened", "synchronize"]


def test_build_probe_file_path_uses_uuid_file_without_paths_filter() -> None:
    path = build_probe_file_path(path_filters=[])

    assert path == "README.md"


def test_build_probe_file_path_uses_literal_pattern_as_is() -> None:
    path = build_probe_file_path(path_filters=["mkdocs.yaml", "**/*.md"])

    assert path == "mkdocs.yaml"


def test_build_probe_file_path_generates_match_for_glob_pattern() -> None:
    path = build_probe_file_path(path_filters=["**/*.md"])

    assert path.startswith("docs/")
    assert path.endswith(".md")


def test_write_probe_file_writes_content(tmp_path: Path) -> None:
    _write_probe_file(
        workspace_path=tmp_path,
        file_path="probe.txt",
        content="a",
    )

    content = (tmp_path / "probe.txt").read_text(encoding="utf-8")
    assert content == "a"


def test_write_probe_file_appends_content(tmp_path: Path) -> None:
    target = tmp_path / "README.md"
    target.write_text("line", encoding="utf-8")

    _write_probe_file(
        workspace_path=tmp_path,
        file_path="README.md",
        content="a",
        append=True,
    )

    content = target.read_text(encoding="utf-8")
    assert content == "linea"


def test_build_probe_file_change_plan_no_filters_with_existing_readme(
    tmp_path: Path,
) -> None:
    (tmp_path / "README.md").write_text("# Existing\n", encoding="utf-8")

    plan = build_probe_file_change_plan(
        workspace_path=tmp_path,
        path_filters=[],
    )

    assert plan == {"file_path": "README.md", "content": "a", "append": True}


def test_build_probe_file_change_plan_no_filters_without_readme(tmp_path: Path) -> None:
    plan = build_probe_file_change_plan(
        workspace_path=tmp_path,
        path_filters=[],
    )

    assert plan == {"file_path": "README.md", "content": "a", "append": False}


def test_build_probe_file_change_plan_for_wildcard_filter(tmp_path: Path) -> None:
    plan = build_probe_file_change_plan(
        workspace_path=tmp_path,
        path_filters=["**/*.md"],
    )

    assert plan["append"] is False
    assert plan["content"] == "a"
    assert plan["file_path"].startswith("docs/")
    assert plan["file_path"].endswith(".md")


def test_build_probe_file_change_plan_for_specific_file_filter(tmp_path: Path) -> None:
    plan = build_probe_file_change_plan(
        workspace_path=tmp_path,
        path_filters=["docs/guide.md"],
    )

    assert plan == {"file_path": "docs/guide.md", "content": "a", "append": True}


def test_probe_pr_body_and_branch_avoid_token_word(tmp_path: Path, monkeypatch) -> None:
    captured: dict[str, str] = {}

    class _FakeClient:
        def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
            _ = (repo_name, path, ref)
            return "on:\n  pull_request_target:\n"

        def create_pull_request(
            self,
            repo_name: str,
            title: str,
            body: str,
            head: str,
            base: str,
            draft: bool = False,
        ):
            _ = (repo_name, title, base)
            captured["title"] = title
            captured["body"] = body
            captured["head"] = head
            captured["draft"] = str(draft)
            return {"number": 1, "html_url": "https://example/pull/1"}

        def get_pull_request(self, repo_name: str, pull_number: int):
            _ = (repo_name, pull_number)
            return {"head": {"sha": "abc"}}

        def get_workflow_runs(self, repo_name: str, per_page: int = 100, page: int = 1):
            _ = (repo_name, per_page, page)
            return {"workflow_runs": [{"id": 7, "head_sha": "abc", "path": ".github/workflows/ci.yml@main"}]}

        def get_workflow_run(self, repo_name: str, run_id: int):
            _ = (repo_name, run_id)
            return {"id": 7, "conclusion": "success", "html_url": "https://example/runs/7"}

        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            _ = (repo_name, run_id)
            return b""

        def close_pull_request(self, repo_name: str, pull_number: int):
            _ = (repo_name, pull_number)
            return {}

        def create_pull_request_comment(
            self, repo_name: str, pull_number: int, body: str
        ):
            _ = (repo_name, pull_number)
            captured["close_comment"] = body
            return {}

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._prepare_probe_workspace",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._write_probe_file",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._commit_and_push_probe_change",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._wait_for_probe_workflow_run",
        lambda **kwargs: {"id": 7, "html_url": "https://example/runs/7"},
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe.parse_github_token_permissions_from_logs",
        lambda logs: {
            "Actions": "write",
            "ArtifactMetadata": "write",
            "Attestations": "write",
            "Checks": "write",
            "Contents": "write",
            "Deployments": "write",
            "Discussions": "write",
            "Issues": "write",
            "Metadata": "read",
            "Models": "read",
            "Packages": "write",
            "Pages": "write",
            "PullRequests": "write",
            "RepositoryProjects": "write",
            "SecurityEvents": "write",
            "Statuses": "write",
        },
    )

    service = GitHubTokenProbeService(lambda _token: _FakeClient())
    result = service.resolve_unknown_status(
        repo_name="owner/repo",
        source_default_branch="main",
        vulnerable_commit_hash="deadbeef",
        focused_workflow=".github/workflows/ci.yml",
        workspace_path=tmp_path,
        user_a_token="token-a",
        user_a_fork="user-a/repo",
        user_b_token="token-b",
        user_b_fork="user-b/repo",
    )

    assert result["resolved_permissions"]["status"] == "write"
    assert captured["title"] == "Update README.md"
    assert captured["body"] == ""
    assert captured["draft"] == "True"
    assert captured["close_comment"] == "Never mind"
    assert "token" not in captured["head"].lower()


def test_probe_returns_read_for_incomplete_permissions_block_without_write(
    tmp_path: Path, monkeypatch
) -> None:
    class _FakeClient:
        def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
            _ = (repo_name, path, ref)
            return "on:\n  pull_request_target:\n"

        def create_pull_request(
            self,
            repo_name: str,
            title: str,
            body: str,
            head: str,
            base: str,
            draft: bool = False,
        ):
            _ = (repo_name, title, body, head, base, draft)
            return {"number": 1, "html_url": "https://example/pull/1"}

        def get_pull_request(self, repo_name: str, pull_number: int):
            _ = (repo_name, pull_number)
            return {"head": {"sha": "abc"}}

        def get_workflow_runs(self, repo_name: str, per_page: int = 100, page: int = 1):
            _ = (repo_name, per_page, page)
            return {"workflow_runs": [{"id": 7, "head_sha": "abc", "path": ".github/workflows/ci.yml@main"}]}

        def get_workflow_run(self, repo_name: str, run_id: int):
            _ = (repo_name, run_id)
            return {"id": 7, "conclusion": "success", "html_url": "https://example/runs/7"}

        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            _ = (repo_name, run_id)
            return b""

        def close_pull_request(self, repo_name: str, pull_number: int):
            _ = (repo_name, pull_number)
            return {}

        def create_pull_request_comment(
            self, repo_name: str, pull_number: int, body: str
        ):
            _ = (repo_name, pull_number, body)
            return {}

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._prepare_probe_workspace",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._write_probe_file",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._commit_and_push_probe_change",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._wait_for_probe_workflow_run",
        lambda **kwargs: {"id": 7, "html_url": "https://example/runs/7"},
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe.parse_github_token_permissions_from_logs",
        lambda logs: {
            "Contents": "read",
            "Metadata": "read",
            "Packages": "read",
        },
    )

    service = GitHubTokenProbeService(lambda _token: _FakeClient())
    result = service.resolve_unknown_status(
        repo_name="owner/repo",
        source_default_branch="main",
        vulnerable_commit_hash="deadbeef",
        focused_workflow=".github/workflows/ci.yml",
        workspace_path=tmp_path,
        user_a_token="token-a",
        user_a_fork="user-a/repo",
        user_b_token="token-b",
        user_b_fork="user-b/repo",
    )

    assert result["resolved_permissions"]["status"] == "read"
    assert (
        result["resolved_permissions"]["reason"]
        == "probe_permissions_block_found_without_write"
    )
    assert result["probe"]["status"] == "completed_read"


def test_probe_retries_log_download_after_transient_404(
    tmp_path: Path, monkeypatch
) -> None:
    class _FakeClient:
        def __init__(self) -> None:
            self.log_calls = 0

        def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
            _ = (repo_name, path, ref)
            return "on:\n  pull_request_target:\n"

        def create_pull_request(
            self,
            repo_name: str,
            title: str,
            body: str,
            head: str,
            base: str,
            draft: bool = False,
        ):
            _ = (repo_name, title, body, head, base, draft)
            return {"number": 1, "html_url": "https://example/pull/1"}

        def get_pull_request(self, repo_name: str, pull_number: int):
            _ = (repo_name, pull_number)
            return {"head": {"sha": "abc"}}

        def get_workflow_runs(self, repo_name: str, per_page: int = 100, page: int = 1):
            _ = (repo_name, per_page, page)
            return {
                "workflow_runs": [
                    {"id": 7, "head_sha": "abc", "path": ".github/workflows/ci.yml@main"}
                ]
            }

        def get_workflow_run(self, repo_name: str, run_id: int):
            _ = (repo_name, run_id)
            return {"id": 7, "conclusion": "success", "html_url": "https://example/runs/7"}

        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            _ = (repo_name, run_id)
            self.log_calls += 1
            if self.log_calls == 1:
                raise GitHubApiError(
                    "GitHub API request failed for /repos/owner/repo/actions/runs/7/logs: "
                    "404 Not Found"
                )
            return b""

        def close_pull_request(self, repo_name: str, pull_number: int):
            _ = (repo_name, pull_number)
            return {}

        def create_pull_request_comment(
            self, repo_name: str, pull_number: int, body: str
        ):
            _ = (repo_name, pull_number, body)
            return {}

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._prepare_probe_workspace",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._write_probe_file",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._commit_and_push_probe_change",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe.time.sleep",
        lambda _s: None,
    )

    client = _FakeClient()
    service = GitHubTokenProbeService(lambda _token: client, poll_interval=0.01)
    result = service.resolve_unknown_status(
        repo_name="owner/repo",
        source_default_branch="main",
        vulnerable_commit_hash="deadbeef",
        focused_workflow=".github/workflows/ci.yml",
        workspace_path=tmp_path,
        user_a_token="token-a",
        user_a_fork="user-a/repo",
        user_b_token="token-b",
        user_b_fork="user-b/repo",
    )

    assert client.log_calls == 2
    assert result["resolved_permissions"]["status"] == "unknown"
    assert result["resolved_permissions"]["reason"] == "probe_no_permissions_block_in_logs"


def test_probe_cleanup_uses_actor_client_that_created_pr(
    tmp_path: Path, monkeypatch
) -> None:
    class _SourceClient:
        def __init__(self) -> None:
            self.comment_calls = 0
            self.close_calls = 0

        def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
            _ = (repo_name, path, ref)
            return "on:\n  pull_request_target:\n"

        def get_pull_request(self, repo_name: str, pull_number: int):
            _ = (repo_name, pull_number)
            return {"head": {"sha": "abc"}}

        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            _ = (repo_name, run_id)
            return b""

        def create_pull_request_comment(
            self, repo_name: str, pull_number: int, body: str
        ):
            _ = (repo_name, pull_number, body)
            self.comment_calls += 1
            return {}

        def close_pull_request(self, repo_name: str, pull_number: int):
            _ = (repo_name, pull_number)
            self.close_calls += 1
            return {}

    class _ActorClient:
        def __init__(self) -> None:
            self.comment_calls = 0
            self.close_calls = 0

        def create_pull_request(
            self,
            repo_name: str,
            title: str,
            body: str,
            head: str,
            base: str,
            draft: bool = False,
        ):
            _ = (repo_name, title, body, head, base, draft)
            return {"number": 11, "html_url": "https://example/pull/11"}

        def create_pull_request_comment(
            self, repo_name: str, pull_number: int, body: str
        ):
            _ = (repo_name, pull_number, body)
            self.comment_calls += 1
            return {}

        def close_pull_request(self, repo_name: str, pull_number: int):
            _ = (repo_name, pull_number)
            self.close_calls += 1
            return {}

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._prepare_probe_workspace",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._write_probe_file",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._commit_and_push_probe_change",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._wait_for_probe_workflow_run",
        lambda **kwargs: {"id": 7, "html_url": "https://example/runs/7"},
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe.parse_github_token_permissions_from_logs",
        lambda logs: {"Contents": "read"},
    )

    source_client = _SourceClient()
    actor_client = _ActorClient()
    clients = {"token-a": source_client, "token-b": actor_client}
    service = GitHubTokenProbeService(lambda token: clients[token])
    result = service.resolve_unknown_status(
        repo_name="owner/repo",
        source_default_branch="main",
        vulnerable_commit_hash="deadbeef",
        focused_workflow=".github/workflows/ci.yml",
        workspace_path=tmp_path,
        user_a_token="token-a",
        user_a_fork="user-a/repo",
        user_b_token="token-b",
        user_b_fork="user-b/repo",
    )

    assert result["probe"]["actor_used"] == "user_b"
    assert actor_client.comment_calls == 1
    assert actor_client.close_calls == 1
    assert source_client.comment_calls == 0
    assert source_client.close_calls == 0


def test_probe_workspace_uses_target_repo_as_base_clone(tmp_path: Path, monkeypatch) -> None:
    captured_prepare: dict[str, str] = {}

    class _FakeClient:
        def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
            _ = (repo_name, path, ref)
            return "on:\n  pull_request_target:\n"

        def create_pull_request(
            self,
            repo_name: str,
            title: str,
            body: str,
            head: str,
            base: str,
            draft: bool = False,
        ):
            _ = (repo_name, title, body, head, base, draft)
            return {"number": 1, "html_url": "https://example/pull/1"}

        def get_pull_request(self, repo_name: str, pull_number: int):
            _ = (repo_name, pull_number)
            return {"head": {"sha": "abc"}}

        def get_workflow_runs(self, repo_name: str, per_page: int = 100, page: int = 1):
            _ = (repo_name, per_page, page)
            return {
                "workflow_runs": [
                    {"id": 7, "head_sha": "abc", "path": ".github/workflows/ci.yml@main"}
                ]
            }

        def get_workflow_run(self, repo_name: str, run_id: int):
            _ = (repo_name, run_id)
            return {"id": 7, "conclusion": "success", "html_url": "https://example/runs/7"}

        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            _ = (repo_name, run_id)
            return b""

        def close_pull_request(self, repo_name: str, pull_number: int):
            _ = (repo_name, pull_number)
            return {}

        def create_pull_request_comment(
            self, repo_name: str, pull_number: int, body: str
        ):
            _ = (repo_name, pull_number, body)
            return {}

    def _capture_prepare(**kwargs):
        captured_prepare["base_clone_url"] = kwargs["base_clone_url"]
        captured_prepare["push_clone_url"] = kwargs["push_clone_url"]

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._prepare_probe_workspace",
        _capture_prepare,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._write_probe_file",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._commit_and_push_probe_change",
        lambda **kwargs: None,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe._wait_for_probe_workflow_run",
        lambda **kwargs: {"id": 7, "html_url": "https://example/runs/7"},
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.github_token_probe.parse_github_token_permissions_from_logs",
        lambda logs: {"Contents": "read"},
    )

    service = GitHubTokenProbeService(lambda _token: _FakeClient())
    result = service.resolve_unknown_status(
        repo_name="owner/repo",
        source_default_branch="main",
        vulnerable_commit_hash="deadbeef",
        focused_workflow=".github/workflows/ci.yml",
        workspace_path=tmp_path,
        user_a_token="token-a",
        user_a_fork="user-a/repo",
        user_b_token="token-b",
        user_b_fork="user-b/repo",
    )

    assert result["resolved_permissions"]["status"] == "read"
    assert captured_prepare["base_clone_url"] == (
        "https://x-access-token:token-a@github.com/owner/repo.git"
    )
    assert captured_prepare["push_clone_url"] == (
        "https://x-access-token:token-b@github.com/user-b/repo.git"
    )
