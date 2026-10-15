from __future__ import annotations

import subprocess

from pwn_hunter_ai.attack.sandbox_manager import (
    ATTACK_GITIGNORE_ENTRIES,
    HostRepositorySandbox,
    RepositorySandbox,
    SandboxManager,
)


class _NoChangesSandbox(RepositorySandbox):
    def __init__(self) -> None:
        pass

    def _ensure_origin_uses_token(self) -> None:
        return None

    def run_git(
        self, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess:
        _ = check
        self.calls.append(args)
        if args == ["status", "--porcelain", "--untracked-files=no"]:
            return subprocess.CompletedProcess(args, 0, stdout="", stderr="")
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")


class _HeadlessEnvSandbox(RepositorySandbox):
    def __init__(self) -> None:
        pass

    def _run_in_container(
        self,
        cmd: list[str],
        cwd: str = "/workspace",
        check: bool = True,
        env: dict[str, str] | None = None,
        stream_output: bool = False,
    ) -> subprocess.CompletedProcess:
        _ = (cwd, check)
        self.exec_calls.append((cmd, env, stream_output))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def run_git(
        self, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess:
        _ = check
        self.git_calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")


class _CloneSandbox(RepositorySandbox):
    def __init__(
        self,
        *,
        existing_repo_cwd: str | None = None,
    ) -> None:
        self.existing_repo_cwd = existing_repo_cwd
        self.container_calls: list[tuple[list[str], str]] = []
        self.git_calls: list[list[str]] = []
        self._repo_cwd = "/workspace"
        self._git_token = None

    def _discover_existing_repo_cwd(self) -> str | None:
        return self.existing_repo_cwd

    def _run_in_container(
        self,
        cmd: list[str],
        cwd: str = "/workspace",
        check: bool = True,
        env: dict[str, str] | None = None,
        stream_output: bool = False,
    ) -> subprocess.CompletedProcess:
        _ = (check, env, stream_output)
        self.container_calls.append((cmd, cwd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    def run_git(
        self, args: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess:
        _ = check
        self.git_calls.append(args)
        return subprocess.CompletedProcess(args, 0, stdout="", stderr="")


class _RunGitSandbox(RepositorySandbox):
    def __init__(self) -> None:
        self.container_calls: list[tuple[list[str], str]] = []
        self._repo_cwd = "/workspace"

    def _run_in_container(
        self,
        cmd: list[str],
        cwd: str = "/workspace",
        check: bool = True,
        env: dict[str, str] | None = None,
        stream_output: bool = False,
    ) -> subprocess.CompletedProcess:
        _ = (check, env, stream_output)
        self.container_calls.append((cmd, cwd))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


class _HostRunGitSandbox(HostRepositorySandbox):
    def __init__(self, workspace_path):
        super().__init__(workspace_path)
        self.local_calls: list[tuple[list[str], str]] = []

    def _run_locally(
        self,
        cmd: list[str],
        *,
        cwd=None,
        check: bool = True,
        env: dict[str, str] | None = None,
        stream_output: bool = False,
    ) -> subprocess.CompletedProcess:
        _ = (check, env, stream_output)
        effective_cwd = cwd or self._repo_cwd
        self.local_calls.append((cmd, str(effective_cwd)))
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")


def test_commit_and_push_ignores_untracked_files_when_detecting_changes() -> None:
    sandbox = _NoChangesSandbox()
    sandbox.calls = []

    committed = sandbox.commit_and_push(
        branch="feature/test",
        exclude_paths=["agent-task.md", "agent-output.json"],
    )

    assert committed is False
    assert ["status", "--porcelain", "--untracked-files=no"] in sandbox.calls
    assert ["commit", "-m", "Add temporary change"] not in sandbox.calls


def test_attack_gitignore_entries_include_learning_handoff_files() -> None:
    assert "LEARNINGS.md" in ATTACK_GITIGNORE_ENTRIES
    assert "GEMINI.md" in ATTACK_GITIGNORE_ENTRIES


def test_attack_gitignore_entries_keep_agent_retry_files_visible() -> None:
    assert "agent-output.json" not in ATTACK_GITIGNORE_ENTRIES
    assert "test-exploit-locally.py" not in ATTACK_GITIGNORE_ENTRIES
    assert ".pwnhunter-workflow-logs/" not in ATTACK_GITIGNORE_ENTRIES


def test_ensure_attack_gitignore_entries_removes_legacy_agent_file_excludes(
    tmp_path,
) -> None:
    workspace = tmp_path / "workspace"
    exclude_path = workspace / ".git" / "info" / "exclude"
    exclude_path.parent.mkdir(parents=True, exist_ok=True)
    exclude_path.write_text(
        "\n".join(
            [
                "agent-output.json",
                "test-exploit-locally.py",
                ".pwnhunter-workflow-logs/",
                "custom-entry.txt",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    sandbox = HostRepositorySandbox(workspace)
    sandbox._ensure_attack_gitignore_entries()  # noqa: SLF001

    rewritten = exclude_path.read_text(encoding="utf-8")
    assert "agent-output.json\n" not in rewritten
    assert "test-exploit-locally.py\n" not in rewritten
    assert ".pwnhunter-workflow-logs/\n" not in rewritten
    assert "custom-entry.txt\n" in rewritten
    assert "agent-task.md\n" in rewritten
    assert "LEARNINGS.md\n" in rewritten


def test_run_openhands_headless_hardens_git_auth_env(monkeypatch) -> None:
    sandbox = _HeadlessEnvSandbox()
    sandbox.exec_calls = []
    sandbox.git_calls = []
    monkeypatch.setenv("GEMINI_API_KEY", "test-api-key")
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_should_not_leak")

    result = sandbox.run_openhands_headless(timeout=10)

    assert result.returncode == 0
    final_cmd, final_env, final_stream_output = sandbox.exec_calls[-1]
    assert final_cmd[:2] == ["bash", "-lc"]
    assert final_stream_output is True
    assert final_env is not None
    assert final_env["HOME"] == "/workspace/.pwnhunter-home"
    assert final_env["XDG_CONFIG_HOME"] == "/workspace/.pwnhunter-xdg"
    assert final_env["GIT_CONFIG_GLOBAL"] == "/workspace/.gitconfig.pwnhunter"
    assert (
        final_env["PWNHUNTER_OPENHANDS_CONVERSATION_ID_PATH"]
        == "/workspace/.pwnhunter-openhands-conversation-id"
    )
    assert (
        final_env["PWNHUNTER_OPENHANDS_PERSISTENCE_DIR"]
        == "/workspace/.pwnhunter-openhands-state"
    )
    assert final_env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert final_env["GIT_TERMINAL_PROMPT"] == "0"
    assert final_env["GIT_ASKPASS"] == "/bin/false"
    assert final_env["SSH_ASKPASS"] == "/bin/false"
    assert "GITHUB_TOKEN" not in final_env
    assert ["config", "user.email", "research@pwnhunter.local"] in sandbox.git_calls
    assert ["config", "user.name", "PwnHunter Research"] in sandbox.git_calls


def test_clone_repository_appends_attack_entries_to_gitignore_after_clone() -> None:
    sandbox = _CloneSandbox()
    sandbox.clone_repository("https://github.com/example/repo.git")

    assert sandbox.container_calls
    assert sandbox.container_calls[0][0][:3] == ["git", "clone", "--depth"]
    assert ["remote", "set-url", "origin", "https://github.com/example/repo.git"] in sandbox.git_calls
    assert ["config", "user.email", "research@pwnhunter.local"] in sandbox.git_calls
    assert ["config", "user.name", "PwnHunter Research"] in sandbox.git_calls


def test_clone_repository_appends_attack_entries_when_reusing_existing_repo() -> None:
    sandbox = _CloneSandbox(existing_repo_cwd="/workspace/repo")
    sandbox.clone_repository("https://github.com/example/repo.git")

    assert ["remote", "set-url", "origin", "https://github.com/example/repo.git"] in sandbox.git_calls
    assert ["config", "user.email", "research@pwnhunter.local"] in sandbox.git_calls
    assert ["config", "user.name", "PwnHunter Research"] in sandbox.git_calls


def test_repository_sandbox_run_git_marks_repo_as_safe_directory() -> None:
    sandbox = _RunGitSandbox()

    sandbox.run_git(["remote", "set-url", "origin", "https://github.com/example/repo.git"])

    cmd, cwd = sandbox.container_calls[-1]
    assert cwd == "/workspace"
    assert cmd[:3] == ["git", "-c", "safe.directory=/workspace"]
    assert cmd[3:] == ["remote", "set-url", "origin", "https://github.com/example/repo.git"]


def test_host_sandbox_run_git_marks_repo_as_safe_directory(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    sandbox = _HostRunGitSandbox(workspace)

    sandbox.run_git(["status"], check=False)

    cmd, cwd = sandbox.local_calls[-1]
    assert cwd == str(workspace)
    assert cmd[:3] == ["git", "-c", f"safe.directory={workspace}"]
    assert cmd[3:] == ["status"]


def test_host_sandbox_gitignore_entries_append_on_new_line(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    gitignore_path = workspace / ".gitignore"
    gitignore_path.write_text("pubspec_overrides.yaml", encoding="utf-8")

    sandbox = HostRepositorySandbox(workspace)
    sandbox.start(workspace)
    (workspace / ".git").mkdir(parents=True, exist_ok=True)
    sandbox._ensure_attack_gitignore_entries()

    content = (workspace / ".git" / "info" / "exclude").read_text(encoding="utf-8")
    assert ".pwnhunter-home/" in content


def test_host_sandbox_start_keeps_workspace_empty_until_clone(tmp_path) -> None:
    workspace = tmp_path / "workspace"
    sandbox = HostRepositorySandbox(workspace)

    sandbox.start(workspace)

    assert workspace.exists()
    assert list(workspace.iterdir()) == []


def test_sandbox_manager_can_create_host_sandbox(tmp_path) -> None:
    manager = SandboxManager(use_host=True)
    sandbox = manager.create_sandbox(
        repository_name="owner/repo",
        workspace_path=tmp_path / "workspace",
        git_token="token-b",
    )

    assert isinstance(sandbox, HostRepositorySandbox)
    assert (tmp_path / "workspace").exists()


def test_host_sandbox_discovery_skips_missing_repo_subdir(monkeypatch, tmp_path) -> None:
    workspace = tmp_path / "workspace"
    sandbox = HostRepositorySandbox(workspace)
    sandbox.start(workspace)

    seen_cwds: list[str] = []

    def _fake_run(cmd, cwd, capture_output, text, check, env=None):
        _ = (cmd, capture_output, text, check, env)
        seen_cwds.append(cwd)
        return subprocess.CompletedProcess(args=cmd, returncode=1, stdout="", stderr="")

    monkeypatch.setattr("pwn_hunter_ai.attack.sandbox_manager.subprocess.run", _fake_run)

    assert sandbox._discover_existing_repo_cwd() is None
    assert str(workspace / "repo") not in seen_cwds
    assert str(workspace) in seen_cwds


def test_host_sandbox_discovery_rejects_parent_git_worktree(
    monkeypatch, tmp_path
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir(parents=True, exist_ok=True)
    sandbox = HostRepositorySandbox(workspace)

    class _Result:
        def __init__(self, returncode: int, stdout: str):
            self.returncode = returncode
            self.stdout = stdout
            self.stderr = ""

    calls: list[tuple[list[str], str]] = []

    def _fake_run(cmd, cwd, capture_output, text, check, env=None):
        _ = (capture_output, text, check, env)
        calls.append((cmd, cwd))
        if cmd[3:] == ["rev-parse", "--is-inside-work-tree"]:
            return _Result(0, "true\n")
        if cmd[3:] == ["rev-parse", "--show-toplevel"]:
            return _Result(0, str(tmp_path) + "\n")
        return _Result(1, "")

    monkeypatch.setattr("pwn_hunter_ai.attack.sandbox_manager.subprocess.run", _fake_run)

    assert sandbox._discover_existing_repo_cwd() is None
    assert any(cmd[:3] == ["git", "-c", f"safe.directory={workspace}"] for cmd, _ in calls)
    assert any(cmd[3:] == ["rev-parse", "--show-toplevel"] for cmd, _ in calls)
