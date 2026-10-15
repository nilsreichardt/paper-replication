from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path
import time

from pwn_hunter_ai.attack.gemini_cli_manager import (
    GeminiCliConfig,
    GeminiCliRuntimeManager,
    _path_after_nvm_use,
    _redact_sensitive_text,
    _run_with_live_output,
)


def test_gemini_cli_launch_reports_unavailable(tmp_path: Path) -> None:
    manager = GeminiCliRuntimeManager()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = tmp_path / "agent-task.md"
    prompt_path.write_text("prompt", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    result = manager.launch(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
    )

    assert result.status == "unavailable"
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert payload["provider"] == "gemini-cli"
    assert payload["status"] == "unavailable"
    assert "launch mode" in payload["reason"].lower()


def test_gemini_cli_run_headless_builds_command_and_hardens_env(
    tmp_path: Path, monkeypatch, caplog
) -> None:
    manager = GeminiCliRuntimeManager(config=GeminiCliConfig(model="gemini-2.5-pro"))
    captured: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        _ = kwargs
        if cmd[:2] == ["node", "-p"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="20\n", stderr="")
        raise AssertionError(f"Unexpected subprocess.run call: {cmd}")

    class _FakePopenProcess:
        def __init__(self) -> None:
            self.returncode = 0
            self.stdout = io.StringIO(
                '{"type":"init","session_id":"s1","model":"gemini-3"}\n'
                '{"type":"message","role":"assistant","content":"step-1","delta":true}\n'
                '{"type":"tool_use","tool_name":"run_shell_command","tool_id":"t1","parameters":{"command":"echo hi"}}\n'
                '{"type":"tool_result","tool_id":"t1","status":"success","output":"hi"}\n'
                '{"type":"result","status":"success","stats":{"tool_calls":1}}\n'
            )
            self.stderr = io.StringIO("reasoning: trying exploit\n")
            self._killed = False

        def wait(self, timeout: int | None = None) -> int:
            captured["wait_timeout"] = timeout
            return self.returncode

        def kill(self) -> None:
            self._killed = True

    def fake_popen(command, **kwargs):
        captured["command"] = list(command)
        captured["cwd"] = kwargs.get("cwd")
        captured["env"] = kwargs.get("env")
        return _FakePopenProcess()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("HOME", "/home/test-user")
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")
    monkeypatch.setenv("GITHUB_TOKEN", "ghs_secret_should_not_pass")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = tmp_path / "agent-task.md"
    prompt_path.write_text("solve task", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    with caplog.at_level("INFO"):
        result = manager.run_headless(
            workspace_path=workspace,
            prompt_path=prompt_path,
            metadata_path=metadata_path,
            timeout=45,
        )

    assert result.status == "completed"
    assert result.exit_code == 0
    assert captured["cwd"] == workspace
    assert captured["wait_timeout"] == 45
    command = captured["command"]
    assert isinstance(command, list)
    assert command[0] == "gemini"
    assert "--output-format" in command
    output_flag_index = command.index("--output-format")
    assert command[output_flag_index + 1] == "stream-json"
    assert "--approval-mode" in command
    assert "--model" in command
    assert "gemini-2.5-pro" in command
    assert "--resume" not in command

    env = captured["env"]
    assert isinstance(env, dict)
    assert "GEMINI_API_KEY" not in env
    assert "GITHUB_TOKEN" not in env
    assert env["HOME"] == "/home/test-user"
    assert env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["GIT_TERMINAL_PROMPT"] == "0"

    gitconfig_path = Path(env["GIT_CONFIG_GLOBAL"])
    assert gitconfig_path.exists()
    assert "helper =" in gitconfig_path.read_text(encoding="utf-8")

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["provider"] == "gemini-cli"
    assert metadata["status"] == "completed"
    assert metadata["exit_code"] == 0
    assert metadata["executor"] == "gemini-cli"
    assert metadata["resumed_chat_id"] is None
    assert metadata["chat_id"] == "s1"
    assert '"type":"init"' in Path(metadata["stdout_path"]).read_text(encoding="utf-8")
    assert (
        Path(metadata["stderr_path"]).read_text(encoding="utf-8")
        == "reasoning: trying exploit\n"
    )
    assert (workspace / ".pwnhunter-gemini-chat-id").read_text(encoding="utf-8").strip() == "s1"
    assert "Gemini CLI session init: session_id=s1 model=gemini-3" in caplog.text
    assert "Gemini CLI assistant delta: step-1" in caplog.text
    assert "Gemini CLI tool_use: name=run_shell_command id=t1" in caplog.text
    assert "Gemini CLI tool_result: id=t1 status=success output=hi" in caplog.text
    assert "Gemini CLI result: status=success" in caplog.text
    assert "Gemini CLI stderr: reasoning: trying exploit" in caplog.text


def test_gemini_cli_run_headless_api_billing_passes_api_key(
    tmp_path: Path, monkeypatch
) -> None:
    manager = GeminiCliRuntimeManager(
        config=GeminiCliConfig(model="gemini-2.5-pro", billing="api")
    )
    captured: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        _ = kwargs
        if cmd[:2] == ["node", "-p"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="20\n", stderr="")
        raise AssertionError(f"Unexpected subprocess.run call: {cmd}")

    class _FakePopenProcess:
        def __init__(self) -> None:
            self.returncode = 0
            self.stdout = io.StringIO('{"type":"result","status":"success","stats":{}}\n')
            self.stderr = io.StringIO("")

        def wait(self, timeout: int | None = None) -> int:
            _ = timeout
            return self.returncode

        def kill(self) -> None:
            return None

    def fake_popen(command, **kwargs):
        captured["command"] = list(command)
        captured["cwd"] = kwargs.get("cwd")
        captured["env"] = kwargs.get("env")
        return _FakePopenProcess()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    monkeypatch.setenv("GEMINI_API_KEY", "test-gemini-key")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = tmp_path / "agent-task.md"
    prompt_path.write_text("solve task", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    result = manager.run_headless(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
        timeout=45,
    )

    assert result.status == "completed"
    env = captured["env"]
    assert isinstance(env, dict)
    assert env["GEMINI_API_KEY"] == "test-gemini-key"
    assert env["HOME"] == str(workspace / ".pwnhunter-home")


def test_gemini_cli_run_headless_timeout_persists_partial_logs(
    tmp_path: Path, monkeypatch
) -> None:
    manager = GeminiCliRuntimeManager()

    def fake_run(cmd, **kwargs):
        _ = kwargs
        if cmd[:2] == ["node", "-p"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="20\n", stderr="")
        raise AssertionError(f"Unexpected subprocess.run call: {cmd}")

    class _FakePopenTimeoutProcess:
        def __init__(self) -> None:
            self.returncode = -9
            self.stdout = io.StringIO("partial stdout\n")
            self.stderr = io.StringIO("partial stderr\n")
            self._killed = False

        def wait(self, timeout: int | None = None) -> int:
            if not self._killed:
                raise subprocess.TimeoutExpired(cmd=["gemini"], timeout=timeout or 0)
            return self.returncode

        def kill(self) -> None:
            self._killed = True

    def fake_popen(*_args, **_kwargs):
        return _FakePopenTimeoutProcess()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr("subprocess.run", fake_run)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = tmp_path / "agent-task.md"
    prompt_path.write_text("solve task", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    result = manager.run_headless(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
        timeout=3,
    )

    assert result.status == "timeout"
    assert result.exit_code is None
    assert result.stdout_path.read_text(encoding="utf-8") == "partial stdout\n"
    assert result.stderr_path.read_text(encoding="utf-8") == "partial stderr\n"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["status"] == "timeout"
    assert metadata["exit_code"] is None


def test_gemini_cli_run_headless_reuses_cached_chat_id_and_refreshes_it(
    tmp_path: Path, monkeypatch
) -> None:
    manager = GeminiCliRuntimeManager()
    captured: dict[str, object] = {}

    def fake_run(cmd, **kwargs):
        _ = kwargs
        if cmd[:2] == ["node", "-p"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="20\n", stderr="")
        raise AssertionError(f"Unexpected subprocess.run call: {cmd}")

    class _FakePopenProcess:
        def __init__(self) -> None:
            self.returncode = 0
            self.stdout = io.StringIO(
                '{"type":"init","session_id":"chat-new","model":"gemini-3"}\n'
                '{"type":"result","status":"success","stats":{"tool_calls":0}}\n'
            )
            self.stderr = io.StringIO("")

        def wait(self, timeout: int | None = None) -> int:
            captured["wait_timeout"] = timeout
            return self.returncode

        def kill(self) -> None:
            return None

    def fake_popen(command, **kwargs):
        captured["command"] = list(command)
        captured["cwd"] = kwargs.get("cwd")
        return _FakePopenProcess()

    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setenv("PATH", "/usr/bin:/bin")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".pwnhunter-gemini-chat-id").write_text("chat-old\n", encoding="utf-8")
    prompt_path = tmp_path / "agent-task.md"
    prompt_path.write_text("solve task", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    result = manager.run_headless(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
        timeout=30,
    )

    assert result.status == "completed"
    command = captured["command"]
    assert isinstance(command, list)
    assert "--resume" in command
    resume_index = command.index("--resume")
    assert command[resume_index + 1] == "chat-old"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["resumed_chat_id"] == "chat-old"
    assert metadata["chat_id"] == "chat-new"
    assert (workspace / ".pwnhunter-gemini-chat-id").read_text(encoding="utf-8").strip() == "chat-new"


def test_gemini_cli_run_headless_marks_unavailable_when_no_supported_node(
    tmp_path: Path, monkeypatch
) -> None:
    manager = GeminiCliRuntimeManager()

    def fake_run(cmd, **kwargs):
        _ = kwargs
        if cmd[:2] == ["node", "-p"]:
            return subprocess.CompletedProcess(cmd, 0, stdout="18\n", stderr="")
        if cmd[:2] == ["/bin/zsh", "-lc"] and "command -v nvm >/dev/null 2>&1" in cmd[2]:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="")
        raise AssertionError(f"Unexpected subprocess.run call: {cmd}")

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setenv("SHELL", "/bin/zsh")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = tmp_path / "agent-task.md"
    prompt_path.write_text("solve task", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    result = manager.run_headless(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
        timeout=30,
    )

    assert result.status == "unavailable"
    assert result.exit_code is None
    payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert payload["status"] == "unavailable"
    assert "node.js >= 20" in str(payload.get("reason", "")).lower()


def test_path_after_nvm_use_uses_version_only_and_loads_nvm(monkeypatch) -> None:
    captured: dict[str, list[str]] = {}

    def fake_run(cmd, **kwargs):
        _ = kwargs
        captured["cmd"] = list(cmd)
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout="__PWNHUNTER_PATH__=/tmp/node/bin:/usr/bin\n",
            stderr="",
        )

    monkeypatch.setattr("subprocess.run", fake_run)

    path_value = _path_after_nvm_use(shell="/bin/zsh", target_version="24")

    assert path_value == "/tmp/node/bin:/usr/bin"
    command = captured["cmd"][2]
    assert "nvm use 24" in command
    assert "nvm use node 24" not in command
    assert 'NVM_DIR="${NVM_DIR:-$HOME/.nvm}"' in command


def test_run_with_live_output_timeout_closes_streams_without_hanging(
    tmp_path: Path, monkeypatch
) -> None:
    class _SlowDrainStream:
        def __init__(self, first_line: str, delay_seconds: float) -> None:
            self._first_line = first_line
            self._delay_seconds = delay_seconds
            self._started = False
            self._closed = False

        def readline(self) -> str:
            if not self._started:
                self._started = True
                return self._first_line
            waited = 0.0
            step = 0.01
            while not self._closed and waited < self._delay_seconds:
                time.sleep(step)
                waited += step
            return ""

        def close(self) -> None:
            self._closed = True

    class _FakePopenTimeoutWithSlowStreams:
        def __init__(self) -> None:
            self.returncode = -9
            self.stdout = _SlowDrainStream("partial stdout\n", delay_seconds=2.0)
            self.stderr = _SlowDrainStream("partial stderr\n", delay_seconds=2.0)
            self._killed = False

        def wait(self, timeout: int | None = None) -> int:
            if not self._killed:
                raise subprocess.TimeoutExpired(cmd=["gemini"], timeout=timeout or 0)
            return self.returncode

        def kill(self) -> None:
            self._killed = True

    def fake_popen(*_args, **_kwargs):
        return _FakePopenTimeoutWithSlowStreams()

    monkeypatch.setattr("subprocess.Popen", fake_popen)

    stdout_buffer = io.StringIO()
    stderr_buffer = io.StringIO()
    started = time.monotonic()
    try:
        _run_with_live_output(
            ["gemini", "--prompt", "hi"],
            cwd=tmp_path,
            timeout=1,
            env={"PATH": "/usr/bin"},
            stdout_file=stdout_buffer,
            stderr_file=stderr_buffer,
        )
    except subprocess.TimeoutExpired:
        elapsed = time.monotonic() - started
    else:  # pragma: no cover - defensive
        raise AssertionError("Expected timeout")

    assert elapsed < 1.0
    assert stdout_buffer.getvalue() == "partial stdout\n"
    assert stderr_buffer.getvalue() == "partial stderr\n"


def test_gemini_cli_telemetry_override_writes_local_outfile(
    tmp_path: Path, monkeypatch
) -> None:
    manager = GeminiCliRuntimeManager()
    monkeypatch.setenv("PWNHUNTER_GEMINI_TELEMETRY_ENABLED", "true")
    monkeypatch.setenv("PWNHUNTER_GEMINI_TELEMETRY_TARGET", "local")
    monkeypatch.setenv("PWNHUNTER_GEMINI_TELEMETRY_LOG_PROMPTS", "true")

    env = manager._build_headless_env(tmp_path / "workspace")  # noqa: SLF001

    assert env["GEMINI_TELEMETRY_ENABLED"] == "true"
    assert env["GEMINI_TELEMETRY_TARGET"] == "local"
    assert env["GEMINI_TELEMETRY_LOG_PROMPTS"] == "true"
    outfile = Path(env["GEMINI_TELEMETRY_OUTFILE"])
    assert outfile.is_absolute()
    assert outfile.parent.exists()


def test_gemini_cli_headless_env_loads_workspace_secrets_file(
    tmp_path: Path, monkeypatch
) -> None:
    manager = GeminiCliRuntimeManager()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".secrets").write_text(
        "GITHUB_TOKEN=token-from-secrets\nFERN_TOKEN=fern-from-secrets\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("GITHUB_TOKEN", "host-token-should-not-leak")

    env = manager._build_headless_env(workspace)  # noqa: SLF001

    assert "GITHUB_TOKEN" not in env
    assert env["FERN_TOKEN"] == "fern-from-secrets"


def test_redact_sensitive_text_masks_github_credentials() -> None:
    raw = (
        "https://x-access-token:abc123@github.com/org/repo "
        "https://ghp_secret123@github.com/org/repo2 "
        "ghs_inlineSecret"
    )

    redacted = _redact_sensitive_text(raw)

    assert "abc123" not in redacted
    assert "ghp_secret123" not in redacted
    assert "ghs_inlineSecret" not in redacted
    assert "https://***@github.com/org/repo" in redacted
