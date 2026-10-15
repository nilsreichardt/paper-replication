from __future__ import annotations

import base64
import io
import json
import os
from pathlib import Path
import subprocess
from types import SimpleNamespace

from pwn_hunter_ai.attack.openhands_manager import (
    OpenHandsLaunchManager,
    OpenHandsTracingConfig,
    _build_headless_base_env,
)


class _FakePopenProcess:
    def __init__(
        self,
        *,
        returncode: int,
        stdout_text: str = "",
        stderr_text: str = "",
    ) -> None:
        self.returncode = returncode
        self.stdout = io.StringIO(stdout_text)
        self.stderr = io.StringIO(stderr_text)

    def wait(self, timeout: int | None = None) -> int:
        return self.returncode

    def kill(self) -> None:
        return None


def test_openhands_tracing_config_builds_env_with_default_endpoint() -> None:
    config = OpenHandsTracingConfig(
        public_key="pk-lf-test",
        secret_key="sk-lf-test",
        host=None,
    )

    env = config.build_env()
    expected_header = base64.b64encode(b"pk-lf-test:sk-lf-test").decode("ascii")

    assert env["OPENHANDS_TRACING"] == "1"
    assert env["OTEL_EXPORTER"] == "otlp_http"
    assert env["OTEL_EXPORTER_OTLP_PROTOCOL"] == "http/protobuf"
    assert env["OTEL_EXPORTER_OTLP_TRACES_PROTOCOL"] == "http/protobuf"
    assert env["OTEL_SERVICE_NAME"] == "pwnhunter-attack-openhands"
    assert env["OTEL_EXPORTER_OTLP_ENDPOINT"] == "https://cloud.langfuse.com/api/public/otel"
    assert (
        env["OTEL_EXPORTER_OTLP_TRACES_ENDPOINT"]
        == "https://cloud.langfuse.com/api/public/otel/v1/traces"
    )
    assert env["OTEL_EXPORTER_OTLP_HEADERS"] == f"authorization=Basic {expected_header}"
    assert env["OTEL_EXPORTER_OTLP_TRACES_HEADERS"] == f"authorization=Basic {expected_header}"


def test_openhands_tracing_config_returns_empty_env_without_keys() -> None:
    config = OpenHandsTracingConfig(public_key=None, secret_key=None)

    assert config.build_env() == {}
    assert config.metadata() == {
        "enabled": False,
        "service_name": "pwnhunter-attack-openhands",
        "endpoint": None,
    }


def test_openhands_launch_injects_tracing_env(
    tmp_path: Path, monkeypatch
) -> None:
    tracing = OpenHandsTracingConfig(
        public_key="pk-lf-test",
        secret_key="sk-lf-test",
        host="https://us.cloud.langfuse.com/",
    )
    manager = OpenHandsLaunchManager(
        host="127.0.0.1",
        start_port=3000,
        tracing=tracing,
    )

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = tmp_path / "task.md"
    prompt_path.write_text("prompt", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    result = manager.launch(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
    )

    assert result.status == "unavailable"
    assert result.tracing == {
        "enabled": True,
        "service_name": "pwnhunter-attack-openhands",
        "endpoint": "https://us.cloud.langfuse.com/api/public/otel",
    }
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["tracing"] == result.tracing


def test_openhands_run_headless_injects_tracing_env(
    tmp_path: Path, monkeypatch
) -> None:
    tracing = OpenHandsTracingConfig(
        public_key="pk-lf-test",
        secret_key="sk-lf-test",
        host="https://cloud.langfuse.com",
    )
    manager = OpenHandsLaunchManager(
        host="127.0.0.1",
        start_port=3000,
        tracing=tracing,
    )

    captured = {}

    def fake_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=0)

    def fake_popen(*args, **kwargs):
        captured["env"] = kwargs.get("env", {})
        return _FakePopenProcess(returncode=0, stdout_text="agent thought\n")

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", fake_popen)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = tmp_path / "task.md"
    prompt_path.write_text("prompt", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    result = manager.run_headless(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
        timeout=30,
        git_token=None,
    )

    assert result.status == "completed"
    assert captured["env"]["OPENHANDS_TRACING"] == "1"
    assert (
        captured["env"]["OTEL_EXPORTER_OTLP_ENDPOINT"]
        == "https://cloud.langfuse.com/api/public/otel"
    )
    assert captured["env"]["GIT_CONFIG_GLOBAL"].endswith(".gitconfig.pwnhunter")
    assert captured["env"]["PWNHUNTER_AGENT_PERSISTENCE_DIR"].endswith(
        "/.pwnhunter-openhands-state"
    )
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["tracing"]["enabled"] is True


def test_openhands_run_headless_injects_risk_trace_context_for_langfuse(
    tmp_path: Path, monkeypatch
) -> None:
    tracing = OpenHandsTracingConfig(
        public_key="pk-lf-test",
        secret_key="sk-lf-test",
        host="https://cloud.langfuse.com",
    )
    manager = OpenHandsLaunchManager(
        host="127.0.0.1",
        start_port=3000,
        tracing=tracing,
    )

    captured: dict[str, str] = {}

    def fake_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=0)

    def fake_popen(*_args, **kwargs):
        env = kwargs.get("env", {})
        if isinstance(env, dict):
            captured.update(env)
        return _FakePopenProcess(returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", fake_popen)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = tmp_path / "task.md"
    prompt_path.write_text("prompt", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    (tmp_path / "attack-context.json").write_text(
        json.dumps(
            {
                "repository_name": "owner/repo",
                "risk": {
                    "initial_workflow": ".github/workflows/pull_request.yml",
                    "issue_type": "PwnRequestResult",
                    "path": [],
                },
            }
        ),
        encoding="utf-8",
    )

    result = manager.run_headless(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
        timeout=30,
        git_token=None,
    )

    assert result.status == "completed"
    assert captured["PWNHUNTER_LANGFUSE_TRACE_ID"].startswith("risk-")
    assert captured["PWNHUNTER_LANGFUSE_SESSION_ID"] == "owner__repo"
    assert json.loads(captured["PWNHUNTER_LANGFUSE_TAGS"]) == [
        "pwnhunter",
        "attack",
        "openhands",
        "repo:owner/repo",
        "workflow:.github/workflows/pull_request.yml",
        "issue:PwnRequestResult",
    ]
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["risk_trace"]["session_id"] == "owner__repo"
    assert metadata["risk_trace"]["trace_id"].startswith("risk-")


def test_openhands_run_headless_uses_local_git_config_only(
    tmp_path: Path, monkeypatch
) -> None:
    manager = OpenHandsLaunchManager(
        host="127.0.0.1",
        start_port=3000,
    )

    calls: list[list[str]] = []

    def fake_run(*args, **kwargs):
        calls.append(list(args[0]))
        return SimpleNamespace(returncode=0)

    def fake_popen(*_args, **_kwargs):
        return _FakePopenProcess(returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", fake_popen)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = tmp_path / "task.md"
    prompt_path.write_text("prompt", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    manager.run_headless(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
        timeout=30,
        git_token="ghp_dummy",
    )

    assert ["git", "config", "user.email", "research@pwnhunter.local"] in calls
    assert ["git", "config", "user.name", "PwnHunter Research"] in calls
    assert [
        "git",
        "config",
        "--global",
        "user.email",
        "research@pwnhunter.local",
    ] not in calls
    assert [
        "git",
        "config",
        "--global",
        "user.name",
        "PwnHunter Research",
    ] not in calls


def test_openhands_run_headless_fallbacks_to_flash_with_tools_after_flash_failure(
    tmp_path: Path, monkeypatch
) -> None:
    manager = OpenHandsLaunchManager(
        host="127.0.0.1",
        start_port=3000,
    )

    env_calls: list[dict[str, str]] = []

    def fake_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=0)

    def fake_popen(*args, **kwargs):
        env = kwargs.get("env", {})
        if isinstance(env, dict) and env.get("LLM_MODEL"):
            env_calls.append(env)
        returncode = 1 if len(env_calls) == 1 else 0
        return _FakePopenProcess(returncode=returncode)

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", fake_popen)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = tmp_path / "task.md"
    prompt_path.write_text("prompt", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    result = manager.run_headless(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
        timeout=30,
        git_token=None,
    )

    assert result.status == "completed"
    assert len(env_calls) == 2
    assert env_calls[0]["LLM_MODEL"] == "gemini/gemini-3.1-flash-lite-preview"
    assert env_calls[1]["LLM_MODEL"] == "gemini/gemini-3.1-flash-lite-preview"

    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["llm_strategy"] == "gemini_flash_google_search"
    assert len(metadata["attempts"]) == 2


def test_openhands_run_headless_sets_absolute_prompt_env_with_relative_workspace(
    tmp_path: Path, monkeypatch
) -> None:
    manager = OpenHandsLaunchManager(
        host="127.0.0.1",
        start_port=3000,
    )

    captured: dict[str, dict[str, str]] = {}

    def fake_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=0)

    def fake_popen(*_args, **kwargs):
        env = kwargs.get("env", {})
        if isinstance(env, dict):
            captured["env"] = env
        return _FakePopenProcess(returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", fake_popen)

    original_cwd = Path.cwd()
    try:
        os.chdir(tmp_path)
        workspace = Path("attack-artifacts/run/repo/workspace")
        workspace.mkdir(parents=True)
        prompt_path = Path("attack-artifacts/run/repo/agent-task.md")
        prompt_path.write_text("prompt", encoding="utf-8")
        metadata_path = Path("attack-artifacts/run/repo/agent-runtime.json")

        result = manager.run_headless(
            workspace_path=workspace,
            prompt_path=prompt_path,
            metadata_path=metadata_path,
            timeout=30,
            git_token=None,
        )
    finally:
        os.chdir(original_cwd)

    assert result.status == "completed"
    expected_prompt_path = (tmp_path / workspace / "agent-task.md").resolve()
    assert captured["env"]["PWNHUNTER_AGENT_PROMPT_PATH"] == str(
        expected_prompt_path
    )


def test_openhands_run_headless_includes_persisted_conversation_id_in_metadata(
    tmp_path: Path, monkeypatch
) -> None:
    manager = OpenHandsLaunchManager(
        host="127.0.0.1",
        start_port=3000,
    )

    def fake_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=0)

    def fake_popen(*_args, **_kwargs):
        return _FakePopenProcess(returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", fake_popen)

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".pwnhunter-openhands-conversation-id").write_text(
        "52910506-d4e5-4129-9512-dae4399500bc\n",
        encoding="utf-8",
    )
    prompt_path = tmp_path / "task.md"
    prompt_path.write_text("prompt", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    result = manager.run_headless(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
        timeout=30,
        git_token=None,
    )

    assert result.status == "completed"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    assert metadata["conversation_id"] == "52910506-d4e5-4129-9512-dae4399500bc"


def test_openhands_run_headless_does_not_expose_github_tokens_to_agent(
    tmp_path: Path, monkeypatch
) -> None:
    manager = OpenHandsLaunchManager(
        host="127.0.0.1",
        start_port=3000,
    )
    captured: dict[str, dict[str, str]] = {}

    def fake_run(*_args, **_kwargs):
        return SimpleNamespace(returncode=0)

    def fake_popen(*_args, **kwargs):
        env = kwargs.get("env", {})
        if isinstance(env, dict):
            captured["env"] = env
        return _FakePopenProcess(returncode=0)

    monkeypatch.setattr("subprocess.run", fake_run)
    monkeypatch.setattr("subprocess.Popen", fake_popen)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_should_not_leak")
    monkeypatch.setenv("GITHUB_TOKENS_USER_A", "ghp_should_not_leak_a")
    monkeypatch.setenv("GITHUB_TOKENS_USER_B", "ghp_should_not_leak_b")

    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = tmp_path / "task.md"
    prompt_path.write_text("prompt", encoding="utf-8")
    metadata_path = tmp_path / "agent-runtime.json"

    result = manager.run_headless(
        workspace_path=workspace,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
        timeout=30,
        git_token="ghp_git_token_should_not_leak",
    )

    assert result.status == "completed"
    assert "GITHUB_TOKEN" not in captured["env"]
    assert "GITHUB_TOKENS_USER_A" not in captured["env"]
    assert "GITHUB_TOKENS_USER_B" not in captured["env"]
    assert "GIT_TOKEN" not in captured["env"]
    assert captured["env"]["GIT_CONFIG_NOSYSTEM"] == "1"
    assert captured["env"]["GIT_TERMINAL_PROMPT"] == "0"
    assert captured["env"]["GIT_ASKPASS"] == "/bin/false"
    assert captured["env"]["SSH_ASKPASS"] == "/bin/false"
    assert captured["env"]["HOME"].endswith("/.pwnhunter-home")
    assert captured["env"]["XDG_CONFIG_HOME"].endswith("/.pwnhunter-xdg")


def test_openhands_headless_env_disables_credential_helpers(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    prompt_path = workspace / "agent-task.md"
    prompt_path.write_text("prompt", encoding="utf-8")
    global_config = workspace / ".gitconfig.pwnhunter"

    env = _build_headless_base_env(
        workspace_path=workspace,
        prompt_copy_in_workspace=prompt_path,
        isolated_global_gitconfig=global_config,
        conversation_id_path=workspace / ".pwnhunter-openhands-conversation-id",
        conversation_persistence_dir=workspace / ".pwnhunter-openhands-state",
        tracing_env={},
        risk_trace_context=None,
    )

    helper_result = subprocess.run(
        ["git", "config", "--get-all", "credential.helper"],
        cwd=workspace,
        env=env,
        check=False,
        capture_output=True,
        text=True,
    )
    assert helper_result.stdout.strip() == ""

    credential_result = subprocess.run(
        ["git", "credential", "fill"],
        cwd=workspace,
        env=env,
        check=False,
        capture_output=True,
        input="protocol=https\nhost=github.com\n\n",
        text=True,
    )
    assert "password=" not in credential_result.stdout
