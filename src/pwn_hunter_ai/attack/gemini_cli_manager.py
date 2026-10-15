from __future__ import annotations

from dataclasses import dataclass
import json
import logging
import os
from pathlib import Path
import re
import shlex
import signal
import subprocess
import threading
import time
from typing import Any

from pwn_hunter_ai.attack.agent_runtime import (
    AttackAgentHeadlessResult,
    AttackAgentLaunchResult,
    AttackAgentProvider,
)
from pwn_hunter_ai.attack.git_identity import (
    DEFAULT_GIT_USER_EMAIL,
    DEFAULT_GIT_USER_NAME,
    render_isolated_gitconfig,
)

LOGGER = logging.getLogger(__name__)
LOCAL_SECRETS_FILENAME = ".secrets"
GEMINI_CHAT_ID_FILENAME = ".pwnhunter-gemini-chat-id"
_MIN_NODE_MAJOR_VERSION = 20
_NVM_NODE_FALLBACKS = ("24", "22", "20")


@dataclass(frozen=True, slots=True)
class GeminiCliConfig:
    model: str | None = None
    billing: str = "oauth"


class GeminiCliRuntimeManager:
    def __init__(self, *, config: GeminiCliConfig | None = None) -> None:
        self._config = config or GeminiCliConfig()

    @property
    def provider_name(self) -> AttackAgentProvider:
        return AttackAgentProvider.GEMINI_CLI

    def launch(
        self,
        *,
        workspace_path: Path,
        prompt_path: Path,
        metadata_path: Path,
    ) -> AttackAgentLaunchResult:
        _ = (workspace_path, prompt_path)
        payload = {
            "provider": self.provider_name.value,
            "status": "unavailable",
            "reason": (
                "Gemini CLI does not support long-lived launch mode. "
                "Use --auto-execute or run Gemini manually with the generated prompt."
            ),
            "base_url": None,
            "pid": None,
            "command": [],
            "tracing": {
                "enabled": False,
                "service_name": "pwnhunter-attack-gemini-cli",
                "endpoint": None,
            },
        }
        metadata_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return AttackAgentLaunchResult(
            status="unavailable",
            base_url=None,
            pid=None,
            command=[],
            metadata_path=metadata_path,
            tracing=payload["tracing"],
        )

    def run_headless(
        self,
        *,
        workspace_path: Path,
        prompt_path: Path,
        metadata_path: Path,
        timeout: int = 900,
        git_token: str | None = None,
        git_user_name: str | None = None,
        git_user_email: str | None = None,
    ) -> AttackAgentHeadlessResult:
        _ = git_token
        stdout_path = metadata_path.with_name("gemini-cli-headless.stdout.log")
        stderr_path = metadata_path.with_name("gemini-cli-headless.stderr.log")

        prompt_text = prompt_path.read_text(encoding="utf-8")
        prompt_bytes = len(prompt_text.encode("utf-8"))
        LOGGER.info(
            "attack.lifecycle %s",
            json.dumps(
                {
                    "event": "prompt_build",
                    "provider": self.provider_name.value,
                    "prompt_transport": "stdin",
                    "prompt_bytes": prompt_bytes,
                    "prompt_path": str(prompt_path),
                    "workspace_path": str(workspace_path),
                },
                sort_keys=True,
            ),
        )
        command = [
            "gemini",
            "--prompt",
            "Prompt content provided on stdin.",
            "--output-format",
            "stream-json",
            "--approval-mode",
            "yolo",
        ]
        if self._config.model:
            command.extend(["--model", self._config.model])
        resumed_chat_id = _read_workspace_chat_id(workspace_path)
        if resumed_chat_id:
            command.extend(["--resume", resumed_chat_id])

        env = self._build_headless_env(
            workspace_path,
            git_user_name=git_user_name,
            git_user_email=git_user_email,
        )
        runtime_unavailable_reason: str | None = None
        try:
            env = _ensure_supported_node_runtime(env)
        except RuntimeError as exc:
            runtime_unavailable_reason = str(exc)
            LOGGER.warning("Gemini CLI runtime unavailable: %s", runtime_unavailable_reason)
        status = "completed"
        exit_code: int | None = 0
        if runtime_unavailable_reason is not None:
            status = "unavailable"
            exit_code = None
            stdout_path.write_text("", encoding="utf-8")
            stderr_path.write_text(runtime_unavailable_reason + "\n", encoding="utf-8")
            payload: dict[str, Any] = {
                "provider": self.provider_name.value,
                "executor": "gemini-cli",
                "status": status,
                "reason": runtime_unavailable_reason,
                "exit_code": exit_code,
                "resumed_chat_id": resumed_chat_id,
                "command": [_redact_sensitive_text(part) for part in command],
                "workspace_path": str(workspace_path),
                "prompt_path": str(prompt_path),
                "stdout_path": str(stdout_path),
                "stderr_path": str(stderr_path),
                "tracing": {
                    "enabled": False,
                    "service_name": "pwnhunter-attack-gemini-cli",
                    "endpoint": None,
                },
                "chat_id": None,
            }
            metadata_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
            return AttackAgentHeadlessResult(
                status=status,
                pid=None,
                exit_code=exit_code,
                stdout_path=stdout_path,
                stderr_path=stderr_path,
                tracing=payload["tracing"],
            )
        LOGGER.info(
            "Starting Gemini CLI headless run in %s with timeout=%ss",
            workspace_path,
            timeout,
        )
        with (
            stdout_path.open("w", encoding="utf-8") as stdout_handle,
            stderr_path.open("w", encoding="utf-8") as stderr_handle,
        ):
            try:
                exit_code = _run_with_live_output(
                    command,
                    cwd=workspace_path,
                    env=env,
                    timeout=max(1, timeout),
                    stdout_file=stdout_handle,
                    stderr_file=stderr_handle,
                    stdout_line_callback=self._log_stream_event_line,
                    stdin_input=prompt_text,
                )
                if exit_code != 0:
                    status = "failed"
            except subprocess.TimeoutExpired as exc:
                _ = exc
                status = "timeout"
                exit_code = None
                LOGGER.warning("Gemini CLI headless run timed out after %ss", timeout)
        if exit_code is not None:
            LOGGER.info("Gemini CLI headless run finished with exit code %s", exit_code)

        payload: dict[str, Any] = {
            "provider": self.provider_name.value,
            "executor": "gemini-cli",
            "status": status,
            "exit_code": exit_code,
            "resumed_chat_id": resumed_chat_id,
            "command": [_redact_sensitive_text(part) for part in command],
            "workspace_path": str(workspace_path),
            "prompt_path": str(prompt_path),
            "prompt_transport": "stdin",
            "prompt_bytes": prompt_bytes,
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
            "tracing": {
                "enabled": False,
                "service_name": "pwnhunter-attack-gemini-cli",
                "endpoint": None,
            },
        }
        latest_chat_id = _extract_latest_session_id(stdout_path)
        if latest_chat_id:
            _write_workspace_chat_id(workspace_path, latest_chat_id)
        payload["chat_id"] = latest_chat_id
        metadata_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

        return AttackAgentHeadlessResult(
            status=status,
            pid=None,
            exit_code=exit_code,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            tracing=payload["tracing"],
        )

    def _build_headless_env(
        self,
        workspace_path: Path,
        *,
        git_user_name: str | None = None,
        git_user_email: str | None = None,
    ) -> dict[str, str]:
        source_env = os.environ
        env: dict[str, str] = {}

        passthrough_keys = (
            "PATH",
            "LANG",
            "LC_ALL",
            "LC_CTYPE",
            "TERM",
            "TMPDIR",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "NO_PROXY",
        )
        for key in passthrough_keys:
            if value := source_env.get(key):
                env[key] = value

        billing_mode = str(self._config.billing).strip().lower()
        if billing_mode == "api":
            for key in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "LLM_API_KEY"):
                if value := source_env.get(key):
                    env[key] = value
        env.update(_load_workspace_secrets(workspace_path / LOCAL_SECRETS_FILENAME))
        if billing_mode != "api":
            for key in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "LLM_API_KEY"):
                env.pop(key, None)
        env.pop("GITHUB_TOKEN", None)

        for key in (
            "OTLP_GOOGLE_CLOUD_PROJECT",
            "GOOGLE_CLOUD_PROJECT",
            "GOOGLE_APPLICATION_CREDENTIALS",
            "GEMINI_CLI_SURFACE",
        ):
            if value := source_env.get(key):
                env[key] = value
        for key, value in source_env.items():
            if key.startswith("GEMINI_TELEMETRY_"):
                env[key] = value

        isolated_home = workspace_path / ".pwnhunter-home"
        isolated_xdg_home = workspace_path / ".pwnhunter-xdg"
        isolated_gitconfig = workspace_path / ".gitconfig.pwnhunter"
        _write_isolated_global_gitconfig(
            isolated_gitconfig,
            git_user_name=git_user_name or DEFAULT_GIT_USER_NAME,
            git_user_email=git_user_email or DEFAULT_GIT_USER_EMAIL,
        )

        if billing_mode == "oauth":
            if source_home := source_env.get("HOME"):
                env["HOME"] = source_home
            env.pop("XDG_CONFIG_HOME", None)
        else:
            isolated_home.mkdir(parents=True, exist_ok=True)
            isolated_xdg_home.mkdir(parents=True, exist_ok=True)
            env["HOME"] = str(isolated_home)
            env["XDG_CONFIG_HOME"] = str(isolated_xdg_home)
        env["GIT_CONFIG_GLOBAL"] = str(isolated_gitconfig)
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_ASKPASS"] = "/bin/false"
        env["SSH_ASKPASS"] = "/bin/false"
        self._apply_pwnhunter_telemetry_overrides(
            env=env,
            workspace_path=workspace_path,
        )
        return env

    def _apply_pwnhunter_telemetry_overrides(
        self,
        *,
        env: dict[str, str],
        workspace_path: Path,
    ) -> None:
        enabled_raw = os.getenv("PWNHUNTER_GEMINI_TELEMETRY_ENABLED")
        if enabled_raw is None:
            return
        enabled = _is_truthy(enabled_raw)
        env["GEMINI_TELEMETRY_ENABLED"] = "true" if enabled else "false"
        if not enabled:
            LOGGER.info("Gemini CLI telemetry disabled via PWNHUNTER override.")
            return

        target = os.getenv("PWNHUNTER_GEMINI_TELEMETRY_TARGET", "local").strip().lower()
        if target in {"local", "gcp"}:
            env["GEMINI_TELEMETRY_TARGET"] = target

        outfile_raw = os.getenv("PWNHUNTER_GEMINI_TELEMETRY_OUTFILE")
        outfile_path: Path | None = None
        if outfile_raw:
            candidate = Path(outfile_raw)
            outfile_path = candidate if candidate.is_absolute() else workspace_path / candidate
        elif env.get("GEMINI_TELEMETRY_TARGET") == "local":
            outfile_path = workspace_path / ".gemini" / "telemetry.log"
        if outfile_path is not None:
            outfile_path.parent.mkdir(parents=True, exist_ok=True)
            env["GEMINI_TELEMETRY_OUTFILE"] = str(outfile_path)
            LOGGER.info("Gemini CLI telemetry local outfile: %s", outfile_path)

        log_prompts_raw = os.getenv("PWNHUNTER_GEMINI_TELEMETRY_LOG_PROMPTS")
        if log_prompts_raw is not None:
            env["GEMINI_TELEMETRY_LOG_PROMPTS"] = (
                "true" if _is_truthy(log_prompts_raw) else "false"
            )

    def _log_stream_event_line(self, line_text: str) -> None:
        try:
            event = json.loads(line_text)
        except json.JSONDecodeError:
            LOGGER.info("Gemini CLI stdout: %s", line_text)
            return
        if not isinstance(event, dict):
            LOGGER.info("Gemini CLI stdout event: %s", line_text)
            return

        event_type = str(event.get("type") or "").strip()
        if event_type == "init":
            LOGGER.info(
                "Gemini CLI session init: session_id=%s model=%s",
                event.get("session_id"),
                event.get("model"),
            )
            return
        if event_type == "message":
            role = str(event.get("role") or "unknown")
            content = str(event.get("content") or "")
            is_delta = event.get("delta") is True
            suffix = " delta" if is_delta else ""
            LOGGER.info("Gemini CLI %s%s: %s", role, suffix, content)
            return
        if event_type == "tool_use":
            tool_name = str(event.get("tool_name") or "unknown")
            tool_id = str(event.get("tool_id") or "unknown")
            parameters = event.get("parameters")
            params_text = _truncate_json(parameters, limit=1_500)
            LOGGER.info(
                "Gemini CLI tool_use: name=%s id=%s params=%s",
                tool_name,
                tool_id,
                params_text,
            )
            return
        if event_type == "tool_result":
            tool_id = str(event.get("tool_id") or "unknown")
            status = str(event.get("status") or "unknown")
            output_text = _truncate_text(str(event.get("output") or ""), limit=1_500)
            LOGGER.info(
                "Gemini CLI tool_result: id=%s status=%s output=%s",
                tool_id,
                status,
                output_text,
            )
            return
        if event_type == "error":
            message = str(event.get("message") or event.get("error") or "")
            LOGGER.warning("Gemini CLI stream error: %s", message)
            return
        if event_type == "result":
            status = str(event.get("status") or "unknown")
            stats_text = _truncate_json(event.get("stats"), limit=2_000)
            LOGGER.info("Gemini CLI result: status=%s stats=%s", status, stats_text)
            return

        LOGGER.info(
            "Gemini CLI event (%s): %s",
            event_type or "unknown",
            _truncate_json(event, limit=2_000),
        )


def _write_isolated_global_gitconfig(
    path: Path,
    *,
    git_user_name: str = DEFAULT_GIT_USER_NAME,
    git_user_email: str = DEFAULT_GIT_USER_EMAIL,
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = render_isolated_gitconfig(
        git_user_name=git_user_name,
        git_user_email=git_user_email,
    )
    path.write_text(payload, encoding="utf-8")


def _load_workspace_secrets(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    secrets: dict[str, str] = {}
    try:
        content = path.read_text(encoding="utf-8")
    except OSError:
        return {}
    for raw_line in content.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if key:
            secrets[key] = value
    return secrets


def _workspace_chat_id_path(workspace_path: Path) -> Path:
    return workspace_path / GEMINI_CHAT_ID_FILENAME


def _read_workspace_chat_id(workspace_path: Path) -> str | None:
    chat_id_path = _workspace_chat_id_path(workspace_path)
    try:
        value = chat_id_path.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return value or None


def _write_workspace_chat_id(workspace_path: Path, chat_id: str) -> None:
    value = chat_id.strip()
    if not value:
        return
    chat_id_path = _workspace_chat_id_path(workspace_path)
    try:
        chat_id_path.write_text(value + "\n", encoding="utf-8")
    except OSError as exc:
        LOGGER.warning("Failed writing Gemini CLI chat id cache %s: %s", chat_id_path, exc)


def _extract_latest_session_id(stdout_path: Path) -> str | None:
    try:
        lines = stdout_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    latest_session_id: str | None = None
    for raw_line in lines:
        line = raw_line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(payload, dict):
            continue
        if str(payload.get("type") or "").strip() != "init":
            continue
        session_id = payload.get("session_id")
        if isinstance(session_id, str) and session_id.strip():
            latest_session_id = session_id.strip()
    return latest_session_id


def _redact_sensitive_text(value: str) -> str:
    redacted = value.replace("\n", " ")
    redacted = re.sub(
        r"x-access-token:[^@\s]+@github\.com",
        "x-access-token:***@github.com",
        redacted,
    )
    redacted = re.sub(
        r"https://[^/\s]+@github\.com",
        "https://***@github.com",
        redacted,
    )
    redacted = re.sub(r"\bgh[pousr]_[A-Za-z0-9_]+\b", "***", redacted)
    if len(redacted) > 300:
        redacted = redacted[:300] + "..."
    return shlex.quote(redacted) if redacted else redacted


def _ensure_supported_node_runtime(base_env: dict[str, str]) -> dict[str, str]:
    node_major = _read_node_major_version(base_env)
    if node_major is not None and node_major >= _MIN_NODE_MAJOR_VERSION:
        return base_env

    shell = os.environ.get("SHELL") or "/bin/zsh"
    if not _shell_command_succeeds(shell, _with_nvm_loaded("command -v nvm >/dev/null 2>&1")):
        raise RuntimeError(
            "Node.js >= 20 is required for Gemini CLI. Current node is missing or < 20, "
            "and nvm is not available."
        )

    for target_version in _NVM_NODE_FALLBACKS:
        resolved_path = _path_after_nvm_use(shell=shell, target_version=target_version)
        if resolved_path is None:
            continue
        candidate_env = dict(base_env)
        candidate_env["PATH"] = resolved_path
        node_major = _read_node_major_version(candidate_env)
        if node_major is not None and node_major >= _MIN_NODE_MAJOR_VERSION:
            return candidate_env

    raise RuntimeError(
        "Gemini CLI skipped: unable to activate Node.js 24, 22, or 20 via nvm "
        "(Node.js >= 20 required)."
    )


def _read_node_major_version(env: dict[str, str]) -> int | None:
    try:
        completed = subprocess.run(
            [
                "node",
                "-p",
                'Number(process.versions.node.split(".")[0])',
            ],
            env=env,
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError, OSError):
        return None
    output = completed.stdout.strip()
    if not output:
        return None
    try:
        return int(output)
    except ValueError:
        return None


def _shell_command_succeeds(shell: str, command: str) -> bool:
    try:
        completed = subprocess.run(
            [shell, "-lc", command],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return False
    return completed.returncode == 0


def _path_after_nvm_use(*, shell: str, target_version: str) -> str | None:
    marker = "__PWNHUNTER_PATH__="
    command = _with_nvm_loaded(
        f"nvm use {target_version} >/dev/null 2>&1 || exit 1; "
        f'printf "{marker}%s\\n" "$PATH"'
    )
    try:
        completed = subprocess.run(
            [shell, "-lc", command],
            check=False,
            capture_output=True,
            text=True,
        )
    except OSError:
        return None
    if completed.returncode != 0:
        return None
    for raw_line in reversed(completed.stdout.splitlines()):
        line = raw_line.strip()
        if line.startswith(marker):
            path_value = line[len(marker) :].strip()
            if path_value:
                return path_value
    return None


def _with_nvm_loaded(command: str) -> str:
    # nvm is usually a shell function defined by sourcing nvm.sh.
    return (
        'export NVM_DIR="${NVM_DIR:-$HOME/.nvm}"; '
        '[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"; '
        f"{command}"
    )


def _is_truthy(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _truncate_text(value: str, *, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "...(truncated)"


def _truncate_json(payload: Any, *, limit: int) -> str:
    try:
        raw = json.dumps(payload, ensure_ascii=True)
    except Exception:
        raw = str(payload)
    return _truncate_text(raw, limit=limit)


def _run_with_live_output(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    env: dict[str, str],
    stdout_file,
    stderr_file,
    stdout_line_callback=None,
    stdin_input: str | None = None,
) -> int:
    popen_kwargs: dict[str, Any] = {
        "cwd": cwd,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
        "bufsize": 1,
        "env": env,
    }
    if stdin_input is not None:
        popen_kwargs["stdin"] = subprocess.PIPE
    if os.name != "nt":
        popen_kwargs["start_new_session"] = True
    process = subprocess.Popen(
        command,
        **popen_kwargs,
    )

    process_stdin = getattr(process, "stdin", None)
    if stdin_input is not None and process_stdin is not None:
        process_stdin.write(stdin_input)
        process_stdin.close()

    assert process.stdout is not None
    assert process.stderr is not None

    def _forward_lines(source, destination, stream_name: str) -> None:
        try:
            for line in iter(source.readline, ""):
                destination.write(line)
                destination.flush()
                line_text = line.rstrip("\n")
                if not line_text:
                    continue
                if stream_name == "stdout" and callable(stdout_line_callback):
                    stdout_line_callback(line_text)
                else:
                    LOGGER.info("Gemini CLI %s: %s", stream_name, line_text)
        except ValueError:
            # The stream may already be closed during timeout teardown.
            return
        finally:
            try:
                source.close()
            except Exception:
                pass

    stdout_thread = threading.Thread(
        target=_forward_lines,
        args=(process.stdout, stdout_file, "stdout"),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_forward_lines,
        args=(process.stderr, stderr_file, "stderr"),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    timed_out = False
    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        _terminate_process_tree(process)
        process.wait()
        raise
    finally:
        if timed_out:
            _close_process_streams(process)
            _join_output_threads([stdout_thread, stderr_thread], timeout_seconds=3.0)
        else:
            stdout_thread.join()
            stderr_thread.join()

    return process.returncode


def _terminate_process_tree(process: subprocess.Popen[Any]) -> None:
    if os.name != "nt":
        try:
            os.killpg(process.pid, signal.SIGKILL)
            return
        except Exception:
            pass
    process.kill()


def _close_process_streams(process: subprocess.Popen[Any]) -> None:
    for stream in (process.stdout, process.stderr):
        if stream is None:
            continue
        try:
            stream.close()
        except Exception:
            continue


def _join_output_threads(
    threads: list[threading.Thread], *, timeout_seconds: float
) -> None:
    deadline = time.monotonic() + max(0.0, timeout_seconds)
    for thread in threads:
        remaining = max(0.0, deadline - time.monotonic())
        thread.join(timeout=remaining)
    for thread in threads:
        if thread.is_alive():
            LOGGER.warning(
                "Gemini CLI stream forwarding thread did not exit cleanly after %.1fs.",
                timeout_seconds,
            )
