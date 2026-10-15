from __future__ import annotations

import base64
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
from typing import Any
import uuid

from openhands.sdk import Agent, Conversation, LLM, Tool
from openhands.tools.file_editor import FileEditorTool
from openhands.tools.task_tracker import TaskTrackerTool
from openhands.tools.terminal import TerminalTool
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

_ = (Agent, Conversation, LLM, Tool, FileEditorTool, TaskTrackerTool, TerminalTool)


OpenHandsLaunchResult = AttackAgentLaunchResult
OpenHandsHeadlessResult = AttackAgentHeadlessResult


@dataclass(frozen=True, slots=True)
class OpenHandsTracingConfig:
    public_key: str | None
    secret_key: str | None
    host: str | None = None
    service_name: str = "pwnhunter-attack-openhands"

    def build_env(self) -> dict[str, str]:
        if not self.public_key or not self.secret_key:
            return {}
        credentials = f"{self.public_key}:{self.secret_key}".encode("utf-8")
        encoded_credentials = base64.b64encode(credentials).decode("ascii")
        normalized_host = (self.host or "https://cloud.langfuse.com").rstrip("/")
        endpoint = self._build_endpoint(normalized_host)
        traces_endpoint = f"{endpoint}/v1/traces"
        headers = f"authorization=Basic {encoded_credentials}"
        return {
            "OPENHANDS_TRACING": "1",
            # OpenHands observability uses Laminar OTLP exporter. Force HTTP OTLP to
            # avoid gRPC transport failures against some Langfuse cloud ingress setups.
            "OTEL_EXPORTER": "otlp_http",
            "OTEL_EXPORTER_OTLP_PROTOCOL": "http/protobuf",
            "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
            "OTEL_SERVICE_NAME": self.service_name,
            "OTEL_EXPORTER_OTLP_ENDPOINT": endpoint,
            "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": traces_endpoint,
            # Keep lowercase header key for compatibility across OTLP transports.
            "OTEL_EXPORTER_OTLP_HEADERS": headers,
            "OTEL_EXPORTER_OTLP_TRACES_HEADERS": headers,
            "LANGFUSE_PUBLIC_KEY": self.public_key,
            "LANGFUSE_SECRET_KEY": self.secret_key,
            "LANGFUSE_OTEL_HOST": normalized_host,
        }

    def metadata(self) -> dict[str, Any]:
        env = self.build_env()
        if not env:
            return {
                "enabled": False,
                "service_name": self.service_name,
                "endpoint": None,
            }
        return {
            "enabled": True,
            "service_name": self.service_name,
            "endpoint": env["OTEL_EXPORTER_OTLP_ENDPOINT"],
        }

    def _build_endpoint(self, normalized_host: str | None = None) -> str:
        normalized_host = normalized_host or (self.host or "https://cloud.langfuse.com").rstrip("/")
        return f"{normalized_host}/api/public/otel"


@dataclass(frozen=True, slots=True)
class RiskTraceContext:
    trace_id: str
    session_id: str
    tags: list[str]
    generation_name: str


@dataclass(frozen=True, slots=True)
class HeadlessLLMStrategy:
    name: str
    model: str
    allow_tools: bool
    allow_google_search: bool


HEADLESS_LLM_STRATEGIES: tuple[HeadlessLLMStrategy, ...] = (
    HeadlessLLMStrategy(
        name="gemini_flash_lite_no_tools",
        model="gemini/gemini-3.1-flash-lite-preview",
        allow_tools=True,
        allow_google_search=True,
    ),
    HeadlessLLMStrategy(
        name="gemini_flash_google_search",
        model="gemini/gemini-3.1-flash-lite-preview",
        allow_tools=True,
        allow_google_search=True,
    ),
)


class OpenHandsLaunchManager:
    def __init__(
        self,
        *,
        host: str,
        start_port: int,
        tracing: OpenHandsTracingConfig | None = None,
    ) -> None:
        self._host = host
        self._next_port = start_port
        self._tracing = tracing

    @property
    def provider_name(self) -> AttackAgentProvider:
        return AttackAgentProvider.OPENHANDS

    def launch(
        self,
        *,
        workspace_path: Path,
        prompt_path: Path,
        metadata_path: Path,
    ) -> OpenHandsLaunchResult:
        _ = (workspace_path, prompt_path)
        return self.unavailable(
            metadata_path=metadata_path,
            reason=(
                "OpenHands web-server launch via CLI has been removed. "
                "Use --auto-execute for SDK-based headless execution."
            ),
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
    ) -> OpenHandsHeadlessResult:
        return self._run_headless_with_sdk(
            workspace_path=workspace_path,
            prompt_path=prompt_path,
            metadata_path=metadata_path,
            timeout=timeout,
            git_token=git_token,
            git_user_name=git_user_name,
            git_user_email=git_user_email,
        )

    def _run_headless_with_sdk(
        self,
        *,
        workspace_path: Path,
        prompt_path: Path,
        metadata_path: Path,
        timeout: int = 900,
        git_token: str | None = None,
        git_user_name: str | None = None,
        git_user_email: str | None = None,
    ) -> OpenHandsHeadlessResult:
        stdout_path = metadata_path.with_name("openhands-headless.stdout.log")
        stderr_path = metadata_path.with_name("openhands-headless.stderr.log")
        isolated_global_gitconfig = workspace_path / ".gitconfig.pwnhunter"

        prompt_copy_in_workspace = workspace_path / "agent-task.md"
        conversation_id_path = workspace_path / ".pwnhunter-openhands-conversation-id"
        conversation_persistence_dir = workspace_path / ".pwnhunter-openhands-state"
        import shutil as sh

        sh.copy2(prompt_path, prompt_copy_in_workspace)
        base_prompt_text = prompt_copy_in_workspace.read_text(encoding="utf-8")

        resolved_git_user_name = git_user_name or DEFAULT_GIT_USER_NAME
        resolved_git_user_email = git_user_email or DEFAULT_GIT_USER_EMAIL

        self._setup_git_credentials(
            workspace_path,
            git_user_name=resolved_git_user_name,
            git_user_email=resolved_git_user_email,
        )

        command = [sys.executable, "-c", _SDK_HEADLESS_RUNNER_CODE]
        risk_trace_context = _load_risk_trace_context(metadata_path.parent)

        base_env = _build_headless_base_env(
            workspace_path=workspace_path,
            prompt_copy_in_workspace=prompt_copy_in_workspace,
            isolated_global_gitconfig=isolated_global_gitconfig,
            conversation_id_path=conversation_id_path,
            conversation_persistence_dir=conversation_persistence_dir,
            tracing_env=self._tracing_env(),
            risk_trace_context=risk_trace_context,
            git_user_name=resolved_git_user_name,
            git_user_email=resolved_git_user_email,
        )

        process = None
        attempt_records: list[dict[str, Any]] = []
        selected_strategy = HEADLESS_LLM_STRATEGIES[-1]
        for index, strategy in enumerate(HEADLESS_LLM_STRATEGIES, start=1):
            selected_strategy = strategy
            stdout_path = metadata_path.with_name(
                f"openhands-headless.{strategy.name}.stdout.log"
            )
            stderr_path = metadata_path.with_name(
                f"openhands-headless.{strategy.name}.stderr.log"
            )
            prompt_copy_in_workspace.write_text(
                _build_strategy_prompt(base_prompt_text, strategy),
                encoding="utf-8",
            )
            env = _build_strategy_env(base_env=base_env, strategy=strategy)

            with (
                stdout_path.open("w", encoding="utf-8") as stdout_handle,
                stderr_path.open("w", encoding="utf-8") as stderr_handle,
            ):
                return_code = _run_with_live_output(
                    command,
                    cwd=workspace_path,
                    timeout=timeout,
                    env=env,
                    stdout_file=stdout_handle,
                    stderr_file=stderr_handle,
                )
                process = subprocess.CompletedProcess(
                    args=command,
                    returncode=return_code,
                )
            attempt_records.append(
                {
                    "attempt": index,
                    "strategy": strategy.name,
                    "model": strategy.model,
                    "allow_tools": strategy.allow_tools,
                    "allow_google_search": strategy.allow_google_search,
                    "exit_code": process.returncode,
                    "stdout_path": str(stdout_path),
                    "stderr_path": str(stderr_path),
                }
            )
            if process.returncode == 0:
                break

        if process is None:
            raise RuntimeError("No headless strategy executed.")

        payload = {
            "status": "completed" if process.returncode == 0 else "failed",
            "exit_code": process.returncode,
            "command": command,
            "executor": "openhands-sdk",
            "conversation_id": _read_conversation_id(conversation_id_path),
            "llm_strategy": selected_strategy.name,
            "llm_model": selected_strategy.model,
            "attempts": attempt_records,
            "tracing": self._tracing_metadata(),
            "risk_trace": (
                {
                    "trace_id": risk_trace_context.trace_id,
                    "session_id": risk_trace_context.session_id,
                    "tags": risk_trace_context.tags,
                    "generation_name": risk_trace_context.generation_name,
                }
                if risk_trace_context is not None
                else None
            ),
            "workspace_path": str(workspace_path),
            "prompt_path": str(prompt_path),
            "stdout_path": str(stdout_path),
            "stderr_path": str(stderr_path),
        }
        metadata_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

        return OpenHandsHeadlessResult(
            status=payload["status"],
            pid=None,
            exit_code=process.returncode,
            stdout_path=stdout_path,
            stderr_path=stderr_path,
            tracing=self._tracing_metadata(),
        )

    def _setup_git_credentials(
        self,
        workspace_path: Path,
        *,
        git_user_name: str,
        git_user_email: str,
    ) -> None:
        import subprocess as sp

        sp.run(
            ["git", "config", "user.email", git_user_email],
            cwd=workspace_path,
            check=True,
            capture_output=True,
        )
        sp.run(
            ["git", "config", "user.name", git_user_name],
            cwd=workspace_path,
            check=True,
            capture_output=True,
        )

    def unavailable(self, *, metadata_path: Path, reason: str) -> OpenHandsLaunchResult:
        payload = {
            "status": "unavailable",
            "reason": reason,
            "base_url": None,
            "pid": None,
            "command": [],
            "tracing": self._tracing_metadata(),
        }
        metadata_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
        return OpenHandsLaunchResult(
            status="unavailable",
            base_url=None,
            pid=None,
            command=[],
            metadata_path=metadata_path,
            tracing=self._tracing_metadata(),
        )

    def _tracing_env(self) -> dict[str, str]:
        if self._tracing is None:
            return {}
        return self._tracing.build_env()

    def _tracing_metadata(self) -> dict[str, Any]:
        if self._tracing is None:
            return {
                "enabled": False,
                "service_name": "pwnhunter-attack-openhands",
                "endpoint": None,
            }
        return self._tracing.metadata()


def _build_strategy_prompt(base_prompt: str, strategy: HeadlessLLMStrategy) -> str:
    if strategy.allow_tools:
        instruction = (
            "Model strategy: retry with Gemini Pro. If available, you may use Google Search as a tool. "
            "Do not finish with planning-only output; edit required repository files (or update agent-output.json when appropriate) before finishing."
        )
    else:
        instruction = (
            "Model strategy: first attempt with Gemini Flash. Do not use external tools. "
            "Do not finish with planning-only output; edit required repository files (or update agent-output.json when appropriate) before finishing."
        )
    return f"{base_prompt.rstrip()}\n\n{instruction}\n"


def _build_strategy_env(*, base_env: dict[str, str], strategy: HeadlessLLMStrategy) -> dict[str, str]:
    env = dict(base_env)
    env["LLM_MODEL"] = strategy.model
    env["LLM_PROVIDER"] = "gemini"
    return env


def _build_headless_base_env(
    *,
    workspace_path: Path,
    prompt_copy_in_workspace: Path,
    isolated_global_gitconfig: Path,
    conversation_id_path: Path,
    conversation_persistence_dir: Path,
    tracing_env: dict[str, str],
    risk_trace_context: RiskTraceContext | None,
    git_user_name: str = DEFAULT_GIT_USER_NAME,
    git_user_email: str = DEFAULT_GIT_USER_EMAIL,
) -> dict[str, str]:
    source_env = os.environ
    env: dict[str, str] = {}
    isolated_home = workspace_path / ".pwnhunter-home"
    isolated_xdg_home = workspace_path / ".pwnhunter-xdg"
    isolated_home.mkdir(parents=True, exist_ok=True)
    isolated_xdg_home.mkdir(parents=True, exist_ok=True)
    _write_isolated_global_gitconfig(
        isolated_global_gitconfig,
        git_user_name=git_user_name,
        git_user_email=git_user_email,
    )

    passthrough_keys = (
        "PATH",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "TMPDIR",
        "PYTHONPATH",
        "VIRTUAL_ENV",
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
        value = source_env.get(key)
        if value:
            env[key] = value

    llm_keys = ("GEMINI_API_KEY", "GOOGLE_API_KEY", "LLM_API_KEY", "LLM_BASE_URL")
    for key in llm_keys:
        value = source_env.get(key)
        if value:
            env[key] = value

    env["PWNHUNTER_WORKSPACE"] = str(workspace_path.absolute())
    env["PWNHUNTER_AGENT_PROMPT_PATH"] = str(prompt_copy_in_workspace.resolve())
    env["PWNHUNTER_AGENT_CONVERSATION_ID_PATH"] = str(
        conversation_id_path.resolve()
    )
    env["PWNHUNTER_AGENT_PERSISTENCE_DIR"] = str(
        conversation_persistence_dir.resolve()
    )
    env["HOME"] = str(isolated_home)
    env["XDG_CONFIG_HOME"] = str(isolated_xdg_home)
    env["GIT_CONFIG_GLOBAL"] = str(isolated_global_gitconfig)
    env["GIT_CONFIG_NOSYSTEM"] = "1"
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "/bin/false"
    env["SSH_ASKPASS"] = "/bin/false"
    has_langfuse_credentials = bool(
        tracing_env.get("LANGFUSE_PUBLIC_KEY") and tracing_env.get("LANGFUSE_SECRET_KEY")
    )
    if risk_trace_context is not None and has_langfuse_credentials:
        env["PWNHUNTER_LANGFUSE_TRACE_ID"] = risk_trace_context.trace_id
        env["PWNHUNTER_LANGFUSE_SESSION_ID"] = risk_trace_context.session_id
        env["PWNHUNTER_LANGFUSE_TAGS"] = json.dumps(
            risk_trace_context.tags, separators=(",", ":")
        )
        env["PWNHUNTER_LANGFUSE_GENERATION_NAME"] = (
            risk_trace_context.generation_name
        )
    env.update(tracing_env)
    return env


def _read_conversation_id(path: Path) -> str | None:
    try:
        raw_value = path.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    if not raw_value:
        return None
    try:
        return str(uuid.UUID(raw_value))
    except Exception:
        return None


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


def _load_risk_trace_context(artifact_root: Path) -> RiskTraceContext | None:
    context_path = artifact_root / "attack-context.json"
    if not context_path.exists():
        return None
    try:
        payload = json.loads(context_path.read_text(encoding="utf-8"))
    except Exception:
        return None
    repository_name = str(payload.get("repository_name") or "").strip()
    risk = payload.get("risk")
    if not repository_name or not isinstance(risk, dict):
        return None

    workflow = str(risk.get("initial_workflow") or "unknown-workflow")
    issue_type = str(risk.get("issue_type") or "unknown-issue")
    path = risk.get("gato-x-path")
    if path is None:
        path = risk.get("path")
    path_repr = json.dumps(path if isinstance(path, list) else [], sort_keys=True)
    digest_source = "|".join([repository_name, workflow, issue_type, path_repr])
    trace_id = f"risk-{hashlib.sha256(digest_source.encode('utf-8')).hexdigest()[:32]}"
    session_id = repository_name.replace("/", "__")[:200]
    tags = [
        "pwnhunter",
        "attack",
        "openhands",
        f"repo:{repository_name}",
        f"workflow:{workflow}",
        f"issue:{issue_type}",
    ]
    return RiskTraceContext(
        trace_id=trace_id,
        session_id=session_id,
        tags=tags,
        generation_name="openhands-sdk-generation",
    )


_SDK_HEADLESS_RUNNER_CODE = r"""
import os
import json
import uuid
from pathlib import Path

from openhands.sdk import Agent, Conversation, LLM, Tool
from openhands.tools.file_editor import FileEditorTool
from openhands.tools.task_tracker import TaskTrackerTool
from openhands.tools.terminal import TerminalTool


def _load_conversation_id(path: Path) -> uuid.UUID | None:
    try:
        raw_value = path.read_text(encoding="utf-8").strip()
    except Exception:
        return None
    if not raw_value:
        return None
    try:
        return uuid.UUID(raw_value)
    except Exception:
        return None


def _save_conversation_id(path: Path, value: uuid.UUID) -> None:
    try:
        path.write_text(str(value) + "\n", encoding="utf-8")
    except Exception:
        pass


def _resolve_api_key(model: str) -> str | None:
    normalized = model.lower()
    if normalized.startswith("gemini/") or normalized.startswith("google/"):
        return (
            os.getenv("GEMINI_API_KEY")
            or os.getenv("GOOGLE_API_KEY")
            or os.getenv("LLM_API_KEY")
        )
    return os.getenv("LLM_API_KEY")


def _configure_langfuse_litellm() -> None:
    trace_id = os.getenv("PWNHUNTER_LANGFUSE_TRACE_ID")
    has_langfuse_credentials = bool(
        os.getenv("LANGFUSE_PUBLIC_KEY") and os.getenv("LANGFUSE_SECRET_KEY")
    )
    if not trace_id or not has_langfuse_credentials:
        return

    try:
        import litellm
        import openhands.sdk.llm.llm as openhands_llm_module
    except Exception:
        return

    callbacks = getattr(litellm, "callbacks", None) or []
    if isinstance(callbacks, str):
        callbacks = [callbacks]
    if "langfuse_otel" not in callbacks:
        callbacks = list(callbacks)
        callbacks.append("langfuse_otel")
        litellm.callbacks = callbacks

    metadata_template = {"trace_id": trace_id}
    session_id = os.getenv("PWNHUNTER_LANGFUSE_SESSION_ID")
    if session_id:
        metadata_template["session_id"] = session_id
    generation_name = os.getenv("PWNHUNTER_LANGFUSE_GENERATION_NAME")
    if generation_name:
        metadata_template["generation_name"] = generation_name
    raw_tags = os.getenv("PWNHUNTER_LANGFUSE_TAGS")
    if raw_tags:
        try:
            parsed = json.loads(raw_tags)
            if isinstance(parsed, list):
                metadata_template["tags"] = parsed
        except Exception:
            pass

    original_completion = openhands_llm_module.litellm_completion

    def _completion_with_langfuse_metadata(*args, **kwargs):
        metadata = kwargs.get("metadata")
        if not isinstance(metadata, dict):
            metadata = {}
        merged_metadata = dict(metadata_template)
        merged_metadata.update(metadata)
        kwargs["metadata"] = merged_metadata
        return original_completion(*args, **kwargs)

    openhands_llm_module.litellm_completion = _completion_with_langfuse_metadata


workspace = Path(os.environ["PWNHUNTER_WORKSPACE"]).resolve()
prompt_path = Path(
    os.environ.get("PWNHUNTER_AGENT_PROMPT_PATH")
    or os.environ["PWNHUNTER_OPENHANDS_PROMPT_PATH"]
).resolve()
conversation_id_path = Path(
    os.environ.get(
        "PWNHUNTER_AGENT_CONVERSATION_ID_PATH",
        os.environ.get(
            "PWNHUNTER_OPENHANDS_CONVERSATION_ID_PATH",
        str(workspace / ".pwnhunter-openhands-conversation-id"),
        ),
    )
).resolve()
conversation_persistence_dir = Path(
    os.environ.get(
        "PWNHUNTER_AGENT_PERSISTENCE_DIR",
        os.environ.get(
            "PWNHUNTER_OPENHANDS_PERSISTENCE_DIR",
        str(workspace / ".pwnhunter-openhands-state"),
        ),
    )
).resolve()
prompt = prompt_path.read_text(encoding="utf-8")
model = os.getenv("LLM_MODEL", "gemini/gemini-3.1-pro-preview")
api_key = _resolve_api_key(model)
_configure_langfuse_litellm()

llm = LLM(
    model=model,
    api_key=api_key,
    base_url=os.getenv("LLM_BASE_URL"),
)
agent = Agent(
    llm=llm,
    tools=[
        Tool(name=TerminalTool.name),
        Tool(name=FileEditorTool.name),
        Tool(name=TaskTrackerTool.name),
    ],
)
conversation_id = _load_conversation_id(conversation_id_path)
has_persisted_state = False
if conversation_id is not None:
    state_path = conversation_persistence_dir / conversation_id.hex / "base_state.json"
    has_persisted_state = state_path.exists()
    if has_persisted_state:
        print(f"[PWNHUNTER] Resuming OpenHands conversation {conversation_id}", flush=True)
    else:
        print(
            f"[PWNHUNTER] Conversation ID {conversation_id} found without persisted state; starting fresh state.",
            flush=True,
        )
else:
    print("[PWNHUNTER] Starting new OpenHands conversation", flush=True)
conversation = Conversation(
    agent=agent,
    workspace=str(workspace),
    conversation_id=conversation_id,
    persistence_dir=str(conversation_persistence_dir),
)
_save_conversation_id(conversation_id_path, conversation.id)
conversation.send_message(prompt)
conversation.run()
"""


def _run_with_live_output(
    command: list[str],
    *,
    cwd: Path,
    timeout: int,
    env: dict[str, str],
    stdout_file,
    stderr_file,
) -> int:
    process = subprocess.Popen(
        command,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )

    assert process.stdout is not None
    assert process.stderr is not None

    def _forward_lines(source, destination, console_stream) -> None:
        for line in iter(source.readline, ""):
            destination.write(line)
            destination.flush()
            console_stream.write(line)
            console_stream.flush()
        source.close()

    stdout_thread = threading.Thread(
        target=_forward_lines,
        args=(process.stdout, stdout_file, sys.stdout),
        daemon=True,
    )
    stderr_thread = threading.Thread(
        target=_forward_lines,
        args=(process.stderr, stderr_file, sys.stderr),
        daemon=True,
    )
    stdout_thread.start()
    stderr_thread.start()

    try:
        process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise
    finally:
        stdout_thread.join()
        stderr_thread.join()

    return process.returncode
