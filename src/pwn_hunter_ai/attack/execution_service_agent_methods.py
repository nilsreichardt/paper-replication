from __future__ import annotations

import inspect
import json
import re
import subprocess
import shutil
from pathlib import Path
import threading
from typing import Any

from pwn_hunter_ai.attack.agent_runtime import AttackAgentProvider
from pwn_hunter_ai.attack.gemini_cli_manager import GeminiCliRuntimeManager
from pwn_hunter_ai.attack.openhands_manager import OpenHandsLaunchManager
from pwn_hunter_ai.attack.sandbox_manager import RepositorySandbox
from pwn_hunter_ai.attack.workflow_secrets import build_dummy_secret_value
from pwn_hunter_ai.attack.execution_service import (
    AGENT_LEARNING_PROMPT_FILENAME,
    AGENT_LEARNING_RUNTIME_METADATA_FILENAME,
    AGENT_OUTPUT_FILENAME,
    AGENT_RUNTIME_METADATA_FILENAME,
    AGENT_TASK_FILENAME,
    GEMINI_CONTEXT_FILENAME,
    LEARNINGS_FILENAME,
    LOCAL_ACTRC_CONTENT,
    LOCAL_ACTRC_FILENAME,
    LOCAL_EVENT_FILENAME,
    LOCAL_EXPLOIT_TEST_FILENAME,
    LOCAL_RUNNER_ENV_FILENAME,
    LOCAL_SECRETS_FILENAME,
    LEARNING_BULLET_PATTERN,
    LOGGER,
    OPENHANDS_LEARNINGS_PROMPT_NOTE,
    SAFE_CONFIRMATION_ATTEMPTS,
    SUCCESS_LEARNING_PROMPT,
    _LEARNINGS_FILE_LOCK,
    _read_local_exploit_test_script_template,
    _read_local_secrets_template,
)

_DOCKER_ACT_CLEANUP_LOCK = threading.Lock()
_SECRETS_LINE_PATTERN = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=(.*)$")
_SECRETS_PROMPT_MARKER = "## Workspace Secrets Notes"
_SECRETS_PROMPT_GUIDANCE = (
    "\n\n"
    "## Workspace Secrets Notes\n\n"
    "- You may edit `.secrets` in this workspace when a workflow needs additional or adjusted secret values.\n"
    "- The controller will sync changed `.secrets` entries to repository Actions secrets on the User A fork before workflow execution.\n"
)


def _run_agent_with_fallback(
    self,
    *,
    sandbox: RepositorySandbox,
    workspace_path: Path,
    timeout: int,
    git_token: str,
) -> dict[str, Any]:
    use_host_directly = self._should_use_host_agent_directly()
    if use_host_directly:
        LOGGER.info(
            "Running Agent directly on host because "
            "host-direct mode is enabled for this provider."
        )
        host_result = self._run_openhands_headless_on_host(
            workspace_path=workspace_path,
            timeout=timeout,
            git_token=git_token,
        )
        if isinstance(host_result, dict):
            return host_result
        host_ok = bool(host_result)
        return {"ok": host_ok, "exit_code": 0 if host_ok else 1}

    if self._agent_provider != AttackAgentProvider.OPENHANDS:
        return {"ok": False, "exit_code": None, "status": "unavailable"}

    if not hasattr(sandbox, "run_openhands_headless"):
        return {"ok": True, "exit_code": None}

    sandbox_result = sandbox.run_openhands_headless(timeout=timeout)
    if sandbox_result.returncode == 0:
        return {"ok": True, "exit_code": 0}
    return {"ok": False, "exit_code": sandbox_result.returncode}


def _run_agent_with_secret_sync(
    self,
    *,
    sandbox: RepositorySandbox,
    workspace_path: Path,
    timeout: int,
    git_token: str,
) -> dict[str, Any]:
    result = self._run_agent_with_fallback(
        sandbox=sandbox,
        workspace_path=workspace_path,
        timeout=timeout,
        git_token=git_token,
    )
    if result.get("ok"):
        self._sync_workspace_secrets_to_repository(workspace_path)
    return result

def _prepare_agent_prompt_in_workspace(self, workspace_path: Path) -> None:
    workspace_path.mkdir(parents=True, exist_ok=True)
    prompt_path = workspace_path.parent / AGENT_TASK_FILENAME
    workspace_prompt_path = workspace_path / AGENT_TASK_FILENAME
    if prompt_path.exists():
        workspace_prompt_path.write_text(
            prompt_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    elif not workspace_prompt_path.exists():
        # Keep execution resilient for direct unit-test setups and legacy flows.
        workspace_prompt_path.write_text("", encoding="utf-8")
    artifact_agent_output_path = workspace_path.parent / "agent-output.json"
    workspace_agent_output_path = workspace_path / "agent-output.json"
    if artifact_agent_output_path.exists() and not workspace_agent_output_path.exists():
        workspace_agent_output_path.write_text(
            artifact_agent_output_path.read_text(encoding="utf-8"),
            encoding="utf-8",
        )
    if workspace_prompt_path.exists():
        workspace_prompt = workspace_prompt_path.read_text(encoding="utf-8")
        if _SECRETS_PROMPT_MARKER not in workspace_prompt:
            workspace_prompt_path.write_text(
                workspace_prompt.rstrip() + _SECRETS_PROMPT_GUIDANCE,
                encoding="utf-8",
            )
    learnings_content = self._sync_learnings_into_workspace(workspace_path)
    if self._agent_provider == AttackAgentProvider.GEMINI_CLI:
        self._prepare_gemini_context_in_workspace(
            workspace_path=workspace_path,
            learnings_content=learnings_content,
        )
    if (
        self._agent_provider == AttackAgentProvider.OPENHANDS
        and learnings_content
        and workspace_prompt_path.exists()
    ):
        workspace_prompt = workspace_prompt_path.read_text(encoding="utf-8")
        workspace_prompt_path.write_text(
            workspace_prompt.rstrip() + OPENHANDS_LEARNINGS_PROMPT_NOTE,
            encoding="utf-8",
        )
    self._prepare_local_test_files_in_workspace(workspace_path)

def _persist_run_level_learning(
    self,
    *,
    workspace_path: Path,
    repository_name: str,
) -> None:
    learning = self._read_learning_from_agent_output(workspace_path)
    if learning is None:
        return
    normalized_learning = self._normalize_learning_text(learning)
    if not normalized_learning:
        return

    run_root = self._resolve_run_root(workspace_path)
    run_root.mkdir(parents=True, exist_ok=True)
    run_level_learnings_path = run_root / LEARNINGS_FILENAME
    workspace_learnings_path = workspace_path / LEARNINGS_FILENAME
    entry_repo_name = repository_name or "(unknown-repo)"

    with _LEARNINGS_FILE_LOCK:
        if run_level_learnings_path.exists():
            existing_content = run_level_learnings_path.read_text(
                encoding="utf-8"
            )
        else:
            existing_content = ""

        existing_entries = self._extract_learning_entries(existing_content)
        if any(
            existing_learning == normalized_learning
            for _, existing_learning in existing_entries
        ):
            if not workspace_learnings_path.exists() and existing_content.strip():
                workspace_learnings_path.write_text(
                    existing_content,
                    encoding="utf-8",
                )
            return

        bullet = f"- [{entry_repo_name}] {normalized_learning}"
        if existing_content.strip():
            updated_content = existing_content.rstrip() + "\n" + bullet + "\n"
        else:
            updated_content = f"# Learnings\n\n{bullet}\n"
        run_level_learnings_path.write_text(updated_content, encoding="utf-8")
        if not workspace_learnings_path.exists():
            workspace_learnings_path.write_text(
                updated_content,
                encoding="utf-8",
            )

def _collect_and_persist_learning_after_success(
    self,
    *,
    workspace_path: Path,
    repository_name: str,
    timeout: int,
    git_token: str,
) -> None:
    _ = git_token
    self._clear_learning_field_in_agent_output(workspace_path)
    if self._agent_provider != AttackAgentProvider.GEMINI_CLI:
        LOGGER.info(
            "Skipping post-success learning prompt for unsupported provider: %s",
            self._agent_provider.value,
        )
        return
    self._prompt_gemini_for_success_learning(
        workspace_path=workspace_path,
        timeout=timeout,
    )
    self._persist_run_level_learning(
        workspace_path=workspace_path,
        repository_name=repository_name,
    )

def _clear_learning_field_in_agent_output(self, workspace_path: Path) -> None:
    candidate_paths = (
        workspace_path / AGENT_OUTPUT_FILENAME,
        workspace_path.parent / AGENT_OUTPUT_FILENAME,
    )
    for candidate_path in candidate_paths:
        if not candidate_path.exists():
            continue
        try:
            payload = json.loads(candidate_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("learning") == "":
            continue
        payload["learning"] = ""
        candidate_path.write_text(
            json.dumps(payload, indent=2) + "\n",
            encoding="utf-8",
        )

def _prompt_gemini_for_success_learning(
    self,
    *,
    workspace_path: Path,
    timeout: int,
) -> None:
    prompt_path = workspace_path.parent / AGENT_LEARNING_PROMPT_FILENAME
    metadata_path = workspace_path.parent / AGENT_LEARNING_RUNTIME_METADATA_FILENAME
    prompt_path.write_text(SUCCESS_LEARNING_PROMPT, encoding="utf-8")

    manager = self._agent_runtime
    if manager is None or not hasattr(manager, "run_headless"):
        manager = GeminiCliRuntimeManager()
    result = manager.run_headless(
        workspace_path=workspace_path,
        prompt_path=prompt_path,
        metadata_path=metadata_path,
        timeout=timeout,
        git_token=None,
    )
    if result.exit_code != 0:
        LOGGER.warning(
            "Gemini post-success learning prompt failed with status=%s exit_code=%s",
            result.status,
            result.exit_code,
        )

def _sync_learnings_into_workspace(
    self, workspace_path: Path
) -> str | None:
    run_level_learnings_path = self._resolve_run_root(workspace_path) / LEARNINGS_FILENAME
    with _LEARNINGS_FILE_LOCK:
        if not run_level_learnings_path.exists():
            return None
        learnings_content = run_level_learnings_path.read_text(encoding="utf-8")
    if not learnings_content.strip():
        return None

    (workspace_path / LEARNINGS_FILENAME).write_text(
        learnings_content,
        encoding="utf-8",
    )
    return learnings_content

def _prepare_gemini_context_in_workspace(
    self,
    *,
    workspace_path: Path,
    learnings_content: str | None,
) -> None:
    _ = self
    gemini_context_path = workspace_path / GEMINI_CONTEXT_FILENAME
    if not learnings_content:
        if gemini_context_path.exists():
            gemini_context_path.unlink()
        return
    gemini_context_path.write_text(
        learnings_content,
        encoding="utf-8",
    )

def _read_learning_from_agent_output(self, workspace_path: Path) -> str | None:
    candidate_paths = (
        workspace_path / AGENT_OUTPUT_FILENAME,
        workspace_path.parent / AGENT_OUTPUT_FILENAME,
    )
    for candidate_path in candidate_paths:
        if not candidate_path.exists():
            continue
        try:
            payload = json.loads(candidate_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue
        learning = payload.get("learning")
        if isinstance(learning, str) and learning.strip():
            return learning.strip()
    return None

def _resolve_run_root(workspace_path: Path) -> Path:
    resolved_workspace = workspace_path.resolve()
    if resolved_workspace.name == "workspace":
        artifact_root = resolved_workspace.parent
        if artifact_root.parent.name == "risks":
            repository_root = artifact_root.parent.parent
            if repository_root != artifact_root:
                return repository_root.parent
        run_root = artifact_root.parent
        if run_root != artifact_root:
            return run_root
    return resolved_workspace.parent

def _normalize_learning_text(learning: str) -> str:
    normalized = learning.strip().replace("\r", "").replace("\n", " ")
    return " ".join(normalized.split())

def _extract_learning_entries(content: str) -> list[tuple[str, str]]:
    entries: list[tuple[str, str]] = []
    for raw_line in content.splitlines():
        stripped_line = raw_line.strip()
        if not stripped_line:
            continue
        match = LEARNING_BULLET_PATTERN.match(stripped_line)
        if not match:
            continue
        repository_name = match.group("repo").strip()
        learning_text = _normalize_learning_text(match.group("learning"))
        if not learning_text:
            continue
        entries.append((repository_name, learning_text))
    return entries


def _parse_local_secrets_values(content: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in content.splitlines():
        match = _SECRETS_LINE_PATTERN.match(raw_line)
        if match is None:
            continue
        key, value = match.groups()
        key = key.strip()
        if not key:
            continue
        values[key] = value.strip()
    return values


def _render_local_secrets_with_dummy_values(
    *,
    base_content: str,
    seeded_secret_names: list[str],
    overlay_values: dict[str, str] | None = None,
) -> tuple[str, dict[str, str]]:
    lines = base_content.splitlines()
    line_indexes_by_key: dict[str, int] = {}
    existing_values: dict[str, str] = {}
    for index, raw_line in enumerate(lines):
        match = _SECRETS_LINE_PATTERN.match(raw_line)
        if match is None:
            continue
        key, value = match.groups()
        normalized_key = key.strip()
        if not normalized_key:
            continue
        if normalized_key not in line_indexes_by_key:
            line_indexes_by_key[normalized_key] = index
        existing_values[normalized_key] = value.strip()

    for secret_name, secret_value in (overlay_values or {}).items():
        normalized_name = secret_name.strip()
        if not normalized_name or normalized_name.upper().startswith("GITHUB_"):
            continue
        if normalized_name in line_indexes_by_key:
            lines[line_indexes_by_key[normalized_name]] = (
                f"{normalized_name}={secret_value}"
            )
        else:
            lines.append(f"{normalized_name}={secret_value}")
        existing_values[normalized_name] = secret_value.strip()

    normalized_seeded_names: list[str] = []
    seen_seeded_names: set[str] = set()
    for secret_name in seeded_secret_names:
        normalized_name = secret_name.strip()
        if not normalized_name or normalized_name in seen_seeded_names:
            continue
        seen_seeded_names.add(normalized_name)
        normalized_seeded_names.append(normalized_name)

    for secret_name in normalized_seeded_names:
        if existing_values.get(secret_name, "").strip():
            continue
        dummy_value = build_dummy_secret_value(secret_name)
        if secret_name in line_indexes_by_key:
            lines[line_indexes_by_key[secret_name]] = f"{secret_name}={dummy_value}"
        else:
            lines.append(f"{secret_name}={dummy_value}")

    rendered_content = "\n".join(lines)
    if rendered_content and not rendered_content.endswith("\n"):
        rendered_content += "\n"
    return rendered_content, _parse_local_secrets_values(rendered_content)


def _filter_persistable_secret_values(values: dict[str, str]) -> dict[str, str]:
    filtered: dict[str, str] = {}
    for secret_name, secret_value in values.items():
        normalized_name = secret_name.strip()
        if not normalized_name or normalized_name.upper().startswith("GITHUB_"):
            continue
        if not secret_value:
            continue
        filtered[normalized_name] = secret_value.strip()
    return filtered


def _resolve_shared_secrets_state_path(setup: dict[str, Any]) -> Path | None:
    raw_path = str(setup.get("shared_secrets_state_path") or "").strip()
    if not raw_path:
        return None
    return Path(raw_path)


def _load_shared_secret_values(shared_secrets_state_path: Path | None) -> dict[str, str]:
    if shared_secrets_state_path is None or not shared_secrets_state_path.exists():
        return {}
    try:
        payload = json.loads(shared_secrets_state_path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}
    if not isinstance(payload, dict):
        return {}
    return _filter_persistable_secret_values(
        {
            str(secret_name): str(secret_value)
            for secret_name, secret_value in payload.items()
        }
    )


def _write_shared_secret_values(
    shared_secrets_state_path: Path | None,
    values: dict[str, str],
) -> None:
    if shared_secrets_state_path is None:
        return
    shared_secrets_state_path.parent.mkdir(parents=True, exist_ok=True)
    shared_secrets_state_path.write_text(
        json.dumps(_filter_persistable_secret_values(values), indent=2) + "\n",
        encoding="utf-8",
    )


def _sync_workspace_secrets_to_repository(self, workspace_path: Path) -> None:
    setup = self._active_local_test_setup
    if not isinstance(setup, dict):
        return

    secrets_path = workspace_path / LOCAL_SECRETS_FILENAME
    if not secrets_path.exists() or not secrets_path.is_file():
        return

    try:
        current_values = _parse_local_secrets_values(
            secrets_path.read_text(encoding="utf-8")
        )
    except OSError as exc:
        LOGGER.warning("Failed reading workspace secrets file %s: %s", secrets_path, exc)
        return

    previous_values_raw = setup.get("workspace_secrets_last_synced")
    previous_values = (
        previous_values_raw if isinstance(previous_values_raw, dict) else {}
    )
    shared_secrets_state_path = _resolve_shared_secrets_state_path(setup)
    filtered_current_values = _filter_persistable_secret_values(current_values)
    if current_values == previous_values:
        _write_shared_secret_values(shared_secrets_state_path, filtered_current_values)
        return

    user_a_token = str(setup.get("user_a_token") or "").strip()
    user_a_fork = str(setup.get("user_a_fork") or "").strip()
    if not user_a_token or not user_a_fork:
        setup["workspace_secrets_last_synced"] = current_values
        _write_shared_secret_values(shared_secrets_state_path, filtered_current_values)
        return

    client = self._github_client_factory(user_a_token)
    if not hasattr(client, "set_actions_secret"):
        setup["workspace_secrets_last_synced"] = current_values
        _write_shared_secret_values(shared_secrets_state_path, filtered_current_values)
        return

    synced_secret_names: list[str] = []
    for secret_name, secret_value in current_values.items():
        if secret_name.upper().startswith("GITHUB_"):
            continue
        if not secret_value:
            continue
        if previous_values.get(secret_name) == secret_value:
            continue
        try:
            client.set_actions_secret(user_a_fork, secret_name, secret_value)
            synced_secret_names.append(secret_name)
        except Exception as exc:
            LOGGER.warning(
                "Failed syncing workspace secret `%s` to `%s`: %s",
                secret_name,
                user_a_fork,
                exc,
            )

    setup["workspace_secrets_last_synced"] = current_values
    _write_shared_secret_values(shared_secrets_state_path, filtered_current_values)
    if synced_secret_names:
        LOGGER.info(
            "Synced %s workspace secret value(s) from `%s` to `%s`: %s",
            len(synced_secret_names),
            secrets_path,
            user_a_fork,
            ", ".join(sorted(synced_secret_names)),
        )


def _prepare_local_test_files_in_workspace(self, workspace_path: Path) -> None:
    setup = self._active_local_test_setup
    if not isinstance(setup, dict):
        return

    user_b_token = str(setup.get("user_b_token") or "").strip()
    user_a_fork = str(setup.get("user_a_fork") or "").strip()
    user_b_fork = str(setup.get("user_b_fork") or "").strip()
    pr_base_branch = str(setup.get("pr_base_branch") or "").strip() or "main"
    focused_workflow = str(setup.get("focused_workflow") or "").strip() or "(none)"
    head_ref = str(setup.get("head_ref") or "").strip() or "feature-branch"
    seeded_secret_names = (
        [
            secret_name.strip()
            for secret_name in setup.get("seeded_secrets")
            if isinstance(secret_name, str) and secret_name.strip()
        ]
        if isinstance(setup.get("seeded_secrets"), list)
        else []
    )
    shared_secrets_state_path = _resolve_shared_secrets_state_path(setup)
    shared_secret_values = _load_shared_secret_values(shared_secrets_state_path)

    local_secrets_content = _read_local_secrets_template()
    if user_b_token:
        local_secrets_content = local_secrets_content.replace(
            "{{GITHUB_TOKEN}}",
            user_b_token,
        )
    local_secrets_content, local_secret_values = _render_local_secrets_with_dummy_values(
        base_content=local_secrets_content,
        seeded_secret_names=seeded_secret_names,
        overlay_values=shared_secret_values,
    )
    (workspace_path / LOCAL_SECRETS_FILENAME).write_text(
        local_secrets_content,
        encoding="utf-8",
    )
    setup["workspace_secrets_last_synced"] = local_secret_values
    _write_shared_secret_values(shared_secrets_state_path, local_secret_values)

    if user_a_fork and user_b_fork:
        event_payload = self._build_local_pull_request_target_event(
            user_a_fork=user_a_fork,
            user_b_fork=user_b_fork,
            pr_base_branch=pr_base_branch,
            head_ref=head_ref,
        )
        (workspace_path / LOCAL_EVENT_FILENAME).write_text(
            json.dumps(event_payload, indent=2) + "\n",
            encoding="utf-8",
        )
        runner_env = self._build_local_runner_env(
            user_a_fork=user_a_fork,
            user_b_fork=user_b_fork,
        )
        (workspace_path / LOCAL_RUNNER_ENV_FILENAME).write_text(
            runner_env,
            encoding="utf-8",
        )

    local_test_script = _read_local_exploit_test_script_template().replace(
        "{{focused_workflow}}",
        focused_workflow.replace("\\", "\\\\").replace('"', '\\"'),
    )
    local_test_script_path = workspace_path / LOCAL_EXPLOIT_TEST_FILENAME
    local_test_script_path.write_text(local_test_script, encoding="utf-8")
    (workspace_path / LOCAL_ACTRC_FILENAME).write_text(
        LOCAL_ACTRC_CONTENT,
        encoding="utf-8",
    )

def _build_local_pull_request_target_event(
    *,
    user_a_fork: str,
    user_b_fork: str,
    pr_base_branch: str,
    head_ref: str,
) -> dict[str, Any]:
    user_b_owner = user_b_fork.split("/", 1)[0] if "/" in user_b_fork else user_b_fork
    return {
        "action": "opened",
        "number": 1,
        "pull_request": {
            "number": 1,
            "user": {
                "login": user_b_owner or "octocat-forker",
                "id": 123456,
            },
            "head": {
                "ref": head_ref,
                "sha": "1234567890abcdef",
                "repo": {
                    "full_name": user_b_fork,
                    "fork": True,
                },
            },
            "base": {
                "ref": pr_base_branch,
                "sha": "abcdef1234567890",
                "repo": {
                    "full_name": user_a_fork,
                    "fork": True,
                },
            },
        },
        "sender": {
            "login": user_b_owner or "octocat-forker",
        },
    }

def _build_local_runner_env(*, user_a_fork: str, user_b_fork: str) -> str:
    user_a_owner = user_a_fork.split("/", 1)[0] if "/" in user_a_fork else user_a_fork
    user_b_owner = user_b_fork.split("/", 1)[0] if "/" in user_b_fork else user_b_fork
    lines = [
        "CI=true",
        "IS_RUNNING_IN_ACT=true",
        f"GITHUB_ACTOR={user_b_owner or 'octocat-forker'}",
        f"GITHUB_REPOSITORY={user_a_fork}",
        "GITHUB_API_URL=https://api.github.com",
        f"GITHUB_REPOSITORY_OWNER={user_a_owner}",
    ]
    return "\n".join(lines) + "\n"


def _cleanup_docker_resources_after_repository_processing(
    self,
    *,
    repository_name: str,
) -> None:
    if self._agent_provider != AttackAgentProvider.GEMINI_CLI:
        return

    with _DOCKER_ACT_CLEANUP_LOCK:
        for command in (
            ["docker", "container", "prune", "--force"],
            ["docker", "volume", "prune", "--force"],
        ):
            try:
                completed = subprocess.run(
                    command,
                    check=False,
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            except FileNotFoundError:
                LOGGER.debug(
                    "Skipping Docker cleanup for repo=%s because docker is unavailable.",
                    repository_name or "unknown-repository",
                )
                return
            except subprocess.TimeoutExpired:
                LOGGER.warning(
                    "Docker cleanup command timed out for repo=%s: %s",
                    repository_name or "unknown-repository",
                    " ".join(command),
                )
                continue
            except OSError as exc:
                LOGGER.warning(
                    "Docker cleanup command failed for repo=%s: %s (%s)",
                    repository_name or "unknown-repository",
                    " ".join(command),
                    exc,
                )
                continue

            if completed.returncode != 0:
                stderr = (completed.stderr or "").strip()
                LOGGER.warning(
                    "Docker cleanup command exited with %s for repo=%s: %s%s",
                    completed.returncode,
                    repository_name or "unknown-repository",
                    " ".join(command),
                    f" ({stderr})" if stderr else "",
                )

def _confirm_not_vulnerable_with_fresh_conversations(
    self,
    *,
    sandbox: RepositorySandbox,
    workspace_path: Path,
    timeout: int,
    git_token: str,
    initial_signal: dict[str, Any],
) -> dict[str, Any] | None:
    confirmations = [self._build_safe_confirmation_record(1, initial_signal)]
    use_host_directly = self._should_use_host_agent_directly()
    can_rerun_agent = use_host_directly or hasattr(
        sandbox, "run_openhands_headless"
    )
    prompt_path = workspace_path.parent / AGENT_TASK_FILENAME
    if not can_rerun_agent or not prompt_path.exists():
        reason = (
            initial_signal.get("reason")
            or "Agent marked repository as not vulnerable."
        )
        return {
            "vulnerable": False,
            "reason": reason,
            "controller_signal": initial_signal,
            "safe_conversation_confirmations": confirmations,
        }

    for attempt in range(2, SAFE_CONFIRMATION_ATTEMPTS + 1):
        self._reset_agent_conversation_state(workspace_path)
        self._prepare_agent_prompt_in_workspace(workspace_path)
        retry_result = self._run_agent_with_secret_sync(
            sandbox=sandbox,
            workspace_path=workspace_path,
            timeout=timeout,
            git_token=git_token,
        )
        if not retry_result.get("ok"):
            LOGGER.warning(
                "Agent safe confirmation attempt %s/%s failed with exit code %s.",
                attempt,
                SAFE_CONFIRMATION_ATTEMPTS,
                retry_result.get("exit_code"),
            )
            return None
        retry_signal = self._read_controller_signal_from_sandbox(sandbox)
        if not self._is_not_vulnerable_signal(retry_signal):
            LOGGER.info(
                "Agent safe confirmation attempt %s/%s did not conclude not_vulnerable.",
                attempt,
                SAFE_CONFIRMATION_ATTEMPTS,
            )
            return None
        confirmations.append(
            self._build_safe_confirmation_record(attempt, retry_signal)
        )

    reason = (
        initial_signal.get("reason")
        or "Agent marked repository as not vulnerable."
    )
    LOGGER.info(
        "Agent marked repository as not vulnerable in %s/%s fresh conversations: %s",
        SAFE_CONFIRMATION_ATTEMPTS,
        SAFE_CONFIRMATION_ATTEMPTS,
        reason,
    )
    return {
        "vulnerable": False,
        "reason": reason,
        "controller_signal": initial_signal,
        "safe_conversation_confirmations": confirmations,
    }

def _build_safe_confirmation_record(
    self, attempt: int, signal: dict[str, Any]
) -> dict[str, Any]:
    return {
        "attempt": attempt,
        "status": "not_vulnerable",
        "reason": signal.get("reason") or "",
    }

def _is_not_vulnerable_signal(self, signal: dict[str, Any] | None) -> bool:
    if not isinstance(signal, dict):
        return False
    return str(signal.get("status") or "").strip() == "not_vulnerable"

def _reset_agent_conversation_state(self, workspace_path: Path) -> None:
    if self._agent_provider != AttackAgentProvider.OPENHANDS:
        return
    conversation_id_path = workspace_path / ".pwnhunter-openhands-conversation-id"
    conversation_state_dir = workspace_path / ".pwnhunter-openhands-state"
    try:
        conversation_id_path.unlink(missing_ok=True)
    except OSError:
        LOGGER.warning(
            "Failed removing Agent conversation id file before retry: %s",
            conversation_id_path,
        )
    try:
        shutil.rmtree(conversation_state_dir, ignore_errors=True)
    except OSError:
        LOGGER.warning(
            "Failed removing Agent conversation state before retry: %s",
            conversation_state_dir,
        )

def _run_agent_headless_on_host(
    self, *, workspace_path: Path, timeout: int, git_token: str
) -> dict[str, Any]:
    prompt_path = workspace_path.parent / AGENT_TASK_FILENAME
    metadata_path = workspace_path.parent / AGENT_RUNTIME_METADATA_FILENAME
    manager = self._agent_runtime
    if manager is None:
        if self._agent_provider == AttackAgentProvider.GEMINI_CLI:
            manager = GeminiCliRuntimeManager()
        else:
            manager = OpenHandsLaunchManager(host="127.0.0.1", start_port=3000)
    setup = self._active_local_test_setup
    git_user_name: str | None = None
    git_user_email: str | None = None
    if isinstance(setup, dict):
        candidate_name = str(setup.get("git_user_name") or "").strip()
        candidate_email = str(setup.get("git_user_email") or "").strip()
        git_user_name = candidate_name or None
        git_user_email = candidate_email or None

    run_headless_kwargs: dict[str, Any] = {
        "workspace_path": workspace_path,
        "prompt_path": prompt_path,
        "metadata_path": metadata_path,
        "timeout": timeout,
        "git_token": git_token,
    }
    try:
        signature = inspect.signature(manager.run_headless)
        parameter_names = set(signature.parameters)
    except (TypeError, ValueError):
        parameter_names = set()
    if "git_user_name" in parameter_names:
        run_headless_kwargs["git_user_name"] = git_user_name
    if "git_user_email" in parameter_names:
        run_headless_kwargs["git_user_email"] = git_user_email

    result = manager.run_headless(**run_headless_kwargs)
    reason = _read_runtime_failure_reason(metadata_path)
    status = str(result.status or "").strip().lower()
    if status == "unavailable" and "node.js" in reason.lower():
        status = "skipped_node_runtime_unavailable"
    return {
        "ok": result.exit_code == 0,
        "exit_code": result.exit_code,
        "status": status,
        "reason": reason,
    }

# Backward-compatible private aliases for tests and external callers.
def _run_openhands_with_fallback(self, **kwargs):
    return self._run_agent_with_fallback(**kwargs)

def _prepare_openhands_prompt_in_workspace(self, workspace_path: Path) -> None:
    self._prepare_agent_prompt_in_workspace(workspace_path)

def _run_openhands_headless_on_host(
    self, *, workspace_path: Path, timeout: int, git_token: str
) -> dict[str, Any]:
    return self._run_agent_headless_on_host(
        workspace_path=workspace_path,
        timeout=timeout,
        git_token=git_token,
    )

def _retry_initial_gemini_timeout_if_needed(
    self,
    *,
    initial_result: dict[str, Any],
    sandbox: RepositorySandbox,
    workspace_path: Path,
    timeout: int,
    git_token: str,
    max_retries: int,
) -> dict[str, Any]:
    result = initial_result
    if result.get("ok"):
        return result
    if not self._is_retryable_initial_gemini_timeout(workspace_path=workspace_path):
        return result

    retry_attempts = max(0, max_retries - 1)
    for retry_attempt in range(1, retry_attempts + 1):
        LOGGER.warning(
            "Gemini CLI agent run timed out. Retrying attempt %s/%s.",
            retry_attempt,
            retry_attempts,
        )
        self._prepare_agent_prompt_in_workspace(workspace_path)
        result = self._run_agent_with_secret_sync(
            sandbox=sandbox,
            workspace_path=workspace_path,
            timeout=timeout,
            git_token=git_token,
        )
        if result.get("ok"):
            return result
        if not self._is_retryable_initial_gemini_timeout(
            workspace_path=workspace_path
        ):
            return result
    return result

def _is_retryable_initial_gemini_timeout(self, *, workspace_path: Path) -> bool:
    if self._agent_provider != AttackAgentProvider.GEMINI_CLI:
        return False
    status = self._read_latest_agent_runtime_status(workspace_path=workspace_path)
    return status == "timeout"

def _read_latest_agent_runtime_status(self, *, workspace_path: Path) -> str:
    metadata_path = workspace_path.parent / AGENT_RUNTIME_METADATA_FILENAME
    if not metadata_path.exists():
        return ""
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return ""
    if not isinstance(payload, dict):
        return ""
    status = payload.get("status")
    if not isinstance(status, str):
        return ""
    return status.strip().lower()


def _read_runtime_failure_reason(metadata_path: Path) -> str:
    if not metadata_path.exists():
        return ""
    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return ""
    if not isinstance(payload, dict):
        return ""
    reason = payload.get("reason")
    if not isinstance(reason, str):
        return ""
    return reason.strip()
