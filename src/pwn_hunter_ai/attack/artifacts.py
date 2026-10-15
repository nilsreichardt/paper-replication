from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timezone
import json
from pathlib import Path
import shutil
import subprocess
from typing import Any

from pwn_hunter_ai.ai_enumerate.prompting import render_template_file


PROMPTS_DIR = Path(__file__).parent / "prompts"
AI_ENUMERATE_AGENT_PROMPT_TEMPLATE_PATH = PROMPTS_DIR / "agent_task.md"
GATO_X_AGENT_PROMPT_TEMPLATE_PATH = PROMPTS_DIR / "agent_task_gato_x.md"
SHARED_SECRETS_STATE_FILENAME = "shared-secrets.json"


@dataclass(frozen=True, slots=True)
class RepositoryArtifactBundle:
    artifact_root: Path
    workspace_path: Path
    context_path: Path
    agent_prompt_path: Path
    agent_output_path: Path
    attempt_state_path: Path
    agent_metadata_path: Path
    shared_secrets_state_path: Path


class AttackArtifactsManager:
    def __init__(self, base_dir: Path, *, clone_runner=None) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        self._run_root = base_dir / timestamp
        self._run_root.mkdir(parents=True, exist_ok=True)
        self._clone_runner = clone_runner or _git_clone

    @property
    def run_root(self) -> Path:
        return self._run_root

    def prepare_repository_shared_state(
        self,
        *,
        repository_name: str,
        shared_secrets: dict[str, str] | None = None,
    ) -> Path:
        repository_root = self.repository_root(repository_name)
        repository_root.mkdir(parents=True, exist_ok=True)
        shared_secrets_state_path = (
            repository_root / SHARED_SECRETS_STATE_FILENAME
        )
        if not shared_secrets_state_path.exists():
            shared_secrets_state_path.write_text(
                json.dumps(dict(shared_secrets or {}), indent=2) + "\n",
                encoding="utf-8",
            )
        return shared_secrets_state_path

    def repository_root(self, repository_name: str) -> Path:
        return self._run_root / _slugify(repository_name)

    def prepare_risk_bundle(
        self,
        *,
        repository_name: str,
        risk_key: str,
        vulnerable_commit_hash: str,
        user_b_fork: str,
        agent_provider: str,
        context_payload: dict[str, Any],
        reset_workspace: bool,
        max_retries: int,
        bin_id: str | None = None,
    ) -> RepositoryArtifactBundle:
        repository_root = self.repository_root(repository_name)
        shared_secrets_state_path = self.prepare_repository_shared_state(
            repository_name=repository_name
        )
        artifact_root = repository_root / "risks" / _slugify(risk_key)
        workspace_path = artifact_root / "workspace"
        artifact_root.mkdir(parents=True, exist_ok=True)

        if reset_workspace and workspace_path.exists():
            shutil.rmtree(workspace_path)

        workspace_path.mkdir(parents=True, exist_ok=True)

        context_path = artifact_root / "attack-context.json"
        context_document = deepcopy(context_payload)
        context_document["workspace_path"] = str(workspace_path)
        context_document["vulnerable_commit_hash"] = vulnerable_commit_hash
        context_document["agent_provider"] = agent_provider
        context_path.write_text(
            json.dumps(context_document, indent=2) + "\n", encoding="utf-8"
        )

        agent_prompt_path = artifact_root / "agent-task.md"
        agent_prompt_path.write_text(
            _build_agent_prompt(context_document, bin_id=bin_id),
            encoding="utf-8",
        )

        agent_output_path = artifact_root / "agent-output.json"
        agent_output_path.write_text(
            json.dumps(
                {
                    "vulnerable": "unconfirmed",
                    "human_review_needed": False,
                    "exploit_file": "",
                    "exploit_job": "",
                    "workflow_file": "",
                    "sink": "",
                    "local_test_result": "not_executed_yet",
                    "reason": "",
                    "notes": "",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        attempt_state_path = artifact_root / "attempt-state.json"
        attempt_state_path.write_text(
            json.dumps(
                {
                    "max_retries": max_retries,
                    "attempts": [],
                    "flagged_for_human_review": False,
                    "next_attempt_number": 1,
                    "status": "prepared",
                },
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )

        agent_metadata_path = artifact_root / "agent-runtime.json"

        return RepositoryArtifactBundle(
            artifact_root=artifact_root,
            workspace_path=workspace_path,
            context_path=context_path,
            agent_prompt_path=agent_prompt_path,
            agent_output_path=agent_output_path,
            attempt_state_path=attempt_state_path,
            agent_metadata_path=agent_metadata_path,
            shared_secrets_state_path=shared_secrets_state_path,
        )

    def _clone_public_fork(self, user_b_fork: str, destination: Path) -> None:
        clone_url = f"https://github.com/{user_b_fork}.git"
        self._clone_runner(clone_url, destination)


def _slugify(repository_name: str) -> str:
    return repository_name.replace("/", "__")


def _build_agent_prompt(
    context_payload: dict[str, Any], bin_id: str | None = None
) -> str:
    _ = bin_id
    risk = context_payload["risk"]
    attack_result = context_payload["attack_result"]
    attack_input_source = _resolve_attack_input_source(context_payload)
    suggested = risk.get("pwn_request_result") or risk.get("ai-analysis") or {}
    suggested_poc = suggested.get("poc", "")
    ai_analysis = risk.get("ai-analysis")
    ai_analysis_explanation = (
        ai_analysis.get("explanation", "")
        if isinstance(ai_analysis, dict)
        else ""
    )
    path_entries = risk.get("gato-x-path")
    if path_entries is None:
        path_entries = risk.get("path")
    template_path = (
        GATO_X_AGENT_PROMPT_TEMPLATE_PATH
        if attack_input_source == "gato-x"
        else AI_ENUMERATE_AGENT_PROMPT_TEMPLATE_PATH
    )
    return render_template_file(
        template_path,
        repository_name=context_payload["repository_name"],
        vulnerable_commit_hash=context_payload["vulnerable_commit_hash"],
        focused_workflow=attack_result.get("focused_workflow") or "(none)",
        user_a_fork=attack_result.get("user_a_fork") or "(none)",
        user_b_fork=attack_result.get("user_b_fork") or "(none)",
        suggested_poc=suggested_poc.strip() or "(none)",
        gato_x_path=_render_path_entries(path_entries),
        sink=str(risk.get("gato-x-sink") or risk.get("sink") or "").strip() or "(none)",
        ai_analysis_explanation=str(ai_analysis_explanation).strip() or "(none)",
        agent_provider=context_payload.get("agent_provider") or "openhands",
    )


def _resolve_attack_input_source(context_payload: dict[str, Any]) -> str:
    source = context_payload.get("attack_input_source")
    if isinstance(source, str) and source.strip():
        return source.strip()
    risk = context_payload.get("risk")
    if isinstance(risk, dict):
        risk_source = risk.get("attack_input_source")
        if isinstance(risk_source, str) and risk_source.strip():
            return risk_source.strip()
    return "ai-enumerate"


def _render_path_entries(path_entries: Any) -> str:
    if isinstance(path_entries, list) and path_entries:
        return json.dumps(path_entries, indent=2)
    return "(none)"


def _git_clone(clone_url: str, destination: Path) -> None:
    subprocess.run(
        ["git", "clone", "--depth", "1", clone_url, str(destination)],
        check=True,
        capture_output=True,
        text=True,
    )
