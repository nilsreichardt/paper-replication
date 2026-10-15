from __future__ import annotations

import json
import os
from pathlib import Path, PurePosixPath
import re

from pwn_hunter_ai.models import PromptFile, ReferencedFile


WORKFLOW_PATH_PATTERN = re.compile(r"\.github/workflows/[^:#'\s]+")
PLACEHOLDER_PATTERN = re.compile(r"\{\{([a-zA-Z_][a-zA-Z0-9_]*)\}\}")
PROMPT_TEMPLATE_PATH = Path(__file__).parent / "prompts" / "ai_analysis_prompt.md"


def extract_referenced_files(
    risk: dict,
    *,
    fallback_repo_name: str,
    fallback_ref: str | None,
) -> list[ReferencedFile]:
    seen: set[tuple[str, str, str | None]] = set()
    result: list[ReferencedFile] = []

    for path_entry in risk.get("path", []):
        node_value = path_entry.get("node", "")
        descriptor = _extract_descriptor(node_value)
        if descriptor is None:
            continue

        repo_name, ref, remainder = descriptor
        for match in WORKFLOW_PATH_PATTERN.finditer(remainder):
            file_ref = ReferencedFile(repo_name=repo_name, path=match.group(0), ref=ref)
            cache_key = (file_ref.repo_name.lower(), file_ref.path, file_ref.ref)
            if cache_key in seen:
                continue
            seen.add(cache_key)
            result.append(file_ref)

    if result:
        return result

    workflow_name = risk.get("initial_workflow")
    if workflow_name:
        workflow_path = workflow_name
        if not workflow_path.startswith(".github/workflows/"):
            workflow_path = f".github/workflows/{workflow_name}"
        return [
            ReferencedFile(
                repo_name=fallback_repo_name,
                path=workflow_path,
                ref=fallback_ref,
            )
        ]

    return []


def build_analysis_prompt(
    *,
    repository_name: str,
    repository_creation_date: str,
    analyzed_ref: str,
    risk: dict,
    files: list[PromptFile],
) -> str:
    file_sections = []
    for file in files:
        suffix = PurePosixPath(file.path).suffix.lower()
        language = "yaml" if suffix in {".yaml", ".yml"} else "text"
        label = f"{file.repo_name}@{file.ref}:{file.path}"
        content = file.content.rstrip()
        file_sections.append(
            f"`{label}`:\n\n```{language}\n{content}\n```"
        )

    risk_context = {
        "repository_name": repository_name,
        "analyzed_ref": analyzed_ref,
        "risk": {
            "issue_type": risk.get("issue_type"),
            "triggers": risk.get("triggers"),
            "initial_workflow": risk.get("initial_workflow"),
            "confidence": risk.get("confidence"),
            "attack_complexity": risk.get("attack_complexity"),
            "explanation": risk.get("explanation"),
            "sink": risk.get("sink"),
            "path": risk.get("path", []),
        },
    }
    instructions = render_prompt_template(
        repository_creation_date=repository_creation_date,
        risk_context_json=json.dumps(risk_context, indent=2),
    )

    return "\n\n".join(
        [instructions] + file_sections
    )


def render_prompt_template(**placeholders: str) -> str:
    return render_template_file(PROMPT_TEMPLATE_PATH, **placeholders)


def render_template_file(template_path: Path, **placeholders: str) -> str:
    template = template_path.read_text(encoding="utf-8")
    placeholders.setdefault("hookbin_base_url", os.environ.get("PWNHUNTER_HOOKBIN_URL", "http://127.0.0.1:8787").rstrip("/"))
    placeholders.setdefault("memdump_url", os.environ.get("PWNHUNTER_MEMDUMP_URL", "https://example.invalid/memdump.py"))

    def replace(match: re.Match[str]) -> str:
        name = match.group(1)
        if name not in placeholders:
            raise KeyError(f"Missing prompt template placeholder: {name}")
        return placeholders[name]

    return PLACEHOLDER_PATTERN.sub(replace, template)


def _extract_descriptor(node_value: str) -> tuple[str, str | None, str] | None:
    if "('" not in node_value or not node_value.endswith("')"):
        return None
    payload = node_value.split("('", 1)[1][:-2]
    parts = payload.split(":", 2)
    if len(parts) != 3:
        return None
    repo_name, ref, remainder = parts
    return repo_name, ref or None, remainder
