from __future__ import annotations

from collections.abc import Iterable
import re


SECRET_PATTERNS = (
    re.compile(r"\bsecrets\.([A-Za-z_][A-Za-z0-9_]*)"),
    re.compile(r"secrets\[['\"]([A-Za-z_][A-Za-z0-9_]*)['\"]\]"),
)


def _is_supported_secret_name(secret_name: str) -> bool:
    return not secret_name.upper().startswith("GITHUB_")


def extract_secret_names(workflow_content: str) -> set[str]:
    secret_names: set[str] = set()
    for pattern in SECRET_PATTERNS:
        secret_names.update(
            match.group(1)
            for match in pattern.finditer(workflow_content)
            if _is_supported_secret_name(match.group(1))
        )
    return secret_names


def build_dummy_secret_value(secret_name: str) -> str:
    normalized = secret_name.lower().replace("_", "-")
    return f"flag{{{normalized}}}"


def collect_workflow_secrets(workflows: Iterable[tuple[str, str]]) -> dict[str, set[str]]:
    secret_map: dict[str, set[str]] = {}
    for path, content in workflows:
        names = extract_secret_names(content)
        if names:
            secret_map[path] = names
    return secret_map
