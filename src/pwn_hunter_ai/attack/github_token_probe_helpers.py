from __future__ import annotations

import fnmatch
from pathlib import Path
import shutil
import subprocess
from typing import Any
from typing import TypedDict

import yaml


class ProbeFileChangePlan(TypedDict):
    file_path: str
    content: str
    append: bool


def parse_pull_request_target_filters(workflow_content: str) -> dict[str, Any]:
    parsed = yaml.safe_load(workflow_content)
    if not isinstance(parsed, dict):
        return {
            "branches": [],
            "paths": [],
            "types": [],
            "types_explicit": False,
        }

    on_section = parsed.get("on")
    if on_section is None:
        on_section = parsed.get(True)

    if isinstance(on_section, list):
        return {
            "branches": [],
            "paths": [],
            "types": [],
            "types_explicit": False,
        }
    if isinstance(on_section, str):
        return {
            "branches": [],
            "paths": [],
            "types": [],
            "types_explicit": False,
        }
    if not isinstance(on_section, dict):
        return {
            "branches": [],
            "paths": [],
            "types": [],
            "types_explicit": False,
        }

    pr_target = on_section.get("pull_request_target")
    if isinstance(pr_target, list):
        return {
            "branches": [],
            "paths": [],
            "types": [],
            "types_explicit": False,
        }
    if pr_target is None or isinstance(pr_target, bool):
        return {
            "branches": [],
            "paths": [],
            "types": [],
            "types_explicit": False,
        }
    if not isinstance(pr_target, dict):
        return {
            "branches": [],
            "paths": [],
            "types": [],
            "types_explicit": False,
        }

    branch_filters = _coerce_string_list(pr_target.get("branches"))
    if not branch_filters:
        branch_filters = _coerce_string_list(pr_target.get("branch"))
    explicit_types = "types" in pr_target
    raw_types = _coerce_string_list(pr_target.get("types"))
    normalized_types: list[str] = []
    seen: set[str] = set()
    for entry in raw_types:
        normalized = entry.strip().lower()
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        normalized_types.append(normalized)

    return {
        "branches": branch_filters,
        "paths": _coerce_string_list(pr_target.get("paths")),
        "types": normalized_types,
        "types_explicit": explicit_types,
    }


def select_pull_request_target_base_branch(
    *,
    source_default_branch: str,
    workflow_content: str,
) -> str:
    filters = parse_pull_request_target_filters(workflow_content)
    return _select_base_branch(
        source_default_branch=source_default_branch,
        branch_filters=filters.get("branches") or [],
    )


def build_probe_file_path(*, path_filters: list[str]) -> str:
    selected_pattern = _select_primary_path_filter(path_filters=path_filters)
    if selected_pattern is None:
        return "README.md"

    if not _has_wildcards(selected_pattern):
        return selected_pattern.strip().lstrip("/")

    candidate = _build_candidate_from_pattern(
        pattern=selected_pattern,
    )
    if candidate and fnmatch.fnmatch(candidate, selected_pattern):
        return candidate
    return "README.md"


def build_probe_file_change_plan(
    *,
    workspace_path: Path,
    path_filters: list[str],
) -> ProbeFileChangePlan:
    selected_pattern = _select_primary_path_filter(path_filters=path_filters)
    if selected_pattern is None:
        readme_path = workspace_path / "README.md"
        if readme_path.exists():
            return {
                "file_path": "README.md",
                "content": "a",
                "append": True,
            }
        return {
            "file_path": "README.md",
            "content": "a",
            "append": False,
        }

    if _has_wildcards(selected_pattern):
        return {
            "file_path": build_probe_file_path(
                path_filters=path_filters,
            ),
            "content": "a",
            "append": False,
        }

    return {
        "file_path": selected_pattern.strip().lstrip("/"),
        "content": "a",
        "append": True,
    }


def _build_candidate_from_pattern(*, pattern: str) -> str | None:
    raw = pattern.strip().lstrip("/")
    if not raw:
        return None

    wildcard_chars = set("*?[]{}")
    has_wildcards = any(char in wildcard_chars for char in raw)

    if not has_wildcards:
        if raw.endswith("/"):
            return f"{raw}a.txt"
        return raw

    candidate = raw
    candidate = candidate.replace("**/", "docs/")
    candidate = candidate.replace("**", "docs")
    candidate = candidate.replace("*", "a")
    candidate = candidate.replace("?", "a")
    candidate = candidate.replace("[", "").replace("]", "")
    candidate = candidate.replace("{", "").replace("}", "")
    candidate = candidate.replace(",", "")

    if candidate.endswith("/"):
        candidate = f"{candidate}a.txt"

    return candidate


def _select_primary_path_filter(*, path_filters: list[str]) -> str | None:
    for pattern in path_filters:
        stripped = pattern.strip()
        if not stripped or stripped.startswith("!"):
            continue
        return stripped
    return None


def _has_wildcards(pattern: str) -> bool:
    return any(char in pattern for char in "*?[]{}")


def _coerce_string_list(value: Any) -> list[str]:
    if isinstance(value, str):
        stripped = value.strip()
        return [stripped] if stripped else []
    if not isinstance(value, list):
        return []
    items: list[str] = []
    for entry in value:
        if isinstance(entry, str):
            stripped = entry.strip()
            if stripped:
                items.append(stripped)
    return items


def _select_base_branch(*, source_default_branch: str, branch_filters: list[str]) -> str:
    if not branch_filters:
        return source_default_branch
    for pattern in branch_filters:
        if fnmatch.fnmatch(source_default_branch, pattern):
            return source_default_branch
    return branch_filters[0]


def _prepare_probe_workspace(
    *,
    workspace_path: Path,
    base_clone_url: str,
    push_clone_url: str,
    base_branch: str,
    branch_name: str,
    env: dict[str, str],
    git_user_name: str = "PwnHunter Research",
    git_user_email: str = "research@pwnhunter.local",
) -> None:
    workspace_path.parent.mkdir(parents=True, exist_ok=True)
    shutil.rmtree(workspace_path, ignore_errors=True)
    _git(
        workspace_path.parent,
        [
            "clone",
            "--depth",
            "1",
            "--branch",
            base_branch,
            base_clone_url,
            str(workspace_path.resolve()),
        ],
        env=env,
    )

    _assert_probe_workspace_repo(workspace_path, env=env)
    _git(workspace_path, ["remote", "set-url", "origin", push_clone_url], env=env)
    _git(workspace_path, ["checkout", "-B", branch_name, "HEAD"], env=env)
    _git(
        workspace_path,
        ["config", "user.email", git_user_email],
        env=env,
    )
    _git(
        workspace_path,
        ["config", "user.name", git_user_name],
        env=env,
    )


def _write_probe_file(
    *,
    workspace_path: Path,
    file_path: str,
    content: str,
    append: bool = False,
) -> None:
    target = workspace_path / file_path
    target.parent.mkdir(parents=True, exist_ok=True)
    if append:
        with target.open("a", encoding="utf-8") as handle:
            handle.write(content)
        return
    target.write_text(content, encoding="utf-8")


def _commit_and_push_probe_change(
    *,
    workspace_path: Path,
    branch_name: str,
    file_path: str,
    env: dict[str, str],
) -> None:
    _assert_probe_workspace_repo(workspace_path, env=env)
    _git(workspace_path, ["add", "-f", "--", file_path], env=env)
    _git(workspace_path, ["commit", "-m", "Temporary"], env=env)
    _git(workspace_path, ["push", "origin", branch_name, "--force"], env=env)


def _git(cwd: Path, args: list[str], *, env: dict[str, str]) -> None:
    subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )


def _git_stdout(cwd: Path, args: list[str], *, env: dict[str, str]) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    return result.stdout.strip()


def _assert_probe_workspace_repo(workspace_path: Path, *, env: dict[str, str]) -> None:
    top_level = _git_stdout(
        workspace_path,
        ["rev-parse", "--show-toplevel"],
        env=env,
    )
    if Path(top_level).resolve() != workspace_path.resolve():
        raise RuntimeError(
            "Safety check failed: token probe git workspace does not match expected path."
        )


_TOKEN_URL_PATTERN = "https://x-access-token:"


def _sanitize_error_text(value: str) -> str:
    if _TOKEN_URL_PATTERN not in value:
        return value
    prefix, _, suffix = value.partition(_TOKEN_URL_PATTERN)
    if "@github.com/" not in suffix:
        return value
    _, _, tail = suffix.partition("@github.com/")
    return f"{prefix}{_TOKEN_URL_PATTERN}***@github.com/{tail}"
