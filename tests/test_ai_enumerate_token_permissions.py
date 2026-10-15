from __future__ import annotations

import io
import zipfile

from pwn_hunter_ai.ai_enumerate.token_permissions import (
    detect_default_github_token_permissions,
    has_complete_permissions_catalog,
    parse_github_token_permissions_from_logs,
)
from pwn_hunter_ai.github_client import GitHubApiError


class FakePermissionDetectionClient:
    def __init__(
        self,
        *,
        workflow_contents: dict[str, str],
        runs_pages: list[list[dict]],
        logs_by_run_id: dict[int, bytes] | None = None,
        failing_run_ids: set[int] | None = None,
    ) -> None:
        self._workflow_contents = workflow_contents
        self._runs_pages = runs_pages
        self._logs_by_run_id = logs_by_run_id or {}
        self._failing_run_ids = failing_run_ids or set()

    def list_directory(self, repo_name: str, path: str, ref: str) -> list[dict]:
        return [
            {"type": "file", "path": workflow_path}
            for workflow_path in self._workflow_contents
        ]

    def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
        return self._workflow_contents[path]

    def get_workflow_runs(self, repo_name: str, per_page: int = 30, page: int = 1) -> dict:
        runs = self._runs_pages[page - 1] if page - 1 < len(self._runs_pages) else []
        return {"workflow_runs": runs}

    def get_commit(self, repo_name: str, ref: str) -> dict:
        _ = (repo_name, ref)
        return {"sha": "deadbeef1234"}

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        if run_id in self._failing_run_ids:
            raise GitHubApiError(
                "GitHub API request failed for /repos/ThePHPF/thephp.foundation/actions/runs/1/logs: "
                "403 Must have admin rights to Repository."
            )
        return self._logs_by_run_id.get(run_id, b"")


def test_detect_default_github_token_permissions_write() -> None:
    client = FakePermissionDetectionClient(
        workflow_contents=_api_shaped_workflow_contents(),
        runs_pages=[
            [
                {
                    "id": 22782208095,
                    "path": ".github/workflows/netlify.yml",
                    "head_sha": "deadbeef1234",
                    "workflow_id": 22863629,
                    "event": "pull_request_target",
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": "https://github.com/ThePHPF/thephp.foundation/actions/runs/22782208095",
                },
            ]
        ],
        logs_by_run_id={
            22782208095: _zip_logs(
                {
                    "0_Deploy website/1_Set up job.txt": (
                        "2026-03-06T21:13:20.000Z GITHUB_TOKEN Permissions\n"
                        + _full_permissions_block(action_level="write")
                    )
                }
            )
        },
    )

    result = detect_default_github_token_permissions(
        client, repo_name="ThePHPF/thephp.foundation", ref="main"
    )

    assert result == {
        "status": "write",
        "evidence_log_url": "https://github.com/ThePHPF/thephp.foundation/actions/runs/22782208095",
        "reason": "write_permission_found_in_setup_job",
        "permissions": _full_permissions_dict(action_level="write"),
    }


def test_detect_default_github_token_permissions_non_write() -> None:
    client = FakePermissionDetectionClient(
        workflow_contents=_api_shaped_workflow_contents(),
        runs_pages=[
            [
                {
                    "id": 22781534248,
                    "path": ".github/workflows/netlify.yml",
                    "head_sha": "deadbeef1234",
                    "workflow_id": 31183937,
                    "event": "pull_request_target",
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": "https://github.com/ThePHPF/thephp.foundation/actions/runs/22781534248",
                }
            ]
        ],
        logs_by_run_id={
            22781534248: _zip_logs(
                {
                    "0_Build and Deploy to Netlify/1_Set up job.txt": (
                        "GITHUB_TOKEN Permissions\n"
                        + _full_permissions_block(action_level="read")
                    )
                }
            )
        },
    )

    result = detect_default_github_token_permissions(
        client, repo_name="ThePHPF/thephp.foundation", ref="main"
    )

    assert result == {
        "status": "non-write",
        "evidence_log_url": "https://github.com/ThePHPF/thephp.foundation/actions/runs/22781534248",
        "reason": "permissions_block_found_without_write",
        "permissions": _full_permissions_dict(action_level="read"),
    }


def test_detect_default_github_token_permissions_unknown_when_logs_forbidden() -> None:
    client = FakePermissionDetectionClient(
        workflow_contents=_api_shaped_workflow_contents(),
        runs_pages=[
            [
                {
                    "id": 22782208095,
                    "path": ".github/workflows/netlify.yml",
                    "head_sha": "deadbeef1234",
                    "workflow_id": 22863629,
                    "event": "pull_request_target",
                    "status": "completed",
                    "conclusion": "success",
                    "html_url": "https://github.com/ThePHPF/thephp.foundation/actions/runs/22782208095",
                },
            ]
        ],
        failing_run_ids={22782208095},
    )

    result = detect_default_github_token_permissions(
        client, repo_name="ThePHPF/thephp.foundation", ref="main"
    )

    assert result == {
        "status": "unknown",
        "evidence_log_url": None,
        "reason": "logs_unavailable_or_forbidden",
    }


def test_detect_default_github_token_permissions_unknown_without_candidates() -> None:
    client = FakePermissionDetectionClient(
        workflow_contents={
            ".github/workflows/issue-roundup.yml": (
                "jobs:\n  create_issue:\n    permissions:\n      issues: write\n"
            ),
            ".github/workflows/junie.yml": (
                "permissions:\n  contents: write\n  pull-requests: write\n"
            ),
        },
        runs_pages=[],
    )

    result = detect_default_github_token_permissions(
        client, repo_name="ThePHPF/thephp.foundation", ref="main"
    )

    assert result == {
        "status": "unknown",
        "evidence_log_url": None,
        "reason": "no_pull_request_target_workflows_without_permissions",
    }


def test_parse_github_token_permissions_from_logs_ignores_unrelated_files() -> None:
    logs = _zip_logs(
        {
            "0_Deploy website/2_Checkout.txt": (
                "some unrelated output\n"
                "not a permissions block\n"
            ),
            "0_Deploy website/1_Set up job.txt": (
                "line before\n"
                "GITHUB_TOKEN Permissions\n"
                "  Contents: write\n"
                "  Metadata: read\n"
                "next section\n"
            ),
        }
    )

    parsed = parse_github_token_permissions_from_logs(logs)

    assert parsed == {"Contents": "write", "Metadata": "read"}


def test_parse_github_token_permissions_from_logs_supports_flat_run_log_files() -> None:
    logs = _zip_logs(
        {
            "0_run.txt": (
                "2026-03-17T23:33:56.6818187Z ##[group]GITHUB_TOKEN Permissions\n"
                "2026-03-17T23:33:56.6821305Z Actions: write\n"
                "2026-03-17T23:33:56.6828967Z Metadata: read\n"
                "2026-03-17T23:33:56.6829869Z Models: read\n"
            ),
            "run/system.txt": "runner internals\n",
        }
    )

    parsed = parse_github_token_permissions_from_logs(logs)

    assert parsed == {
        "Actions": "write",
        "Metadata": "read",
        "Models": "read",
    }


def test_detect_default_github_token_permissions_write_when_block_incomplete() -> None:
    client = FakePermissionDetectionClient(
        workflow_contents=_api_shaped_workflow_contents(),
        runs_pages=[
            [
                {
                    "id": 22781534248,
                    "path": ".github/workflows/netlify.yml",
                    "head_sha": "deadbeef1234",
                    "html_url": "https://github.com/ThePHPF/thephp.foundation/actions/runs/22781534248",
                }
            ]
        ],
        logs_by_run_id={
            22781534248: _zip_logs(
                {
                    "0_Build and Deploy to Netlify/1_Set up job.txt": (
                        "GITHUB_TOKEN Permissions\n"
                        "  Actions: write\n"
                        "  Metadata: read\n"
                        "  Models: read\n"
                    )
                }
            )
        },
    )

    result = detect_default_github_token_permissions(
        client, repo_name="ThePHPF/thephp.foundation", ref="main"
    )

    assert result == {
        "status": "write",
        "evidence_log_url": "https://github.com/ThePHPF/thephp.foundation/actions/runs/22781534248",
        "reason": "write_permission_found_in_setup_job",
        "permissions": {
            "Actions": "write",
            "Metadata": "read",
            "Models": "read",
        },
    }


def test_detect_default_github_token_permissions_prefers_ref_sha_when_available() -> None:
    client = FakePermissionDetectionClient(
        workflow_contents=_api_shaped_workflow_contents(),
        runs_pages=[
            [
                {
                    "id": 1,
                    "path": ".github/workflows/netlify.yml",
                    "head_sha": "cafebabe9999",
                    "event": "pull_request_target",
                    "html_url": "https://github.com/ThePHPF/thephp.foundation/actions/runs/1",
                },
                {
                    "id": 2,
                    "path": ".github/workflows/netlify.yml",
                    "head_sha": "deadbeef1234",
                    "event": "pull_request_target",
                    "html_url": "https://github.com/ThePHPF/thephp.foundation/actions/runs/2",
                },
            ]
        ],
        logs_by_run_id={
            1: _zip_logs(
                {
                    "0_Deploy website/1_Set up job.txt": (
                        "GITHUB_TOKEN Permissions\n"
                        + _full_permissions_block(action_level="write")
                    )
                }
            ),
            2: _zip_logs(
                {
                    "0_Deploy website/1_Set up job.txt": (
                        "GITHUB_TOKEN Permissions\n"
                        + _full_permissions_block(action_level="read")
                    )
                }
            ),
        },
    )

    result = detect_default_github_token_permissions(
        client, repo_name="ThePHPF/thephp.foundation", ref="main"
    )

    assert result["status"] == "non-write"
    assert result["evidence_log_url"] == (
        "https://github.com/ThePHPF/thephp.foundation/actions/runs/2"
    )


def test_detect_default_github_token_permissions_falls_back_to_recent_matching_run() -> None:
    client = FakePermissionDetectionClient(
        workflow_contents=_api_shaped_workflow_contents(),
        runs_pages=[
            [
                {
                    "id": 1,
                    "path": ".github/workflows/netlify.yml",
                    "head_sha": "cafebabe9999",
                    "event": "pull_request_target",
                    "html_url": "https://github.com/ThePHPF/thephp.foundation/actions/runs/1",
                },
                {
                    "id": 2,
                    "path": ".github/workflows/netlify.yml",
                    "head_sha": "deadbeef1234",
                    "event": "push",
                    "html_url": "https://github.com/ThePHPF/thephp.foundation/actions/runs/2",
                },
            ]
        ],
        logs_by_run_id={
            1: _zip_logs(
                {
                    "0_Build and Deploy to Netlify/1_Set up job.txt": (
                        "GITHUB_TOKEN Permissions\n"
                        + _full_permissions_block(action_level="write")
                    )
                }
            ),
            2: _zip_logs(
                {
                    "0_Build and Deploy to Netlify/1_Set up job.txt": (
                        "GITHUB_TOKEN Permissions\n"
                        + _full_permissions_block(action_level="read")
                    )
                }
            ),
        },
    )

    result = detect_default_github_token_permissions(
        client, repo_name="ThePHPF/thephp.foundation", ref="main"
    )

    assert result["status"] == "write"
    assert result["evidence_log_url"] == (
        "https://github.com/ThePHPF/thephp.foundation/actions/runs/1"
    )


def test_detect_default_github_token_permissions_ignores_non_pr_target_workflows() -> None:
    client = FakePermissionDetectionClient(
        workflow_contents={
            ".github/workflows/build.yml": (
                "name: Build\n"
                "on:\n"
                "  push:\n"
                "    branches: [main]\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
            ),
            ".github/workflows/pr-check.yml": (
                "name: PR check\n"
                "on:\n"
                "  pull_request:\n"
                "jobs:\n"
                "  check:\n"
                "    runs-on: ubuntu-latest\n"
            ),
        },
        runs_pages=[],
    )

    result = detect_default_github_token_permissions(
        client, repo_name="ThePHPF/thephp.foundation", ref="main"
    )

    assert result == {
        "status": "unknown",
        "evidence_log_url": None,
        "reason": "no_pull_request_target_workflows_without_permissions",
    }


def test_has_complete_permissions_catalog_requires_all_categories() -> None:
    assert has_complete_permissions_catalog(
        {
            "Actions": "write",
            "Metadata": "read",
            "Models": "read",
        }
    ) is False
    assert has_complete_permissions_catalog(
        {
            "Actions": "read",
            "ArtifactMetadata": "read",
            "Attestations": "read",
            "Checks": "read",
            "Contents": "read",
            "Deployments": "read",
            "Discussions": "read",
            "Issues": "read",
            "Metadata": "read",
            "Models": "read",
            "Packages": "read",
            "Pages": "read",
            "PullRequests": "read",
            "RepositoryProjects": "read",
            "SecurityEvents": "read",
            "Statuses": "read",
        }
    ) is True


def _zip_logs(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buffer.getvalue()


def _api_shaped_workflow_contents() -> dict[str, str]:
    return {
        ".github/workflows/deploy-site.yml": (
            "name: Deploy website\n"
            "on:\n"
            "  push:\n"
            "    branches:\n"
            "    - \"main\"\n"
            "jobs:\n"
            "  deploy:\n"
            "    runs-on: \"ubuntu-22.04\"\n"
        ),
        ".github/workflows/issue-roundup.yml": (
            "jobs:\n"
            "  create_issue:\n"
            "    permissions:\n"
            "      issues: write\n"
        ),
        ".github/workflows/junie.yml": (
            "permissions:\n"
            "  contents: write\n"
            "  pull-requests: write\n"
            "  packages: read\n"
        ),
        ".github/workflows/netlify.yml": (
            "name: Build and Deploy to Netlify\n"
            "on:\n"
            "  pull_request_target:\n"
            "jobs:\n"
            "  build:\n"
            "    runs-on: \"ubuntu-22.04\"\n"
        ),
    }


def _full_permissions_block(*, action_level: str) -> str:
    normalized = action_level.lower()
    assert normalized in {"read", "write", "none"}
    return (
        f"  Actions: {normalized}\n"
        f"  ArtifactMetadata: {normalized}\n"
        f"  Attestations: {normalized}\n"
        f"  Checks: {normalized}\n"
        f"  Contents: {normalized}\n"
        f"  Deployments: {normalized}\n"
        f"  Discussions: {normalized}\n"
        f"  Issues: {normalized}\n"
        "  Metadata: read\n"
        "  Models: read\n"
        f"  Packages: {normalized}\n"
        f"  Pages: {normalized}\n"
        f"  PullRequests: {normalized}\n"
        f"  RepositoryProjects: {normalized}\n"
        f"  SecurityEvents: {normalized}\n"
        f"  Statuses: {normalized}\n"
    )


def _full_permissions_dict(*, action_level: str) -> dict[str, str]:
    normalized = action_level.lower()
    assert normalized in {"read", "write", "none"}
    return {
        "Actions": normalized,
        "ArtifactMetadata": normalized,
        "Attestations": normalized,
        "Checks": normalized,
        "Contents": normalized,
        "Deployments": normalized,
        "Discussions": normalized,
        "Issues": normalized,
        "Metadata": "read",
        "Models": "read",
        "Packages": normalized,
        "Pages": normalized,
        "PullRequests": normalized,
        "RepositoryProjects": normalized,
        "SecurityEvents": normalized,
        "Statuses": normalized,
    }
