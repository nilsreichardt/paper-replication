from __future__ import annotations

from pathlib import Path

from pwn_hunter_ai.attack.cleanup import AttackCleanupService
from pwn_hunter_ai.github_client import GitHubApiError


class FakeCleanupGitHubClient:
    def __init__(self, tokens: list[str] | None = None) -> None:
        self.deleted: list[str] = []
        self.existing = {
            "user-a/repo": {"name": "user-a/repo"},
            "user-b/repo": {"name": "user-b/repo"},
        }

    def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
        if repo_name not in self.existing:
            raise GitHubApiError(f"GitHub API request failed for /repos/{repo_name}: 404 Not Found")
        return self.existing[repo_name]

    def delete_repo(self, repo_name: str) -> None:
        self.deleted.append(repo_name)
        self.existing.pop(repo_name, None)


def test_attack_cleanup_service_deletes_forks_and_artifacts(tmp_path: Path) -> None:
    client = FakeCleanupGitHubClient()
    artifact_root = tmp_path / "artifact-root"
    artifact_root.mkdir()
    (artifact_root / "file.txt").write_text("x", encoding="utf-8")

    service = AttackCleanupService(github_client_factory=lambda token: client)
    result = service.run(
        {
            "ai_enumeration": [
                {
                    "risks": [
                        {
                            "attack_result": {
                                "user_a_fork": "user-a/repo",
                                "user_b_fork": "user-b/repo",
                                "artifact_root": str(artifact_root),
                            }
                        }
                    ]
                }
            ]
        },
        github_token="token",
        delete_forks=True,
        delete_artifacts=True,
    )

    assert result["deleted_forks"] == ["user-b/repo", "user-a/repo"]
    assert result["deleted_artifacts"] == [str(artifact_root)]
    assert not artifact_root.exists()


def test_attack_cleanup_service_keeps_persisted_security_reports_outside_artifacts(
    tmp_path: Path,
) -> None:
    client = FakeCleanupGitHubClient()
    artifact_root = tmp_path / "artifact-root"
    artifact_root.mkdir()
    (artifact_root / "file.txt").write_text("x", encoding="utf-8")
    reports_dir = tmp_path / "security-reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    report_path = reports_dir / "owner-repo-risk-1-github-workflows-ci.yml.md"
    report_path.write_text("# Security Report\n", encoding="utf-8")

    service = AttackCleanupService(github_client_factory=lambda token: client)
    result = service.run(
        {
            "ai_enumeration": [
                {
                    "risks": [
                        {
                            "attack_result": {
                                "user_a_fork": "user-a/repo",
                                "user_b_fork": "user-b/repo",
                                "artifact_root": str(artifact_root),
                                "security_report_path": str(report_path),
                            }
                        }
                    ]
                }
            ]
        },
        github_token="token",
        delete_forks=True,
        delete_artifacts=True,
    )

    assert result["deleted_artifacts"] == [str(artifact_root)]
    assert not artifact_root.exists()
    assert report_path.exists()
