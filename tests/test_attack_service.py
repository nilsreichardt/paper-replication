from __future__ import annotations

import io
import json
from pathlib import Path
import zipfile

import pytest

from pwn_hunter_ai.attack.artifacts import AttackArtifactsManager
from pwn_hunter_ai.attack.openhands_manager import (
    OpenHandsHeadlessResult,
    OpenHandsLaunchResult,
)
from pwn_hunter_ai.attack.service import AttackPreparationService
from pwn_hunter_ai.attack.tokens import AttackTokenBroker
from pwn_hunter_ai.github_client import GitHubApiError


class FakeAttackGitHubClient:
    _repos: dict[str, dict[str, str]] = {
        "owner/repo": {
            "full_name": "owner/repo",
            "created_at": "2024-01-01T00:00:00Z",
            "default_branch": "main",
            "parent_full_name": "",
        }
    }
    _workflow_listing = [
        {"type": "file", "path": ".github/workflows/pull_request.yml"},
        {"type": "file", "path": ".github/workflows/release.yaml"},
    ]
    _workflow_contents = {
        ".github/workflows/pull_request.yml": "steps:\n  - run: echo ${{ secrets.FIRST_SECRET }}\n  - run: echo ${{ secrets.GITHUB_TOKEN }}\n",
        ".github/workflows/release.yaml": "env:\n  TOKEN: ${{ secrets['SECOND_SECRET'] }}\n",
    }
    enabled_actions: list[tuple[str, bool]] = []
    enabled_workflows: list[tuple[str, str]] = []
    seeded_secrets: list[tuple[str, str, str]] = []
    created_forks: list[tuple[str, str]] = []
    workflow_updates: list[dict[str, str]] = []
    operation_log: list[tuple[str, str]] = []

    def __init__(self, tokens: list[str] | None = None) -> None:
        token = (tokens or [""])[0]
        self.token = token
        self.login = {
            "token-a": "synthetic-target",
            "token-b": "synthetic-attacker",
        }[token]

    @classmethod
    def reset(cls) -> None:
        cls._repos = {
            "owner/repo": {
                "full_name": "owner/repo",
                "created_at": "2024-01-01T00:00:00Z",
                "default_branch": "main",
                "parent_full_name": "",
            }
        }
        cls.enabled_actions = []
        cls.enabled_workflows = []
        cls.seeded_secrets = []
        cls.created_forks = []
        cls.workflow_updates = []
        cls.operation_log = []

    def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
        try:
            return self._repos[repo_name]
        except KeyError as exc:
            raise GitHubApiError(f"GitHub API request failed for /repos/{repo_name}: 404 Not Found") from exc

    def get_branch_head_sha(self, repo_name: str, branch: str) -> str:
        assert repo_name == "owner/repo"
        assert branch == "main"
        return "deadbeef1234"

    def get_authenticated_user(self) -> dict[str, str]:
        return {"login": self.login}

    def create_fork(self, repo_name: str, name: str | None = None) -> dict[str, str]:
        repo_name_part = name.strip() if isinstance(name, str) and name.strip() else repo_name.split("/", 1)[1]
        fork_name = f"{self.login}/{repo_name_part}"
        self._repos[fork_name] = {
            "full_name": fork_name,
            "created_at": "2024-01-02T00:00:00Z",
            "default_branch": "main",
            "parent_full_name": repo_name,
        }
        self.created_forks.append((repo_name, fork_name))
        self.operation_log.append(("create_fork", fork_name))
        return {"full_name": fork_name}

    def delete_repo(self, repo_name: str) -> None:
        self._repos.pop(repo_name, None)

    def enable_actions(self, repo_name: str, *, enabled: bool = True) -> None:
        self.enabled_actions.append((repo_name, enabled))

    def enable_workflow(self, repo_name: str, workflow_id: str) -> None:
        self.enabled_workflows.append((repo_name, workflow_id))
        self.operation_log.append(("enable_workflow", workflow_id))

    def list_directory(self, repo_name: str, path: str, ref: str) -> list[dict[str, str]]:
        assert repo_name == "owner/repo"
        assert path == ".github/workflows"
        assert ref == "deadbeef1234"
        return list(self._workflow_listing)

    def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
        assert repo_name == "owner/repo"
        assert ref == "deadbeef1234"
        return self._workflow_contents[path]

    def get_file_sha(self, repo_name: str, path: str, ref: str) -> str:
        _ = ref
        if repo_name not in self._repos:
            raise GitHubApiError(
                f"GitHub API request failed for /repos/{repo_name}/contents/{path}: 404 Not Found"
            )
        return f"sha-{path}"

    def create_or_update_file(
        self,
        repo_name: str,
        path: str,
        content: str,
        message: str,
        branch: str,
        sha: str | None = None,
    ) -> dict[str, str]:
        _ = message
        if repo_name not in self._repos:
            raise GitHubApiError(
                f"GitHub API request failed for /repos/{repo_name}/contents/{path}: 404 Not Found"
            )
        self.workflow_updates.append(
            {
                "repo_name": repo_name,
                "path": path,
                "content": content,
                "branch": branch,
                "sha": sha or "",
            }
        )
        self.operation_log.append(("update_workflow", path))
        return {"content": {"path": path}}

    def set_actions_secret(self, repo_name: str, name: str, value: str) -> None:
        self.seeded_secrets.append((repo_name, name, value))

    def get_workflow_runs(self, repo_name: str, per_page: int = 100, page: int = 1) -> dict:
        _ = (repo_name, per_page, page)
        return {"workflow_runs": []}

    def get_commit(self, repo_name: str, ref: str) -> dict[str, str]:
        assert repo_name == "owner/repo"
        assert ref == "deadbeef1234"
        return {
            "sha": "deadbeef1234",
            "commit": {
                "committer": {"date": "2024-01-03T04:05:06Z"},
            },
        }

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        _ = (repo_name, run_id)
        return b""


def _zip_logs(files: dict[str, str]) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, content in files.items():
            zf.writestr(name, content)
    return buffer.getvalue()


def _full_permissions_block(*, level: str) -> str:
    normalized = level.lower()
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


def _fake_clone_runner(clone_url: str, destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    (destination / ".git-clone-url").write_text(clone_url, encoding="utf-8")


@pytest.fixture(autouse=True)
def _isolate_local_secrets_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    secrets_path = tmp_path / ".secrets"
    secrets_path.write_text("GITHUB_TOKEN={{GITHUB_TOKEN}}\n", encoding="utf-8")
    monkeypatch.setattr("pwn_hunter_ai.attack.service.LOCAL_SECRETS_PATH", secrets_path)


def test_attack_preparation_service_prepares_owned_forks_and_dummy_secrets(
    tmp_path: Path,
) -> None:
    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(tmp_path / "artifacts", clone_runner=_fake_clone_runner)
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "timestamp": "Sun Mar 01 17:17:02 2026",
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 1,
                    "repository_creation_date": "2024-01-01T00:00:00Z",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "pull_request.yml",
                            "path": [],
                            "gato-x-path": [
                                {
                                    "node": "Workflow('.github/workflows/pull_request.yml')",
                                }
                            ],
                            "ai-analysis": {
                                "vulnerable": True,
                                "confidence": "high",
                                "explanation": "The workflow executes attacker-controlled files on pull_request_target.",
                            },
                            "pwn_request_result": {
                                "vulnerable": True,
                                "explanation": "x",
                                "impact": "y",
                                "poc": "z",
                            },
                        }
                    ],
                }
            ],
        },
        parallel_jobs=1,
    )

    repository = output_payload["ai_enumeration"][0]
    risk = repository["risks"][0]

    assert repository["vulnerable_commit_hash"] == "deadbeef1234"
    assert repository["source_last_commit_timestamp"] == "2024-01-03T04:05:06Z"
    assert repository["repo_vulnerable"] == "unknown"
    assert repository["act_repo_vulnerable"] is False
    assert isinstance(risk["attack_processed_time"], str)
    assert risk["attack_processed_time"]
    assert risk["attack_result"]["status"] == "prepared_for_manual_validation"
    assert risk["attack_result"]["focused_workflow"] == ".github/workflows/pull_request.yml"
    assert risk["attack_result"]["focused_workflows"] == [
        ".github/workflows/pull_request.yml"
    ]
    assert risk["attack_result"]["focused_workflow_refs"] == [
        {
            "repo_name": "owner/repo",
            "path": ".github/workflows/pull_request.yml",
            "ref": None,
        }
    ]
    assert risk["attack_result"]["user_a_fork"] == "synthetic-target/repo"
    assert risk["attack_result"]["user_b_fork"] == "synthetic-attacker/repo"
    assert risk["attack_result"]["seeded_secrets"] == ["FIRST_SECRET", "SECOND_SECRET"]
    assert Path(risk["attack_result"]["artifact_root"]).exists()
    assert Path(risk["attack_result"]["workspace_path"]).exists()
    assert Path(risk["attack_result"]["agent_prompt_path"]).exists()
    assert Path(risk["attack_result"]["context_path"]).exists()
    assert Path(risk["attack_result"]["agent_output_path"]).exists()
    assert Path(risk["attack_result"]["attempt_state_path"]).exists()
    assert Path(risk["attack_result"]["shared_secrets_state_path"]).exists()
    context_payload = Path(risk["attack_result"]["context_path"]).read_text(encoding="utf-8")
    prompt_payload = Path(risk["attack_result"]["agent_prompt_path"]).read_text(encoding="utf-8")
    agent_output_payload = json.loads(
        Path(risk["attack_result"]["agent_output_path"]).read_text(encoding="utf-8")
    )
    assert '"path": ".github/workflows/pull_request.yml"' in context_payload
    assert "Controller execution order (strict):" in prompt_payload
    assert "Available exploit modes:" not in prompt_payload
    assert "`direct_file_edit`" not in prompt_payload
    assert "`package_exploit`" not in prompt_payload
    assert "GITHUB_RUN_ID" in prompt_payload
    assert "http://127.0.0.1:8787/$GITHUB_RUN_ID" in prompt_payload
    assert "Do not create a random Hookbin bin ID." in prompt_payload
    assert "agent-output.json" in prompt_payload
    assert 'update `vulnerable` to `"no"` in `agent-output.json`' in prompt_payload
    assert "update `human_review_needed` to `true` in `agent-output.json`" in prompt_payload
    assert "You may edit `.secrets` in the workspace" in prompt_payload
    assert "Gato X Path from input:" in prompt_payload
    assert "Workflow('.github/workflows/pull_request.yml')" in prompt_payload
    assert "AI Analysis Explanation from input:" in prompt_payload
    assert (
        "The workflow executes attacker-controlled files on pull_request_target."
        in prompt_payload
    )
    assert "update `learning` in `agent-output.json`" not in prompt_payload
    assert (
        prompt_payload.index("1. Read")
        < prompt_payload.index("2. Identify")
        < prompt_payload.index("3. Modify")
        < prompt_payload.index("4. The modifications will be automatically committed")
        < prompt_payload.index("5. After the workflow runs")
    )
    assert FakeAttackGitHubClient.enabled_actions == [("synthetic-target/repo", True)]
    assert FakeAttackGitHubClient.enabled_workflows == []
    assert FakeAttackGitHubClient.seeded_secrets == [
        ("synthetic-target/repo", "FIRST_SECRET", "flag{first-secret}"),
        ("synthetic-target/repo", "SECOND_SECRET", "flag{second-secret}"),
    ]
    assert agent_output_payload["vulnerable"] == "unconfirmed"
    assert agent_output_payload["human_review_needed"] is False
    assert agent_output_payload["exploit_file"] == ""
    assert agent_output_payload["exploit_job"] == ""
    assert agent_output_payload["sink"] == ""
    assert agent_output_payload["local_test_result"] == "not_executed_yet"
    assert agent_output_payload["reason"] == ""
    assert agent_output_payload["notes"] == ""
    assert "learning" not in agent_output_payload


def test_attack_preparation_service_skips_selected_repositories(tmp_path: Path) -> None:
    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(tmp_path / "artifacts", clone_runner=_fake_clone_runner)
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "timestamp": "Sun Mar 01 17:17:02 2026",
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "pull_request.yml",
                            "ai-analysis": {"vulnerable": True},
                        }
                    ],
                },
                {
                    "name": "owner/keep",
                    "risks": [],
                },
            ],
        },
        parallel_jobs=1,
        skip_repositories={"OWNER/REPO"},
    )

    assert [repository["name"] for repository in output_payload["ai_enumeration"]] == [
        "owner/keep"
    ]


def test_attack_preparation_service_skips_owner_wildcard_repositories(
    tmp_path: Path,
) -> None:
    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts",
        clone_runner=_fake_clone_runner,
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "timestamp": "Sun Mar 01 17:17:02 2026",
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [],
                },
                {
                    "name": "owner/keep",
                    "risks": [],
                },
                {
                    "name": "other/repo",
                    "risks": [],
                },
            ],
        },
        parallel_jobs=1,
        skip_repositories={"OWNER/*"},
    )

    assert [repository["name"] for repository in output_payload["ai_enumeration"]] == [
        "other/repo"
    ]


def test_attack_preparation_service_uses_gato_x_prompt_without_ai_sections(
    tmp_path: Path,
) -> None:
    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts",
        clone_runner=_fake_clone_runner,
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "attack_input_source": "gato-x",
                            "vulnerable": True,
                            "repository_name": "owner/repo",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "pull_request.yml",
                            "confidence": "high",
                            "attack_complexity": "No Interaction",
                            "explanation": "Untrusted PR code is executed.",
                            "path": [
                                {
                                    "node": (
                                        "WorkflowNode('owner/repo:main:.github/workflows/pull_request.yml')"
                                    )
                                }
                            ],
                            "gato-x-path": [
                                {
                                    "node": (
                                        "WorkflowNode('owner/repo:main:.github/workflows/pull_request.yml')"
                                    )
                                }
                            ],
                            "sink": "make test",
                            "gato-x-sink": "make test",
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    prompt_payload = Path(risk["attack_result"]["agent_prompt_path"]).read_text(
        encoding="utf-8"
    )
    context_payload = json.loads(
        Path(risk["attack_result"]["context_path"]).read_text(encoding="utf-8")
    )

    assert context_payload["attack_input_source"] == "gato-x"
    assert "Gato X Path from input:" in prompt_payload
    assert "Sink from input:" in prompt_payload
    assert "make test" in prompt_payload
    assert "AI Analysis Explanation from input:" not in prompt_payload
    assert "Suggested PoC from input:" not in prompt_payload
    assert "Only do this after you have tried the workflow-guided path" in prompt_payload


def test_attack_preparation_service_seeds_local_secrets_without_modifying_repo_secrets_file(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secrets_path = tmp_path / ".secrets"
    secrets_path.write_text(
        "GITHUB_TOKEN={{GITHUB_TOKEN}}\n"
        "FIRST_SECRET=local-first\n"
        "EXTRA_LOCAL=extra-local\n",
        encoding="utf-8",
    )
    monkeypatch.setattr("pwn_hunter_ai.attack.service.LOCAL_SECRETS_PATH", secrets_path)

    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts",
        clone_runner=_fake_clone_runner,
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )
    risk = output_payload["ai_enumeration"][0]["risks"][0]

    assert risk["attack_result"]["seeded_secrets"] == [
        "EXTRA_LOCAL",
        "FIRST_SECRET",
        "SECOND_SECRET",
    ]
    assert ("synthetic-target/repo", "FIRST_SECRET", "local-first") in (
        FakeAttackGitHubClient.seeded_secrets
    )
    assert ("synthetic-target/repo", "SECOND_SECRET", "flag{second-secret}") in (
        FakeAttackGitHubClient.seeded_secrets
    )
    assert ("synthetic-target/repo", "EXTRA_LOCAL", "extra-local") in (
        FakeAttackGitHubClient.seeded_secrets
    )
    assert (
        secrets_path.read_text(encoding="utf-8")
        == "GITHUB_TOKEN={{GITHUB_TOKEN}}\nFIRST_SECRET=local-first\nEXTRA_LOCAL=extra-local\n"
    )
    assert not any(
        secret_name == "GITHUB_TOKEN"
        for _repo_name, secret_name, _secret_value in FakeAttackGitHubClient.seeded_secrets
    )


def test_attack_preparation_service_creates_distinct_risk_workspaces_per_repository(
    tmp_path: Path,
) -> None:
    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts",
        clone_runner=_fake_clone_runner,
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "issue_type": "First Risk",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        },
                        {
                            "repository_name": "owner/repo",
                            "issue_type": "Second Risk",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        },
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risks = output_payload["ai_enumeration"][0]["risks"]
    workspace_paths = [Path(risk["attack_result"]["workspace_path"]) for risk in risks]
    shared_secrets_paths = [
        Path(risk["attack_result"]["shared_secrets_state_path"]) for risk in risks
    ]

    assert len(workspace_paths) == 2
    assert workspace_paths[0] != workspace_paths[1]
    assert all(path.exists() for path in workspace_paths)
    assert workspace_paths[0].parent.parent.name == "risks"
    assert workspace_paths[1].parent.parent.name == "risks"
    assert shared_secrets_paths[0] == shared_secrets_paths[1]
    assert shared_secrets_paths[0].exists()


def test_attack_preparation_service_preprocesses_workflows_before_user_b_fork(
    tmp_path: Path,
) -> None:
    class PreprocessingClient(FakeAttackGitHubClient):
        _workflow_listing = [
            {"type": "file", "path": ".github/workflows/pull_request.yml"},
        ]
        _workflow_contents = {
            ".github/workflows/pull_request.yml": (
                "name: CI\n"
                "on:\n"
                "  pull_request_target:\n"
                "jobs:\n"
                "  build:\n"
                "    if: github.repository_owner == 'owner'\n"
                "    runs-on: [self-hosted, linux, x64]\n"
                "    steps:\n"
                "      - run: echo build\n"
                "  matrix-test:\n"
                "    runs-on: ${{ matrix.os }}\n"
                "    strategy:\n"
                "      matrix:\n"
                "        os: [ubuntu-20.04, macos-12]\n"
                "    steps:\n"
                "      - run: echo matrix\n"
            ),
        }

    PreprocessingClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: PreprocessingClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    assert len(PreprocessingClient.workflow_updates) == 1
    update = PreprocessingClient.workflow_updates[0]
    assert update["repo_name"] == "synthetic-target/repo"
    assert update["path"] == ".github/workflows/pull_request.yml"
    assert update["branch"] == "main"
    assert "github.repository_owner == 'synthetic-target'" in update["content"]
    assert "runs-on: ubuntu-latest" in update["content"]
    assert "- ubuntu-latest" in update["content"]
    assert "- macos-latest" in update["content"]

    create_a_index = PreprocessingClient.operation_log.index(
        ("create_fork", "synthetic-target/repo")
    )
    update_index = PreprocessingClient.operation_log.index(
        ("update_workflow", ".github/workflows/pull_request.yml")
    )
    create_b_index = PreprocessingClient.operation_log.index(
        ("create_fork", "synthetic-attacker/repo")
    )
    assert create_a_index < update_index < create_b_index


def test_attack_preparation_service_enables_focused_scheduled_workflow_before_user_b_fork(
    tmp_path: Path,
) -> None:
    class ScheduledWorkflowClient(FakeAttackGitHubClient):
        _workflow_listing = [
            {"type": "file", "path": ".github/workflows/python-tests.yml"},
            {"type": "file", "path": ".github/workflows/release.yaml"},
        ]
        _workflow_contents = {
            ".github/workflows/python-tests.yml": (
                "name: Python Tests\n"
                "on:\n"
                "  push:\n"
                "    branches: [\"main\"]\n"
                "  pull_request_target:\n"
                "    branches: [\"main\"]\n"
                "  schedule:\n"
                "    - cron: '0 0 1-31/15 * *'\n"
                "jobs:\n"
                "  build:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: echo test\n"
            ),
            ".github/workflows/release.yaml": (
                "name: Release\n"
                "on:\n"
                "  push:\n"
                "    branches: [\"main\"]\n"
                "jobs:\n"
                "  release:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: echo release\n"
            ),
        }

    ScheduledWorkflowClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: ScheduledWorkflowClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "python-tests.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    assert ScheduledWorkflowClient.enabled_workflows == [
        ("synthetic-target/repo", "python-tests.yml")
    ]

    create_a_index = ScheduledWorkflowClient.operation_log.index(
        ("create_fork", "synthetic-target/repo")
    )
    enable_index = ScheduledWorkflowClient.operation_log.index(
        ("enable_workflow", "python-tests.yml")
    )
    create_b_index = ScheduledWorkflowClient.operation_log.index(
        ("create_fork", "synthetic-attacker/repo")
    )
    assert create_a_index < enable_index < create_b_index


def test_attack_preparation_service_prefers_gato_x_path_workflow_for_focus(
    tmp_path: Path,
) -> None:
    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(tmp_path / "artifacts", clone_runner=_fake_clone_runner)
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "gato-x-path": [
                                {
                                    "node": (
                                        "WorkflowNode('owner/repo:main:.github/workflows/release.yaml')"
                                    )
                                },
                                {
                                    "node": (
                                        "JobNode('owner/repo:main:.github/workflows/release.yaml:publish#L10')"
                                    )
                                },
                            ],
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["attack_result"]["focused_workflow"] == ".github/workflows/release.yaml"
    assert risk["attack_result"]["focused_workflows"] == [
        ".github/workflows/release.yaml"
    ]
    assert risk["attack_result"]["focused_workflow_refs"] == [
        {
            "repo_name": "owner/repo",
            "path": ".github/workflows/release.yaml",
            "ref": "main",
        }
    ]


def test_attack_preparation_service_repairs_basename_conflict_by_recreating_primary_fork(
    tmp_path: Path,
) -> None:
    FakeAttackGitHubClient.reset()
    FakeAttackGitHubClient._repos = {
        "owner/repo1": {
            "full_name": "owner/repo1",
            "created_at": "2024-01-01T00:00:00Z",
            "default_branch": "main",
            "parent_full_name": "",
        },
        "other-owner/repo1": {
            "full_name": "other-owner/repo1",
            "created_at": "2024-01-01T00:00:00Z",
            "default_branch": "main",
            "parent_full_name": "",
        },
        "synthetic-attacker/repo1": {
            "full_name": "synthetic-attacker/repo1",
            "created_at": "2024-01-02T00:00:00Z",
            "default_branch": "main",
            "parent_full_name": "owner/repo1",
        },
    }

    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )
    user_b_client = FakeAttackGitHubClient(tokens=["token-b"])

    reused_fork_name = service._ensure_fork(
        client=user_b_client,
        source_repo="owner/repo1",
        fork_owner="synthetic-attacker",
    )
    alternate_fork_name = service._ensure_fork(
        client=user_b_client,
        source_repo="other-owner/repo1",
        fork_owner="synthetic-attacker",
    )

    assert reused_fork_name == "synthetic-attacker/repo1"
    assert alternate_fork_name == "synthetic-attacker/repo1"
    assert (
        FakeAttackGitHubClient._repos["synthetic-attacker/repo1"]["parent_full_name"]
        == "other-owner/repo1"
    )
    assert ("create_fork", "synthetic-attacker/repo1") in (
        FakeAttackGitHubClient.operation_log
    )


def test_attack_preparation_service_retries_transient_404_when_validating_new_fork(
    tmp_path: Path,
) -> None:
    class EventuallyConsistentForkClient(FakeAttackGitHubClient):
        _metadata_calls: dict[str, int] = {}

        @classmethod
        def reset(cls) -> None:
            super().reset()
            cls._metadata_calls = {}

        def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
            if repo_name == "synthetic-target/repo-from-owner":
                attempt = self._metadata_calls.get(repo_name, 0) + 1
                self._metadata_calls[repo_name] = attempt
                if attempt < 3:
                    raise GitHubApiError(
                        f"GitHub API request failed for /repos/{repo_name}: 404 Not Found"
                    )
            return super().get_repo_metadata(repo_name)

    EventuallyConsistentForkClient.reset()
    EventuallyConsistentForkClient._repos["synthetic-target/repo"] = {
        "full_name": "synthetic-target/repo",
        "created_at": "2024-01-02T00:00:00Z",
        "default_branch": "main",
        # Non-fork collision should still fall back to alternate name path.
        "parent_full_name": "",
    }

    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: EventuallyConsistentForkClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["attack_result"]["status"] == "prepared_for_manual_validation"
    assert risk["attack_result"]["user_a_fork"] == "synthetic-target/repo-from-owner"
    assert EventuallyConsistentForkClient._metadata_calls[
        "synthetic-target/repo-from-owner"
    ] >= 3


def test_attack_preparation_service_repairs_conflicting_wrong_parent_fork(
    tmp_path: Path,
) -> None:
    class RepairingForkClient(FakeAttackGitHubClient):
        deleted_repos: list[str] = []

        @classmethod
        def reset(cls) -> None:
            super().reset()
            cls.deleted_repos = []

        def delete_repo(self, repo_name: str) -> None:
            self.deleted_repos.append(repo_name)
            super().delete_repo(repo_name)

    RepairingForkClient.reset()
    RepairingForkClient._repos["synthetic-target/repo"] = {
        "full_name": "synthetic-target/repo",
        "created_at": "2024-01-02T00:00:00Z",
        "default_branch": "main",
        "parent_full_name": "owner/repo",
    }
    RepairingForkClient._repos["synthetic-attacker/repo"] = {
        "full_name": "synthetic-attacker/repo",
        "created_at": "2024-01-03T00:00:00Z",
        "default_branch": "main",
        "parent_full_name": "someone-else/repo",
    }
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: RepairingForkClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )
    user_b_client = RepairingForkClient(tokens=["token-b"])

    repaired_fork = service._ensure_fork(
        client=user_b_client,
        source_repo="synthetic-target/repo",
        fork_owner="synthetic-attacker",
    )

    assert repaired_fork == "synthetic-attacker/repo"
    assert RepairingForkClient.deleted_repos == ["synthetic-attacker/repo"]
    assert (
        RepairingForkClient._repos["synthetic-attacker/repo"]["parent_full_name"]
        == "synthetic-target/repo"
    )


def test_attack_preparation_service_refreshes_parent_validation_after_recreate(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class CachedRepairingForkClient(FakeAttackGitHubClient):
        deleted_repos: list[str] = []
        _metadata_cache: dict[str, dict[str, str]] = {}
        _stale_parent_by_repo: dict[str, str] = {}
        _stale_reads_remaining: dict[str, int] = {}

        @classmethod
        def reset(cls) -> None:
            super().reset()
            cls.deleted_repos = []
            cls._metadata_cache = {}
            cls._stale_parent_by_repo = {}
            cls._stale_reads_remaining = {}

        def get_repo_metadata(
            self, repo_name: str, force_refresh: bool = False
        ) -> dict[str, str]:
            if not force_refresh and repo_name in self._metadata_cache:
                return dict(self._metadata_cache[repo_name])

            metadata = dict(super().get_repo_metadata(repo_name))
            stale_reads_remaining = self._stale_reads_remaining.get(repo_name, 0)
            if stale_reads_remaining > 0:
                metadata["parent_full_name"] = self._stale_parent_by_repo[repo_name]
                self._stale_reads_remaining[repo_name] = stale_reads_remaining - 1
            self._metadata_cache[repo_name] = dict(metadata)
            return metadata

        def delete_repo(self, repo_name: str) -> None:
            self.deleted_repos.append(repo_name)
            old_parent = self._repos.get(repo_name, {}).get("parent_full_name")
            if isinstance(old_parent, str) and old_parent:
                self._stale_parent_by_repo[repo_name] = old_parent
            self._metadata_cache.pop(repo_name, None)
            super().delete_repo(repo_name)

        def create_fork(self, repo_name: str, name: str | None = None) -> dict[str, str]:
            result = super().create_fork(repo_name, name=name)
            fork_name = result["full_name"]
            if fork_name in self._stale_parent_by_repo:
                self._stale_reads_remaining[fork_name] = 1
            return result

    monkeypatch.setattr("pwn_hunter_ai.attack.service.random.uniform", lambda _a, _b: 0.0)
    monkeypatch.setattr("pwn_hunter_ai.attack.service.time.sleep", lambda _seconds: None)

    CachedRepairingForkClient.reset()
    CachedRepairingForkClient._repos["synthetic-target/repo"] = {
        "full_name": "synthetic-target/repo",
        "created_at": "2024-01-02T00:00:00Z",
        "default_branch": "main",
        "parent_full_name": "owner/repo",
    }
    CachedRepairingForkClient._repos["synthetic-attacker/repo"] = {
        "full_name": "synthetic-attacker/repo",
        "created_at": "2024-01-03T00:00:00Z",
        "default_branch": "main",
        "parent_full_name": "someone-else/repo",
    }
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: CachedRepairingForkClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )
    user_b_client = CachedRepairingForkClient(tokens=["token-b"])

    repaired_fork = service._ensure_fork(
        client=user_b_client,
        source_repo="synthetic-target/repo",
        fork_owner="synthetic-attacker",
    )

    assert repaired_fork == "synthetic-attacker/repo"
    assert CachedRepairingForkClient.deleted_repos == ["synthetic-attacker/repo"]
    assert CachedRepairingForkClient._metadata_cache["synthetic-attacker/repo"][
        "parent_full_name"
    ] == "synthetic-target/repo"


def test_attack_preparation_service_classifies_fork_name_not_honored(
    tmp_path: Path,
) -> None:
    class NameMismatchForkClient(FakeAttackGitHubClient):
        def create_fork(self, repo_name: str, name: str | None = None) -> dict[str, str]:
            _ = name
            super().create_fork(repo_name, name=repo_name.split("/", 1)[1])
            return {"full_name": f"{self.login}/{repo_name.split('/', 1)[1]}"}

    NameMismatchForkClient.reset()
    NameMismatchForkClient._repos["synthetic-target/repo"] = {
        "full_name": "synthetic-target/repo",
        "created_at": "2024-01-02T00:00:00Z",
        "default_branch": "main",
        "parent_full_name": "owner/repo",
    }
    NameMismatchForkClient._repos["synthetic-attacker/repo"] = {
        "full_name": "synthetic-attacker/repo",
        "created_at": "2024-01-03T00:00:00Z",
        "default_branch": "main",
        # Keep as non-fork collision so alternate naming is attempted.
        "parent_full_name": "",
    }
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: NameMismatchForkClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["attack_result"]["status"] == "blocked_preparation_error"
    assert risk["attack_result"]["error_class"] == "fork_name_not_honored"
    assert risk["attack_result"]["failure_fingerprint"] == "fork_name_not_honored"


def test_attack_preparation_service_reports_user_a_fork_denial_to_token_broker(
    tmp_path: Path,
) -> None:
    class ForkDeniedClient(FakeAttackGitHubClient):
        def create_fork(self, repo_name: str, name: str | None = None) -> dict[str, str]:
            _ = name
            raise RuntimeError(
                f"GitHub API request failed for /repos/{repo_name}/forks: 403 You cannot fork this repository at this time"
            )

    class RecordingBroker(AttackTokenBroker):
        def __init__(self) -> None:
            super().__init__(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
            self.reports: list[dict[str, str]] = []

        def report_preparation_token_failure(
            self,
            *,
            token: str,
            token_role: str,
            repository_name: str,
            stage: str,
            reason: str,
        ) -> None:
            self.reports.append(
                {
                    "token": token,
                    "token_role": token_role,
                    "repository_name": repository_name,
                    "stage": stage,
                    "reason": reason,
                }
            )

    ForkDeniedClient.reset()
    broker = RecordingBroker()
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: ForkDeniedClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["attack_result"]["status"] == "blocked_preparation_error"
    assert broker.reports == [
        {
            "token": "token-a",
            "token_role": "user_a",
            "repository_name": "owner/repo",
            "stage": "ensure_user_a_fork",
            "reason": "GitHub API request failed for /repos/owner/repo/forks: 403 You cannot fork this repository at this time",
        }
    ]


def test_attack_preparation_service_marks_source_repo_not_found(
    tmp_path: Path,
) -> None:
    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/missing-repo",
                    "risks": [
                        {
                            "repository_name": "owner/missing-repo",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["attack_result"]["status"] == "blocked_preparation_error"
    assert risk["attack_result"]["error_class"] == "source_repo_not_found"
    assert risk["attack_result"]["failure_fingerprint"] == "source_repo_not_found"


def test_attack_preparation_service_marks_fork_visibility_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class ForkVisibilityTimeoutClient(FakeAttackGitHubClient):
        def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
            if repo_name in {
                "synthetic-target/repo",
                "synthetic-attacker/repo",
            }:
                raise GitHubApiError(
                    f"GitHub API request failed for /repos/{repo_name}: 404 Not Found"
                )
            return super().get_repo_metadata(repo_name)

    monkeypatch.setattr(
        "pwn_hunter_ai.attack.service.FORK_PARENT_VALIDATION_MAX_ATTEMPTS",
        3,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.service.FORK_PARENT_VALIDATION_MAX_ELAPSED_SECONDS",
        0.01,
    )
    monkeypatch.setattr(
        "pwn_hunter_ai.attack.service.time.sleep",
        lambda _seconds: None,
    )
    ForkVisibilityTimeoutClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: ForkVisibilityTimeoutClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["attack_result"]["status"] == "blocked_preparation_error"
    assert risk["attack_result"]["error_class"] == "fork_visibility_timeout"
    assert risk["attack_result"]["failure_fingerprint"] == "fork_visibility_timeout"


def test_attack_preparation_service_blocks_invalid_same_owner_fork_chain(
    tmp_path: Path,
) -> None:
    class SameOwnerFakeClient(FakeAttackGitHubClient):
        _repos: dict[str, dict[str, str]] = {
            "owner/repo": {
                "full_name": "owner/repo",
                "created_at": "2024-01-01T00:00:00Z",
                "default_branch": "main",
                "parent_full_name": "",
            }
        }

        def __init__(self, tokens: list[str] | None = None) -> None:
            token = (tokens or [""])[0]
            self.token = token
            self.login = {
                "token-a": "owner",
                "token-b": "synthetic-attacker",
            }[token]

        def get_branch_head_sha(self, repo_name: str, branch: str) -> str:
            assert repo_name == "owner/repo"
            assert branch == "main"
            return "deadbeef1234"

    SameOwnerFakeClient.reset()
    SameOwnerFakeClient._repos = {
        "owner/repo": {
            "full_name": "owner/repo",
            "created_at": "2024-01-01T00:00:00Z",
            "default_branch": "main",
            "parent_full_name": "",
        }
    }
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: SameOwnerFakeClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert isinstance(risk["attack_processed_time"], str)
    assert risk["attack_processed_time"]
    assert risk["attack_result"]["status"] == "blocked_preparation_error"
    assert "Invalid fork chain" in risk["attack_result"]["reason"]


def test_attack_preparation_service_blocks_when_secret_preflight_never_ready(
    tmp_path: Path,
) -> None:
    class SecretPreflightFailClient(FakeAttackGitHubClient):
        def get_actions_secret_public_key(self, repo_name: str) -> dict[str, str]:
            _ = repo_name
            raise GitHubApiError(
                "GitHub API request failed for /repos/synthetic-target/repo/actions/secrets/public-key: "
                "400 Bad Request [request_id=REQPREP123]"
            )

    SecretPreflightFailClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: SecretPreflightFailClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    attack_result = risk["attack_result"]
    assert attack_result["status"] == "blocked_preparation_error"
    assert attack_result["error_stage"] == "preparation"
    assert attack_result["error_class"] == "repo_not_ready"
    assert attack_result["failure_fingerprint"] == "seed_secret_repo_not_ready"
    assert attack_result["secret_seed_summary"]["succeeded"] == 0
    failures = attack_result["secret_seed_failures"]
    assert isinstance(failures, list) and failures
    assert failures[0]["secret_name"] == "__preflight__"
    assert failures[0]["http_status"] == 400
    assert failures[0]["github_request_id"] == "REQPREP123"


def test_attack_preparation_service_includes_openhands_tracing_metadata(
    tmp_path: Path, monkeypatch
) -> None:
    class FakeOpenHandsManager:
        def launch(self, *, workspace_path: Path, prompt_path: Path, metadata_path: Path):
            return OpenHandsLaunchResult(
                status="running",
                base_url="http://127.0.0.1:3000",
                pid=1234,
                command=["openhands", "web"],
                metadata_path=metadata_path,
                tracing={
                    "enabled": True,
                    "service_name": "pwnhunter-attack-openhands",
                    "endpoint": "https://cloud.langfuse.com/api/public/otel",
                },
            )

    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
        launch_agent=True,
        openhands_manager=FakeOpenHandsManager(),
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    attack_result = output_payload["ai_enumeration"][0]["risks"][0]["attack_result"]
    assert attack_result["agent_runtime"]["status"] == "running"
    assert attack_result["agent_runtime"]["tracing"] == {
        "enabled": True,
        "service_name": "pwnhunter-attack-openhands",
        "endpoint": "https://cloud.langfuse.com/api/public/otel",
    }


def test_attack_preparation_service_headless_uses_sdk_without_cli(
    tmp_path: Path, monkeypatch
) -> None:
    class FakeOpenHandsManager:
        def run_headless(
            self,
            *,
            workspace_path: Path,
            prompt_path: Path,
            metadata_path: Path,
            timeout: int,
            git_token: str | None,
        ):
            _ = (workspace_path, prompt_path, timeout, git_token)
            return OpenHandsHeadlessResult(
                status="completed",
                pid=None,
                exit_code=0,
                stdout_path=metadata_path.with_name("openhands-headless.stdout.log"),
                stderr_path=metadata_path.with_name("openhands-headless.stderr.log"),
                tracing={
                    "enabled": False,
                    "service_name": "pwnhunter-attack-openhands",
                    "endpoint": None,
                },
            )

    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
        launch_agent=True,
        openhands_headless=True,
        openhands_manager=FakeOpenHandsManager(),
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    attack_result = output_payload["ai_enumeration"][0]["risks"][0]["attack_result"]
    assert attack_result["agent_runtime"]["status"] == "completed"


def test_attack_preparation_service_resolves_unknown_with_default_logs(
    tmp_path: Path,
) -> None:
    class NoSecretsFakeAttackGitHubClient(FakeAttackGitHubClient):
        _workflow_listing = [
            {"type": "file", "path": ".github/workflows/no_secrets.yml"},
        ]
        _workflow_contents = {
            ".github/workflows/no_secrets.yml": "name: ci\non:\n  pull_request_target:\njobs:\n  test:\n    runs-on: ubuntu-latest\n",
        }
        _runs = [
            {
                "id": 123,
                "path": ".github/workflows/no_secrets.yml",
                "head_sha": "deadbeef1234",
                "html_url": "https://github.com/owner/repo/actions/runs/123",
            }
        ]
        _logs = _zip_logs(
            {
                "0_ci/1_Set up job.txt": (
                    "GITHUB_TOKEN Permissions\n"
                    + _full_permissions_block(level="read")
                )
            }
        )

        def get_workflow_runs(
            self, repo_name: str, per_page: int = 100, page: int = 1
        ) -> dict:
            _ = (repo_name, per_page)
            return {"workflow_runs": self._runs if page == 1 else []}

        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            _ = repo_name
            if run_id == 123:
                return self._logs
            return b""

    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: NoSecretsFakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "no_secrets.yml",
                            "github_token_permissions": {"status": "unknown"},
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["github_token_permissions"]["status"] == "non-write"
    assert risk["github_token_permissions"]["reason"] == "permissions_block_found_without_write"
    assert risk["github_token_permissions"]["permissions"]["Contents"] == "read"
    assert risk["attack_result"]["status"] == "skipped_read_only_token_without_secrets"
    assert "Detected permissions:" in risk["attack_result"]["reason"]
    assert risk["attack_result"]["github_token_permissions"]["status"] == "non-write"
    assert risk["attack_result"]["github_token_permissions_classification"] == "non-write"
    assert risk["attack_result"]["github_token_probe"] is None


def test_attack_preparation_service_uses_explicit_top_level_permissions(
    tmp_path: Path,
) -> None:
    class ExplicitTopLevelClient(FakeAttackGitHubClient):
        _workflow_contents = {
            ".github/workflows/pull_request.yml": (
                "permissions:\n"
                "  contents: read\n"
                "  pull-requests: write\n"
                "jobs:\n"
                "  install:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: echo hi\n"
            ),
            ".github/workflows/release.yaml": "jobs: {}\n",
        }

    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: ExplicitTopLevelClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "github_token_permissions": {"status": "unknown"},
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["github_token_permissions"]["status"] == "write"
    assert (
        risk["github_token_permissions"]["reason"]
        == "explicit_top_level_permissions_include_write"
    )
    assert risk["attack_result"]["github_token_permissions"]["status"] == "write"
    assert risk["attack_result"]["github_token_permissions_classification"] == "write"
    assert risk["attack_result"]["github_token_probe"] is None


def test_attack_preparation_service_sets_after_agentic_for_unknown_permissions(
    tmp_path: Path,
) -> None:
    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "github_token_permissions": {"status": "unknown"},
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["attack_result"]["github_token_permissions"]["status"] == "unknown"
    assert risk["attack_result"]["github_token_permissions_classification"] == "unknown"
    assert risk["attack_result"]["github_token_probe_timing"] == "after_agentic"


def test_attack_preparation_service_skips_default_permission_log_read_when_enabled(
    tmp_path: Path,
) -> None:
    class RaiseIfDefaultLogsReadClient(FakeAttackGitHubClient):
        _workflow_listing = [{"type": "file", "path": ".github/workflows/no_perms.yml"}]
        _workflow_contents = {
            ".github/workflows/no_perms.yml": (
                "on:\n"
                "  pull_request_target:\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: python main.py\n"
            ),
            ".github/workflows/release.yaml": "jobs: {}\n",
        }

        def get_workflow_runs(
            self, repo_name: str, per_page: int = 100, page: int = 1
        ) -> dict:
            raise AssertionError("default workflow logs should not be read")

        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            raise AssertionError("default workflow logs should not be read")

    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: RaiseIfDefaultLogsReadClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
        skip_default_permission_log_read=True,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "no_perms.yml",
                            "github_token_permissions": {"status": "unknown"},
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["github_token_permissions"]["status"] == "unknown"
    assert risk["github_token_permissions"]["reason"] == "default_permission_log_read_skipped"
    assert risk["attack_result"]["github_token_permissions_classification"] == "unknown"
    assert risk["attack_result"]["github_token_probe_timing"] == "after_agentic"


def test_attack_preparation_service_uses_explicit_single_job_permissions(
    tmp_path: Path,
) -> None:
    class ExplicitSingleJobPermissionsClient(FakeAttackGitHubClient):
        _workflow_contents = {
            ".github/workflows/pull_request.yml": (
                "on:\n"
                "  pull_request_target:\n"
                "jobs:\n"
                "  install:\n"
                "    permissions:\n"
                "      contents: read\n"
                "      checks: write\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: python main.py\n"
            ),
            ".github/workflows/release.yaml": "jobs: {}\n",
        }

    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: ExplicitSingleJobPermissionsClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "github_token_permissions": {"status": "unknown"},
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["github_token_permissions"]["status"] == "write"
    assert (
        risk["github_token_permissions"]["reason"]
        == "explicit_single_job_permissions_include_write"
    )
    assert risk["attack_result"]["github_token_permissions"]["status"] == "write"
    assert risk["attack_result"]["github_token_permissions_classification"] == "write"


def test_attack_preparation_service_marks_not_clear_for_multi_job_permissions(
    tmp_path: Path,
) -> None:
    class MultiJobPermissionsClient(FakeAttackGitHubClient):
        _workflow_contents = {
            ".github/workflows/pull_request.yml": (
                "jobs:\n"
                "  auth:\n"
                "    permissions:\n"
                "      contents: read\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: echo ok\n"
                "  install:\n"
                "    permissions:\n"
                "      pull-requests: write\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: python main.py\n"
            ),
            ".github/workflows/release.yaml": "jobs: {}\n",
        }

    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: MultiJobPermissionsClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "github_token_permissions": {"status": "unknown"},
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["github_token_permissions"]["status"] == "not-clear"
    assert (
        risk["github_token_permissions"]["reason"]
        == "multi_job_with_job_level_permissions_not_clear"
    )
    assert risk["attack_result"]["github_token_permissions_classification"] == "not-clear"
    assert risk["attack_result"]["github_token_probe_timing"] == "not_needed"


def test_attack_preparation_service_resolves_default_logs_write(
    tmp_path: Path,
) -> None:
    class DefaultLogsWriteClient(FakeAttackGitHubClient):
        _workflow_listing = [{"type": "file", "path": ".github/workflows/no_perms.yml"}]
        _workflow_contents = {
            ".github/workflows/no_perms.yml": (
                "on:\n"
                "  pull_request_target:\n"
                "jobs:\n"
                "  test:\n"
                "    runs-on: ubuntu-latest\n"
                "    steps:\n"
                "      - run: python main.py\n"
            ),
        }
        _runs = [
            {
                "id": 777,
                "path": ".github/workflows/no_perms.yml",
                "head_sha": "deadbeef1234",
                "html_url": "https://github.com/owner/repo/actions/runs/777",
            }
        ]
        _logs = _zip_logs(
            {
                "0_test/1_Set up job.txt": (
                    "GITHUB_TOKEN Permissions\n"
                    + _full_permissions_block(level="write")
                )
            }
        )

        def get_workflow_runs(
            self, repo_name: str, per_page: int = 100, page: int = 1
        ) -> dict:
            _ = (repo_name, per_page)
            return {"workflow_runs": self._runs if page == 1 else []}

        def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
            _ = repo_name
            return self._logs if run_id == 777 else b""

    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: DefaultLogsWriteClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "no_perms.yml",
                            "github_token_permissions": {"status": "unknown"},
                            "pwn_request_result": {"vulnerable": True},
                        }
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risk = output_payload["ai_enumeration"][0]["risks"][0]
    assert risk["github_token_permissions"]["status"] == "write"
    assert risk["github_token_permissions"]["reason"] == "write_permission_found_in_setup_job"
    assert risk["attack_result"]["github_token_permissions_classification"] == "write"
    assert risk["attack_result"]["github_token_probe_timing"] == "not_needed"


def test_attack_preparation_service_omits_non_vulnerable_risks_from_output(
    tmp_path: Path,
) -> None:
    FakeAttackGitHubClient.reset()
    broker = AttackTokenBroker(user_a_tokens=["token-a"], user_b_tokens=["token-b"])
    artifacts_manager = AttackArtifactsManager(
        tmp_path / "artifacts", clone_runner=_fake_clone_runner
    )
    service = AttackPreparationService(
        token_broker=broker,
        github_client_factory=lambda token: FakeAttackGitHubClient(tokens=[token]),
        reset_forks=False,
        artifacts_manager=artifacts_manager,
    )

    output_payload = service.run(
        {
            "ai_enumeration": [
                {
                    "name": "owner/repo",
                    "risks": [
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "vulnerable": False,
                        },
                        {
                            "repository_name": "owner/repo",
                            "initial_workflow": "pull_request.yml",
                            "vulnerable": True,
                        },
                    ],
                }
            ]
        },
        parallel_jobs=1,
    )

    risks = output_payload["ai_enumeration"][0]["risks"]
    repository = output_payload["ai_enumeration"][0]
    assert len(risks) == 1
    assert repository["repo_vulnerable"] == "unknown"
    assert repository["act_repo_vulnerable"] is False
    assert risks[0]["vulnerable"] is True
    assert risks[0]["attack_result"]["status"] == "prepared_for_manual_validation"
