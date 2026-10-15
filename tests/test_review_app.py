from __future__ import annotations

import json
from pathlib import Path

from pwn_hunter_ai.review_app import _extract_workflow_refs, _parse_node_inner
from pwn_hunter_ai.review_app import ReviewApp


class FakeGitHubClient:
    def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
        return f"{repo_name}:{ref}:{path}"


def test_parse_node_inner_extracts_yaml_path() -> None:
    parsed = _parse_node_inner("owner/repo:main:.github/workflows/test.yaml#L10")
    assert parsed is not None
    assert parsed.repo_name == "owner/repo"
    assert parsed.ref == "main"
    assert parsed.path == ".github/workflows/test.yaml"


def test_extract_workflow_refs_ignores_non_workflow_nodes() -> None:
    risk = {
        "gato-x-path": [
            {"node": "WorkflowNode('owner/repo:main:.github/workflows/ci.yml')"},
            {"node": "JobNode('owner/repo:main:README.md#L1')"},
            {"node": "StepNode('owner/repo:main:.github/workflows/ci.yml:job#L8')"},
        ]
    }
    refs = _extract_workflow_refs(risk)
    assert [(ref.repo_name, ref.ref, ref.path) for ref in refs] == [
        ("owner/repo", "main", ".github/workflows/ci.yml")
    ]


def test_build_attack_command_creates_single_repository_input(tmp_path: Path) -> None:
    payload = {
        "generated_at": "2026-03-16T00:00:00Z",
        "ai_enumeration": [
            {"name": "owner/one", "risks": [{"id": 1}]},
            {"name": "owner/two", "risks": [{"id": 2}]},
        ],
    }
    input_path = tmp_path / "results_part1.json"
    app = ReviewApp(payload, input_path=input_path, github_client=FakeGitHubClient())

    command_payload = app.build_attack_command("owner/two")

    attack_input_path = Path(command_payload["attack_input_path"])
    attack_output_path = Path(command_payload["attack_output_path"])
    assert attack_input_path.parent == tmp_path / "results_part1"
    assert attack_input_path.name == "owner_two.json"
    assert attack_output_path.name == "attack_results_owner_two.json"

    prepared_payload = json.loads(attack_input_path.read_text(encoding="utf-8"))
    assert [repository["name"] for repository in prepared_payload["ai_enumeration"]] == [
        "owner/two"
    ]
    assert "--auto-execute" in command_payload["command"]


def test_build_attack_command_raises_for_missing_repository(tmp_path: Path) -> None:
    payload = {"ai_enumeration": [{"name": "owner/one", "risks": []}]}
    app = ReviewApp(
        payload,
        input_path=tmp_path / "results.json",
        github_client=FakeGitHubClient(),
    )

    try:
        app.build_attack_command("owner/unknown")
    except KeyError as exc:
        assert str(exc) == "'owner/unknown'"
    else:
        raise AssertionError("Expected build_attack_command to raise KeyError")


def test_list_repositories_uses_attack_result_verdicts(tmp_path: Path) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo",
                "risks": [
                    {
                        "issue_type": "one",
                        "ai-analysis": {"vulnerable": False},
                        "attack_result": {"status": "vulnerable_confirmed"},
                    },
                    {
                        "issue_type": "two",
                        "attack_result": {"status": "human_review_required"},
                    },
                    {
                        "issue_type": "three",
                        "attack_result": {"status": "not_vulnerable_after_execution"},
                    },
                    {
                        "issue_type": "four",
                        "attack_result": {
                            "status": "execution_error",
                            "error_class": "runtime_execution_error",
                        },
                    },
                ],
            }
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repositories = app.list_repositories()

    assert len(repositories) == 1
    repo = repositories[0]
    assert repo["vulnerable_count"] == 1
    assert repo["needs_review_count"] == 1
    assert repo["not_vulnerable_count"] == 1
    assert repo["error_count"] == 1
    assert repo["has_vulnerable_risk"] is False


def test_list_repositories_marks_vulnerable_from_repo_or_act_flags(
    tmp_path: Path,
) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/flagged",
                "repo_vulnerable": "unknown",
                "act_repo_vulnerable": True,
                "risks": [
                    {
                        "attack_result": {"status": "not_vulnerable_after_execution"},
                    }
                ],
            }
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repositories = app.list_repositories()

    assert repositories[0]["vulnerable_count"] == 0
    assert repositories[0]["has_vulnerable_risk"] is True


def test_list_repositories_exposes_secret_or_write_token_vulnerability_flag(
    tmp_path: Path,
) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/secret-token",
                "repo_vulnerable": "true",
                "act_repo_vulnerable": False,
                "vulnerable_with_secret_or_write_gh_token": True,
                "risks": [],
            },
            {
                "name": "owner/repo-only",
                "repo_vulnerable": "true",
                "act_repo_vulnerable": False,
                "vulnerable_with_secret_or_write_gh_token": False,
                "risks": [],
            },
        ]
    }
    app = ReviewApp(
        payload,
        input_path=tmp_path / "results.json",
        github_client=FakeGitHubClient(),
    )

    repositories = app.list_repositories()

    assert repositories[0]["vulnerable_with_secret_or_write_gh_token"] is True
    assert repositories[0]["has_vulnerable_risk"] is True
    assert repositories[1]["vulnerable_with_secret_or_write_gh_token"] is False
    assert repositories[1]["has_vulnerable_risk"] is True


def test_get_repository_includes_attack_summary_and_repository_error(tmp_path: Path) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo",
                "error": "Repository failed during preparation",
                "risks": [
                    {
                        "issue_type": "one",
                        "attack_processed_time": "Sun Mar 29 08:00:00 2026",
                        "attack_result": {
                            "status": "execution_error",
                            "reason": "Runner init failed",
                            "error_class": "runtime_execution_error",
                            "failure_fingerprint": "execution_runtime_error",
                            "execution_result": {"vulnerable": False, "run_id": 123},
                        },
                    }
                ],
            }
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repository = app.get_repository(0)

    assert repository["error"] == "Repository failed during preparation"
    assert repository["verdict_counts"]["error"] == 1
    assert repository["risks"][0]["attack_processed_time"] == "Sun Mar 29 08:00:00 2026"
    attack_summary = repository["risks"][0]["attack_summary"]
    assert attack_summary is not None
    assert attack_summary["status"] == "execution_error"
    assert attack_summary["error_class"] == "runtime_execution_error"
    assert attack_summary["execution_run_id"] == 123


def test_get_repository_includes_vulnerable_commit_hash(tmp_path: Path) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo",
                "vulnerable_commit_hash": "abcdef123456",
                "risks": [],
            }
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repository = app.get_repository(0)

    assert repository["vulnerable_commit_hash"] == "abcdef123456"


def test_security_report_verification_sources_mark_vulnerable(tmp_path: Path) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo",
                "risks": [
                    {
                        "issue_type": "act-only-confirmed",
                        "attack_result": {
                            "status": "not_vulnerable_after_execution",
                            "security_report_verification_sources": ["act"],
                            "execution_result": {"vulnerable": False},
                        },
                    },
                    {
                        "issue_type": "not-confirmed",
                        "attack_result": {
                            "status": "not_vulnerable_after_execution",
                            "security_report_verification_sources": [],
                            "execution_result": {"vulnerable": False},
                        },
                    },
                ],
            }
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repositories = app.list_repositories()

    assert repositories[0]["vulnerable_count"] == 1
    assert repositories[0]["not_vulnerable_count"] == 1


def test_attack_summary_includes_verification_sources_and_hookbin_logs(
    tmp_path: Path,
) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo",
                "risks": [
                    {
                        "attack_result": {
                            "status": "vulnerable_confirmed",
                            "security_report_verification_sources": ["hosted", "act"],
                            "execution_result": {
                                "vulnerable": True,
                                "hookbin_url": "http://127.0.0.1:8787/123",
                                "hookbin_logs": "token=redacted",
                            },
                        }
                    }
                ],
            }
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repository = app.get_repository(0)
    attack_summary = repository["risks"][0]["attack_summary"]
    assert attack_summary is not None
    assert attack_summary["security_report_verification_sources"] == ["hosted", "act"]
    assert attack_summary["security_report_verification_label"] == "Hosted + Act"
    assert attack_summary["hookbin_url"] == "http://127.0.0.1:8787/123"
    assert attack_summary["hookbin_logs"] == "token=redacted"


def test_attack_summary_extracts_exploit_job_from_attempt_agent_output(
    tmp_path: Path,
) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo",
                "risks": [
                    {
                        "attack_result": {
                            "status": "not_vulnerable_after_execution",
                            "execution_result": {
                                "vulnerable": False,
                                "attempts": [
                                    {
                                        "attempt": 1,
                                        "agent_output": {
                                            "exploit_job": "post-update",
                                        },
                                    }
                                ],
                            },
                        }
                    }
                ],
            }
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repository = app.get_repository(0)
    attack_summary = repository["risks"][0]["attack_summary"]
    assert attack_summary is not None
    assert attack_summary["exploit_job"] == "post-update"


def test_attack_summary_extracts_exploit_patch_from_execution_result(
    tmp_path: Path,
) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo",
                "risks": [
                    {
                        "attack_result": {
                            "status": "vulnerable_confirmed",
                            "execution_result": {
                                "vulnerable": True,
                                "exploit_patch": {
                                    "patch": "From abc\n+line",
                                },
                            },
                        }
                    }
                ],
            }
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repository = app.get_repository(0)
    attack_summary = repository["risks"][0]["attack_summary"]
    assert attack_summary is not None
    assert attack_summary["exploit_patch"] == "From abc\n+line"


def test_list_repositories_includes_review_focus_flags(tmp_path: Path) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/mismatch",
                "repo_vulnerable": True,
                "act_repo_vulnerable": False,
                "risks": [],
            },
            {
                "name": "owner/hookbin-empty",
                "repo_vulnerable": True,
                "act_repo_vulnerable": True,
                "risks": [
                    {
                        "attack_result": {
                            "execution_result": {
                                "hookbin_logs": "",
                            }
                        }
                    }
                ],
            },
            {
                "name": "owner/hookbin-missing",
                "repo_vulnerable": True,
                "act_repo_vulnerable": True,
                "risks": [{"attack_result": {"execution_result": {}}}],
            },
            {
                "name": "owner/hookbin-not-empty",
                "repo_vulnerable": True,
                "act_repo_vulnerable": True,
                "risks": [
                    {
                        "attack_result": {
                            "execution_result": {
                                "hookbin_logs": "token=abc",
                            }
                        }
                    }
                ],
            },
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repositories = app.list_repositories()

    mismatch_focus = repositories[0]["review_focus"]
    assert mismatch_focus["mismatch"] is True
    assert mismatch_focus["needs_human_review"] is True

    hookbin_empty_focus = repositories[1]["review_focus"]
    assert hookbin_empty_focus["hookbin_empty_string"] is True
    assert hookbin_empty_focus["hookbin_missing_field"] is False
    assert hookbin_empty_focus["hookbin_not_empty_string"] is False
    assert hookbin_empty_focus["needs_human_review"] is True

    hookbin_missing_focus = repositories[2]["review_focus"]
    assert hookbin_missing_focus["hookbin_missing_field"] is True
    assert hookbin_missing_focus["hookbin_empty_string"] is False
    assert hookbin_missing_focus["hookbin_not_empty_string"] is False
    assert hookbin_missing_focus["needs_human_review"] is True

    hookbin_not_empty_focus = repositories[3]["review_focus"]
    assert hookbin_not_empty_focus["hookbin_not_empty_string"] is True
    assert hookbin_not_empty_focus["hookbin_empty_string"] is False
    assert hookbin_not_empty_focus["hookbin_missing_field"] is False


def test_list_repositories_marks_has_security_source(tmp_path: Path) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/with-source",
                "risks": [
                    {
                        "attack_result": {
                            "security_report_verification_sources": ["act"],
                        }
                    }
                ],
            },
            {
                "name": "owner/without-source",
                "risks": [
                    {
                        "attack_result": {
                            "security_report_verification_sources": [],
                        }
                    }
                ],
            },
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repositories = app.list_repositories()

    assert repositories[0]["review_focus"]["has_security_source"] is True
    assert repositories[1]["review_focus"]["has_security_source"] is False


def test_human_review_status_has_priority_over_execution_vulnerable_false(
    tmp_path: Path,
) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo",
                "risks": [
                    {
                        "attack_result": {
                            "status": "human_review_required",
                            "execution_result": {"vulnerable": False},
                        }
                    }
                ],
            }
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repositories = app.list_repositories()

    assert repositories[0]["needs_review_count"] == 1
    assert repositories[0]["not_vulnerable_count"] == 0


def test_list_repositories_includes_review_reason_preview(tmp_path: Path) -> None:
    payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo",
                "risks": [
                    {
                        "attack_result": {
                            "status": "human_review_required",
                            "reason": "Trust gate present before execution.",
                        }
                    },
                    {
                        "attack_result": {
                            "status": "human_review_required",
                            "reason": "Trust gate present before execution.",
                        }
                    },
                    {
                        "attack_result": {
                            "status": "human_review_required",
                            "reason": "Label approval required by workflow.",
                        }
                    },
                ],
            }
        ]
    }
    app = ReviewApp(payload, input_path=tmp_path / "results.json", github_client=FakeGitHubClient())

    repositories = app.list_repositories()

    assert repositories[0]["needs_review_count"] == 3
    assert repositories[0]["review_reasons"] == [
        "Trust gate present before execution.",
        "Label approval required by workflow.",
    ]
