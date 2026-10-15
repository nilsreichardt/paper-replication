from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess


SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "analyze_attack.py"


def _load_script_module():
    spec = importlib.util.spec_from_file_location("analyze_attack", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_load_entries_supports_enumeration_repositories_shape(tmp_path: Path) -> None:
    module = _load_script_module()
    target = tmp_path / "attack_results.json"
    payload = {
        "username": "tester",
        "enumeration": {
            "repositories": [
                {
                    "name": "org/repo",
                    "enum_time": "Tue Mar 10 03:25:17 2026",
                    "repo_vulnerable": "false",
                    "act_repo_vulnerable": False,
                    "risks": [
                        {
                            "attack_processed_time": "Sat Apr 11 23:48:43 2026",
                            "attack_result": {
                                "status": "not_vulnerable_after_execution",
                                "execution_result": {
                                    "vulnerable": False,
                                    "attempt_count": 2,
                                },
                            },
                        }
                    ],
                }
            ]
        },
    }
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    entries, meta = module._load_entries(target)

    assert len(entries) == 1
    assert entries[0]["name"] == "org/repo"
    assert meta["payload_kind"] == "enumeration_repositories"
    assert meta["normalized_from"] == "enumeration.repositories"


def test_analyze_accepts_entries_loaded_from_enumeration_repositories(tmp_path: Path) -> None:
    module = _load_script_module()
    target = tmp_path / "attack_results.json"
    payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "org/vuln",
                    "repo_vulnerable": "true",
                    "act_repo_vulnerable": True,
                    "risks": [
                        {
                            "attack_result": {
                                "status": "vulnerable_confirmed",
                                "execution_result": {
                                    "vulnerable": True,
                                    "attempt": 1,
                                    "hookbin_logs": '{"FLAG":{"value":"flag{demo}","isSecret":true}}',
                                },
                            }
                        }
                    ],
                }
            ]
        }
    }
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    entries, _ = module._load_entries(target)
    analysis = module.analyze(entries)

    assert analysis["total_entries_processed"] == 1
    assert analysis["vulnerable_repositories"]["repos"] == ["org/vuln"]
    assert analysis["github_hosted_vulnerable_repositories"]["repos"] == ["org/vuln"]
    assert analysis["act_vulnerable_repositories"]["repos"] == ["org/vuln"]
    assert analysis["repo_vulnerable_true_act_repo_vulnerable_true"]["count"] == 1
    assert (
        analysis["hookbin_logs_for_repos_with_repo_or_act_true"][
            "hookbin_logs_not_empty_string_and_github_token_write_or_has_secret"
        ]["repos"]
        == ["org/vuln"]
    )
    assert (
        analysis["hookbin_logs_for_repos_with_repo_or_act_true"][
            "hookbin_logs_not_empty_string_and_github_token_write_or_has_secret_or_clear_permissions"
        ]["repos"]
        == ["org/vuln"]
    )


def test_analyze_reports_separate_github_hosted_and_act_vulnerable_totals() -> None:
    module = _load_script_module()

    analysis = module.analyze(
        [
            {
                "name": "org/github-hosted-only",
                "repo_vulnerable": True,
                "act_repo_vulnerable": False,
            },
            {
                "name": "org/act-only",
                "repo_vulnerable": False,
                "act_repo_vulnerable": True,
            },
            {
                "name": "org/both",
                "repo_vulnerable": "true",
                "act_repo_vulnerable": "true",
            },
            {
                "name": "org/github-hosted-with-unknown-act",
                "repo_vulnerable": "true",
                "act_repo_vulnerable": "unknown",
            },
        ]
    )

    assert analysis["vulnerable_repositories"]["count"] == 4
    assert analysis["github_hosted_vulnerable_repositories"]["repos"] == [
        "org/both",
        "org/github-hosted-only",
        "org/github-hosted-with-unknown-act",
    ]
    assert analysis["act_vulnerable_repositories"]["repos"] == [
        "org/act-only",
        "org/both",
    ]
    assert analysis["mismatch_total"] == 2


def test_analyze_counts_clear_exploit_job_permissions_in_new_hookbin_bucket(
    tmp_path: Path,
) -> None:
    module = _load_script_module()
    target = tmp_path / "attack_results.json"
    payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "org/clear-now",
                    "repo_vulnerable": "true",
                    "act_repo_vulnerable": True,
                    "risks": [
                        {
                            "attack_result": {
                                "exploit_job_github_token_permissions": {
                                    "status": "non-write",
                                },
                                "execution_result": {
                                    "hookbin_logs": (
                                        '{"github_token":{"value":"ghs_demo","isSecret":true}}'
                                    ),
                                },
                            }
                        }
                    ],
                }
            ]
        }
    }
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    entries, _ = module._load_entries(target)
    analysis = module.analyze(entries)

    assert (
        analysis["hookbin_logs_for_repos_with_repo_or_act_true"][
            "hookbin_logs_not_empty_string_and_github_token_write_or_has_secret"
        ]["repos"]
        == []
    )
    assert (
        analysis["hookbin_logs_for_repos_with_repo_or_act_true"][
            "hookbin_logs_not_empty_string_and_github_token_write_or_has_secret_or_clear_permissions"
        ]["repos"]
        == ["org/clear-now"]
    )


def test_cli_can_annotate_vulnerable_with_secret_or_write_gh_token(
    tmp_path: Path,
) -> None:
    target = tmp_path / "attack_results.json"
    annotated = tmp_path / "attack_results.annotated.json"
    payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "org/has-secret",
                    "repo_vulnerable": "true",
                    "act_repo_vulnerable": False,
                    "risks": [
                        {
                            "attack_result": {
                                "execution_result": {
                                    "hookbin_logs": (
                                        '{"FLAG":{"value":"flag{demo}","isSecret":true}}'
                                    ),
                                },
                            }
                        }
                    ],
                },
                {
                    "name": "org/clear-permissions",
                    "repo_vulnerable": False,
                    "act_repo_vulnerable": True,
                    "risks": [
                        {
                            "attack_result": {
                                "exploit_job_github_token_permissions": {
                                    "status": "read",
                                },
                                "execution_result": {
                                    "hookbin_logs": (
                                        '{"github_token":{"value":"ghs_demo","isSecret":true}}'
                                    ),
                                },
                            }
                        }
                    ],
                },
                {
                    "name": "org/empty-hookbin",
                    "repo_vulnerable": True,
                    "act_repo_vulnerable": True,
                    "risks": [
                        {
                            "attack_result": {
                                "execution_result": {
                                    "hookbin_logs": "",
                                },
                            }
                        }
                    ],
                },
                {
                    "name": "org/not-vulnerable",
                    "repo_vulnerable": False,
                    "act_repo_vulnerable": False,
                    "risks": [
                        {
                            "attack_result": {
                                "execution_result": {
                                    "hookbin_logs": (
                                        '{"FLAG":{"value":"flag{demo}","isSecret":true}}'
                                    ),
                                },
                            }
                        }
                    ],
                },
            ]
        }
    }
    target.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")

    result = subprocess.run(
        [
            "uv",
            "run",
            "python",
            str(SCRIPT_PATH),
            "--input",
            str(target),
            "--add-vulnerable-with-secret-or-write-gh-token",
            "--annotated-output",
            str(annotated),
        ],
        check=True,
        capture_output=True,
        text=True,
    )

    annotated_payload = json.loads(annotated.read_text(encoding="utf-8"))
    repositories = annotated_payload["enumeration"]["repositories"]
    assert [
        repository["vulnerable_with_secret_or_write_gh_token"]
        for repository in repositories
    ] == [True, True, False, False]
    assert (
        "Repositories with vulnerable_with_secret_or_write_gh_token=true: 2"
        in result.stdout
    )
