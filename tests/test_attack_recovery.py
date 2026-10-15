from __future__ import annotations

import json
from pathlib import Path

from pwn_hunter_ai.attack_recovery import recover_attack_output


def _build_input_payload(repo_names: list[str]) -> dict:
    return {
        "ai_enumeration": [
            {
                "name": repo_name,
                "risks": [
                    {
                        "issue_type": "PwnRequestResult",
                        "initial_workflow": "ci.yml",
                        "ai-analysis": {"vulnerable": True},
                    }
                ],
            }
            for repo_name in repo_names
        ]
    }


def test_recover_attack_output_merges_partial_output_with_log_inference(tmp_path: Path) -> None:
    input_path = tmp_path / "input.json"
    partial_path = tmp_path / "partial.json"
    log_path = tmp_path / "attack.log"
    output_path = tmp_path / "recovered.json"

    input_payload = _build_input_payload(
        ["owner/repo-a", "owner/repo-b", "owner/repo-c"]
    )
    input_path.write_text(json.dumps(input_payload), encoding="utf-8")

    partial_payload = {
        "ai_enumeration": [
            {
                "name": "owner/repo-a",
                "risks": [
                    {
                        "issue_type": "PwnRequestResult",
                        "initial_workflow": "ci.yml",
                        "ai-analysis": {"vulnerable": True},
                        "attack_result": {
                            "status": "human_review_required",
                            "reason": "already persisted",
                        },
                    }
                ],
            }
        ]
    }
    partial_path.write_text(json.dumps(partial_payload), encoding="utf-8")

    log_path.write_text(
        "\n".join(
            [
                "2026-03-22 00:00:01 INFO pwn_hunter_ai.attack.sandbox_manager: Host exec: git clone ... "
                "(cwd=/tmp/attack-artifacts/20260321T221337Z/owner__repo-b/workspace)",
                "2026-03-22 00:00:02 INFO pwn_hunter_ai.attack.execution_service: Created PR #1 from attacker/repo-b to owner/repo-b",
                "2026-03-22 00:00:03 INFO pwn_hunter_ai.attack.execution_service: [PWNHUNTER] Pull request URL: https://github.com/owner/repo-b/pull/1",
                "2026-03-22 00:00:04 INFO pwn_hunter_ai.attack.execution_service: Workflow run 123 conclusion: failure",
                "2026-03-22 00:00:05 INFO pwn_hunter_ai.attack.execution_service: All workflow runs completed but no secrets exfiltrated. Attempt 1 failed.",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    output_payload = recover_attack_output(
        input_path=input_path,
        output_path=output_path,
        log_path=log_path,
        partial_output_path=partial_path,
        max_retries=10,
    )

    recovered = output_payload["ai_enumeration"]
    assert [repo["name"] for repo in recovered] == ["owner/repo-a", "owner/repo-b"]

    repo_a = recovered[0]
    assert repo_a["risks"][0]["attack_result"]["status"] == "human_review_required"
    assert repo_a["risks"][0]["attack_result"]["reason"] == "already persisted"

    repo_b = recovered[1]
    attack_result = repo_b["risks"][0]["attack_result"]
    assert attack_result["status"] == "not_vulnerable_after_execution"
    assert attack_result["pull_request_url"] == "https://github.com/owner/repo-b/pull/1"
    assert attack_result["user_a_fork"] == "owner/repo-b"
    assert attack_result["user_b_fork"] == "attacker/repo-b"
    assert attack_result["attempt_count"] == 1
    assert attack_result["max_retries"] == 10


def test_recover_attack_output_reads_artifacts_attempt_state(tmp_path: Path) -> None:
    input_path = tmp_path / "input.json"
    output_path = tmp_path / "recovered.json"
    artifacts_dir = tmp_path / "attack-artifacts"
    repo_artifact_dir = artifacts_dir / "20260321T221337Z" / "owner__repo-d"
    repo_artifact_dir.mkdir(parents=True, exist_ok=True)

    input_payload = _build_input_payload(["owner/repo-d"])
    input_path.write_text(json.dumps(input_payload), encoding="utf-8")

    attack_context_payload = {
        "repository_name": "owner/repo-d",
        "vulnerable_commit_hash": "cafebabe",
        "attack_result": {
            "status": "prepared_for_manual_validation",
            "user_a_fork": "owner/repo-d",
            "user_b_fork": "attacker/repo-d",
            "focused_workflow": "ci.yml",
        },
    }
    (repo_artifact_dir / "attack-context.json").write_text(
        json.dumps(attack_context_payload), encoding="utf-8"
    )
    (repo_artifact_dir / "attempt-state.json").write_text(
        json.dumps(
            {
                "status": "needs_human_review",
                "flagged_for_human_review": True,
                "max_retries": 10,
                "attempts": [{"attempt": 1, "status": "failed"}],
            }
        ),
        encoding="utf-8",
    )

    output_payload = recover_attack_output(
        input_path=input_path,
        output_path=output_path,
        artifacts_dir=artifacts_dir,
    )

    recovered_repo = output_payload["ai_enumeration"][0]
    assert recovered_repo["name"] == "owner/repo-d"
    assert recovered_repo["vulnerable_commit_hash"] == "cafebabe"
    attack_result = recovered_repo["risks"][0]["attack_result"]
    assert attack_result["status"] == "human_review_required"
    assert attack_result["flagged_for_human_review"] is True
    assert attack_result["attempt_count"] == 1
    assert attack_result["max_retries"] == 10
    assert attack_result["user_a_fork"] == "owner/repo-d"
    assert attack_result["user_b_fork"] == "attacker/repo-d"

