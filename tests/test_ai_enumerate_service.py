from __future__ import annotations

import logging

from pwn_hunter_ai.ai_enumerate.service import AIEnumerationService
from pwn_hunter_ai.github_client import GitHubApiError
from pwn_hunter_ai.models import AiAnalysis


class FakeGitHubClient:
    def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
        return {
            "name": repo_name,
            "created_at": "2024-01-01T00:00:00Z",
            "default_branch": "main",
        }

    def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
        return f"# {repo_name}@{ref}:{path}\n"


class FakeBatchAnalyzer:
    def analyze_prompt(self, prompt: str, *, metadata=None) -> AiAnalysis:
        raise AssertionError("Synchronous path should not be used in this test.")

    def analyze_prompts_batch(self, requests: list) -> list[AiAnalysis]:
        analyses: list[AiAnalysis] = []
        for request in requests:
            vulnerable = "true-risk" in request.prompt
            analyses.append(
                AiAnalysis(
                    vulnerable=vulnerable,
                    confidence="high",
                    explanation="batch verdict",
                    impact="impact" if vulnerable else "none",
                    poc="poc" if vulnerable else "",
                )
            )
        return analyses


class FakeFailingAnalyzer:
    def analyze_prompt(self, prompt: str, *, metadata=None) -> AiAnalysis:
        if "bad-risk" in prompt:
            raise ValueError("invalid structured output")
        vulnerable = "true-risk" in prompt
        return AiAnalysis(
            vulnerable=vulnerable,
            confidence="high",
            explanation="verdict",
            impact="impact" if vulnerable else "none",
            poc="poc" if vulnerable else "",
        )

    def analyze_prompts_batch(self, requests: list) -> list[AiAnalysis]:
        raise AssertionError("Batch path should not be used in this test.")


class FakeBatchFailureAnalyzer(FakeFailingAnalyzer):
    def analyze_prompts_batch(self, requests: list) -> list[AiAnalysis]:
        raise RuntimeError("batch output row invalid")


class FakeBrokenGitHubClient(FakeGitHubClient):
    def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
        if repo_name == "repo/broken":
            raise RuntimeError("rate limited")
        return super().get_repo_metadata(repo_name)


class FakeMissingGitHubClient(FakeGitHubClient):
    def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
        if repo_name == "repo/missing":
            raise GitHubApiError(
                f"GitHub API request failed for /repos/{repo_name}: 404 Not Found"
            )
        return super().get_repo_metadata(repo_name)


def test_service_batch_mode_preserves_order_and_filtering() -> None:
    service = AIEnumerationService(FakeGitHubClient(), FakeBatchAnalyzer())
    input_payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "repo/one",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 1,
                    "risks": [
                        {
                            "repository_name": "repo/one",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "false-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        },
                        {
                            "repository_name": "repo/one",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "true-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        },
                    ],
                },
                {
                    "name": "repo/two",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 2,
                    "risks": [
                        {
                            "repository_name": "repo/two",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "true-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        }
                    ],
                },
            ]
        }
    }

    output_payload = service.run(
        input_payload,
        parallel_jobs=2,
        gemini_batch=True,
        output_only_vulnerable=True,
    )

    assert [repo["name"] for repo in output_payload["ai_enumeration"]] == [
        "repo/one",
        "repo/two",
    ]
    assert [
        risk["initial_workflow"]
        for risk in output_payload["ai_enumeration"][0]["risks"]
    ] == ["true-risk.yml"]
    assert output_payload["ai_enumeration"][1]["risks"][0]["initial_workflow"] == "true-risk.yml"


def test_service_continues_when_single_risk_analysis_fails() -> None:
    service = AIEnumerationService(FakeGitHubClient(), FakeFailingAnalyzer())
    input_payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "repo/one",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 1,
                    "risks": [
                        {
                            "repository_name": "repo/one",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "bad-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        },
                        {
                            "repository_name": "repo/one",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "true-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        },
                    ],
                }
            ]
        }
    }

    output_payload = service.run(
        input_payload,
        parallel_jobs=2,
        gemini_batch=False,
        output_only_vulnerable=False,
    )

    risks = output_payload["ai_enumeration"][0]["risks"]
    assert risks[0]["ai-analysis"]["vulnerable"] is False
    assert risks[0]["ai-analysis"]["confidence"] == "very low"
    assert risks[0]["ai-analysis-error"] == "ValueError: invalid structured output"
    assert risks[1]["ai-analysis"]["vulnerable"] is True


def test_service_batch_mode_falls_back_to_per_risk_analysis() -> None:
    service = AIEnumerationService(FakeGitHubClient(), FakeBatchFailureAnalyzer())
    input_payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "repo/one",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 1,
                    "risks": [
                        {
                            "repository_name": "repo/one",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "bad-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        },
                        {
                            "repository_name": "repo/one",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "true-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        },
                    ],
                }
            ]
        }
    }

    output_payload = service.run(
        input_payload,
        parallel_jobs=2,
        gemini_batch=True,
        output_only_vulnerable=False,
    )

    risks = output_payload["ai_enumeration"][0]["risks"]
    assert risks[0]["ai-analysis-error"] == "ValueError: invalid structured output"
    assert risks[1]["ai-analysis"]["vulnerable"] is True


def test_service_continues_when_repository_preparation_fails() -> None:
    service = AIEnumerationService(FakeBrokenGitHubClient(), FakeFailingAnalyzer())
    input_payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "repo/broken",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 1,
                    "risks": [],
                },
                {
                    "name": "repo/ok",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 2,
                    "risks": [
                        {
                            "repository_name": "repo/ok",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "true-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        }
                    ],
                },
            ]
        }
    }

    output_payload = service.run(
        input_payload,
        parallel_jobs=2,
        gemini_batch=False,
        output_only_vulnerable=False,
    )

    assert [repo["name"] for repo in output_payload["ai_enumeration"]] == [
        "repo/broken",
        "repo/ok",
    ]
    assert output_payload["ai_enumeration"][0]["error"] == "RuntimeError: rate limited"
    assert output_payload["ai_enumeration"][0]["risks"] == []
    assert output_payload["ai_enumeration"][1]["risks"][0]["ai-analysis"]["vulnerable"] is True


def test_service_skips_missing_repository_and_logs_it(caplog) -> None:
    service = AIEnumerationService(FakeMissingGitHubClient(), FakeFailingAnalyzer())
    input_payload = {
        "enumeration": {
            "repositories": [
                {
                    "name": "repo/missing",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 1,
                    "risks": [],
                },
                {
                    "name": "repo/ok",
                    "enum_time": "Sat Feb 28 12:30:10 2026",
                    "can_fork": True,
                    "stars": 2,
                    "risks": [
                        {
                            "repository_name": "repo/ok",
                            "issue_type": "PwnRequestResult",
                            "triggers": ["pull_request_target"],
                            "initial_workflow": "true-risk.yml",
                            "confidence": "Unknown",
                            "attack_complexity": "No Interaction",
                            "explanation": "x",
                            "path": [],
                            "sink": "Not Detected",
                        }
                    ],
                },
            ]
        }
    }

    with caplog.at_level(logging.WARNING):
        output_payload = service.run(
            input_payload,
            parallel_jobs=2,
            gemini_batch=False,
            output_only_vulnerable=False,
        )

    assert [repo["name"] for repo in output_payload["ai_enumeration"]] == ["repo/ok"]
    assert "Skipping repository repo/missing because it is no longer accessible on GitHub" in caplog.text
