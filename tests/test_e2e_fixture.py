from __future__ import annotations

import json
from pathlib import Path
import re

import pytest

from pwn_hunter_ai.models import AiAnalysis
from pwn_hunter_ai.cli import main


class FixtureGitHubClient:
    def __init__(self, tokens: list[str] | None = None) -> None:
        self.tokens = tokens or []

    def get_repo_metadata(self, repo_name: str) -> dict[str, str]:
        return {
            "name": repo_name,
            "created_at": "2022-01-01T00:00:00Z",
            "default_branch": "main",
        }

    def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
        return f"name: fixture\n# {repo_name}@{ref}:{path}\n"

    def list_directory(self, repo_name: str, path: str, ref: str) -> list[dict[str, str]]:
        return []


class FakeTracer:
    def flush(self) -> None:
        return None


@pytest.fixture
def input_payload() -> dict:
    fixture_path = Path("test_e2e/input.json")
    return json.loads(fixture_path.read_text(encoding="utf-8"))


def test_fixture_expected_results_match_fake_analyzer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    input_payload: dict,
) -> None:
    risk_expectations: dict[tuple[str, str, int], bool] = {}
    for repository in input_payload["enumeration"]["repositories"]:
        for risk_index, risk in enumerate(repository["risks"]):
            key = (repository["name"], risk["initial_workflow"], risk_index)
            risk_expectations[key] = bool(risk["vulnerable"])

    class FakeAnalyzer:
        def __init__(self, api_key: str, **kwargs) -> None:
            self.api_key = api_key

        def analyze_prompt(self, prompt: str, *, metadata=None) -> AiAnalysis:
            match = re.search(
                r"Risk context:\n(\{.*?\})(?=\n\n`|\Z)",
                prompt,
                re.DOTALL,
            )
            assert match, "Risk context JSON block missing from prompt."
            risk_context = json.loads(match.group(1))
            repository_name = risk_context["repository_name"]
            workflow_name = risk_context["risk"]["initial_workflow"]
            risk_path = risk_context["risk"]["path"]

            key = None
            for repo in input_payload["enumeration"]["repositories"]:
                if repo["name"] != repository_name:
                    continue
                for risk_index, risk in enumerate(repo["risks"]):
                    if (
                        risk["initial_workflow"] == workflow_name
                        and risk["path"] == risk_path
                    ):
                        key = (repository_name, workflow_name, risk_index)
                        break
                if key is not None:
                    break

            assert key is not None, "Unable to match risk context back to fixture data."
            vulnerable = risk_expectations[key]
            return AiAnalysis(
                vulnerable=vulnerable,
                confidence="high",
                explanation="fixture verdict",
                impact="impact" if vulnerable else "none",
                poc="poc" if vulnerable else "",
            )

    output_path = tmp_path / "output.json"
    monkeypatch.setattr("pwn_hunter_ai.cli.GitHubClient", FixtureGitHubClient)
    monkeypatch.setattr("pwn_hunter_ai.cli.GeminiAnalyzer", FakeAnalyzer)
    monkeypatch.setattr("pwn_hunter_ai.cli.build_tracer", lambda **kwargs: FakeTracer())

    exit_code = main(
        [
            "ai-enumerate",
            "--input",
            "test_e2e/input.json",
            "--output",
            str(output_path),
            "--parallel-jobs",
            "2",
            "--github-token",
            "token-a,token-b",
            "--gemini-api-key",
            "test-key",
            "--log-file",
            str(tmp_path / "test.log"),
        ]
    )

    assert exit_code == 0
    output_payload = json.loads(output_path.read_text(encoding="utf-8"))

    actual = [
        risk["ai-analysis"]["vulnerable"]
        for repository in output_payload["ai_enumeration"]
        for risk in repository["risks"]
    ]
    expected = [
        risk["vulnerable"]
        for repository in input_payload["enumeration"]["repositories"]
        for risk in repository["risks"]
    ]
    assert actual == expected
