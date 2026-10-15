from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace

import pytest

from pwn_hunter_ai.gemini_client import (
    AI_ANALYSIS_JSON_SCHEMA,
    GEMINI_DEFAULT_MODEL,
    GEMINI_MAX_OUTPUT_TOKENS,
    GEMINI_RETRY_THINKING_BUDGET,
    GEMINI_THINKING_LEVEL_DEFAULT,
    GEMINI_THINKING_LEVEL_RETRY,
    GEMINI_THINKING_BUDGET_AUTOMATIC,
    GeminiAnalyzer,
    GeminiBatchError,
    _build_batch_generate_content_request,
    _build_thinking_config,
    _extract_cacheable_prompt_prefix,
    _write_batch_request_file,
)
from pwn_hunter_ai.models import AnalysisPromptRequest


def test_generate_response_returns_provider_response() -> None:
    response = SimpleNamespace(
        text='{"vulnerable": false, "confidence": "high"}',
        parsed=None,
        model_version="gemini-2.5-flash",
        usage_metadata=SimpleNamespace(
            prompt_token_count=120,
            candidates_token_count=40,
            total_token_count=160,
        ),
        candidates=[SimpleNamespace(finish_reason="STOP")],
    )

    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)
    analyzer._model = GEMINI_DEFAULT_MODEL
    analyzer._client = SimpleNamespace(
        models=SimpleNamespace(generate_content=lambda **kwargs: response)
    )
    analyzer._types = SimpleNamespace(
        GenerateContentConfig=lambda **kwargs: kwargs,
        ThinkingConfig=lambda **kwargs: kwargs,
        Tool=lambda **kwargs: kwargs,
        GoogleSearch=lambda: "google_search",
        UrlContext=lambda: "url_context",
        AutomaticFunctionCallingConfig=lambda **kwargs: kwargs,
    )

    returned = analyzer._generate_response("prompt", attempt=1)

    assert returned is response


def test_build_generate_response_config_enables_gemini_thinking() -> None:
    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)
    analyzer._model = GEMINI_DEFAULT_MODEL
    analyzer._types = SimpleNamespace(
        GenerateContentConfig=lambda **kwargs: kwargs,
        ThinkingConfig=lambda **kwargs: kwargs,
        Tool=lambda **kwargs: kwargs,
        GoogleSearch=lambda: "google_search",
        UrlContext=lambda: "url_context",
        AutomaticFunctionCallingConfig=lambda **kwargs: kwargs,
    )

    config = analyzer._build_generate_response_config()

    assert config["thinking_config"]["thinking_level"] == GEMINI_THINKING_LEVEL_DEFAULT
    assert config["max_output_tokens"] == GEMINI_MAX_OUTPUT_TOKENS


def test_analyze_human_review_precheck_returns_structured_response() -> None:
    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)
    analyzer._generate_structured_response = lambda *args, **kwargs: SimpleNamespace(
        parsed={
            "needs_human_review": True,
            "reason": "Trust gate detected.",
        },
        text='{"needs_human_review":true,"reason":"Trust gate detected."}',
        candidates=[],
    )

    result = analyzer.analyze_human_review_precheck(
        {
            "vulnerable": True,
            "confidence": "high",
            "explanation": "The workflow uses safe-to-test label as trust gate.",
            "impact": "RCE",
            "poc": "x",
        }
    )

    assert result["needs_human_review"] is True
    assert "Trust gate" in result["reason"]


def test_build_generate_response_config_disables_thinking_on_retry() -> None:
    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)
    analyzer._model = GEMINI_DEFAULT_MODEL
    analyzer._types = SimpleNamespace(
        GenerateContentConfig=lambda **kwargs: kwargs,
        ThinkingConfig=lambda **kwargs: kwargs,
        Tool=lambda **kwargs: kwargs,
        GoogleSearch=lambda: "google_search",
        UrlContext=lambda: "url_context",
        AutomaticFunctionCallingConfig=lambda **kwargs: kwargs,
    )

    config = analyzer._build_generate_response_config(attempt=2)

    assert config["thinking_config"]["thinking_level"] == GEMINI_THINKING_LEVEL_RETRY


def test_build_generate_response_config_uses_budget_for_older_models() -> None:
    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)
    analyzer._model = "gemini-2.5-flash"
    analyzer._types = SimpleNamespace(
        GenerateContentConfig=lambda **kwargs: kwargs,
        ThinkingConfig=lambda **kwargs: kwargs,
        Tool=lambda **kwargs: kwargs,
        GoogleSearch=lambda: "google_search",
        UrlContext=lambda: "url_context",
        AutomaticFunctionCallingConfig=lambda **kwargs: kwargs,
    )

    config = analyzer._build_generate_response_config()
    retry_config = analyzer._build_generate_response_config(attempt=2)

    assert config["thinking_config"]["thinking_budget"] == GEMINI_THINKING_BUDGET_AUTOMATIC
    assert retry_config["thinking_config"]["thinking_budget"] == GEMINI_RETRY_THINKING_BUDGET


def test_analyze_prompt_logs_repository_context_on_retry(caplog) -> None:
    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)
    responses = iter(["first-response", "second-response"])

    analyzer._generate_response = lambda prompt, *, attempt: next(responses)

    def parse_response(response):
        if response == "first-response":
            raise ValueError("invalid structured output")
        return SimpleNamespace(
            vulnerable=False,
            confidence="high",
            explanation="ok",
            impact="none",
            poc="",
        )

    analyzer._parse_response = parse_response

    with caplog.at_level(logging.WARNING):
        analyzer.analyze_prompt(
            "prompt",
            metadata={
                "repository_name": "owner/repo",
                "initial_workflow": "ci.yml",
            },
        )

    assert (
        "Gemini returned invalid structured output for owner/repo / ci.yml"
        in caplog.text
    )


def test_write_batch_request_file_contains_keys_and_json_schema(tmp_path: Path) -> None:
    request_path = tmp_path / "requests.jsonl"

    request_keys = _write_batch_request_file(
        request_path,
        [
            AnalysisPromptRequest(
                prompt="prompt one",
                metadata={
                    "repository_name": "owner/repo",
                    "initial_workflow": "ci.yml",
                },
            ),
            AnalysisPromptRequest(prompt="prompt two", metadata=None),
        ],
    )

    assert request_keys == ["00000-owner__repo-ci.yml", "00001"]
    lines = request_path.read_text(encoding="utf-8").splitlines()
    first = json.loads(lines[0])
    second = json.loads(lines[1])
    assert first["key"] == "00000-owner__repo-ci.yml"
    assert first["request"]["generation_config"]["response_json_schema"] == AI_ANALYSIS_JSON_SCHEMA
    assert first["request"]["generation_config"]["thinking_config"]["thinking_level"] == "HIGH"
    assert first["request"]["contents"][0]["parts"][0]["text"] == "prompt one"
    assert second["key"] == "00001"


def test_write_batch_request_file_passes_cached_content(tmp_path: Path) -> None:
    request_path = tmp_path / "requests.jsonl"

    _write_batch_request_file(
        request_path,
        [AnalysisPromptRequest(prompt="prompt one", metadata=None)],
        cached_content_resolver=lambda _: "cachedContents/x",
    )

    line = json.loads(request_path.read_text(encoding="utf-8").splitlines()[0])
    assert line["request"]["cached_content"] == "cachedContents/x"


def test_build_batch_generate_content_request_uses_uppercase_thinking_level() -> None:
    request = _build_batch_generate_content_request("prompt")

    assert request["generation_config"]["thinking_config"]["thinking_level"] == "HIGH"
    assert request["generation_config"]["max_output_tokens"] == GEMINI_MAX_OUTPUT_TOKENS
    assert request["tools"] == [{"google_search": {}}]


def test_build_batch_generate_content_request_includes_cached_content() -> None:
    request = _build_batch_generate_content_request("prompt", cached_content="cachedContents/x")

    assert request["cached_content"] == "cachedContents/x"
    assert "tools" not in request


def test_build_batch_generate_content_request_uses_budget_for_older_models() -> None:
    request = _build_batch_generate_content_request("prompt", model="gemini-2.5-flash")

    assert (
        request["generation_config"]["thinking_config"]["thinking_budget"]
        == GEMINI_THINKING_BUDGET_AUTOMATIC
    )


def test_build_thinking_config_uses_plain_levels_for_gemini_3() -> None:
    config = _build_thinking_config("gemini-3.1-pro-preview", attempt=1)

    assert config == {"thinking_level": GEMINI_THINKING_LEVEL_DEFAULT}
    assert config["thinking_level"].startswith("thinking_level_") is False


def test_build_generate_response_config_includes_cached_content() -> None:
    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)
    analyzer._model = GEMINI_DEFAULT_MODEL
    analyzer._types = SimpleNamespace(
        GenerateContentConfig=lambda **kwargs: kwargs,
        ThinkingConfig=lambda **kwargs: kwargs,
        Tool=lambda **kwargs: kwargs,
        GoogleSearch=lambda: "google_search",
        UrlContext=lambda: "url_context",
        AutomaticFunctionCallingConfig=lambda **kwargs: kwargs,
    )
    analyzer._resolve_cached_content_name = lambda prompt: "cachedContents/x"

    config = analyzer._build_generate_response_config(prompt="prompt", attempt=1)

    assert config["cached_content"] == "cachedContents/x"
    assert "tools" not in config


def test_extract_cacheable_prompt_prefix_returns_stable_prefix() -> None:
    prompt = (
        "header instructions\n\nRisk context:\n{\n  \"risk\":1\n}\n\n`file`:\n```yaml\nx\n```"
    )

    prefix = _extract_cacheable_prompt_prefix(prompt)

    assert prefix == "header instructions"


def test_analyze_prompts_batch_retries_once_after_expired_job() -> None:
    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)
    analyzer._model = GEMINI_DEFAULT_MODEL

    submitted_jobs: list[str] = []

    def submit_batch_job(request_path: Path):
        job_name = f"batches/job-{len(submitted_jobs) + 1}"
        submitted_jobs.append(job_name)
        return SimpleNamespace(name=job_name)

    completed_jobs = [
        SimpleNamespace(name="batches/job-1", state=SimpleNamespace(name="JOB_STATE_EXPIRED"), error=None),
        SimpleNamespace(name="batches/job-2", state=SimpleNamespace(name="JOB_STATE_SUCCEEDED"), error=None),
    ]

    analyzer._submit_batch_job = submit_batch_job
    analyzer._wait_for_batch_job = lambda batch_name: completed_jobs.pop(0)
    analyzer._download_batch_analyses = lambda batch_job, request_keys: [
        SimpleNamespace(model_dump=lambda: {})
    ]

    analyses = analyzer.analyze_prompts_batch([AnalysisPromptRequest(prompt="prompt")])

    assert len(analyses) == 1
    assert submitted_jobs == ["batches/job-1", "batches/job-2"]


def test_analyze_prompts_batch_fails_after_second_expired_job() -> None:
    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)
    analyzer._model = GEMINI_DEFAULT_MODEL
    analyzer._submit_batch_job = lambda request_path: SimpleNamespace(name="batches/job")
    completed_job = SimpleNamespace(
        name="batches/job",
        state=SimpleNamespace(name="JOB_STATE_EXPIRED"),
        error=None,
    )
    analyzer._wait_for_batch_job = lambda batch_name: completed_job

    with pytest.raises(GeminiBatchError, match="JOB_STATE_EXPIRED"):
        analyzer.analyze_prompts_batch([AnalysisPromptRequest(prompt="prompt")])


def test_parse_batch_output_maps_results_and_raises_on_item_error() -> None:
    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)
    analyzer._types = SimpleNamespace(
        GenerateContentResponse=SimpleNamespace(
            _from_response=lambda response, kwargs: SimpleNamespace(
                parsed=None,
                text=response["candidates"][0]["content"]["parts"][0]["text"],
            )
        )
    )

    payload = (
        b'{"key":"00000","response":{"candidates":[{"content":{"parts":[{"text":"{\\"vulnerable\\": true, \\"confidence\\": \\"high\\", \\"explanation\\": \\"ok\\", \\"impact\\": \\"impact\\", \\"poc\\": \\"poc\\"}"}]}}]}}\n'
    )
    analyses = analyzer._parse_batch_output(payload, request_keys=["00000"])
    assert analyses[0].vulnerable is True

    error_payload = b'{"key":"00000","error":{"message":"bad row"}}\n'
    with pytest.raises(GeminiBatchError, match="bad row"):
        analyzer._parse_batch_output(error_payload, request_keys=["00000"])


def test_parse_response_prefers_valid_parsed_payload_over_broken_text() -> None:
    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)

    response = SimpleNamespace(
        parsed={
            "vulnerable": True,
            "confidence": "high",
            "explanation": "ok",
            "impact": "impact",
            "poc": "poc",
        },
        text='{"vulnerable": true,',
        candidates=[SimpleNamespace(finish_reason="MAX_TOKENS")],
    )

    analysis = analyzer._parse_response(response)

    assert analysis.vulnerable is True
    assert analysis.confidence == "high"


def test_parse_response_accepts_dict_text_payload() -> None:
    analyzer = GeminiAnalyzer.__new__(GeminiAnalyzer)

    response = SimpleNamespace(
        parsed=None,
        text={
            "vulnerable": False,
            "confidence": "medium",
            "explanation": "ok",
            "impact": "impact",
            "poc": "",
        },
        candidates=[SimpleNamespace(finish_reason="STOP")],
    )

    analysis = analyzer._parse_response(response)

    assert analysis.vulnerable is False
    assert analysis.confidence == "medium"
