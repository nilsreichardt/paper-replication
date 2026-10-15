from __future__ import annotations

import json
import logging
from pathlib import Path
from threading import Lock
import tempfile
import time
from typing import Any, Callable, Sequence
import hashlib

from pydantic import ValidationError

from pwn_hunter_ai.models import AiAnalysis, AnalysisPromptRequest


LOGGER = logging.getLogger(__name__)

AI_ANALYSIS_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "vulnerable": {"type": "boolean"},
        "confidence": {
            "type": "string",
            "enum": ["very low", "low", "medium", "high", "very high"],
        },
        "explanation": {"type": "string", "maxLength": 600},
        "impact": {"type": "string", "maxLength": 300},
        "poc": {"type": "string", "maxLength": 1200},
    },
    "required": ["vulnerable", "confidence", "explanation", "impact", "poc"],
}
HUMAN_REVIEW_CHECK_JSON_SCHEMA = {
    "type": "object",
    "properties": {
        "needs_human_review": {"type": "boolean"},
        "reason": {"type": "string", "maxLength": 160},
    },
    "required": ["needs_human_review", "reason"],
}

BATCH_POLL_INTERVAL_SECONDS = 30
JOB_STATE_SUCCEEDED = "JOB_STATE_SUCCEEDED"
JOB_STATE_EXPIRED = "JOB_STATE_EXPIRED"
JOB_STATE_FAILED = "JOB_STATE_FAILED"
JOB_STATE_CANCELLED = "JOB_STATE_CANCELLED"
GEMINI_THINKING_BUDGET_AUTOMATIC = -1 # Shouldn't be used for Gemini 3 Pro models. Instead use thinking levels.
GEMINI_RETRY_THINKING_BUDGET = 128
GEMINI_THINKING_LEVEL_DEFAULT = "HIGH"
GEMINI_THINKING_LEVEL_RETRY = "MEDIUM"
# GEMINI_DEFAULT_MODEL = "gemini-3.1-pro-preview"
GEMINI_DEFAULT_MODEL = "gemini-3-flash-preview"
GEMINI_MAX_OUTPUT_TOKENS = 65_536
PROMPT_CACHE_SPLIT_MARKER = "\n\nRisk context:\n"
PROMPT_CACHE_TTL_SECONDS = 3600 # 1 hour
ATTACK_PROMPTS_DIR = Path(__file__).parent / "attack" / "prompts"
HUMAN_REVIEW_PRECHECK_PROMPT_PATH = ATTACK_PROMPTS_DIR / "human_review_precheck.md"


class GeminiBatchError(RuntimeError):
    pass


class GeminiAnalyzer:
    def __init__(
        self,
        api_key: str,
        *,
        # model: str = "gemini-3-flash-preview",
        model: str = GEMINI_DEFAULT_MODEL,
    ) -> None:
        try:
            from google import genai
            from google.genai import types
        except ImportError as exc:
            raise RuntimeError(
                "google-genai is not installed. Install project dependencies first."
            ) from exc

        self._client = genai.Client(api_key=api_key)
        self._types = types
        self._model = model
        self._prompt_cache_by_hash: dict[str, str] = {}
        self._prompt_cache_lock = Lock()
        self._prompt_cache_disabled = False

    def analyze_prompt(
        self,
        prompt: str,
        *,
        metadata: dict[str, Any] | None = None,
    ) -> AiAnalysis:
        response = self._generate_response(prompt, attempt=1)
        try:
            return self._parse_response(response)
        except (ValidationError, ValueError) as exc:
            context = _format_request_context(metadata)
            LOGGER.warning(
                "Gemini returned invalid structured output%s, retrying once with shorter JSON instructions: %s",
                context,
                exc,
            )
            retry_prompt = (
                prompt
                + "\n\nImportant: Return strict JSON only."
                "Do not use markdown code fences. Keep the poc field to short actionable steps. "
                "You may use tools if needed, but this response must end with a complete JSON object."
            )
            retry_response = self._generate_response(
                retry_prompt,
                attempt=2,
            )
            return self._parse_response(retry_response)

    def analyze_prompts_batch(
        self,
        requests: Sequence[AnalysisPromptRequest],
    ) -> list[AiAnalysis]:
        request_count = len(requests)
        if request_count == 0:
            return []
        analyses, _, _ = self._run_batch_analysis(requests)
        return analyses

    def analyze_human_review_precheck(
        self,
        ai_analysis: dict[str, Any],
        *,
        metadata: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        context = _format_request_context(metadata)
        prompt = _build_human_review_precheck_prompt(
            ai_analysis=ai_analysis,
            request_context=context,
        )
        response = self._generate_structured_response(
            prompt,
            response_schema=HUMAN_REVIEW_CHECK_JSON_SCHEMA,
            attempt=1,
            use_tools=False,
        )
        parsed = _coerce_json_object_payload(response)
        if _is_valid_human_review_payload(parsed):
            return parsed

        LOGGER.warning(
            "Gemini human review pre-check returned invalid structured output%s, retrying once.",
            context,
        )
        retry_prompt = (
            prompt
            + "\n\nImportant: Return strict JSON only. "
            "Do not use markdown code fences."
        )
        retry_response = self._generate_structured_response(
            retry_prompt,
            response_schema=HUMAN_REVIEW_CHECK_JSON_SCHEMA,
            attempt=2,
            use_tools=False,
        )
        retry_parsed = _coerce_json_object_payload(retry_response)
        if _is_valid_human_review_payload(retry_parsed):
            return retry_parsed

        raise ValueError("Gemini returned invalid human review pre-check response.")

    def _generate_response(
        self,
        prompt: str,
        *,
        attempt: int,
    ):
        LOGGER.debug("Sending prompt to Gemini model %s.", self._model)
        config = self._build_generate_response_config(attempt=attempt, prompt=prompt)
        return self._client.models.generate_content(
            model=self._model,
            contents=prompt,
            config=config,
        )

    def _generate_structured_response(
        self,
        prompt: str,
        *,
        response_schema: dict[str, Any],
        attempt: int,
        use_tools: bool,
    ):
        config_kwargs: dict[str, Any] = {
            "temperature": 1,
            "candidate_count": 1,
            "max_output_tokens": GEMINI_MAX_OUTPUT_TOKENS,
            "thinking_config": self._types.ThinkingConfig(
                **_build_thinking_config(self._model, attempt=attempt)
            ),
            "response_mime_type": "application/json",
            "response_schema": response_schema,
        }
        if use_tools:
            config_kwargs["tools"] = [
                self._types.Tool(google_search=self._types.GoogleSearch()),
            ]
        config = self._types.GenerateContentConfig(**config_kwargs)
        return self._client.models.generate_content(
            model=self._model,
            contents=prompt,
            config=config,
        )

    def _build_generate_response_config(self, *, attempt: int = 1, prompt: str | None = None):
        tools = [
            self._types.Tool(google_search=self._types.GoogleSearch()),
            # self._types.Tool(url_context=self._types.UrlContext()),
        ]
        config_kwargs: dict[str, Any] = {
            "temperature": 1,
            "candidate_count": 1,
            "max_output_tokens": GEMINI_MAX_OUTPUT_TOKENS,
            "thinking_config": self._types.ThinkingConfig(
                **_build_thinking_config(self._model, attempt=attempt)
            ),
            "response_mime_type": "application/json",
            "response_schema": AI_ANALYSIS_JSON_SCHEMA,
        }
        if prompt:
            cached_content = self._resolve_cached_content_name(prompt)
            if cached_content:
                config_kwargs["cached_content"] = cached_content
            else:
                config_kwargs["tools"] = tools
        else:
            config_kwargs["tools"] = tools
        return self._types.GenerateContentConfig(
            **config_kwargs
        )

    def _resolve_cached_content_name(self, prompt: str) -> str | None:
        if getattr(self, "_prompt_cache_disabled", False):
            return None
        if not hasattr(self, "_prompt_cache_by_hash"):
            self._prompt_cache_by_hash = {}
        if not hasattr(self, "_prompt_cache_lock"):
            self._prompt_cache_lock = Lock()
        prefix = _extract_cacheable_prompt_prefix(prompt)
        if not prefix:
            return None

        prompt_hash = hashlib.sha256(prefix.encode("utf-8")).hexdigest()
        with self._prompt_cache_lock:
            cached_content_name = self._prompt_cache_by_hash.get(prompt_hash)
            if cached_content_name:
                return cached_content_name

            try:
                cached_content = self._client.caches.create(
                    model=self._model,
                    config=self._types.CreateCachedContentConfig(
                        display_name=f"pwn-hunter-{prompt_hash[:12]}",
                        contents=[prefix],
                        tools=[
                            self._types.Tool(google_search=self._types.GoogleSearch()),
                            # self._types.Tool(url_context=self._types.UrlContext()),
                        ],
                        ttl=f"{PROMPT_CACHE_TTL_SECONDS}s",
                    ),
                )
            except Exception as exc:
                self._prompt_cache_disabled = True
                LOGGER.warning(
                    "Gemini explicit prompt caching is unavailable; falling back without explicit cache: %s",
                    exc,
                )
                return None

            cache_name = getattr(cached_content, "name", None)
            if not cache_name:
                return None
            cache_name_str = str(cache_name)
            self._prompt_cache_by_hash[prompt_hash] = cache_name_str
            LOGGER.debug(
                "Created Gemini explicit cache %s for stable prompt prefix.",
                cache_name_str,
            )
            return cache_name_str

    def _run_batch_analysis(
        self,
        requests: Sequence[AnalysisPromptRequest],
    ) -> tuple[list[AiAnalysis], str, int]:
        with tempfile.TemporaryDirectory(prefix="gemini-batch-") as temp_dir:
            request_path = Path(temp_dir) / "requests.jsonl"
            request_keys = _write_batch_request_file(
                request_path,
                requests,
                model=self._model,
                cached_content_resolver=self._resolve_cached_content_name,
            )
            LOGGER.info(
                "Created Gemini batch request file %s with %d requests.",
                request_path,
                len(request_keys),
            )

            latest_batch_name = ""
            for attempt in range(1, 3):
                batch_job = self._submit_batch_job(request_path)
                latest_batch_name = batch_job.name or latest_batch_name
                LOGGER.info(
                    "Submitted Gemini batch job %s (attempt %d/2).",
                    latest_batch_name,
                    attempt,
                )

                completed_job = self._wait_for_batch_job(batch_job.name or "")
                state_name = _job_state_name(completed_job.state)

                if state_name == JOB_STATE_SUCCEEDED:
                    analyses = self._download_batch_analyses(
                        completed_job,
                        request_keys=request_keys,
                    )
                    return analyses, completed_job.name or latest_batch_name, attempt

                if state_name == JOB_STATE_EXPIRED and attempt == 1:
                    LOGGER.warning(
                        "Gemini batch job %s expired. Resubmitting once.",
                        completed_job.name,
                    )
                    continue

                raise GeminiBatchError(
                    _format_batch_terminal_error(completed_job)
                )

        raise GeminiBatchError("Gemini batch analysis ended unexpectedly.")

    def _submit_batch_job(self, request_path: Path):
        uploaded_file = self._client.files.upload(
            file=request_path,
            config={
                "display_name": request_path.name,
                "mime_type": "application/jsonl",
            },
        )
        LOGGER.info("Uploaded Gemini batch input file %s.", uploaded_file.name)
        return self._client.batches.create(model=self._model, src=uploaded_file.name)

    def _wait_for_batch_job(self, batch_name: str):
        if not batch_name:
            raise GeminiBatchError("Gemini batch submission returned no batch name.")

        last_state = None
        while True:
            batch_job = self._client.batches.get(name=batch_name)
            state_name = _job_state_name(batch_job.state)
            if state_name != last_state:
                LOGGER.info("Gemini batch job %s state: %s", batch_name, state_name)
                last_state = state_name
            if batch_job.done:
                return batch_job
            time.sleep(BATCH_POLL_INTERVAL_SECONDS)

    def _download_batch_analyses(
        self,
        batch_job,
        *,
        request_keys: Sequence[str],
    ) -> list[AiAnalysis]:
        destination = getattr(batch_job, "dest", None)
        if destination is None:
            raise GeminiBatchError("Gemini batch completed without an output destination.")

        output_file_name = getattr(destination, "file_name", None)
        if not output_file_name:
            raise GeminiBatchError("Gemini batch completed without an output file.")

        LOGGER.info(
            "Downloading Gemini batch output file %s for job %s.",
            output_file_name,
            batch_job.name,
        )
        payload = self._client.files.download(file=output_file_name)
        return self._parse_batch_output(payload, request_keys=request_keys)

    def _parse_batch_output(
        self,
        payload: bytes,
        *,
        request_keys: Sequence[str],
    ) -> list[AiAnalysis]:
        results_by_key: dict[str, AiAnalysis] = {}
        for raw_line in payload.decode("utf-8").splitlines():
            if not raw_line.strip():
                continue
            line_payload = json.loads(raw_line)
            result_key = _extract_batch_result_key(line_payload)

            error_payload = line_payload.get("error") or line_payload.get("status")
            if error_payload:
                raise GeminiBatchError(
                    f"Gemini batch item {result_key} failed: {error_payload}"
                )

            response_payload = line_payload.get("response")
            if not isinstance(response_payload, dict):
                raise GeminiBatchError(
                    f"Gemini batch item {result_key} did not contain a response payload."
                )

            response = self._types.GenerateContentResponse._from_response(
                response=response_payload,
                kwargs={
                    "config": {
                        "response_schema": AI_ANALYSIS_JSON_SCHEMA,
                    }
                },
            )
            try:
                results_by_key[result_key] = self._parse_response(response)
            except (ValidationError, ValueError) as exc:
                raise GeminiBatchError(
                    f"Gemini batch item {result_key} returned invalid structured output: {exc}"
                ) from exc

        missing_keys = [key for key in request_keys if key not in results_by_key]
        if missing_keys:
            raise GeminiBatchError(
                "Gemini batch output did not include all requests. Missing keys: "
                + ", ".join(missing_keys[:5])
            )

        return [results_by_key[key] for key in request_keys]

    def _parse_response(self, response) -> AiAnalysis:
        parsed = getattr(response, "parsed", None)
        if parsed is not None:
            validated = _coerce_ai_analysis_payload(parsed)
            if validated is not None:
                return validated

        response_text = getattr(response, "text", None)
        validated = _coerce_ai_analysis_payload(response_text)
        if validated is not None:
            return validated

        candidate_text = _extract_candidate_text(response)
        if candidate_text and candidate_text != response_text:
            validated = _coerce_ai_analysis_payload(candidate_text)
            if validated is not None:
                return validated

        finish_reason = _extract_finish_reason(response)
        if finish_reason and "MAX_TOKENS" in finish_reason:
            raise ValueError(
                "Gemini response was truncated before producing valid JSON."
            )

        raise ValueError("Gemini returned neither parsed structured output nor text.")


def _write_batch_request_file(
    path: Path,
    requests: Sequence[AnalysisPromptRequest],
    *,
    model: str = GEMINI_DEFAULT_MODEL,
    cached_content_resolver: Callable[[str], str | None] | None = None,
) -> list[str]:
    request_keys: list[str] = []
    lines: list[str] = []
    for index, request in enumerate(requests):
        request_key = _batch_request_key(index, request.metadata)
        request_keys.append(request_key)
        lines.append(
            json.dumps(
                {
                    "key": request_key,
                    "request": _build_batch_generate_content_request(
                        request.prompt,
                        model=model,
                        cached_content=(
                            cached_content_resolver(request.prompt)
                            if cached_content_resolver
                            else None
                        ),
                    ),
                }
            )
        )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return request_keys


def _build_batch_generate_content_request(
    prompt: str,
    *,
    model: str = GEMINI_DEFAULT_MODEL,
    cached_content: str | None = None,
) -> dict[str, Any]:
    request: dict[str, Any] = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": prompt}],
            }
        ],
        "generation_config": {
            "temperature": 1,
            "candidate_count": 1,
            "max_output_tokens": GEMINI_MAX_OUTPUT_TOKENS,
            "thinking_config": _build_thinking_config(model, attempt=1),
            "response_mime_type": "application/json",
            "response_json_schema": AI_ANALYSIS_JSON_SCHEMA,
        },
    }
    if cached_content:
        request["cached_content"] = cached_content
    else:
        request["tools"] = [
            {"google_search": {}},
            # {"url_context": {}},
        ]
    return request


def _extract_cacheable_prompt_prefix(prompt: str) -> str | None:
    marker_index = prompt.find(PROMPT_CACHE_SPLIT_MARKER)
    if marker_index < 0:
        return None
    prefix = prompt[:marker_index].strip()
    if not prefix:
        return None
    return prefix


def _build_thinking_config(model: str, *, attempt: int) -> dict[str, Any]:
    if _is_gemini_3_model(model):
        level = (
            GEMINI_THINKING_LEVEL_DEFAULT
            if attempt == 1
            else GEMINI_THINKING_LEVEL_RETRY
        )
        return {"thinking_level": level}

    thinking_budget = (
        GEMINI_THINKING_BUDGET_AUTOMATIC
        if attempt == 1
        else GEMINI_RETRY_THINKING_BUDGET
    )
    return {"thinking_budget": thinking_budget}


def _is_gemini_3_model(model: str) -> bool:
    normalized_model = model.strip().lower()
    return normalized_model.startswith("gemini-3")


def _batch_request_key(index: int, metadata: dict[str, Any] | None) -> str:
    if metadata and metadata.get("repository_name") and metadata.get("initial_workflow"):
        repository_name = str(metadata["repository_name"]).replace("/", "__")
        workflow_name = str(metadata["initial_workflow"]).replace("/", "__")
        return f"{index:05d}-{repository_name}-{workflow_name}"
    return f"{index:05d}"


def _format_request_context(metadata: dict[str, Any] | None) -> str:
    if not metadata:
        return ""

    repository_name = metadata.get("repository_name")
    initial_workflow = metadata.get("initial_workflow")
    if repository_name and initial_workflow:
        return f" for {repository_name} / {initial_workflow}"
    if repository_name:
        return f" for {repository_name}"
    if initial_workflow:
        return f" for workflow {initial_workflow}"
    return ""


def _extract_batch_result_key(line_payload: dict[str, Any]) -> str:
    for candidate_key in ("key", "id", "custom_id"):
        value = line_payload.get(candidate_key)
        if value:
            return str(value)
    raise GeminiBatchError("Gemini batch output line did not include a request key.")


def _job_state_name(state: Any) -> str:
    if state is None:
        return "UNKNOWN"
    if hasattr(state, "name"):
        return str(state.name)
    return str(state)


def _format_batch_terminal_error(batch_job: Any) -> str:
    batch_name = getattr(batch_job, "name", "<unknown>")
    state_name = _job_state_name(getattr(batch_job, "state", None))
    error = getattr(batch_job, "error", None)
    if error is not None:
        return f"Gemini batch job {batch_name} ended in {state_name}: {error}"
    return f"Gemini batch job {batch_name} ended in {state_name}."


def _validate_ai_analysis(payload: dict) -> AiAnalysis:
    if hasattr(AiAnalysis, "model_validate"):
        return AiAnalysis.model_validate(payload)
    return AiAnalysis.parse_obj(payload)


def _validate_ai_analysis_json(payload: str) -> AiAnalysis:
    if hasattr(AiAnalysis, "model_validate_json"):
        return AiAnalysis.model_validate_json(payload)
    return AiAnalysis.parse_raw(payload)


def _coerce_ai_analysis_payload(payload: Any) -> AiAnalysis | None:
    if payload is None:
        return None
    if isinstance(payload, AiAnalysis):
        return payload
    if isinstance(payload, dict):
        return _validate_ai_analysis(payload)
    if isinstance(payload, str):
        return _validate_ai_analysis_json(payload)
    if hasattr(payload, "model_dump"):
        dumped = payload.model_dump(exclude_none=True)
        if isinstance(dumped, dict):
            return _validate_ai_analysis(dumped)
    return None


def _coerce_json_object_payload(payload: Any) -> dict[str, Any] | None:
    if payload is None:
        return None
    if isinstance(payload, dict):
        return payload
    if isinstance(payload, str):
        try:
            parsed = json.loads(payload)
        except ValueError:
            return None
        return parsed if isinstance(parsed, dict) else None
    parsed = getattr(payload, "parsed", None)
    if isinstance(parsed, dict):
        return parsed
    text = getattr(payload, "text", None)
    if isinstance(text, str):
        try:
            parsed = json.loads(text)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            return parsed
    candidate_text = _extract_candidate_text(payload)
    if candidate_text:
        try:
            parsed = json.loads(candidate_text)
        except ValueError:
            parsed = None
        if isinstance(parsed, dict):
            return parsed
    return None


def _is_valid_human_review_payload(payload: dict[str, Any] | None) -> bool:
    if not isinstance(payload, dict):
        return False
    return isinstance(payload.get("needs_human_review"), bool) and isinstance(
        payload.get("reason"), str
    )


def _extract_candidate_text(response) -> str | None:
    candidates = getattr(response, "candidates", None) or []
    if not candidates:
        return None

    content = getattr(candidates[0], "content", None)
    parts = getattr(content, "parts", None) or []
    for part in parts:
        text = getattr(part, "text", None)
        if text:
            return str(text)
    return None


def _extract_finish_reason(response) -> str | None:
    candidates = getattr(response, "candidates", None) or []
    if not candidates:
        return None
    finish_reason = getattr(candidates[0], "finish_reason", None)
    return str(finish_reason) if finish_reason is not None else None


def _build_human_review_precheck_prompt(
    *,
    ai_analysis: dict[str, Any],
    request_context: str,
) -> str:
    template = HUMAN_REVIEW_PRECHECK_PROMPT_PATH.read_text(encoding="utf-8")
    return (
        template.replace("{{request_context}}", request_context)
        .replace("{{ai_analysis_json}}", json.dumps(ai_analysis, ensure_ascii=True))
    )
