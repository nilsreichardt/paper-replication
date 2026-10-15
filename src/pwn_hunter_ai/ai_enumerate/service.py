from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime
import logging
from typing import Any

from pwn_hunter_ai.ai_enumerate.prompting import (
    build_analysis_prompt,
    extract_referenced_files,
)
from pwn_hunter_ai.gemini_client import GeminiAnalyzer
from pwn_hunter_ai.github_client import GitHubApiError, GitHubClient
from pwn_hunter_ai.models import AiAnalysis, AnalysisPromptRequest, PromptFile


LOGGER = logging.getLogger(__name__)


@dataclass(slots=True)
class PreparedRisk:
    risk: dict[str, Any]
    prompt_request: AnalysisPromptRequest
    analysis: AiAnalysis | None = None
    analysis_error: str | None = None


@dataclass(slots=True)
class PreparedRepository:
    name: str
    enum_time: str
    can_fork: bool
    stars: int
    repository_creation_date: str
    risks: list[PreparedRisk]
    preparation_error: str | None = None


class AIEnumerationService:
    def __init__(self, github_client: GitHubClient, analyzer: GeminiAnalyzer) -> None:
        self._github_client = github_client
        self._analyzer = analyzer

    def run(
        self,
        input_payload: dict[str, Any],
        *,
        parallel_jobs: int,
        gemini_batch: bool,
        output_only_vulnerable: bool,
    ) -> dict[str, Any]:
        repositories = input_payload.get("enumeration", {}).get("repositories", [])
        prepared_repositories = self._prepare_repositories(
            repositories=repositories,
            parallel_jobs=parallel_jobs,
        )

        if gemini_batch:
            self._analyze_prepared_risks_in_batch(
                prepared_repositories,
                parallel_jobs=parallel_jobs,
            )
        else:
            self._analyze_prepared_risks(prepared_repositories, parallel_jobs=parallel_jobs)

        ai_enumeration = [
            self._build_output_repository(repository)
            for repository in prepared_repositories
        ]
        if output_only_vulnerable:
            for repository in ai_enumeration:
                repository["risks"] = [
                    risk
                    for risk in repository["risks"]
                    if risk["ai-analysis"]["vulnerable"]
                ]
            ai_enumeration = [
                repository
                for repository in ai_enumeration
                if repository["risks"]
            ]

        return {
            "timestamp": datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Y"),
            "ai_enumeration": ai_enumeration,
        }

    def _prepare_repositories(
        self,
        *,
        repositories: list[dict[str, Any]],
        parallel_jobs: int,
    ) -> list[PreparedRepository]:
        results: list[PreparedRepository | None] = [None] * len(repositories)

        with ThreadPoolExecutor(max_workers=parallel_jobs) as executor:
            future_to_index = {
                executor.submit(self._prepare_repository, repository): index
                for index, repository in enumerate(repositories)
            }
            for future in as_completed(future_to_index):
                index = future_to_index[future]
                repository = repositories[index]
                try:
                    results[index] = future.result()
                except Exception as exc:
                    if _should_skip_missing_repository(repository["name"], exc):
                        LOGGER.warning(
                            "Skipping repository %s because it is no longer accessible on GitHub: %s",
                            repository["name"],
                            _format_analysis_error(exc),
                        )
                        continue
                    results[index] = self._build_failed_repository(repository, exc)

        return [repository for repository in results if repository is not None]

    def _prepare_repository(self, repository: dict[str, Any]) -> PreparedRepository:
        LOGGER.info("Preparing repository %s for AI analysis", repository["name"])
        metadata = self._github_client.get_repo_metadata(repository["name"])
        repository_ref = repository.get("commit") or metadata["default_branch"]

        prepared_risks = [
            self._prepare_risk(
                repository=repository,
                repository_ref=repository_ref,
                repository_creation_date=metadata["created_at"],
                risk=risk,
            )
            for risk in repository.get("risks", [])
        ]

        return PreparedRepository(
            name=repository["name"],
            enum_time=repository["enum_time"],
            can_fork=repository["can_fork"],
            stars=repository["stars"],
            repository_creation_date=metadata["created_at"],
            risks=prepared_risks,
        )

    def _prepare_risk(
        self,
        *,
        repository: dict[str, Any],
        repository_ref: str,
        repository_creation_date: str,
        risk: dict[str, Any],
    ) -> PreparedRisk:
        referenced_files = extract_referenced_files(
            risk,
            fallback_repo_name=repository["name"],
            fallback_ref=repository_ref,
        )
        prompt_files: list[PromptFile] = []

        for referenced_file in referenced_files:
            resolved_ref = self._resolve_ref(
                analyzed_repository=repository,
                repository_ref=repository_ref,
                referenced_repo_name=referenced_file.repo_name,
                referenced_ref=referenced_file.ref,
            )
            content = self._github_client.get_file_content(
                referenced_file.repo_name,
                referenced_file.path,
                resolved_ref,
            )
            prompt_files.append(
                PromptFile(
                    repo_name=referenced_file.repo_name,
                    path=referenced_file.path,
                    ref=resolved_ref,
                    content=content,
                )
            )

        prompt = build_analysis_prompt(
            repository_name=repository["name"],
            repository_creation_date=repository_creation_date,
            analyzed_ref=repository_ref,
            risk=risk,
            files=prompt_files,
        )
        return PreparedRisk(
            risk=risk,
            prompt_request=AnalysisPromptRequest(
                prompt=prompt,
                metadata={
                    "repository_name": repository["name"],
                    "initial_workflow": risk["initial_workflow"],
                    "issue_type": risk["issue_type"],
                    "triggers": risk["triggers"],
                    "analyzed_ref": repository_ref,
                },
            ),
        )

    def _analyze_prepared_risks(
        self,
        repositories: list[PreparedRepository],
        *,
        parallel_jobs: int,
    ) -> None:
        flattened_risks = [
            prepared_risk
            for repository in repositories
            for prepared_risk in repository.risks
        ]
        if not flattened_risks:
            return

        with ThreadPoolExecutor(max_workers=parallel_jobs) as executor:
            future_to_risk = {
                executor.submit(
                    self._analyzer.analyze_prompt,
                    prepared_risk.prompt_request.prompt,
                    metadata=prepared_risk.prompt_request.metadata,
                ): prepared_risk
                for prepared_risk in flattened_risks
            }
            for future in as_completed(future_to_risk):
                prepared_risk = future_to_risk[future]
                try:
                    prepared_risk.analysis = future.result()
                except Exception as exc:
                    prepared_risk.analysis_error = _format_analysis_error(exc)
                    LOGGER.warning(
                        "AI analysis failed for %s / %s: %s",
                        prepared_risk.prompt_request.metadata.get("repository_name", "<unknown>")
                        if prepared_risk.prompt_request.metadata
                        else "<unknown>",
                        prepared_risk.prompt_request.metadata.get("initial_workflow", "<unknown>")
                        if prepared_risk.prompt_request.metadata
                        else "<unknown>",
                        prepared_risk.analysis_error,
                    )

    def _analyze_prepared_risks_in_batch(
        self,
        repositories: list[PreparedRepository],
        *,
        parallel_jobs: int,
    ) -> None:
        flattened_risks = [
            prepared_risk
            for repository in repositories
            for prepared_risk in repository.risks
        ]
        if not flattened_risks:
            return

        try:
            analyses = self._analyzer.analyze_prompts_batch(
                [prepared_risk.prompt_request for prepared_risk in flattened_risks]
            )
        except Exception as exc:
            LOGGER.warning(
                "Gemini batch analysis failed for %d risks; falling back to per-risk analysis: %s",
                len(flattened_risks),
                _format_analysis_error(exc),
            )
            self._analyze_prepared_risks(repositories, parallel_jobs=parallel_jobs)
            return

        for prepared_risk, analysis in zip(flattened_risks, analyses, strict=True):
            prepared_risk.analysis = analysis

    def _build_output_repository(self, repository: PreparedRepository) -> dict[str, Any]:
        processed_risks = [
            _build_output_risk(prepared_risk)
            for prepared_risk in repository.risks
        ]

        if any(not risk["ai-analysis"]["vulnerable"] for risk in processed_risks):
            LOGGER.debug(
                "Repository %s contains at least one non-vulnerable risk according to AI analysis.",
                repository.name,
            )

        output = {
            "name": repository.name,
            "enum_time": repository.enum_time,
            "can_fork": repository.can_fork,
            "stars": repository.stars,
            "repository_creation_date": repository.repository_creation_date,
            "risks": processed_risks,
        }
        if repository.preparation_error:
            output["error"] = repository.preparation_error
        return output

    def _build_failed_repository(
        self,
        repository: dict[str, Any],
        exc: Exception,
    ) -> PreparedRepository:
        error = _format_analysis_error(exc)
        LOGGER.warning(
            "Failed to prepare repository %s for AI analysis: %s",
            repository["name"],
            error,
        )
        return PreparedRepository(
            name=repository["name"],
            enum_time=repository["enum_time"],
            can_fork=repository["can_fork"],
            stars=repository["stars"],
            repository_creation_date="",
            risks=[],
            preparation_error=error,
        )

    def _resolve_ref(
        self,
        *,
        analyzed_repository: dict[str, Any],
        repository_ref: str,
        referenced_repo_name: str,
        referenced_ref: str | None,
    ) -> str:
        if referenced_repo_name.lower() == analyzed_repository["name"].lower():
            return repository_ref
        if referenced_ref:
            return referenced_ref
        metadata = self._github_client.get_repo_metadata(referenced_repo_name)
        return metadata["default_branch"]


def _build_output_risk(prepared_risk: PreparedRisk) -> dict[str, Any]:
    risk = prepared_risk.risk
    output = {
        "repository_name": risk["repository_name"],
        "issue_type": risk["issue_type"],
        "triggers": risk["triggers"],
        "initial_workflow": risk["initial_workflow"],
        "gato-x-confidence": risk.get("confidence"),
        "gato-x-attack_complexity": risk.get("attack_complexity"),
        "gato-x-explanation": risk.get("explanation"),
        "gato-x-path": risk.get("path", []),
        "gato-x-sink": risk.get("sink"),
        "ai-analysis": _analysis_dump(_resolved_analysis(prepared_risk)),
    }
    if prepared_risk.analysis_error:
        output["ai-analysis-error"] = prepared_risk.analysis_error
    return output


def _analysis_dump(analysis: AiAnalysis) -> dict[str, Any]:
    if hasattr(analysis, "model_dump"):
        return analysis.model_dump()
    return analysis.dict()


def _resolved_analysis(prepared_risk: PreparedRisk) -> AiAnalysis:
    if prepared_risk.analysis is not None:
        return prepared_risk.analysis
    error = prepared_risk.analysis_error or "Analysis did not return a result."
    return AiAnalysis(
        vulnerable=False,
        confidence="very low",
        explanation="AI analysis failed for this risk.",
        impact=f"Unknown: {error}",
        poc="",
    )


def _format_analysis_error(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"


def _should_skip_missing_repository(repo_name: str, exc: Exception) -> bool:
    if not isinstance(exc, GitHubApiError):
        return False

    missing_markers = (
        f"GitHub API request failed for /repos/{repo_name}: 404",
        f"GitHub API request failed for /repos/{repo_name}: 403",
    )
    error_message = str(exc)
    if not error_message.startswith(missing_markers):
        return False

    normalized = error_message.lower()
    return any(
        marker in normalized
        for marker in (
            "not found",
            "repository access blocked",
            "repository unavailable",
        )
    )
