from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any
from urllib.parse import urlparse

from pwn_hunter_ai.cli import _refresh_repo_vulnerable_fields

_ARTIFACT_PATH_RE = re.compile(r"attack-artifacts/([^/\s]+)/([^/\s]+)/")
_CREATED_PR_RE = re.compile(r"Created PR #(\d+) from (\S+) to (\S+)")
_PULL_REQUEST_URL_RE = re.compile(r"Pull request URL:\s*(https://github\.com/\S+/pull/\d+)")
_WORKFLOW_CONCLUSION_RE = re.compile(r"Workflow run (\d+) conclusion: (\w+)")
_ATTEMPT_FAILED_RE = re.compile(
    r"All workflow runs completed but no secrets exfiltrated\. Attempt (\d+) failed\."
)
_HUMAN_REVIEW_RE = re.compile(
    r"(?:Agent|OpenHands) requested human review for repository:\s*(.+)"
)
_NOT_VULN_RE = re.compile(
    r"(?:Agent|OpenHands) marked repository as not vulnerable(?: in \d+/\d+ fresh conversations)?:\s*(.+)"
)
_VULNERABLE_RE = re.compile(r"Found hookbin logs! Repository is VULNERABLE")
_FINAL_STATUS_TO_ATTACK_STATUS = {
    "human_review_required": "human_review_required",
    "needs_human_review": "human_review_required",
    "execution_error": "execution_error",
    "not_vulnerable": "not_vulnerable_after_execution",
    "skipped_node_runtime_unavailable": "skipped_node_runtime_unavailable",
    "vulnerable_confirmed": "vulnerable_confirmed",
}


@dataclass(slots=True)
class RepoObservation:
    repository_name: str
    run_ids: set[str] = field(default_factory=set)
    pull_request_urls: list[str] = field(default_factory=list)
    pull_request_numbers: list[int] = field(default_factory=list)
    workflow_runs: list[dict[str, Any]] = field(default_factory=list)
    user_a_fork: str | None = None
    user_b_fork: str | None = None
    max_failed_attempt: int = 0
    saw_vulnerable: bool = False
    saw_human_review: bool = False
    saw_not_vulnerable: bool = False
    human_review_reason: str | None = None
    not_vulnerable_reason: str | None = None
    artifact_attack_result: dict[str, Any] | None = None
    artifact_vulnerable_commit_hash: str | None = None
    artifact_focused_workflow: str | None = None
    attempt_state_status: str | None = None
    attempt_state_attempts: list[dict[str, Any]] = field(default_factory=list)
    attempt_state_max_retries: int | None = None
    attempt_state_flagged_for_human_review: bool | None = None


def _extract_repo_name_from_pr_url(url: str) -> str | None:
    parsed = urlparse(url)
    if parsed.netloc != "github.com":
        return None
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) < 4:
        return None
    if parts[2] != "pull":
        return None
    return f"{parts[0]}/{parts[1]}"


def _observe_repo(
    observations: dict[str, RepoObservation],
    repository_name: str,
) -> RepoObservation:
    existing = observations.get(repository_name)
    if existing is not None:
        return existing
    obs = RepoObservation(repository_name=repository_name)
    observations[repository_name] = obs
    return obs


def parse_attack_log(log_path: Path) -> tuple[dict[str, RepoObservation], set[str]]:
    observations: dict[str, RepoObservation] = {}
    discovered_run_ids: set[str] = set()
    current_repo: str | None = None
    fallback_repo: str | None = None

    for raw_line in log_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue

        artifact_match = _ARTIFACT_PATH_RE.search(line)
        if artifact_match:
            run_id, slug = artifact_match.groups()
            discovered_run_ids.add(run_id)
            current_repo = slug.replace("__", "/")
            _observe_repo(observations, current_repo).run_ids.add(run_id)
            fallback_repo = current_repo

        created_match = _CREATED_PR_RE.search(line)
        if created_match:
            pr_number_raw, user_b_fork, user_a_fork = created_match.groups()
            try:
                pr_number = int(pr_number_raw)
            except ValueError:
                pr_number = None
            target_repo = user_a_fork.strip()
            repo_for_obs = current_repo or target_repo
            obs = _observe_repo(observations, repo_for_obs)
            obs.user_a_fork = target_repo
            obs.user_b_fork = user_b_fork.strip()
            if pr_number is not None and pr_number not in obs.pull_request_numbers:
                obs.pull_request_numbers.append(pr_number)
            if current_repo is None:
                current_repo = repo_for_obs
            fallback_repo = repo_for_obs

        url_match = _PULL_REQUEST_URL_RE.search(line)
        if url_match:
            pull_request_url = url_match.group(1).strip()
            url_repo = _extract_repo_name_from_pr_url(pull_request_url)
            repo_for_obs = current_repo or url_repo
            if repo_for_obs:
                obs = _observe_repo(observations, repo_for_obs)
                if pull_request_url not in obs.pull_request_urls:
                    obs.pull_request_urls.append(pull_request_url)
                if url_repo and not obs.user_a_fork:
                    obs.user_a_fork = url_repo
                current_repo = repo_for_obs
                fallback_repo = repo_for_obs

        status_repo = current_repo or fallback_repo
        if status_repo is None:
            continue
        obs = _observe_repo(observations, status_repo)

        workflow_match = _WORKFLOW_CONCLUSION_RE.search(line)
        if workflow_match:
            run_id_raw, conclusion = workflow_match.groups()
            try:
                run_id = int(run_id_raw)
            except ValueError:
                run_id = None
            payload = {"conclusion": conclusion}
            if run_id is not None:
                payload["run_id"] = run_id
            obs.workflow_runs.append(payload)
            continue

        failed_attempt_match = _ATTEMPT_FAILED_RE.search(line)
        if failed_attempt_match:
            try:
                attempt_number = int(failed_attempt_match.group(1))
                obs.max_failed_attempt = max(obs.max_failed_attempt, attempt_number)
            except ValueError:
                pass
            continue

        if _VULNERABLE_RE.search(line):
            obs.saw_vulnerable = True
            continue

        human_review_match = _HUMAN_REVIEW_RE.search(line)
        if human_review_match:
            obs.saw_human_review = True
            reason = human_review_match.group(1).strip()
            if reason:
                obs.human_review_reason = reason
            continue

        not_vuln_match = _NOT_VULN_RE.search(line)
        if not_vuln_match:
            obs.saw_not_vulnerable = True
            reason = not_vuln_match.group(1).strip()
            if reason:
                obs.not_vulnerable_reason = reason

    return observations, discovered_run_ids


def collect_artifact_observations(
    artifacts_dir: Path,
    *,
    run_id_filter: set[str] | None = None,
) -> dict[str, RepoObservation]:
    observations: dict[str, RepoObservation] = {}
    if not artifacts_dir.exists():
        return observations

    for context_path in artifacts_dir.glob("**/attack-context.json"):
        run_id = context_path.parent.parent.name
        if run_id_filter and run_id not in run_id_filter:
            continue

        try:
            payload = json.loads(context_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(payload, dict):
            continue

        repository_name = payload.get("repository_name")
        if not isinstance(repository_name, str) or not repository_name.strip():
            continue
        repository_name = repository_name.strip()
        obs = _observe_repo(observations, repository_name)
        obs.run_ids.add(run_id)

        vulnerable_commit_hash = payload.get("vulnerable_commit_hash")
        if isinstance(vulnerable_commit_hash, str) and vulnerable_commit_hash.strip():
            obs.artifact_vulnerable_commit_hash = vulnerable_commit_hash.strip()

        attack_result = payload.get("attack_result")
        if isinstance(attack_result, dict):
            obs.artifact_attack_result = deepcopy(attack_result)
            focused_workflow = attack_result.get("focused_workflow")
            if isinstance(focused_workflow, str) and focused_workflow.strip():
                obs.artifact_focused_workflow = focused_workflow.strip()
            user_a_fork = attack_result.get("user_a_fork")
            user_b_fork = attack_result.get("user_b_fork")
            if isinstance(user_a_fork, str) and user_a_fork.strip():
                obs.user_a_fork = user_a_fork.strip()
            if isinstance(user_b_fork, str) and user_b_fork.strip():
                obs.user_b_fork = user_b_fork.strip()

        attempt_state_path = context_path.parent / "attempt-state.json"
        if not attempt_state_path.exists():
            continue
        try:
            attempt_state_payload = json.loads(
                attempt_state_path.read_text(encoding="utf-8")
            )
        except (OSError, ValueError):
            continue
        if not isinstance(attempt_state_payload, dict):
            continue
        status = attempt_state_payload.get("status")
        if isinstance(status, str) and status.strip():
            obs.attempt_state_status = status.strip()
        max_retries = attempt_state_payload.get("max_retries")
        if isinstance(max_retries, int):
            obs.attempt_state_max_retries = max_retries
        flagged = attempt_state_payload.get("flagged_for_human_review")
        if isinstance(flagged, bool):
            obs.attempt_state_flagged_for_human_review = flagged
        attempts = attempt_state_payload.get("attempts")
        if isinstance(attempts, list):
            obs.attempt_state_attempts = [
                deepcopy(item) for item in attempts if isinstance(item, dict)
            ]

    return observations


def _choose_target_risk_indices(
    repository: dict[str, Any], observation: RepoObservation
) -> list[int]:
    risks = repository.get("risks")
    if not isinstance(risks, list) or not risks:
        return []
    focused_workflow = observation.artifact_focused_workflow
    if focused_workflow:
        matches = [
            idx
            for idx, risk in enumerate(risks)
            if isinstance(risk, dict)
            and str(risk.get("initial_workflow") or "").strip() == focused_workflow
        ]
        if matches:
            return matches
    vulnerable_matches = []
    for idx, risk in enumerate(risks):
        if not isinstance(risk, dict):
            continue
        analysis = risk.get("ai-analysis")
        if isinstance(analysis, dict) and analysis.get("vulnerable") is True:
            vulnerable_matches.append(idx)
    if vulnerable_matches:
        return vulnerable_matches
    return [0]


def _derive_recovered_status(observation: RepoObservation) -> tuple[str, str]:
    attempt_state_status = str(observation.attempt_state_status or "").strip().lower()
    if attempt_state_status in _FINAL_STATUS_TO_ATTACK_STATUS:
        mapped = _FINAL_STATUS_TO_ATTACK_STATUS[attempt_state_status]
        if mapped == "human_review_required":
            reason = observation.human_review_reason or (
                "Recovered from attempt-state status."
            )
        elif mapped == "vulnerable_confirmed":
            reason = "Recovered from attempt-state status."
        else:
            reason = observation.not_vulnerable_reason or (
                "Recovered from attempt-state status."
            )
        return mapped, reason

    if observation.saw_vulnerable:
        return (
            "vulnerable_confirmed",
            "Recovered from attack.log: hookbin evidence was found.",
        )
    if observation.saw_human_review:
        reason = observation.human_review_reason or (
            "Recovered from attack.log: agent requested human review."
        )
        return ("human_review_required", reason)
    if observation.saw_not_vulnerable:
        reason = observation.not_vulnerable_reason or (
            "Recovered from attack.log: agent marked repository as not vulnerable."
        )
        return ("not_vulnerable_after_execution", reason)
    if observation.max_failed_attempt > 0:
        return (
            "not_vulnerable_after_execution",
            "Recovered from attack.log: workflow retries completed without hookbin evidence.",
        )
    if observation.pull_request_urls or observation.pull_request_numbers:
        return (
            "human_review_required",
            "Recovered from attack.log: repository reached PR creation, but final status is missing.",
        )
    if observation.artifact_attack_result:
        existing_status = str(observation.artifact_attack_result.get("status") or "").strip()
        if existing_status:
            return (
                existing_status,
                "Recovered from attack artifacts.",
            )
    return (
        "blocked_preparation_error",
        "Recovered from available artifacts/logs, but execution outcome could not be determined.",
    )


def merge_observation_into_repository(
    repository: dict[str, Any],
    observation: RepoObservation,
    *,
    default_max_retries: int | None = None,
) -> dict[str, Any]:
    result = deepcopy(repository)
    if observation.artifact_vulnerable_commit_hash:
        result["vulnerable_commit_hash"] = observation.artifact_vulnerable_commit_hash
    else:
        result.setdefault("vulnerable_commit_hash", None)

    target_indices = _choose_target_risk_indices(result, observation)
    if not target_indices:
        return result

    derived_status, derived_reason = _derive_recovered_status(observation)
    attempts = (
        deepcopy(observation.attempt_state_attempts)
        if observation.attempt_state_attempts
        else []
    )
    attempt_count = len(attempts)
    if observation.max_failed_attempt > attempt_count:
        attempt_count = observation.max_failed_attempt
    max_retries = observation.attempt_state_max_retries or default_max_retries
    pull_request_url = (
        observation.pull_request_urls[-1] if observation.pull_request_urls else None
    )

    for idx in target_indices:
        risk = result["risks"][idx]
        if not isinstance(risk, dict):
            continue
        attack_result = risk.get("attack_result")
        if not isinstance(attack_result, dict):
            attack_result = {}

        if isinstance(observation.artifact_attack_result, dict):
            for key, value in observation.artifact_attack_result.items():
                attack_result.setdefault(key, deepcopy(value))

        attack_result["status"] = derived_status
        attack_result["reason"] = derived_reason
        if pull_request_url:
            attack_result["pull_request_url"] = pull_request_url
        if observation.user_a_fork:
            attack_result.setdefault("user_a_fork", observation.user_a_fork)
        if observation.user_b_fork:
            attack_result.setdefault("user_b_fork", observation.user_b_fork)
        if attempt_count > 0:
            attack_result["attempt_count"] = attempt_count
        if attempts:
            attack_result["attempts"] = attempts
        if max_retries is not None:
            attack_result.setdefault("max_retries", max_retries)
        if observation.attempt_state_flagged_for_human_review is True:
            attack_result["flagged_for_human_review"] = True
            if attack_result.get("status") != "vulnerable_confirmed":
                attack_result["status"] = "human_review_required"
        risk["attack_result"] = attack_result

    return result


def recover_attack_output(
    *,
    input_path: Path,
    output_path: Path,
    log_path: Path | None = None,
    artifacts_dir: Path | None = None,
    partial_output_path: Path | None = None,
    max_retries: int | None = None,
    restrict_artifacts_to_log_run_ids: bool = True,
) -> dict[str, Any]:
    input_payload = json.loads(input_path.read_text(encoding="utf-8"))
    input_repositories = input_payload.get("ai_enumeration", [])
    if not isinstance(input_repositories, list):
        raise ValueError("Input JSON must contain an 'ai_enumeration' list.")

    input_by_name: dict[str, dict[str, Any]] = {}
    for repository in input_repositories:
        if not isinstance(repository, dict):
            continue
        name = repository.get("name")
        if not isinstance(name, str) or not name.strip():
            continue
        input_by_name[name.strip()] = repository

    observations: dict[str, RepoObservation] = {}
    discovered_run_ids: set[str] = set()
    if log_path is not None:
        log_observations, discovered_run_ids = parse_attack_log(log_path)
        observations.update(log_observations)

    if artifacts_dir is not None:
        run_filter = (
            discovered_run_ids if (restrict_artifacts_to_log_run_ids and discovered_run_ids) else None
        )
        artifact_observations = collect_artifact_observations(
            artifacts_dir,
            run_id_filter=run_filter,
        )
        for repository_name, artifact_observation in artifact_observations.items():
            existing = observations.get(repository_name)
            if existing is None:
                observations[repository_name] = artifact_observation
                continue
            if artifact_observation.artifact_attack_result is not None:
                existing.artifact_attack_result = artifact_observation.artifact_attack_result
            if artifact_observation.artifact_vulnerable_commit_hash:
                existing.artifact_vulnerable_commit_hash = (
                    artifact_observation.artifact_vulnerable_commit_hash
                )
            if artifact_observation.artifact_focused_workflow:
                existing.artifact_focused_workflow = (
                    artifact_observation.artifact_focused_workflow
                )
            if artifact_observation.user_a_fork:
                existing.user_a_fork = artifact_observation.user_a_fork
            if artifact_observation.user_b_fork:
                existing.user_b_fork = artifact_observation.user_b_fork
            if artifact_observation.attempt_state_status:
                existing.attempt_state_status = artifact_observation.attempt_state_status
            if artifact_observation.attempt_state_attempts:
                existing.attempt_state_attempts = artifact_observation.attempt_state_attempts
            if artifact_observation.attempt_state_max_retries is not None:
                existing.attempt_state_max_retries = (
                    artifact_observation.attempt_state_max_retries
                )
            if artifact_observation.attempt_state_flagged_for_human_review is not None:
                existing.attempt_state_flagged_for_human_review = (
                    artifact_observation.attempt_state_flagged_for_human_review
                )
            existing.run_ids.update(artifact_observation.run_ids)

    recovered_by_name: dict[str, dict[str, Any]] = {}

    if partial_output_path is not None and partial_output_path.exists():
        partial_payload = json.loads(partial_output_path.read_text(encoding="utf-8"))
        partial_repositories = partial_payload.get("ai_enumeration", [])
        if isinstance(partial_repositories, list):
            for repository in partial_repositories:
                if not isinstance(repository, dict):
                    continue
                name = repository.get("name")
                if not isinstance(name, str) or not name.strip():
                    continue
                recovered_by_name[name.strip()] = deepcopy(repository)

    for repository_name, observation in observations.items():
        source_repository = recovered_by_name.get(repository_name)
        if source_repository is None:
            source_repository = input_by_name.get(repository_name)
            if source_repository is None:
                continue
        recovered_by_name[repository_name] = merge_observation_into_repository(
            source_repository,
            observation,
            default_max_retries=max_retries,
        )

    ordered_recovered: list[dict[str, Any]] = []
    for repository in input_repositories:
        if not isinstance(repository, dict):
            continue
        name = repository.get("name")
        if not isinstance(name, str):
            continue
        recovered = recovered_by_name.get(name)
        if recovered is not None:
            ordered_recovered.append(recovered)

    output_payload = deepcopy(input_payload)
    output_payload["timestamp"] = datetime.now().astimezone().strftime("%a %b %d %H:%M:%S %Y")
    output_payload["ai_enumeration"] = ordered_recovered
    _refresh_repo_vulnerable_fields(output_payload)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(output_payload, indent=2) + "\n", encoding="utf-8")
    return output_payload
