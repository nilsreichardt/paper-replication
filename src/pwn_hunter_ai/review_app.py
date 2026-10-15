from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import logging
from pathlib import Path
import re
import shlex
from threading import Lock
from typing import Any
from urllib.parse import parse_qs, urlparse

from pwn_hunter_ai.github_client import GitHubApiError, GitHubClient
from pwn_hunter_ai.review.index_html import INDEX_HTML


LOGGER = logging.getLogger(__name__)

_NODE_INNER_PATTERN = re.compile(r"\('([^']+)'\)")


@dataclass(frozen=True, slots=True)
class WorkflowRef:
    repo_name: str
    ref: str
    path: str


class ReviewApp:
    def __init__(
        self,
        payload: dict[str, Any],
        *,
        input_path: Path,
        github_client: GitHubClient,
        prefetch_repository_window: int = 3,
    ) -> None:
        self._input_payload = payload
        self._input_path = input_path
        self._github_client = github_client
        self._prefetch_repository_window = max(prefetch_repository_window, 0)
        self._repositories = _normalize_payload(payload)
        self._workflow_cache: dict[tuple[str, str, str], dict[str, str]] = {}
        self._inflight: set[tuple[str, str, str]] = set()
        self._lock = Lock()
        self._executor = ThreadPoolExecutor(max_workers=8)

    def close(self) -> None:
        self._executor.shutdown(wait=False, cancel_futures=True)

    def list_repositories(self) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for index, repository in enumerate(self._repositories):
            verdict_counts = _compute_risk_verdict_counts(repository["risks"])
            vulnerable_count = verdict_counts["vulnerable"]
            repo_vulnerable = _to_bool(repository.get("repo_vulnerable"))
            act_repo_vulnerable = _to_bool(repository.get("act_repo_vulnerable"))
            review_reasons = _collect_review_reasons(repository["risks"])
            review_focus = _compute_repository_review_focus(repository)
            result.append(
                {
                    "index": index,
                    "name": repository["name"],
                    "risk_count": len(repository["risks"]),
                    "vulnerable_count": vulnerable_count,
                    "vulnerable_with_secret_or_write_gh_token": repository.get(
                        "vulnerable_with_secret_or_write_gh_token"
                    ),
                    "has_vulnerable_risk": (
                        repo_vulnerable is True or act_repo_vulnerable is True
                    ),
                    "needs_review_count": verdict_counts["needs_review"],
                    "not_vulnerable_count": verdict_counts["not_vulnerable"],
                    "error_count": verdict_counts["error"],
                    "unknown_count": verdict_counts["unknown"],
                    "review_reasons": review_reasons,
                    "review_focus": review_focus,
                    "stars": repository["stars"],
                    "can_fork": repository["can_fork"],
                    "repository_creation_date": repository["repository_creation_date"],
                    "error": repository.get("error"),
                }
            )
        return result

    def get_repository(self, index: int) -> dict[str, Any]:
        if index < 0 or index >= len(self._repositories):
            raise IndexError(index)
        repository = self._repositories[index]
        verdict_counts = _compute_risk_verdict_counts(repository["risks"])
        review_focus = _compute_repository_review_focus(repository)
        risks: list[dict[str, Any]] = []
        for risk_index, risk in enumerate(repository["risks"]):
            workflows: list[dict[str, str | None]] = []
            for workflow in risk["workflows"]:
                key = (workflow.repo_name, workflow.ref, workflow.path)
                with self._lock:
                    cached = self._workflow_cache.get(key)
                workflows.append(
                    {
                        "repo_name": workflow.repo_name,
                        "ref": workflow.ref,
                        "path": workflow.path,
                        "cache_status": cached["status"] if cached else "missing",
                    }
                )
            ai_analysis = risk.get("ai-analysis") or {}
            attack_result = risk.get("attack_result")
            attack_summary = _summarize_attack_result(attack_result)
            risks.append(
                {
                    "risk_index": risk_index,
                    "issue_type": risk.get("issue_type"),
                    "triggers": risk.get("triggers", []),
                    "initial_workflow": risk.get("initial_workflow"),
                    "attack_complexity": risk.get("gato-x-attack_complexity"),
                    "sink": risk.get("gato-x-sink"),
                    "gato_path": risk.get("gato-x-path", []),
                    "human_summary": _humanize_ai_analysis(ai_analysis),
                    "ai_analysis": ai_analysis,
                    "attack_result": attack_result if isinstance(attack_result, dict) else None,
                    "attack_summary": attack_summary,
                    "attack_processed_time": risk.get("attack_processed_time"),
                    "workflows": workflows,
                }
            )
        return {
            "index": index,
            "name": repository["name"],
            "enum_time": repository["enum_time"],
            "stars": repository["stars"],
            "can_fork": repository["can_fork"],
            "repository_creation_date": repository["repository_creation_date"],
            "vulnerable_commit_hash": repository.get("vulnerable_commit_hash"),
            "error": repository.get("error"),
            "review_focus": review_focus,
            "verdict_counts": verdict_counts,
            "risks": risks,
        }

    def get_workflow_content(self, *, repo_name: str, ref: str, path: str) -> dict[str, str]:
        key = (repo_name, ref, path)
        with self._lock:
            cached = self._workflow_cache.get(key)
        if cached is not None:
            return cached

        loaded = self._fetch_workflow(key)
        with self._lock:
            self._workflow_cache[key] = loaded
            self._inflight.discard(key)
        return loaded

    def prefetch_from(self, start_index: int) -> int:
        if start_index < 0:
            return 0
        end_index = min(
            len(self._repositories),
            start_index + self._prefetch_repository_window + 1,
        )
        queued = 0
        for repository_index in range(start_index, end_index):
            queued += self._queue_repository(repository_index)
        return queued

    def _queue_repository(self, repository_index: int) -> int:
        repository = self._repositories[repository_index]
        queued = 0
        for risk in repository["risks"]:
            for workflow in risk["workflows"]:
                key = (workflow.repo_name, workflow.ref, workflow.path)
                with self._lock:
                    if key in self._workflow_cache or key in self._inflight:
                        continue
                    self._inflight.add(key)
                self._executor.submit(self._prefetch_worker, key)
                queued += 1
        return queued

    def _prefetch_worker(self, key: tuple[str, str, str]) -> None:
        loaded = self._fetch_workflow(key)
        with self._lock:
            self._workflow_cache[key] = loaded
            self._inflight.discard(key)

    def _fetch_workflow(self, key: tuple[str, str, str]) -> dict[str, str]:
        repo_name, ref, path = key
        try:
            content = self._github_client.get_file_content(repo_name, path, ref)
            return {"status": "loaded", "content": content}
        except GitHubApiError as exc:
            message = str(exc)
            LOGGER.warning(
                "Failed to fetch workflow %s@%s:%s: %s",
                repo_name,
                ref,
                path,
                message,
            )
            return {"status": "error", "error": message}
        except Exception as exc:
            message = f"Unexpected error: {exc}"
            LOGGER.exception(
                "Unexpected failure while fetching workflow %s@%s:%s",
                repo_name,
                ref,
                path,
            )
            return {"status": "error", "error": message}

    def build_attack_command(self, repository_name: str) -> dict[str, str]:
        selected_payload = _filter_payload_for_repository(self._input_payload, repository_name)
        output_dir = self._input_path.parent / self._input_path.stem
        output_dir.mkdir(parents=True, exist_ok=True)

        safe_repo_name = _sanitize_repository_name(repository_name)
        attack_input_path = output_dir / f"{safe_repo_name}.json"
        attack_output_path = output_dir / f"attack_results_{safe_repo_name}.json"
        attack_input_path.write_text(
            json.dumps(selected_payload, indent=2) + "\n",
            encoding="utf-8",
        )

        command = (
            "uv run pwnhunter attack \\\n"
            f"  --input {shlex.quote(str(attack_input_path))} \\\n"
            f"  --output {shlex.quote(str(attack_output_path))} \\\n"
            "  --auto-execute"
        )
        return {
            "repository": repository_name,
            "attack_input_path": str(attack_input_path),
            "attack_output_path": str(attack_output_path),
            "command": command,
        }


def run_review_server(
    *,
    payload: dict[str, Any],
    input_path: Path,
    github_client: GitHubClient,
    host: str,
    port: int,
) -> None:
    app = ReviewApp(payload, input_path=input_path, github_client=github_client)

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            parsed = urlparse(self.path)
            if parsed.path == "/":
                self._respond_html(_INDEX_HTML)
                return

            if parsed.path == "/api/repositories":
                self._respond_json({"repositories": app.list_repositories()})
                return

            if parsed.path == "/api/repository":
                query = parse_qs(parsed.query)
                index = _parse_int_query(query, "index")
                if index is None:
                    self._respond_json(
                        {"error": "Query parameter 'index' is required."},
                        status=HTTPStatus.BAD_REQUEST,
                    )
                    return
                try:
                    repository = app.get_repository(index)
                except IndexError:
                    self._respond_json(
                        {"error": f"Repository index out of range: {index}"},
                        status=HTTPStatus.NOT_FOUND,
                    )
                    return
                self._respond_json({"repository": repository})
                return

            if parsed.path == "/api/workflow":
                query = parse_qs(parsed.query)
                repo_name = _first_value(query, "repo")
                ref = _first_value(query, "ref")
                path = _first_value(query, "path")
                if not repo_name or not ref or not path:
                    self._respond_json(
                        {
                            "error": "Query parameters 'repo', 'ref', and 'path' are required."
                        },
                        status=HTTPStatus.BAD_REQUEST,
                    )
                    return
                payload = app.get_workflow_content(repo_name=repo_name, ref=ref, path=path)
                self._respond_json(payload)
                return

            if parsed.path == "/api/prefetch":
                query = parse_qs(parsed.query)
                start_index = _parse_int_query(query, "from")
                if start_index is None:
                    self._respond_json(
                        {"error": "Query parameter 'from' is required."},
                        status=HTTPStatus.BAD_REQUEST,
                    )
                    return
                queued = app.prefetch_from(start_index)
                self._respond_json({"queued": queued})
                return

            if parsed.path == "/api/attack-command":
                query = parse_qs(parsed.query)
                index = _parse_int_query(query, "index")
                if index is None:
                    self._respond_json(
                        {"error": "Query parameter 'index' is required."},
                        status=HTTPStatus.BAD_REQUEST,
                    )
                    return
                try:
                    repository = app.get_repository(index)
                except IndexError:
                    self._respond_json(
                        {"error": f"Repository index out of range: {index}"},
                        status=HTTPStatus.NOT_FOUND,
                    )
                    return
                try:
                    command_payload = app.build_attack_command(repository["name"])
                except KeyError:
                    self._respond_json(
                        {"error": f"Repository not found in input payload: {repository['name']}"},
                        status=HTTPStatus.NOT_FOUND,
                    )
                    return
                self._respond_json(command_payload)
                return

            self.send_error(HTTPStatus.NOT_FOUND, "Not found")

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
            LOGGER.debug("ReviewAppServer - " + format, *args)

        def _respond_json(self, payload: dict[str, Any], *, status: HTTPStatus = HTTPStatus.OK) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _respond_html(self, content: str) -> None:
            body = content.encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store, max-age=0")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = ThreadingHTTPServer((host, port), Handler)
    print(f"Review app running on http://{host}:{port}")
    try:
        server.serve_forever()
    finally:
        server.server_close()
        app.close()


def _normalize_payload(payload: dict[str, Any]) -> list[dict[str, Any]]:
    repositories = payload.get("ai_enumeration", [])
    if not isinstance(repositories, list):
        return []

    normalized: list[dict[str, Any]] = []
    for repository in repositories:
        risks = repository.get("risks", [])
        if not isinstance(risks, list):
            risks = []
        normalized_risks: list[dict[str, Any]] = []
        for risk in risks:
            normalized_risks.append(
                {
                    **risk,
                    "workflows": _extract_workflow_refs(risk),
                }
            )
        normalized.append(
            {
                "name": repository.get("name", ""),
                "enum_time": repository.get("enum_time"),
                "stars": repository.get("stars"),
                "can_fork": repository.get("can_fork"),
                "repository_creation_date": repository.get("repository_creation_date"),
                "vulnerable_commit_hash": repository.get("vulnerable_commit_hash"),
                "error": repository.get("error"),
                "repo_vulnerable": repository.get("repo_vulnerable"),
                "act_repo_vulnerable": repository.get("act_repo_vulnerable"),
                "vulnerable_with_secret_or_write_gh_token": repository.get(
                    "vulnerable_with_secret_or_write_gh_token"
                ),
                "execution_result": (
                    repository.get("execution_result")
                    if isinstance(repository.get("execution_result"), dict)
                    else None
                ),
                "risks": normalized_risks,
            }
        )
    return normalized


def _compute_risk_verdict_counts(risks: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "vulnerable": 0,
        "not_vulnerable": 0,
        "needs_review": 0,
        "error": 0,
        "unknown": 0,
    }
    for risk in risks:
        verdict = _determine_risk_verdict(risk)
        counts[verdict] = counts.get(verdict, 0) + 1
    return counts


def _collect_review_reasons(risks: list[dict[str, Any]], limit: int = 3) -> list[str]:
    reasons: list[str] = []
    seen: set[str] = set()
    for risk in risks:
        if _determine_risk_verdict(risk) != "needs_review":
            continue
        attack_result = risk.get("attack_result")
        raw_reason: Any = None
        if isinstance(attack_result, dict):
            raw_reason = attack_result.get("reason")
        if not isinstance(raw_reason, str):
            continue
        reason = raw_reason.strip()
        if not reason:
            continue
        if reason in seen:
            continue
        seen.add(reason)
        reasons.append(reason)
        if len(reasons) >= max(limit, 1):
            break
    return reasons


def _determine_risk_verdict(risk: dict[str, Any]) -> str:
    attack_result = risk.get("attack_result")
    if isinstance(attack_result, dict):
        status = str(attack_result.get("status") or "").strip().lower()
        security_report_verification_sources = (
            _extract_security_report_verification_sources(attack_result)
        )
        execution_result = attack_result.get("execution_result")
        execution_vulnerable = (
            execution_result.get("vulnerable")
            if isinstance(execution_result, dict)
            else None
        )
        if status in {
            "execution_error",
            "blocked_preparation_error",
            "skipped_node_runtime_unavailable",
        } or attack_result.get("error_class") is not None:
            return "error"
        if status in {
            "human_review_required",
            "prepared_for_manual_validation",
            "needs_human_review",
        }:
            return "needs_review"
        if security_report_verification_sources:
            return "vulnerable"
        if execution_vulnerable is True or status == "vulnerable_confirmed":
            return "vulnerable"
        if execution_vulnerable is False or status in {
            "not_vulnerable_after_execution",
            "skipped_read_only_token_without_secrets",
            "not_vulnerable",
        }:
            return "not_vulnerable"
        if status:
            return "unknown"

    ai_analysis = risk.get("ai-analysis")
    if isinstance(ai_analysis, dict):
        if bool(ai_analysis.get("vulnerable")):
            return "vulnerable"
        return "not_vulnerable"
    return "unknown"


def _summarize_attack_result(attack_result: Any) -> dict[str, Any] | None:
    if not isinstance(attack_result, dict):
        return None
    verification_sources = _extract_security_report_verification_sources(attack_result)
    execution_result = attack_result.get("execution_result")
    github_probe = attack_result.get("github_token_probe")
    github_permissions = attack_result.get("github_token_permissions")
    return {
        "status": attack_result.get("status"),
        "reason": attack_result.get("reason"),
        "attempt_count": attack_result.get("attempt_count"),
        "pull_request_url": attack_result.get("pull_request_url"),
        "workspace_path": attack_result.get("workspace_path"),
        "error_class": attack_result.get("error_class"),
        "error_stage": attack_result.get("error_stage"),
        "failure_fingerprint": attack_result.get("failure_fingerprint"),
        "execution_vulnerable": (
            execution_result.get("vulnerable")
            if isinstance(execution_result, dict)
            else None
        ),
        "execution_run_id": (
            execution_result.get("run_id")
            if isinstance(execution_result, dict)
            else None
        ),
        "execution_evidence_source": (
            execution_result.get("evidence_source")
            if isinstance(execution_result, dict)
            else None
        ),
        "exploit_job": _extract_exploit_job(
            attack_result=attack_result,
            execution_result=execution_result if isinstance(execution_result, dict) else None,
        ),
        "probe_status": (
            github_probe.get("status")
            if isinstance(github_probe, dict)
            else None
        ),
        "probe_reason": (
            github_probe.get("reason")
            if isinstance(github_probe, dict)
            else None
        ),
        "permissions_classification": attack_result.get(
            "github_token_permissions_classification"
        ),
        "permissions_value": (
            json.dumps(github_permissions, sort_keys=True)
            if isinstance(github_permissions, dict)
            else None
        ),
        "security_report_verification_sources": verification_sources,
        "security_report_verification_label": _render_verification_sources_label(
            verification_sources
        ),
        "hookbin_url": (
            execution_result.get("hookbin_url")
            if isinstance(execution_result, dict)
            else None
        ),
        "hookbin_logs": (
            execution_result.get("hookbin_logs")
            if isinstance(execution_result, dict)
            else None
        ),
        "exploit_patch": _extract_exploit_patch(
            attack_result=attack_result,
            execution_result=execution_result if isinstance(execution_result, dict) else None,
        ),
    }


def _extract_exploit_job(
    *,
    attack_result: dict[str, Any],
    execution_result: dict[str, Any] | None,
) -> str | None:
    direct_attack_value = attack_result.get("exploit_job")
    if isinstance(direct_attack_value, str) and direct_attack_value.strip():
        return direct_attack_value.strip()

    if isinstance(execution_result, dict):
        direct_execution_value = execution_result.get("exploit_job")
        if isinstance(direct_execution_value, str) and direct_execution_value.strip():
            return direct_execution_value.strip()

    candidate_attempt_lists: list[Any] = []
    if isinstance(execution_result, dict):
        candidate_attempt_lists.append(execution_result.get("attempts"))
    candidate_attempt_lists.append(attack_result.get("attempts"))

    for attempts in candidate_attempt_lists:
        if not isinstance(attempts, list):
            continue
        for attempt in attempts:
            if not isinstance(attempt, dict):
                continue
            direct_attempt_value = attempt.get("exploit_job")
            if isinstance(direct_attempt_value, str) and direct_attempt_value.strip():
                return direct_attempt_value.strip()
            agent_output = attempt.get("agent_output")
            if not isinstance(agent_output, dict):
                continue
            nested_value = agent_output.get("exploit_job")
            if isinstance(nested_value, str) and nested_value.strip():
                return nested_value.strip()

    return None


def _extract_exploit_patch(
    *,
    attack_result: dict[str, Any],
    execution_result: dict[str, Any] | None,
) -> str | None:
    candidate_patch_objects: list[Any] = []
    if isinstance(execution_result, dict):
        candidate_patch_objects.append(execution_result.get("exploit_patch"))
    candidate_patch_objects.append(attack_result.get("exploit_patch"))

    for patch_object in candidate_patch_objects:
        if not isinstance(patch_object, dict):
            continue
        patch_value = patch_object.get("patch")
        if isinstance(patch_value, str) and patch_value.strip():
            return patch_value

    return None


def _extract_security_report_verification_sources(
    attack_result: dict[str, Any],
) -> list[str]:
    raw_sources = attack_result.get("security_report_verification_sources")
    if not isinstance(raw_sources, list):
        return []
    normalized: list[str] = []
    for source in raw_sources:
        source_name = str(source).strip().lower()
        if source_name not in {"hosted", "act"}:
            continue
        if source_name in normalized:
            continue
        normalized.append(source_name)
    return normalized


def _render_verification_sources_label(sources: list[str]) -> str:
    source_set = set(sources)
    if source_set == {"hosted", "act"}:
        return "Hosted + Act"
    if source_set == {"hosted"}:
        return "Hosted only"
    if source_set == {"act"}:
        return "Act only"
    return "Not confirmed"


def _compute_repository_review_focus(repository: dict[str, Any]) -> dict[str, Any]:
    repo_vulnerable = _to_bool(repository.get("repo_vulnerable"))
    act_repo_vulnerable = _to_bool(repository.get("act_repo_vulnerable"))
    has_mismatch = (
        repo_vulnerable is not None
        and act_repo_vulnerable is not None
        and repo_vulnerable != act_repo_vulnerable
    )

    in_hookbin_scope = repo_vulnerable is True or act_repo_vulnerable is True
    hookbin_values: list[Any] = []
    has_security_source = False

    risks = repository.get("risks")
    if isinstance(risks, list):
        for risk in risks:
            if not isinstance(risk, dict):
                continue
            attack_result = risk.get("attack_result")
            if not isinstance(attack_result, dict):
                continue
            if _extract_security_report_verification_sources(attack_result):
                has_security_source = True
            execution_result = attack_result.get("execution_result")
            if isinstance(execution_result, dict) and "hookbin_logs" in execution_result:
                hookbin_values.append(execution_result.get("hookbin_logs"))

    execution_result = repository.get("execution_result")
    if isinstance(execution_result, dict) and "hookbin_logs" in execution_result:
        hookbin_values.append(execution_result.get("hookbin_logs"))

    has_hookbin_missing_field = in_hookbin_scope and not hookbin_values
    has_hookbin_empty_string = (
        in_hookbin_scope
        and bool(hookbin_values)
        and not any(value != "" for value in hookbin_values)
    )
    has_hookbin_not_empty_string = (
        in_hookbin_scope
        and bool(hookbin_values)
        and any(value != "" for value in hookbin_values)
    )
    needs_human_review = (
        has_mismatch or has_hookbin_missing_field or has_hookbin_empty_string
    )

    return {
        "repo_vulnerable": repo_vulnerable,
        "act_repo_vulnerable": act_repo_vulnerable,
        "mismatch": has_mismatch,
        "hookbin_in_scope": in_hookbin_scope,
        "hookbin_missing_field": has_hookbin_missing_field,
        "hookbin_empty_string": has_hookbin_empty_string,
        "hookbin_not_empty_string": has_hookbin_not_empty_string,
        "has_security_source": has_security_source,
        "needs_human_review": needs_human_review,
    }


def _to_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    if isinstance(value, (int, float)):
        if value == 1:
            return True
        if value == 0:
            return False
        return None
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "yes", "y", "1"}:
            return True
        if normalized in {"false", "no", "n", "0"}:
            return False
    return None


def _extract_workflow_refs(risk: dict[str, Any]) -> list[WorkflowRef]:
    path_entries = risk.get("gato-x-path") or []
    refs: list[WorkflowRef] = []
    seen: set[tuple[str, str, str]] = set()
    for entry in path_entries:
        node_value = None
        if isinstance(entry, dict):
            raw_value = entry.get("node")
            if isinstance(raw_value, str):
                node_value = raw_value
        if not node_value:
            continue
        inner_match = _NODE_INNER_PATTERN.search(node_value)
        if inner_match is None:
            continue
        parsed = _parse_node_inner(inner_match.group(1))
        if parsed is None:
            continue
        key = (parsed.repo_name, parsed.ref, parsed.path)
        if key in seen:
            continue
        seen.add(key)
        refs.append(parsed)
    return refs


def _parse_node_inner(value: str) -> WorkflowRef | None:
    parts = value.split(":", 2)
    if len(parts) != 3:
        return None
    repo_name, ref, path_fragment = parts
    if not repo_name or not ref or not path_fragment:
        return None

    path = path_fragment.split("#", 1)[0]
    if not (path.endswith(".yaml") or path.endswith(".yml")):
        return None

    return WorkflowRef(repo_name=repo_name, ref=ref, path=path)


def _humanize_ai_analysis(ai_analysis: dict[str, Any]) -> dict[str, str]:
    vulnerable = bool(ai_analysis.get("vulnerable"))
    verdict = "Likely Vulnerable" if vulnerable else "Likely Not Vulnerable"
    confidence = str(ai_analysis.get("confidence") or "unknown").title()
    explanation = str(ai_analysis.get("explanation") or "").strip()
    impact = str(ai_analysis.get("impact") or "").strip()
    poc = str(ai_analysis.get("poc") or "").strip()

    return {
        "verdict": verdict,
        "confidence": confidence,
        "why": explanation or "No explanation was provided.",
        "impact": impact or "No impact details were provided.",
        "review_steps": poc or "No PoC steps were provided.",
    }


def _first_value(query: dict[str, list[str]], key: str) -> str | None:
    values = query.get(key) or []
    if not values:
        return None
    value = values[0].strip()
    return value or None


def _parse_int_query(query: dict[str, list[str]], key: str) -> int | None:
    raw_value = _first_value(query, key)
    if raw_value is None:
        return None
    try:
        return int(raw_value)
    except ValueError:
        return None


def _filter_payload_for_repository(payload: dict[str, Any], repository_name: str) -> dict[str, Any]:
    filtered_payload = deepcopy(payload)

    if isinstance(filtered_payload.get("ai_enumeration"), list):
        matches = [
            repository
            for repository in filtered_payload["ai_enumeration"]
            if isinstance(repository, dict) and repository.get("name") == repository_name
        ]
        if not matches:
            raise KeyError(repository_name)
        filtered_payload["ai_enumeration"] = matches
        return filtered_payload

    enumeration = filtered_payload.get("enumeration")
    if isinstance(enumeration, dict) and isinstance(enumeration.get("repositories"), list):
        matches = [
            repository
            for repository in enumeration["repositories"]
            if isinstance(repository, dict) and repository.get("name") == repository_name
        ]
        if not matches:
            raise KeyError(repository_name)
        enumeration["repositories"] = matches
        return filtered_payload

    raise KeyError(repository_name)


def _sanitize_repository_name(repository_name: str) -> str:
    sanitized = repository_name.replace("/", "_")
    sanitized = re.sub(r"[^A-Za-z0-9._-]+", "_", sanitized).strip("_")
    return sanitized or "repository"



_INDEX_HTML = INDEX_HTML
