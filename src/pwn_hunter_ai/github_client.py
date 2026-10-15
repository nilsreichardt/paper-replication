from __future__ import annotations

from base64 import b64decode, b64encode
from collections import deque
from dataclasses import dataclass, field
import logging
from threading import Lock
import time
from typing import Any
from urllib.parse import quote

import requests


LOGGER = logging.getLogger(__name__)


class GitHubApiError(RuntimeError):
    pass


@dataclass(slots=True)
class _TokenState:
    token: str
    code_search_requests: deque[float] = field(default_factory=deque)
    code_search_reset_at: float = 0.0


class GitHubTokenPool:
    _code_search_limit = 10
    _code_search_window_seconds = 60.0

    def __init__(self, tokens: list[str]) -> None:
        self._states = [_TokenState(token=token) for token in tokens]
        self._index = 0
        self._lock = Lock()

    def current(self) -> str | None:
        if not self._states:
            return None
        with self._lock:
            return self._states[self._index].token

    def rotate(self) -> bool:
        if len(self._states) <= 1:
            return False
        with self._lock:
            self._index = (self._index + 1) % len(self._states)
            return True

    def acquire_code_search_token(self) -> tuple[str | None, float]:
        if not self._states:
            return None, 0.0

        with self._lock:
            now = time.time()
            wait_candidates: list[float] = []

            for offset in range(len(self._states)):
                index = (self._index + offset) % len(self._states)
                state = self._states[index]
                self._prune_code_search_window(state, now)

                if state.code_search_reset_at > now:
                    wait_candidates.append(state.code_search_reset_at - now)
                    continue

                if len(state.code_search_requests) < self._code_search_limit:
                    state.code_search_requests.append(now)
                    self._index = index
                    return state.token, 0.0

                wait_candidates.append(
                    max(
                        state.code_search_requests[0]
                        + self._code_search_window_seconds
                        - now,
                        0.0,
                    )
                )

            return None, min(wait_candidates, default=0.0)

    def mark_code_search_rate_limited(self, token: str, reset_at: float | None) -> None:
        with self._lock:
            state = self._find_state(token)
            if state is None:
                return
            state.code_search_requests.clear()
            state.code_search_reset_at = reset_at or (
                time.time() + self._code_search_window_seconds
            )

    def clear_code_search_rate_limit(self, token: str) -> None:
        with self._lock:
            state = self._find_state(token)
            if state is None:
                return
            if state.code_search_reset_at <= time.time():
                state.code_search_reset_at = 0.0

    @property
    def size(self) -> int:
        return len(self._states)

    def _find_state(self, token: str) -> _TokenState | None:
        for state in self._states:
            if state.token == token:
                return state
        return None

    def _prune_code_search_window(self, state: _TokenState, now: float) -> None:
        if state.code_search_reset_at <= now:
            state.code_search_reset_at = 0.0

        while (
            state.code_search_requests
            and now - state.code_search_requests[0] >= self._code_search_window_seconds
        ):
            state.code_search_requests.popleft()


class GitHubClient:
    api_base_url = "https://api.github.com"
    _max_transient_retries = 5

    def __init__(
        self,
        tokens: list[str] | None = None,
        *,
        session: requests.Session | None = None,
    ) -> None:
        self._token_pool = GitHubTokenPool(tokens or [])
        self._session = session or requests.Session()
        self._repo_cache: dict[str, dict[str, Any]] = {}
        self._content_cache: dict[tuple[str, str, str], str] = {}
        self._cache_lock = Lock()

    def get_repo_metadata(
        self, repo_name: str, *, force_refresh: bool = False
    ) -> dict[str, Any]:
        if not force_refresh:
            with self._cache_lock:
                cached = self._repo_cache.get(repo_name)
                if cached is not None:
                    return cached

        data = self._request_json("GET", f"/repos/{repo_name}")
        metadata = {
            "name": data["full_name"],
            "created_at": data["created_at"],
            "default_branch": data["default_branch"],
            "is_fork": bool(data.get("fork")),
            "parent_full_name": (
                (data.get("parent") or {}).get("full_name")
                if isinstance(data.get("parent"), dict)
                else None
            ),
        }

        with self._cache_lock:
            self._repo_cache[repo_name] = metadata
        return metadata

    def list_commits(
        self,
        repo_name: str,
        *,
        since: str | None = None,
        until: str | None = None,
        page: int = 1,
        per_page: int = 100,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"page": page, "per_page": per_page}
        if since:
            params["since"] = since
        if until:
            params["until"] = until

        response = self._request(
            "GET",
            f"/repos/{repo_name}/commits",
            params=params,
        )
        data = response.json()
        if not isinstance(data, list):
            raise GitHubApiError(
                f"GitHub did not return a commit list for {repo_name}."
            )
        return data

    def get_commit(self, repo_name: str, ref: str) -> dict[str, Any]:
        return self._request_json("GET", f"/repos/{repo_name}/commits/{ref}")

    def get_file_content(self, repo_name: str, path: str, ref: str) -> str:
        cache_key = (repo_name, path, ref)
        with self._cache_lock:
            cached = self._content_cache.get(cache_key)
            if cached is not None:
                return cached

        data = self._request_json(
            "GET",
            f"/repos/{repo_name}/contents/{path}",
            params={"ref": ref},
        )

        if data.get("encoding") != "base64" or "content" not in data:
            raise GitHubApiError(
                f"Unexpected GitHub contents payload for {repo_name}:{path}@{ref}."
            )

        decoded = b64decode(data["content"]).decode("utf-8")
        with self._cache_lock:
            self._content_cache[cache_key] = decoded
        return decoded

    def get_authenticated_user(self) -> dict[str, Any]:
        user = self._request_json("GET", "/user")
        email: str | None = None
        try:
            response = self._request("GET", "/user/emails")
            email = self._select_user_email(response.json())
        except (GitHubApiError, ValueError):
            email = None
        user["email"] = email
        return user

    @staticmethod
    def _select_user_email(emails_data: Any) -> str | None:
        if not isinstance(emails_data, list):
            return None

        fallback: str | None = None
        for item in emails_data:
            if not isinstance(item, dict):
                continue
            candidate = item.get("email")
            if not isinstance(candidate, str):
                continue
            if candidate.lower().endswith("@users.noreply.github.com"):
                return candidate
            if fallback is None and item.get("primary") is True:
                fallback = candidate
            elif fallback is None and item.get("verified") is True:
                fallback = candidate
            elif fallback is None:
                fallback = candidate
        return fallback

    def get_branch_head_sha(self, repo_name: str, branch: str) -> str:
        encoded_branch = quote(branch, safe="")
        data = self._request_json("GET", f"/repos/{repo_name}/branches/{encoded_branch}")
        commit = data.get("commit") or {}
        sha = commit.get("sha")
        if not isinstance(sha, str) or not sha:
            raise GitHubApiError(
                f"GitHub did not return a branch head SHA for {repo_name}@{branch}."
            )
        return sha

    def list_directory(
        self, repo_name: str, path: str, ref: str
    ) -> list[dict[str, Any]]:
        data = self._request_json(
            "GET",
            f"/repos/{repo_name}/contents/{path}",
            params={"ref": ref},
        )
        if not isinstance(data, list):
            raise GitHubApiError(
                f"Expected a directory listing for {repo_name}:{path}@{ref}."
            )
        return data

    def create_fork(self, repo_name: str, name: str | None = None) -> dict[str, Any]:
        json_body: dict[str, Any] | None = None
        if isinstance(name, str) and name.strip():
            json_body = {"name": name.strip()}
        data = self._request_json(
            "POST",
            f"/repos/{repo_name}/forks",
            json_body=json_body,
        )
        full_name = data.get("full_name")
        if isinstance(full_name, str) and full_name:
            self._wait_for_repository(full_name, force_refresh=True)
        return data

    def delete_repo(self, repo_name: str) -> None:
        self._request("DELETE", f"/repos/{repo_name}")
        with self._cache_lock:
            self._repo_cache.pop(repo_name, None)

    def enable_actions(self, repo_name: str, *, enabled: bool = True) -> None:
        self._request(
            "PUT",
            f"/repos/{repo_name}/actions/permissions",
            json_body={"enabled": enabled},
        )

    def enable_workflow(self, repo_name: str, workflow_id: str) -> None:
        identifier = str(workflow_id).strip()
        if not identifier:
            raise ValueError("workflow_id must be a non-empty string.")
        encoded_identifier = quote(identifier, safe="")
        self._request(
            "PUT",
            f"/repos/{repo_name}/actions/workflows/{encoded_identifier}/enable",
        )

    def get_actions_secret_public_key(self, repo_name: str) -> dict[str, str | None]:
        response = self._request("GET", f"/repos/{repo_name}/actions/secrets/public-key")
        try:
            data = response.json()
        except ValueError as exc:
            raise GitHubApiError(
                f"GitHub returned invalid JSON for /repos/{repo_name}/actions/secrets/public-key."
            ) from exc
        key_id = data.get("key_id")
        key = data.get("key")
        if not isinstance(key_id, str) or not isinstance(key, str):
            raise GitHubApiError(
                f"GitHub did not return a valid Actions public key for {repo_name}."
            )
        return {
            "key_id": key_id,
            "key": key,
            "github_request_id": response.headers.get("X-GitHub-Request-Id"),
        }

    def set_actions_secret(
        self, repo_name: str, name: str, value: str
    ) -> dict[str, str | None]:
        key_payload = self.get_actions_secret_public_key(repo_name)
        encrypted_value = _encrypt_actions_secret(
            value=value, public_key=str(key_payload["key"])
        )
        response = self._request(
            "PUT",
            f"/repos/{repo_name}/actions/secrets/{name}",
            json_body={
                "encrypted_value": encrypted_value,
                "key_id": str(key_payload["key_id"]),
            },
        )
        return {
            "key_id": str(key_payload["key_id"]),
            "github_request_id": response.headers.get("X-GitHub-Request-Id"),
        }

    def search_code_count(self, query: str) -> int:
        data = self._request_json(
            "GET",
            "/search/code",
            params={"q": query, "per_page": 1, "page": 1},
        )
        total_count = data.get("total_count")
        if not isinstance(total_count, int):
            raise GitHubApiError(
                f"GitHub search did not return a valid total_count for query: {query}"
            )
        return total_count

    def search_code(
        self, query: str, *, page: int, per_page: int = 100
    ) -> dict[str, Any]:
        return self._request_json(
            "GET",
            "/search/code",
            params={"q": query, "page": page, "per_page": per_page},
        )

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        response = self._request(method, path, params=params, json_body=json_body)
        try:
            return response.json()
        except ValueError as exc:
            raise GitHubApiError(f"GitHub returned invalid JSON for {path}.") from exc

    def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> requests.Response:
        token_attempts = max(self._token_pool.size, 1)
        is_code_search = method == "GET" and path == "/search/code"
        transient_retries = 0
        while True:
            wait_candidates: list[float] = []
            transient_error: Exception | None = None
            transient_wait_seconds: float | None = None
            transient_response: requests.Response | None = None

            for attempt in range(token_attempts):
                headers = {
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                }
                token = self._token_pool.current()
                if is_code_search:
                    token, wait_seconds = self._token_pool.acquire_code_search_token()
                    if wait_seconds > 0:
                        wait_candidates.append(wait_seconds)
                    if token is None:
                        break
                if token:
                    headers["Authorization"] = f"Bearer {token}"

                LOGGER.debug(f"Requesting {method} {path} with params: {params}")
                try:
                    response = self._session.request(
                        method,
                        f"{self.api_base_url}{path}",
                        headers=headers,
                        params=params,
                        json=json_body,
                        timeout=30,
                    )
                except requests.RequestException as exc:
                    if not _is_retryable_exception(exc):
                        raise GitHubApiError(
                            f"GitHub request for {path} failed: {exc}"
                        ) from exc
                    transient_error = exc
                    transient_wait_seconds = _transient_retry_wait_seconds(
                        None, transient_retries
                    )
                    break

                if response.ok:
                    if is_code_search and token:
                        self._token_pool.clear_code_search_rate_limit(token)
                    return response

                if _is_rate_limited(response):
                    wait_seconds = _rate_limit_wait_seconds(response)
                    if is_code_search and token:
                        self._token_pool.mark_code_search_rate_limited(
                            token, _rate_limit_reset_at(response)
                        )
                    if wait_seconds > 0:
                        wait_candidates.append(wait_seconds)
                    if attempt + 1 < token_attempts and self._token_pool.rotate():
                        LOGGER.warning(
                            "GitHub rate limit hit for current token on %s. Switching token (%s/%s).",
                            path,
                            attempt + 1,
                            token_attempts,
                        )
                        continue
                    break

                if _is_retryable_response(response):
                    transient_response = response
                    transient_wait_seconds = _transient_retry_wait_seconds(
                        response, transient_retries
                    )
                    break

                raise GitHubApiError(_build_error_message(response, path))

            if wait_candidates:
                wait_seconds = min(wait_candidates)
                LOGGER.warning(
                    "GitHub rate limit hit for %s across %s token(s). Sleeping %.1f seconds until reset.",
                    path,
                    token_attempts,
                    wait_seconds,
                )
                time.sleep(wait_seconds)
                continue

            if transient_error is not None:
                if transient_retries >= self._max_transient_retries:
                    raise GitHubApiError(
                        f"GitHub request for {path} failed: {transient_error}"
                    ) from transient_error

                transient_retries += 1
                wait_seconds = transient_wait_seconds or 0.0
                LOGGER.warning(
                    "GitHub request for %s failed with a transient transport error (%s). Retrying in %.1f seconds (%s/%s).",
                    path,
                    transient_error.__class__.__name__,
                    wait_seconds,
                    transient_retries,
                    self._max_transient_retries,
                )
                if self._token_pool.size > 1:
                    self._token_pool.rotate()
                time.sleep(wait_seconds)
                continue

            if transient_response is not None:
                if transient_retries >= self._max_transient_retries:
                    raise GitHubApiError(_build_error_message(transient_response, path))

                transient_retries += 1
                wait_seconds = transient_wait_seconds or 0.0
                LOGGER.warning(
                    "GitHub request for %s returned a transient error (%s). Retrying in %.1f seconds (%s/%s).",
                    path,
                    transient_response.status_code,
                    wait_seconds,
                    transient_retries,
                    self._max_transient_retries,
                )
                if self._token_pool.size > 1:
                    self._token_pool.rotate()
                time.sleep(wait_seconds)
                continue

            raise GitHubApiError(
                f"GitHub request for {path} failed without a retryable response."
            )

    def _wait_for_repository(
        self, repo_name: str, *, force_refresh: bool = False
    ) -> None:
        deadline = time.time() + 60.0
        while True:
            try:
                self.get_repo_metadata(repo_name, force_refresh=force_refresh)
                return
            except GitHubApiError:
                if time.time() >= deadline:
                    raise
                time.sleep(2.0)

    def get_ref(self, repo_name: str, ref: str) -> str:
        encoded_ref = quote(ref, safe="")
        data = self._request_json("GET", f"/repos/{repo_name}/git/ref/{encoded_ref}")
        object_data = data.get("object") or {}
        sha = object_data.get("sha")
        if not isinstance(sha, str) or not sha:
            raise GitHubApiError(
                f"GitHub did not return a valid SHA for ref {ref} in {repo_name}."
            )
        return sha

    def create_branch(
        self, repo_name: str, branch_name: str, sha: str
    ) -> dict[str, Any]:
        ref = f"refs/heads/{branch_name}"
        return self._request_json(
            "POST",
            f"/repos/{repo_name}/git/refs",
            json_body={"ref": ref, "sha": sha},
        )

    def get_file_sha(self, repo_name: str, path: str, ref: str) -> str:
        data = self._request_json(
            "GET",
            f"/repos/{repo_name}/contents/{path}",
            params={"ref": ref},
        )
        sha = data.get("sha")
        if not isinstance(sha, str) or not sha:
            raise GitHubApiError(
                f"GitHub did not return a valid SHA for {repo_name}:{path}@{ref}."
            )
        return sha

    def create_or_update_file(
        self,
        repo_name: str,
        path: str,
        content: str,
        message: str,
        branch: str,
        sha: str | None = None,
    ) -> dict[str, Any]:
        import base64

        encoded_content = base64.b64encode(content.encode("utf-8")).decode("utf-8")
        json_body: dict[str, Any] = {
            "message": message,
            "content": encoded_content,
            "branch": branch,
        }
        if sha:
            json_body["sha"] = sha
        return self._request_json(
            "PUT",
            f"/repos/{repo_name}/contents/{path}",
            json_body=json_body,
        )

    def create_pull_request(
        self,
        repo_name: str,
        title: str,
        body: str,
        head: str,
        base: str,
        draft: bool = False,
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            f"/repos/{repo_name}/pulls",
            json_body={
                "title": title,
                "body": body,
                "head": head,
                "base": base,
                "draft": draft,
            },
        )

    def update_pull_request(
        self,
        repo_name: str,
        pull_number: int,
        *,
        title: str | None = None,
        body: str | None = None,
        state: str | None = None,
    ) -> dict[str, Any]:
        json_body: dict[str, Any] = {}
        if title is not None:
            json_body["title"] = title
        if body is not None:
            json_body["body"] = body
        if state is not None:
            json_body["state"] = state
        if not json_body:
            raise GitHubPullRequestError(
                "update_pull_request requires at least one field to update."
            )
        return self._request_json(
            "PATCH",
            f"/repos/{repo_name}/pulls/{pull_number}",
            json_body=json_body,
        )

    def close_pull_request(self, repo_name: str, pull_number: int) -> dict[str, Any]:
        return self._request_json(
            "PATCH",
            f"/repos/{repo_name}/pulls/{pull_number}",
            json_body={"state": "closed"},
        )

    def ready_pull_request_for_review(
        self,
        repo_name: str,
        pull_number: int,
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            f"/repos/{repo_name}/pulls/{pull_number}/ready_for_review",
        )

    def create_pull_request_comment(
        self, repo_name: str, pull_number: int, body: str
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            f"/repos/{repo_name}/issues/{pull_number}/comments",
            json_body={"body": body},
        )

    def get_pull_request(self, repo_name: str, pull_number: int) -> dict[str, Any]:
        return self._request_json("GET", f"/repos/{repo_name}/pulls/{pull_number}")

    def request_pull_request_reviewers(
        self,
        repo_name: str,
        pull_number: int,
        *,
        reviewers: list[str] | None = None,
        team_reviewers: list[str] | None = None,
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            f"/repos/{repo_name}/pulls/{pull_number}/requested_reviewers",
            json_body={
                "reviewers": reviewers or [],
                "team_reviewers": team_reviewers or [],
            },
        )

    def remove_pull_request_reviewers(
        self,
        repo_name: str,
        pull_number: int,
        *,
        reviewers: list[str] | None = None,
        team_reviewers: list[str] | None = None,
    ) -> dict[str, Any]:
        return self._request_json(
            "DELETE",
            f"/repos/{repo_name}/pulls/{pull_number}/requested_reviewers",
            json_body={
                "reviewers": reviewers or [],
                "team_reviewers": team_reviewers or [],
            },
        )

    def create_pull_request_review(
        self,
        repo_name: str,
        pull_number: int,
        *,
        event: str,
        body: str = "",
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            f"/repos/{repo_name}/pulls/{pull_number}/reviews",
            json_body={
                "event": event,
                "body": body,
            },
        )

    def add_issue_assignees(
        self,
        repo_name: str,
        issue_number: int,
        assignees: list[str],
    ) -> dict[str, Any]:
        return self._request_json(
            "POST",
            f"/repos/{repo_name}/issues/{issue_number}/assignees",
            json_body={"assignees": assignees},
        )

    def remove_issue_assignees(
        self,
        repo_name: str,
        issue_number: int,
        assignees: list[str],
    ) -> dict[str, Any]:
        return self._request_json(
            "DELETE",
            f"/repos/{repo_name}/issues/{issue_number}/assignees",
            json_body={"assignees": assignees},
        )

    def graphql(
        self, query: str, variables: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        payload = {
            "query": query,
            "variables": variables or {},
        }
        result = self._request_json("POST", "/graphql", json_body=payload)
        errors = result.get("errors")
        if isinstance(errors, list) and errors:
            first = errors[0]
            if isinstance(first, dict):
                message = str(first.get("message") or "").strip() or str(first)
            else:
                message = str(first)
            raise GitHubApiError(f"GitHub GraphQL request failed: {message}")
        return result

    def convert_pull_request_to_draft(
        self,
        repo_name: str,
        pull_number: int,
    ) -> dict[str, Any]:
        pull_request = self.get_pull_request(repo_name, pull_number)
        pull_request_id = str(pull_request.get("node_id") or "").strip()
        if not pull_request_id:
            raise GitHubPullRequestError(
                f"Missing node_id for pull request {repo_name}#{pull_number}."
            )
        return self.graphql(
            "mutation($pullRequestId: ID!) {"
            "  convertPullRequestToDraft(input: { pullRequestId: $pullRequestId }) {"
            "    pullRequest { id isDraft }"
            "  }"
            "}",
            variables={"pullRequestId": pull_request_id},
        )

    def list_pull_request_files(
        self,
        repo_name: str,
        pull_number: int,
        *,
        per_page: int = 100,
    ) -> list[dict[str, Any]]:
        page = 1
        files: list[dict[str, Any]] = []
        while True:
            data = self._request_json(
                "GET",
                f"/repos/{repo_name}/pulls/{pull_number}/files",
                params={"per_page": per_page, "page": page},
            )
            if not isinstance(data, list):
                raise GitHubApiError(
                    f"Expected a list of pull request files for {repo_name}#{pull_number}."
                )
            if not data:
                break
            files.extend(entry for entry in data if isinstance(entry, dict))
            if len(data) < per_page:
                break
            page += 1
        return files

    def list_pull_requests(
        self,
        repo_name: str,
        state: str = "open",
        head: str | None = None,
        base: str | None = None,
    ) -> list[dict[str, Any]]:
        params: dict[str, Any] = {"state": state}
        if head:
            params["head"] = head
        if base:
            params["base"] = base
        data = self._request_json("GET", f"/repos/{repo_name}/pulls", params=params)
        if not isinstance(data, list):
            raise GitHubPullRequestError(f"Expected a list of PRs for {repo_name}.")
        return data

    def get_workflow_runs(
        self,
        repo_name: str,
        branch: str | None = None,
        status: str | None = None,
        per_page: int = 30,
        page: int = 1,
    ) -> dict[str, Any]:
        params: dict[str, Any] = {"per_page": per_page, "page": page}
        if branch:
            params["branch"] = branch
        if status:
            params["status"] = status
        return self._request_json(
            "GET", f"/repos/{repo_name}/actions/runs", params=params
        )

    def get_workflow_run(self, repo_name: str, run_id: int) -> dict[str, Any]:
        return self._request_json("GET", f"/repos/{repo_name}/actions/runs/{run_id}")

    def get_workflow_run_logs_url(self, repo_name: str, run_id: int) -> str:
        run = self.get_workflow_run(repo_name, run_id)
        logs_url = run.get("logs_url")
        if not isinstance(logs_url, str) or not logs_url:
            raise GitHubWorkflowError(
                f"No logs_url found for run {run_id} in {repo_name}."
            )
        return logs_url

    def download_workflow_run_logs(self, repo_name: str, run_id: int) -> bytes:
        response = self._request("GET", f"/repos/{repo_name}/actions/runs/{run_id}/logs")
        return response.content

    def approve_workflow_run(self, repo_name: str, run_id: int) -> dict[str, Any]:
        return self._request_json(
            "POST",
            f"/repos/{repo_name}/actions/runs/{run_id}/approve",
        )


def _is_rate_limited(response: requests.Response) -> bool:
    if response.status_code not in {403, 429}:
        return False

    remaining = response.headers.get("X-RateLimit-Remaining")
    if remaining == "0":
        return True

    try:
        message = response.json().get("message", "")
    except ValueError:
        return False
    return "rate limit" in message.lower()


def _is_retryable_response(response: requests.Response) -> bool:
    if response.status_code in {500, 502, 503, 504}:
        return True
    if response.status_code != 408:
        return False

    try:
        message = response.json().get("message", "")
    except ValueError:
        message = response.text
    return "timed out" in message.lower() or "timeout" in message.lower()


def _is_retryable_exception(exc: requests.RequestException) -> bool:
    return isinstance(exc, (requests.ConnectionError, requests.Timeout))


def _build_error_message(response: requests.Response, path: str) -> str:
    try:
        payload = response.json()
    except ValueError:
        payload = {}
    message = payload.get("message") or response.text or "unknown error"
    errors = payload.get("errors")
    if isinstance(errors, list) and errors:
        parts: list[str] = []
        for error in errors[:3]:
            if isinstance(error, str):
                detail = error.strip()
            elif isinstance(error, dict):
                resource = str(error.get("resource") or "").strip()
                field = str(error.get("field") or "").strip()
                code = str(error.get("code") or "").strip()
                err_message = str(error.get("message") or "").strip()

                detail_parts = [part for part in (resource, field, code) if part]
                if detail_parts:
                    detail = ".".join(detail_parts)
                    if err_message:
                        detail = f"{detail}: {err_message}"
                else:
                    detail = err_message
            else:
                detail = str(error).strip()
            if detail:
                parts.append(detail)
        if parts:
            message = f"{message} ({'; '.join(parts)})"
    request_id = response.headers.get("X-GitHub-Request-Id")
    request_suffix = f" [request_id={request_id}]" if request_id else ""
    return (
        f"GitHub API request failed for {path}: "
        f"{response.status_code} {message}{request_suffix}"
    )


def _transient_retry_wait_seconds(
    response: requests.Response | None, retry_count: int
) -> float:
    if response is None:
        return float(2**retry_count)
    retry_after = response.headers.get("Retry-After")
    if retry_after:
        try:
            return max(float(retry_after), 0.0)
        except ValueError:
            pass
    return float(2**retry_count)


def _rate_limit_wait_seconds(response: requests.Response) -> float:
    reset_at = _rate_limit_reset_at(response)
    if reset_at is None:
        return 0.0
    return (
        max(reset_at - time.time(), 0.0) + 2.0
    )  # adding two seconds delay edge cases with GitHub rate limit resets


def _rate_limit_reset_at(response: requests.Response) -> float | None:
    reset_at = response.headers.get("X-RateLimit-Reset")
    if not reset_at:
        return None
    try:
        return float(reset_at)
    except ValueError:
        return None


def _encrypt_actions_secret(*, value: str, public_key: str) -> str:
    try:
        from nacl.public import PublicKey, SealedBox
    except ImportError as exc:
        raise RuntimeError(
            "PyNaCl is required for GitHub Actions secret encryption."
        ) from exc

    key = PublicKey(b64decode(public_key))
    sealed_box = SealedBox(key)
    encrypted = sealed_box.encrypt(value.encode("utf-8"))
    return b64encode(encrypted).decode("ascii")


class GitHubPullRequestError(GitHubApiError):
    pass


class GitHubWorkflowError(GitHubApiError):
    pass
