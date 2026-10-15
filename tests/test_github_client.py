from __future__ import annotations

from base64 import b64encode
from http.client import RemoteDisconnected
import json

import pytest
import requests

from pwn_hunter_ai.github_client import GitHubApiError, GitHubClient


class FakeResponse:
    def __init__(self, status_code: int, payload: dict, *, headers: dict | None = None) -> None:
        self.status_code = status_code
        self._payload = payload
        self.headers = headers or {}
        self.text = json.dumps(payload)

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300

    def json(self) -> dict:
        return self._payload


class FakeSession:
    def __init__(self, responses: list[FakeResponse | Exception]) -> None:
        self.responses = responses
        self.calls: list[dict] = []

    def request(self, method: str, url: str, **kwargs) -> FakeResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        response = self.responses.pop(0)
        if isinstance(response, Exception):
            raise response
        return response


def test_github_client_rotates_token_on_rate_limit() -> None:
    session = FakeSession(
        [
            FakeResponse(
                403,
                {"message": "API rate limit exceeded"},
                headers={"X-RateLimit-Remaining": "0"},
            ),
            FakeResponse(
                200,
                {
                    "full_name": "owner/repo",
                    "created_at": "2024-01-01T00:00:00Z",
                    "default_branch": "main",
                },
            ),
        ]
    )
    client = GitHubClient(tokens=["token-1", "token-2"], session=session)

    metadata = client.get_repo_metadata("owner/repo")

    assert metadata["default_branch"] == "main"
    assert session.calls[0]["headers"]["Authorization"] == "Bearer token-1"
    assert session.calls[1]["headers"]["Authorization"] == "Bearer token-2"


def test_github_client_force_refresh_bypasses_repo_metadata_cache() -> None:
    session = FakeSession(
        [
            FakeResponse(
                200,
                {
                    "full_name": "owner/repo",
                    "created_at": "2024-01-01T00:00:00Z",
                    "default_branch": "main",
                    "parent": {"full_name": "owner/source-a"},
                },
            ),
            FakeResponse(
                200,
                {
                    "full_name": "owner/repo",
                    "created_at": "2024-01-01T00:00:00Z",
                    "default_branch": "main",
                    "parent": {"full_name": "owner/source-b"},
                },
            ),
        ]
    )
    client = GitHubClient(tokens=["token"], session=session)

    cached = client.get_repo_metadata("owner/repo")
    cached_again = client.get_repo_metadata("owner/repo")
    refreshed = client.get_repo_metadata("owner/repo", force_refresh=True)

    assert cached["parent_full_name"] == "owner/source-a"
    assert cached_again["parent_full_name"] == "owner/source-a"
    assert refreshed["parent_full_name"] == "owner/source-b"
    assert len(session.calls) == 2


def test_github_client_decodes_content_payload() -> None:
    encoded = b64encode(b"name: CI\n").decode("ascii")
    session = FakeSession(
        [
            FakeResponse(
                200,
                {"encoding": "base64", "content": encoded},
            )
        ]
    )
    client = GitHubClient(tokens=["token"], session=session)

    content = client.get_file_content("owner/repo", ".github/workflows/test.yml", "main")

    assert content == "name: CI\n"


def test_github_client_sleeps_after_all_tokens_are_rate_limited_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(
        [
            FakeResponse(
                403,
                {"message": "API rate limit exceeded"},
                headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "1"},
            ),
            FakeResponse(
                403,
                {"message": "API rate limit exceeded"},
                headers={"X-RateLimit-Remaining": "0", "X-RateLimit-Reset": "3"},
            ),
            FakeResponse(
                200,
                {
                    "full_name": "owner/repo",
                    "created_at": "2024-01-01T00:00:00Z",
                    "default_branch": "main",
                },
            ),
        ]
    )
    client = GitHubClient(tokens=["token-1", "token-2"], session=session)
    slept: list[float] = []

    monkeypatch.setattr("pwn_hunter_ai.github_client.time.time", lambda: 0.0)
    monkeypatch.setattr("pwn_hunter_ai.github_client.time.sleep", slept.append)

    metadata = client.get_repo_metadata("owner/repo")

    assert metadata["name"] == "owner/repo"
    assert slept == [3.0]
    assert len(session.calls) == 3
    assert session.calls[0]["headers"]["Authorization"] == "Bearer token-1"
    assert session.calls[1]["headers"]["Authorization"] == "Bearer token-2"


def test_github_client_proactively_rotates_code_search_tokens_before_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession([FakeResponse(200, {"total_count": 1}) for _ in range(11)])
    client = GitHubClient(tokens=["token-1", "token-2"], session=session)

    call_count = {"value": 0}

    def fake_time() -> float:
        call_count["value"] += 1
        return 0.0 if call_count["value"] <= 10 else 1.0

    monkeypatch.setattr("pwn_hunter_ai.github_client.time.time", fake_time)

    for _ in range(10):
        assert client.search_code_count("query") == 1

    assert client.search_code_count("query") == 1
    assert session.calls[9]["headers"]["Authorization"] == "Bearer token-1"
    assert session.calls[10]["headers"]["Authorization"] == "Bearer token-2"


def test_github_client_waits_until_a_code_search_token_is_available(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession([FakeResponse(200, {"total_count": 1}) for _ in range(21)])
    client = GitHubClient(tokens=["token-1", "token-2"], session=session)
    slept: list[float] = []
    now = {"value": 0.0}

    def fake_time() -> float:
        return now["value"]

    def fake_sleep(seconds: float) -> None:
        slept.append(seconds)
        now["value"] += seconds

    monkeypatch.setattr("pwn_hunter_ai.github_client.time.time", fake_time)
    monkeypatch.setattr("pwn_hunter_ai.github_client.time.sleep", fake_sleep)

    for _ in range(10):
        assert client.search_code_count("query") == 1
    for _ in range(10):
        assert client.search_code_count("query") == 1

    assert client.search_code_count("query") == 1
    assert slept == [60.0]
    assert session.calls[20]["headers"]["Authorization"] == "Bearer token-2"


def test_github_client_retries_search_code_timeouts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(
        [
            FakeResponse(408, {"message": "This query timed out. Try a simpler query, or try again later"}),
            FakeResponse(200, {"total_count": 7}),
        ]
    )
    client = GitHubClient(tokens=["token"], session=session)
    slept: list[float] = []

    monkeypatch.setattr("pwn_hunter_ai.github_client.time.sleep", slept.append)

    total_count = client.search_code_count("query")

    assert total_count == 7
    assert slept == [1.0]
    assert len(session.calls) == 2


def test_github_client_raises_after_exhausting_search_code_timeout_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(
        [
            FakeResponse(408, {"message": "This query timed out. Try a simpler query, or try again later"})
            for _ in range(6)
        ]
    )
    client = GitHubClient(tokens=["token"], session=session)
    slept: list[float] = []

    monkeypatch.setattr("pwn_hunter_ai.github_client.time.sleep", slept.append)

    with pytest.raises(GitHubApiError, match="GitHub API request failed for /search/code: 408"):
        client.search_code_count("query")

    assert slept == [1.0, 2.0, 4.0, 8.0, 16.0]


def test_github_client_retries_remote_disconnects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(
        [
            requests.ConnectionError(RemoteDisconnected("Remote end closed connection without response")),
            FakeResponse(
                200,
                {
                    "full_name": "owner/repo",
                    "created_at": "2024-01-01T00:00:00Z",
                    "default_branch": "main",
                },
            ),
        ]
    )
    client = GitHubClient(tokens=["token"], session=session)
    slept: list[float] = []

    monkeypatch.setattr("pwn_hunter_ai.github_client.time.sleep", slept.append)

    metadata = client.get_repo_metadata("owner/repo")

    assert metadata["name"] == "owner/repo"
    assert slept == [1.0]
    assert len(session.calls) == 2


def test_github_client_raises_after_exhausting_remote_disconnect_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(
        [
            requests.ConnectionError(RemoteDisconnected("Remote end closed connection without response"))
            for _ in range(6)
        ]
    )
    client = GitHubClient(tokens=["token"], session=session)
    slept: list[float] = []

    monkeypatch.setattr("pwn_hunter_ai.github_client.time.sleep", slept.append)

    with pytest.raises(GitHubApiError, match="GitHub request for /repos/owner/repo failed:"):
        client.get_repo_metadata("owner/repo")
    assert slept == [1.0, 2.0, 4.0, 8.0, 16.0]


def test_github_client_approves_workflow_run() -> None:
    session = FakeSession([FakeResponse(201, {"message": "approved"})])
    client = GitHubClient(tokens=["token"], session=session)

    payload = client.approve_workflow_run("owner/repo", 123)

    assert payload["message"] == "approved"
    assert session.calls[0]["method"] == "POST"
    assert session.calls[0]["url"].endswith("/repos/owner/repo/actions/runs/123/approve")


def test_github_client_enables_workflow() -> None:
    session = FakeSession([FakeResponse(204, {})])
    client = GitHubClient(tokens=["token"], session=session)

    client.enable_workflow("owner/repo", ".github/workflows/python-tests.yml")

    assert session.calls[0]["method"] == "PUT"
    assert session.calls[0]["url"].endswith(
        "/repos/owner/repo/actions/workflows/.github%2Fworkflows%2Fpython-tests.yml/enable"
    )


def test_github_client_transient_retry_budget_is_independent_of_token_count(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    session = FakeSession(
        [
            FakeResponse(408, {"message": "This query timed out. Try a simpler query, or try again later"})
            for _ in range(6)
        ]
    )
    client = GitHubClient(tokens=["token-1", "token-2"], session=session)
    slept: list[float] = []

    monkeypatch.setattr("pwn_hunter_ai.github_client.time.sleep", slept.append)

    with pytest.raises(GitHubApiError, match="GitHub API request failed for /search/code: 408"):
        client.search_code_count("query")

    assert slept == [1.0, 2.0, 4.0, 8.0, 16.0]
    assert len(session.calls) == 6


def test_github_client_includes_validation_error_details_in_exception_message() -> None:
    session = FakeSession(
        [
            FakeResponse(
                422,
                {
                    "message": "Validation Failed",
                    "errors": [
                        {
                            "resource": "PullRequest",
                            "field": "head",
                            "code": "invalid",
                        }
                    ],
                },
            )
        ]
    )
    client = GitHubClient(tokens=["token"], session=session)

    with pytest.raises(
        GitHubApiError,
        match=r"422 Validation Failed \(PullRequest\.head\.invalid\)",
    ):
        client.create_pull_request(
            repo_name="owner/repo",
            title="x",
            body="x",
            head="fork:branch",
            base="main",
        )


def test_create_pull_request_includes_draft_flag() -> None:
    session = FakeSession([FakeResponse(201, {"number": 1})])
    client = GitHubClient(tokens=["token"], session=session)

    client.create_pull_request(
        repo_name="owner/repo",
        title="x",
        body="x",
        head="fork:branch",
        base="main",
        draft=True,
    )

    assert session.calls[0]["json"] == {
        "title": "x",
        "body": "x",
        "head": "fork:branch",
        "base": "main",
        "draft": True,
    }


def test_get_branch_head_sha_url_encodes_branch_name() -> None:
    session = FakeSession([FakeResponse(200, {"commit": {"sha": "abc123"}})])
    client = GitHubClient(tokens=["token"], session=session)

    sha = client.get_branch_head_sha("owner/repo", "feature/temp-change")

    assert sha == "abc123"
    assert (
        session.calls[0]["url"]
        == "https://api.github.com/repos/owner/repo/branches/feature%2Ftemp-change"
    )


def test_get_ref_url_encodes_ref_name() -> None:
    session = FakeSession([FakeResponse(200, {"object": {"sha": "def456"}})])
    client = GitHubClient(tokens=["token"], session=session)

    sha = client.get_ref("owner/repo", "heads/feature/temp-change")

    assert sha == "def456"
    assert (
        session.calls[0]["url"]
        == "https://api.github.com/repos/owner/repo/git/ref/heads%2Ffeature%2Ftemp-change"
    )
