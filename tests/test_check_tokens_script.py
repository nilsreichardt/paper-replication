from __future__ import annotations

import importlib.util
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "check_tokens.py"


def _load_script_module():
    spec = importlib.util.spec_from_file_location("check_tokens", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FakeHtmlResponse:
    def __init__(self, status_code: int, text: str) -> None:
        self.status_code = status_code
        self.text = text

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class FakeSession:
    def __init__(self, responses: list[FakeHtmlResponse]) -> None:
        self.responses = responses
        self.calls: list[dict] = []

    def request(self, method: str, url: str, **kwargs) -> FakeHtmlResponse:
        self.calls.append({"method": method, "url": url, **kwargs})
        return self.responses.pop(0)


def test_check_profile_accessibility_uses_browser_headers() -> None:
    module = _load_script_module()
    session = FakeSession([FakeHtmlResponse(200, "<html><title>octocat</title></html>")])

    profile_url, accessible, error = module.check_profile_accessibility(
        session,
        username="octocat",
    )

    assert profile_url == "https://github.com/octocat"
    assert accessible is True
    assert error is None
    assert session.calls == [
        {
            "method": "GET",
            "url": "https://github.com/octocat",
            "headers": module.PROFILE_CHECK_HEADERS,
            "timeout": 30,
            "allow_redirects": True,
        }
    ]
    assert "Mozilla/5.0" in session.calls[0]["headers"]["User-Agent"]
    assert "text/html" in session.calls[0]["headers"]["Accept"]


def test_check_profile_accessibility_flags_404_page() -> None:
    module = _load_script_module()
    session = FakeSession(
        [
            FakeHtmlResponse(
                200,
                "<html><title>Page not found · GitHub</title>"
                "This is not the web page you are looking for.</html>",
            )
        ]
    )

    profile_url, accessible, error = module.check_profile_accessibility(
        session,
        username="blocked-user",
    )

    assert profile_url == "https://github.com/blocked-user"
    assert accessible is False
    assert error == "GitHub profile page returned a 404 page"


def test_parser_skips_profile_page_check_by_default() -> None:
    module = _load_script_module()

    args = module.build_parser().parse_args([])

    assert args.check_profile_page is False


def test_load_tokens_from_env_reads_all_supported_github_variables(
    tmp_path: Path,
) -> None:
    module = _load_script_module()
    env_file = tmp_path / ".env"
    env_file.write_text(
        "\n".join(
            [
                "GITHUB_TOKEN=token-a,token-b",
                "GH_TOKEN=token-b,token-c",
                "GITHUB_TOKENS_USER_A=token-d",
                "GITHUB_TOKENS_USER_B=token-e,token-a",
                "UNRELATED_TOKEN=token-z",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    tokens = module.load_tokens_from_env(str(env_file))

    assert tokens == ["token-a", "token-b", "token-c", "token-d", "token-e"]


def test_check_single_token_keeps_api_result_when_profile_is_inaccessible(
) -> None:
    module = _load_script_module()

    class _FakeResponse:
        def __init__(self, payload: object, headers: dict[str, str] | None = None) -> None:
            self._payload = payload
            self.headers = headers or {}

        def json(self) -> object:
            return self._payload

    class _FakeGitHubClient:
        def __init__(self, tokens: list[str]) -> None:
            assert tokens == ["token-1234"]
            self._session = object()

        def _request(self, method: str, path: str):
            assert method == "GET"
            if path == "/user":
                return _FakeResponse(
                    {"login": "octocat"},
                    headers={
                        "X-OAuth-Scopes": "repo, user, workflow, delete_repo",
                        "X-Accepted-OAuth-Scopes": "user",
                    },
                )
            if path == "/user/emails":
                return _FakeResponse(
                    [{"email": "octocat@users.noreply.github.com", "primary": True}]
                )
            raise AssertionError(f"Unexpected path: {path}")

        def _request_json(self, method: str, path: str):
            assert (method, path) == ("GET", "/rate_limit")
            return {"resources": {"core": {"limit": 5000, "remaining": 4999, "used": 1}}}

        @staticmethod
        def _select_user_email(emails_data: object) -> str | None:
            return "octocat@users.noreply.github.com"

    module.GitHubClient = _FakeGitHubClient
    module.check_profile_accessibility = lambda session, *, username: (
        f"https://github.com/{username}",
        False,
        "GitHub profile page returned a 404 page",
    )

    result = module.check_single_token("token-1234", check_profile_page=True)

    assert result.error is None
    assert result.username == "octocat"
    assert result.email == "octocat@users.noreply.github.com"
    assert result.profile_url == "https://github.com/octocat"
    assert result.profile_accessible is False
    assert result.profile_check_error == "GitHub profile page returned a 404 page"
    assert result.rate_data["resources"]["core"]["limit"] == 5000


def test_check_single_token_skips_profile_check_by_default() -> None:
    module = _load_script_module()
    profile_check_called = {"value": False}

    class _FakeResponse:
        def __init__(self, payload: object, headers: dict[str, str] | None = None) -> None:
            self._payload = payload
            self.headers = headers or {}

        def json(self) -> object:
            return self._payload

    class _FakeGitHubClient:
        def __init__(self, tokens: list[str]) -> None:
            assert tokens == ["token-1234"]
            self._session = object()

        def _request(self, method: str, path: str):
            assert method == "GET"
            if path == "/user":
                return _FakeResponse({"login": "octocat"})
            if path == "/user/emails":
                return _FakeResponse(
                    [{"email": "octocat@users.noreply.github.com", "primary": True}]
                )
            raise AssertionError(f"Unexpected path: {path}")

        def _request_json(self, method: str, path: str):
            assert (method, path) == ("GET", "/rate_limit")
            return {"resources": {"core": {"limit": 5000, "remaining": 4999, "used": 1}}}

        @staticmethod
        def _select_user_email(emails_data: object) -> str | None:
            return "octocat@users.noreply.github.com"

    def _fake_check_profile_accessibility(*args, **kwargs):
        profile_check_called["value"] = True
        raise AssertionError("profile check should not run by default")

    module.GitHubClient = _FakeGitHubClient
    module.check_profile_accessibility = _fake_check_profile_accessibility

    result = module.check_single_token("token-1234")

    assert result.error is None
    assert result.username == "octocat"
    assert result.profile_url is None
    assert result.profile_accessible is None
    assert result.profile_check_error is None
    assert profile_check_called["value"] is False
