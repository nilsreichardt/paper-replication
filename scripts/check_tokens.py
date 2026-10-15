#!/usr/bin/env python3
"""Check GitHub token rate limits and user info."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from pathlib import Path

import requests

from pwn_hunter_ai.github_client import GitHubApiError, GitHubClient

REQUIRED_TOKEN_SCOPES = {"delete_repo", "repo", "user", "workflow"}
DEFAULT_ENV_TOKEN_VARIABLES = (
    "GITHUB_TOKEN",
    "GH_TOKEN",
    "GITHUB_TOKENS_USER_A",
    "GITHUB_TOKENS_USER_B",
)
PROFILE_CHECK_HEADERS = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,*/*;q=0.8"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Cache-Control": "no-cache",
    "Pragma": "no-cache",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/135.0.0.0 Safari/537.36"
    ),
}
GITHUB_404_PAGE_MARKERS = (
    "This is not the web page you are looking for.",
    "<title>Page not found",
)


@dataclass
class TokenCheckResult:
    token_suffix: str
    username: str
    email: str | None
    token_scopes: list[str]
    accepted_scopes: list[str]
    rate_data: dict
    profile_url: str | None = None
    profile_accessible: bool | None = None
    profile_check_error: str | None = None
    error: str | None = None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Check GitHub token rate limits and user info. "
            "By default tokens are read from GitHub token variables in .env."
        )
    )
    parser.add_argument(
        "--env-file",
        default=".env",
        help=(
            "Path to env file containing GitHub token variables such as "
            "GITHUB_TOKEN, GH_TOKEN, GITHUB_TOKENS_USER_A, or "
            "GITHUB_TOKENS_USER_B."
        ),
    )
    parser.add_argument(
        "--github-token",
        default=None,
        help=(
            "GitHub token(s) to check. Supports comma-separated values. "
            "When set, --env-file/.env is ignored."
        ),
    )
    parser.add_argument(
        "--check-profile-page",
        action="store_true",
        help=(
            "Also request https://github.com/<username> and warn when the public "
            "profile page is inaccessible."
        ),
    )
    return parser


def parse_tokens(raw_value: str | None) -> list[str]:
    if raw_value is None:
        return []
    return [token.strip() for token in raw_value.split(",") if token.strip()]


def load_tokens_from_env(env_file: str = ".env") -> list[str]:
    env_path = Path(env_file)
    if not env_path.exists():
        return []

    tokens: list[str] = []
    seen_tokens: set[str] = set()
    for raw_line in env_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if separator != "=" or key not in DEFAULT_ENV_TOKEN_VARIABLES:
            continue
        for token in parse_tokens(value):
            if token in seen_tokens:
                continue
            seen_tokens.add(token)
            tokens.append(token)

    return tokens


def parse_header_scopes(raw_value: str | None) -> list[str]:
    if not raw_value:
        return []
    return [scope.strip() for scope in raw_value.split(",") if scope.strip()]


def _looks_like_github_404_page(body: str) -> bool:
    return any(marker in body for marker in GITHUB_404_PAGE_MARKERS)


def build_profile_url(username: str) -> str:
    return f"https://github.com/{username}"


def check_profile_accessibility(
    session: requests.Session,
    *,
    username: str,
) -> tuple[str, bool | None, str | None]:
    profile_url = build_profile_url(username)

    try:
        response = session.request(
            "GET",
            profile_url,
            headers=PROFILE_CHECK_HEADERS,
            timeout=30,
            allow_redirects=True,
        )
    except requests.RequestException as exc:
        return profile_url, None, f"profile check request failed: {exc}"

    if response.status_code == 404 or _looks_like_github_404_page(response.text):
        return profile_url, False, "GitHub profile page returned a 404 page"
    if not response.ok:
        return profile_url, None, f"GitHub profile page returned HTTP {response.status_code}"
    return profile_url, True, None


def check_single_token(
    token: str,
    *,
    check_profile_page: bool = False,
) -> TokenCheckResult:
    token_suffix = token[-4:]
    client = GitHubClient(tokens=[token])

    try:
        user_response = client._request("GET", "/user")
        user_data = user_response.json()
        token_scopes = parse_header_scopes(user_response.headers.get("X-OAuth-Scopes"))
        accepted_scopes = parse_header_scopes(
            user_response.headers.get("X-Accepted-OAuth-Scopes")
        )
        email = None
        try:
            emails_response = client._request("GET", "/user/emails")
            email = client._select_user_email(emails_response.json())
        except (GitHubApiError, ValueError):
            email = None
        user_data["email"] = email
        rate_data = client._request_json("GET", "/rate_limit")
        username = str(user_data.get("login", "unknown"))
        email = user_data.get("email")
        if email is not None:
            email = str(email)
        profile_url = None
        profile_accessible = None
        profile_check_error = None
        if check_profile_page:
            profile_url, profile_accessible, profile_check_error = (
                check_profile_accessibility(
                    client._session,
                    username=username,
                )
            )
        return TokenCheckResult(
            token_suffix=token_suffix,
            username=username,
            email=email,
            token_scopes=token_scopes,
            accepted_scopes=accepted_scopes,
            rate_data=rate_data if isinstance(rate_data, dict) else {},
            profile_url=profile_url,
            profile_accessible=profile_accessible,
            profile_check_error=profile_check_error,
        )
    except (GitHubApiError, ValueError) as exc:
        return TokenCheckResult(
            token_suffix=token_suffix,
            username="unknown",
            email=None,
            token_scopes=[],
            accepted_scopes=[],
            rate_data={},
            error=str(exc),
        )


def main() -> None:
    args = build_parser().parse_args()

    if args.github_token is not None and args.github_token.strip():
        tokens = parse_tokens(args.github_token)
    else:
        tokens = load_tokens_from_env(args.env_file)

    if not tokens:
        if args.github_token is not None:
            print("No tokens found in --github-token.")
        else:
            print("No GITHUB_TOKEN found in env file or it is empty.")
        return

    users_with_reduced_core_limit: list[tuple[str, int]] = []
    invalid_tokens: list[tuple[str, str]] = []
    tokens_missing_required_scopes: list[tuple[str, str, list[str]]] = []
    users_with_inaccessible_profiles: list[tuple[str, str, str]] = []
    max_workers = max(1, len(tokens))

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(
            executor.map(
                lambda token: check_single_token(
                    token,
                    check_profile_page=args.check_profile_page,
                ),
                tokens,
            )
        )

    for result in results:
        if result.error:
            print(f"user: unknown; email: None; token: ...{result.token_suffix}")
            print(f"  ERROR: {result.error}")
            invalid_tokens.append((result.token_suffix, result.error))
            print()
            continue

        print(
            f"user: {result.username}; email: {result.email}; token: ...{result.token_suffix}"
        )
        print(
            "  token permissions (X-OAuth-Scopes): "
            + (
                ", ".join(result.token_scopes)
                if result.token_scopes
                else "none reported"
            )
        )
        if result.accepted_scopes:
            print(
                "  endpoint accepted scopes (X-Accepted-OAuth-Scopes): "
                + ", ".join(result.accepted_scopes)
            )
        if result.email is None:
            print("  WARNING: /user/emails returned no visible email")
        if result.profile_accessible is True:
            print(
                "  profile page: accessible"
                + (f" ({result.profile_url})" if result.profile_url else "")
            )
        elif result.profile_accessible is False:
            detail = result.profile_check_error or "profile page was not accessible"
            print(f"  WARNING: {detail}")
            if result.profile_url:
                print(f"  profile page: {result.profile_url}")
            users_with_inaccessible_profiles.append(
                (result.username, result.token_suffix, detail)
            )
        elif result.profile_check_error:
            print(f"  WARNING: {result.profile_check_error}")
            if result.profile_url:
                print(f"  profile page: {result.profile_url}")

        missing_required_scopes = sorted(
            REQUIRED_TOKEN_SCOPES.difference(set(result.token_scopes))
        )
        if missing_required_scopes:
            print(
                "  WARNING: missing required scopes: "
                + ", ".join(missing_required_scopes)
            )
            tokens_missing_required_scopes.append(
                (result.username, result.token_suffix, missing_required_scopes)
            )

        core_limit: int | None = None
        if "resources" in result.rate_data:
            resources = result.rate_data["resources"]
            for resource, info in resources.items():
                limit = info.get("limit", "?")
                remaining = info.get("remaining", "?")
                used = info.get("used", "?")
                print(f"  {resource}: {remaining}/{limit} remaining (used: {used})")
            core_info = resources.get("core")
            if isinstance(core_info, dict):
                raw_limit = core_info.get("limit")
                if isinstance(raw_limit, int):
                    core_limit = raw_limit
        else:
            print(f"  rate_limit error: {result.rate_data}")

        if core_limit is not None and core_limit < 5000:
            users_with_reduced_core_limit.append((result.username, core_limit))

        print()

    print("Users with core limit < 5000:")
    if users_with_reduced_core_limit:
        for username, core_limit in users_with_reduced_core_limit:
            print(f"  {username}: {core_limit}")
    else:
        print("  none")

    if args.check_profile_page:
        print("Users with inaccessible profile pages:")
        if users_with_inaccessible_profiles:
            for username, token_suffix, detail in users_with_inaccessible_profiles:
                print(f"  {username} (...{token_suffix}): {detail}")
        else:
            print("  none")

    print("Tokens missing required scopes (delete_repo, repo, user, workflow):")
    if tokens_missing_required_scopes:
        for username, token_suffix, missing in tokens_missing_required_scopes:
            print(
                f"  {username} (...{token_suffix}): missing {', '.join(missing)}"
            )
    else:
        print("  none")

    print("Invalid tokens:")
    if invalid_tokens:
        for token_suffix, error in invalid_tokens:
            print(f"  ...{token_suffix}: {error}")
    else:
        print("  none")


if __name__ == "__main__":
    main()
