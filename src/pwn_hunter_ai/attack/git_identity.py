from __future__ import annotations

from typing import Any

DEFAULT_GIT_USER_NAME = "PwnHunter Research"
DEFAULT_GIT_USER_EMAIL = "research@pwnhunter.local"


def build_git_identity_from_github_user(
    user_payload: dict[str, Any] | None,
) -> tuple[str, str]:
    if not isinstance(user_payload, dict):
        return DEFAULT_GIT_USER_NAME, DEFAULT_GIT_USER_EMAIL

    login = str(user_payload.get("login") or "").strip()
    name = str(user_payload.get("name") or "").strip() or login
    if not name:
        name = DEFAULT_GIT_USER_NAME

    email = str(user_payload.get("email") or "").strip()
    if not email and login:
        raw_id = user_payload.get("id")
        user_id = str(raw_id).strip() if raw_id is not None else ""
        if user_id:
            email = f"{user_id}+{login}@users.noreply.github.com"
        else:
            email = f"{login}@users.noreply.github.com"
    if not email:
        email = DEFAULT_GIT_USER_EMAIL

    return name, email


def render_isolated_gitconfig(*, git_user_name: str, git_user_email: str) -> str:
    return (
        "[user]\n"
        f"\tname = {git_user_name}\n"
        f"\temail = {git_user_email}\n"
        "[credential]\n"
        "\thelper =\n"
    )
