from __future__ import annotations

import yaml

from pwn_hunter_ai.attack.workflow_preprocessing import (
    preprocess_workflow_content,
    workflow_has_schedule_trigger,
)


def test_preprocess_rewrites_deprecated_ubuntu_runner() -> None:
    before = (
        "name: ci\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-20.04\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )

    result = preprocess_workflow_content(
        workflow_content=before,
        source_repo_owner="owner",
        user_a_login="user-a",
    )

    assert result.changed is True
    parsed = yaml.safe_load(result.content)
    assert parsed["jobs"]["test"]["runs-on"] == "ubuntu-latest"


def test_preprocess_rewrites_deprecated_macos_and_windows_runners() -> None:
    before = (
        "name: ci\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  mac:\n"
        "    runs-on: macos-11\n"
        "    steps:\n"
        "      - run: echo mac\n"
        "  windows:\n"
        "    runs-on:\n"
        "      - windows-2019\n"
        "    steps:\n"
        "      - run: echo windows\n"
    )

    result = preprocess_workflow_content(
        workflow_content=before,
        source_repo_owner="owner",
        user_a_login="user-a",
    )

    assert result.changed is True
    parsed = yaml.safe_load(result.content)
    assert parsed["jobs"]["mac"]["runs-on"] == "macos-latest"
    assert parsed["jobs"]["windows"]["runs-on"] == ["windows-latest"]


def test_preprocess_rewrites_self_hosted_runner_with_os_hint() -> None:
    before = (
        "name: ci\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: [self-hosted, windows, x64]\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )

    result = preprocess_workflow_content(
        workflow_content=before,
        source_repo_owner="owner",
        user_a_login="user-a",
    )

    assert result.changed is True
    parsed = yaml.safe_load(result.content)
    assert parsed["jobs"]["test"]["runs-on"] == "windows-latest"


def test_preprocess_rewrites_self_hosted_runner_without_os_hint_to_ubuntu() -> None:
    before = (
        "name: ci\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: [self-hosted, x64]\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )

    result = preprocess_workflow_content(
        workflow_content=before,
        source_repo_owner="owner",
        user_a_login="user-a",
    )

    assert result.changed is True
    parsed = yaml.safe_load(result.content)
    assert parsed["jobs"]["test"]["runs-on"] == "ubuntu-latest"


def test_preprocess_rewrites_repository_owner_if_guard_when_source_owner_matches() -> None:
    before = (
        "name: ci\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  test:\n"
        "    if: github.repository_owner == 'owner' && github.event_name == 'pull_request_target'\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )

    result = preprocess_workflow_content(
        workflow_content=before,
        source_repo_owner="owner",
        user_a_login="user-a",
    )

    assert result.changed is True
    parsed = yaml.safe_load(result.content)
    assert (
        parsed["jobs"]["test"]["if"]
        == "github.repository_owner == 'user-a' && github.event_name == 'pull_request_target'"
    )


def test_preprocess_rewrites_repository_owner_if_guard_with_double_quotes() -> None:
    before = (
        "name: ci\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  test:\n"
        '    if: github.repository_owner == "owner"\n'
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )

    result = preprocess_workflow_content(
        workflow_content=before,
        source_repo_owner="owner",
        user_a_login="user-a",
    )

    assert result.changed is True
    parsed = yaml.safe_load(result.content)
    assert parsed["jobs"]["test"]["if"] == 'github.repository_owner == "user-a"'


def test_preprocess_keeps_repository_owner_if_guard_when_source_owner_does_not_match() -> None:
    before = (
        "name: ci\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  test:\n"
        '    if: github.repository_owner == "another-owner"\n'
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )

    result = preprocess_workflow_content(
        workflow_content=before,
        source_repo_owner="owner",
        user_a_login="user-a",
    )

    assert result.changed is False
    assert result.content == before


def test_preprocess_rewrites_matrix_runner_values_referenced_by_runs_on() -> None:
    before = (
        "name: ci\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ${{ matrix.os }}\n"
        "    strategy:\n"
        "      matrix:\n"
        "        os: [ubuntu-20.04, macos-12]\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )

    result = preprocess_workflow_content(
        workflow_content=before,
        source_repo_owner="owner",
        user_a_login="user-a",
    )

    assert result.changed is True
    parsed = yaml.safe_load(result.content)
    assert parsed["jobs"]["test"]["strategy"]["matrix"]["os"] == [
        "ubuntu-latest",
        "macos-latest",
    ]


def test_workflow_has_schedule_trigger_detects_schedule_in_event_mapping() -> None:
    content = (
        "name: Python Tests\n"
        "on:\n"
        "  push:\n"
        "    branches: [main]\n"
        "  schedule:\n"
        "    - cron: '0 0 * * *'\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )

    assert workflow_has_schedule_trigger(content) is True


def test_workflow_has_schedule_trigger_is_false_without_schedule() -> None:
    content = (
        "name: Python Tests\n"
        "on:\n"
        "  pull_request_target:\n"
        "  workflow_dispatch:\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )

    assert workflow_has_schedule_trigger(content) is False
