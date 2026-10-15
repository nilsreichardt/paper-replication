from pwn_hunter_ai.attack.workflow_secrets import (
    build_dummy_secret_value,
    collect_workflow_secrets,
    extract_secret_names,
)


def test_extract_secret_names_handles_dot_and_indexed_forms() -> None:
    workflow = """
jobs:
  test:
    steps:
      - run: echo ${{ secrets.MY_SECRET }}
      - run: echo ${{ secrets['SECOND_SECRET'] }}
      - run: echo ${{ secrets["THIRD_SECRET"] }}
"""

    assert extract_secret_names(workflow) == {"MY_SECRET", "SECOND_SECRET", "THIRD_SECRET"}


def test_collect_workflow_secrets_ignores_files_without_secrets() -> None:
    workflows = [
        (".github/workflows/ci.yml", "name: CI\n"),
        (".github/workflows/release.yml", "env:\n  TOKEN: ${{ secrets.RELEASE_TOKEN }}\n"),
    ]

    assert collect_workflow_secrets(workflows) == {
        ".github/workflows/release.yml": {"RELEASE_TOKEN"},
    }


def test_extract_secret_names_ignores_github_prefixed_secrets() -> None:
    workflow = """
jobs:
  test:
    steps:
      - run: echo ${{ secrets.GITHUB_TOKEN }}
      - run: echo ${{ secrets['GITHUB_APP_ID'] }}
      - run: echo ${{ secrets["CUSTOM_SECRET"] }}
"""

    assert extract_secret_names(workflow) == {"CUSTOM_SECRET"}


def test_collect_workflow_secrets_ignores_workflows_with_only_github_prefixed_secrets() -> None:
    workflows = [
        (
            ".github/workflows/ci.yml",
            "steps:\n  - run: echo ${{ secrets.GITHUB_TOKEN }}\n",
        ),
        (
            ".github/workflows/release.yml",
            "env:\n  TOKEN: ${{ secrets.RELEASE_TOKEN }}\n",
        ),
    ]

    assert collect_workflow_secrets(workflows) == {
        ".github/workflows/release.yml": {"RELEASE_TOKEN"},
    }


def test_build_dummy_secret_value_normalizes_underscores() -> None:
    assert build_dummy_secret_value("MY_SECRET_TOKEN") == "flag{my-secret-token}"
