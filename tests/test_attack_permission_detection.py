from __future__ import annotations

from pwn_hunter_ai.attack.service import (
    _extract_explicit_workflow_github_token_permissions,
)


def test_permissions_detection_ignores_commented_permissions_and_needs_default() -> None:
    workflow = """\
name: Install

on:
  pull_request_target:
    types: [opened, synchronize, reopened, labeled]

jobs:
  authenticate:
    runs-on: ubuntu-latest
    # permissions:
    #  pull-requests: write
    steps:
      - run: echo "Authenticated!"
"""

    detected = _extract_explicit_workflow_github_token_permissions(workflow)

    assert detected is None


def test_permissions_detection_multi_job_with_job_level_permissions_is_not_clear() -> None:
    workflow = """\
name: Install

on:
  pull_request_target:
    types: [opened, synchronize, reopened, labeled]

jobs:
  authenticate:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - run: echo "Authenticated!"

  install:
    needs: authenticate
    runs-on: ubuntu-latest
    steps:
      - run: echo "Hello Mars"
"""

    detected = _extract_explicit_workflow_github_token_permissions(workflow)

    assert detected is not None
    assert detected["status"] == "not-clear"
    assert detected["reason"] == "multi_job_with_job_level_permissions_not_clear"


def test_permissions_detection_multi_job_job_level_with_top_level_is_not_clear() -> None:
    workflow = """\
name: Install

on:
  pull_request_target:
    types: [opened, synchronize, reopened, labeled]

permissions:
  pull-requests: write

jobs:
  authenticate:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - run: echo "Authenticated!"

  install:
    needs: authenticate
    runs-on: ubuntu-latest
    steps:
      - run: echo "Hello Mars"
"""

    detected = _extract_explicit_workflow_github_token_permissions(workflow)

    assert detected is not None
    assert detected["status"] == "not-clear"
    assert detected["reason"] == "multi_job_with_job_level_permissions_not_clear"


def test_permissions_detection_without_explicit_permissions_needs_default() -> None:
    workflow = """\
name: Install

on:
  pull_request_target:
    types: [opened, synchronize, reopened, labeled]

jobs:
  authenticate:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Authenticated!"

  install:
    needs: authenticate
    runs-on: ubuntu-latest
    steps:
      - run: echo "Hello Mars"
"""

    detected = _extract_explicit_workflow_github_token_permissions(workflow)

    assert detected is None


def test_permissions_detection_top_level_write_is_clear_write() -> None:
    workflow = """\
name: Install

on:
  pull_request_target:
    types: [opened, synchronize, reopened, labeled]

permissions:
  pull-requests: write

jobs:
  authenticate:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Authenticated!"

  install:
    needs: authenticate
    runs-on: ubuntu-latest
    steps:
      - run: echo "Hello Mars"
"""

    detected = _extract_explicit_workflow_github_token_permissions(workflow)

    assert detected is not None
    assert detected["status"] == "write"
    assert detected["reason"] == "explicit_top_level_permissions_include_write"
    assert detected["permissions"] == {"pull-requests": "write"}


def test_permissions_detection_single_job_job_level_is_clear_write() -> None:
    workflow = """\
name: Install

on:
  pull_request_target:
    types: [opened, synchronize, reopened, labeled]

jobs:
  authenticate:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write
    steps:
      - run: echo "Authenticated!"
"""

    detected = _extract_explicit_workflow_github_token_permissions(workflow)

    assert detected is not None
    assert detected["status"] == "write"
    assert detected["reason"] == "explicit_single_job_permissions_include_write"
    assert detected["permissions"] == {"pull-requests": "write"}


def test_permissions_detection_empty_top_level_permissions_is_non_write() -> None:
    workflow = """\
name: GH Azdev Style

on:
  workflow_dispatch:
  pull_request_target:
      types: [opened, labeled, unlabeled, synchronize]
      branches:
        - main

permissions: {}

jobs:
  azdev-style:
    runs-on: ubuntu-latest
    permissions:
      pull-requests: read
      contents: read
    steps:
      - name: Checkout CLI extension repo
        uses: actions/checkout@v4

  other-style:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout CLI extension repo
        uses: actions/checkout@v4
"""

    detected = _extract_explicit_workflow_github_token_permissions(workflow)

    assert detected is not None
    assert detected["status"] == "non-write"
    assert detected["reason"] == "explicit_top_level_permissions_without_write"
