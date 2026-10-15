#!/usr/bin/env python3
"""Highest GITHUB_TOKEN permission scope per repository, by class.

Buckets each confirmed repository's highest observed token scope into
Write / No-write / Not-clear / Unknown, for the privileged and RCE classes. The
scope is ``github_token_permissions_classification`` (highest across the repo's
findings via SCOPE_RANK); see ``corrected_classification.py`` for the field
choice and ``highest_scope``.
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corrected_classification import (  # noqa: E402
    DEFAULT_INPUT,
    classify,
    highest_scope,
    load_repos,
)

BUCKETS = ["Write", "No-write", "Not-clear", "Unknown"]
LABEL = {"privileged": "Confirmed privileged", "rce": "Confirmed RCE"}


def bucket(repo: dict) -> str:
    scope = highest_scope(repo)
    if scope == "write":
        return "Write"
    if scope in ("non-write", "read"):
        return "No-write"
    if scope == "not-clear":
        return "Not-clear"
    return "Unknown"


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--input", default=DEFAULT_INPUT)
    args = ap.parse_args()

    repos = load_repos(args.input)
    grid: dict[str, Counter] = {"privileged": Counter(), "rce": Counter()}
    for r in repos:
        c = classify(r)
        if c in grid:
            grid[c][bucket(r)] += 1

    for c in ("privileged", "rce"):
        row = grid[c]
        print(f"{c:11} " + "  ".join(f"{b}={row[b]}" for b in BUCKETS) + f"  (sum {sum(row.values())})")

    print("\n--- Figure 4.5 coordinates ---")
    for c in ("privileged", "rce"):
        coords = " ".join(f"({b},{grid[c][b]})" for b in BUCKETS)
        print(f"% {LABEL[c]}")
        print(f"\\addplot coordinates {{ {coords} }};")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
