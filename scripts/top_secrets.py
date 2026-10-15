#!/usr/bin/env python3
"""Named secrets exfiltrated to the monitoring endpoint.

This counts how often each named repository secret was actually exfiltrated to
the monitoring endpoint (hookbin) during Stage 3 verification, across the
confirmed-exploitable repositories.

"""

from __future__ import annotations

import argparse
import json
import os
import re
from collections import Counter
from typing import Any

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corrected_classification import classify as _corrected_classify  # single source of truth

SEEDING_ARTIFACTS = {"FERN_TOKEN", "SLACK_WEBHOOK_URL"}
GITHUB_TOKEN_NAMES = {"github_token", "system.github.token", "github.token", "GITHUB_TOKEN"}

# Matches  "NAME":{"value":"...","isSecret":true}  in the raw hookbin log string.
SECRET_RE = re.compile(
    r'"([^"]+)"\s*:\s*\{\s*"value"\s*:\s*"[^"]*"\s*,\s*"isSecret"\s*:\s*true\s*\}'
)


def truthy(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def classify(r: dict) -> str:
    return _corrected_classify(r)  # 'privileged' | 'rce' | 'unconfirmed'


def _hookbin_logs(rk: dict) -> list[str]:
    """All hookbin log strings attached to a finding (execution_result + attempts)."""
    ar = rk.get("attack_result")
    if not isinstance(ar, dict):
        return []
    out: list[str] = []
    er = ar.get("execution_result")
    if isinstance(er, dict):
        if isinstance(er.get("hookbin_logs"), str):
            out.append(er["hookbin_logs"])
        for at in (er.get("attempts") or []):
            if isinstance(at, dict) and isinstance(at.get("hookbin_logs"), str):
                out.append(at["hookbin_logs"])
    for at in (ar.get("attempts") or []):
        if isinstance(at, dict) and isinstance(at.get("hookbin_logs"), str):
            out.append(at["hookbin_logs"])
    return out


def repo_secret_names(r: dict, *, keep_github_token: bool, keep_artifacts: bool) -> set[str]:
    """Distinct named secrets exfiltrated from this repository (deduped)."""
    names: set[str] = set()
    for rk in (r.get("risks") or []):
        for log in _hookbin_logs(rk):
            for m in SECRET_RE.finditer(log):
                nm = m.group(1)
                if not keep_github_token and nm in GITHUB_TOKEN_NAMES:
                    continue
                if not keep_artifacts and nm in SEEDING_ARTIFACTS:
                    continue
                names.add(nm)
    return names


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True)
    ap.add_argument("--top", type=int, default=13)
    ap.add_argument("--keep-artifacts", action="store_true",
                    help="do not filter FERN_TOKEN / SLACK_WEBHOOK_URL")
    ap.add_argument("--keep-github-token", action="store_true",
                    help="do not filter github_token / system.github.token")
    ap.add_argument("--out", default="enrich_output/top_secrets.json")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as fh:
        repos = json.load(fh)["enumeration"]["repositories"]

    repo_counts = Counter()             # name -> number of distinct repos
    repos_with_secret = Counter()       # class -> repos with >=1 named secret
    n_class = Counter()
    for r in repos:
        c = classify(r)
        n_class[c] += 1
        if c not in ("privileged", "rce"):
            continue
        names = repo_secret_names(
            r, keep_github_token=args.keep_github_token, keep_artifacts=args.keep_artifacts
        )
        if names:
            repos_with_secret[c] += 1
        for nm in names:            # one increment per repo per name (deduped)
            repo_counts[nm] += 1

    total_with = repos_with_secret["privileged"] + repos_with_secret["rce"]
    print(f"confirmed repos: privileged={n_class['privileged']} rce={n_class['rce']}")
    print(f"repos exfiltrating >=1 named secret (hookbin, deduped per repo): "
          f"privileged={repos_with_secret['privileged']} "
          f"({round(100*repos_with_secret['privileged']/n_class['privileged'],1)}% of privileged), "
          f"rce={repos_with_secret['rce']}, total={total_with}")

    print(f"\n--- Table 4.7: top {args.top} exfiltrated secret names (distinct repos) ---")
    print(f"{'secret name':36} {'repos':>6}")
    top = repo_counts.most_common(args.top)
    for nm, cnt in top:
        print(f"{nm:36} {cnt:6}")

    out = {
        "source_field": "attack_result.execution_result.hookbin_logs (+ attempt mirrors)",
        "counting_unit": "distinct repositories per secret name (deduped within repo)",
        "excluded": {
            "github_token_names": sorted(GITHUB_TOKEN_NAMES) if not args.keep_github_token else [],
            "seeding_artifacts": sorted(SEEDING_ARTIFACTS) if not args.keep_artifacts else [],
        },
        "n_class": dict(n_class),
        "repos_with_secret_by_class": dict(repos_with_secret),
        "distinct_secret_names": len(repo_counts),
        "top": top,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
