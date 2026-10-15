"""Cross-tabulate repository creation date against observed GITHUB_TOKEN scope.

Answers the question deferred in a few sections of the thesis: are repositories
created before GitHub's February 2023 default-permission change more likely to
carry a write-scoped token than those created after it?

Joins:
* ``attack_results_merged.json`` -> per-repo class + highest observed token scope.
* ``repo_metadata.jsonl`` -> per-repo ``created_at``.

Prints, for the confirmed-exploitable set and per class, P(write | pre-Feb-2023)
vs P(write | post-Feb-2023), plus the share of write-token repos that predate
the change.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from typing import Any

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corrected_classification import classify as _corrected_classify  # single source of truth

FEB_2023 = "2023-02"
SCOPE_RANK = {"write": 4, "non-write": 3, "read": 2, "not-clear": 1, "unknown": 0}


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _classify(repo: dict[str, Any]) -> str:
    c = _corrected_classify(repo)  # 'privileged' | 'rce' | 'unconfirmed'
    return "rce_unclear" if c == "rce" else c


def _highest_scope(repo: dict[str, Any]) -> str | None:
    best: str | None = None
    for risk in repo.get("risks") or []:
        ar = risk.get("attack_result") or {}
        scope = ar.get("github_token_permissions_classification")
        if scope is None:
            gtp = risk.get("github_token_permissions") or {}
            scope = gtp.get("status") if isinstance(gtp, dict) else None
        scope = str(scope) if scope is not None else None
        if scope in SCOPE_RANK and (
            best is None or SCOPE_RANK[scope] > SCOPE_RANK[best]
        ):
            best = scope
    return best


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attack", required=True)
    parser.add_argument("--meta", default="enrich_output/repo_metadata.jsonl")
    parser.add_argument("--out", default="enrich_output/crosstab.json")
    args = parser.parse_args()

    created: dict[str, str] = {}
    with open(args.meta, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except ValueError:
                continue
            if rec.get("status") == "ok" and rec.get("created_at"):
                created[rec["repo"]] = rec["created_at"]

    with open(args.attack, encoding="utf-8") as handle:
        data = json.load(handle)
    repos = data["enumeration"]["repositories"]

    # cohort -> Counter(write / other) per class and combined
    out: dict[str, Any] = {}
    cells: dict[tuple[str, str], Counter] = {}
    for repo in repos:
        name = repo.get("name")
        cdate = created.get(name)
        if not cdate:
            continue
        cls = _classify(repo)
        scope = _highest_scope(repo)
        if scope is None:
            continue
        cohort = "pre" if str(cdate) < FEB_2023 else "post"
        is_write = scope == "write"
        for group in (cls, "confirmed" if cls in ("privileged", "rce_unclear") else "unconfirmed_only", "all"):
            key = (group, cohort)
            cells.setdefault(key, Counter())
            cells[key]["write" if is_write else "other"] += 1

    def line(group: str) -> dict[str, Any]:
        pre = cells.get((group, "pre"), Counter())
        post = cells.get((group, "post"), Counter())
        pre_n = pre["write"] + pre["other"]
        post_n = post["write"] + post["other"]
        write_total = pre["write"] + post["write"]
        return {
            "pre_total": pre_n,
            "pre_write": pre["write"],
            "pre_write_pct": round(100 * pre["write"] / pre_n, 1) if pre_n else 0.0,
            "post_total": post_n,
            "post_write": post["write"],
            "post_write_pct": round(100 * post["write"] / post_n, 1) if post_n else 0.0,
            "write_total": write_total,
            "write_pre_share_pct": round(100 * pre["write"] / write_total, 1) if write_total else 0.0,
        }

    print(f"{'group':14} {'preN':>6} {'preWr':>6} {'pre%W':>6} {'postN':>6} {'postWr':>7} {'post%W':>7} {'Wpre%':>6}")
    for group in ("privileged", "rce_unclear", "confirmed", "unconfirmed", "all"):
        d = line(group)
        out[group] = d
        print(f"{group:14} {d['pre_total']:6} {d['pre_write']:6} {d['pre_write_pct']:6} "
              f"{d['post_total']:6} {d['post_write']:7} {d['post_write_pct']:7} {d['write_pre_share_pct']:6}")

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(out, handle, indent=2)
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
