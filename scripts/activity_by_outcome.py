#!/usr/bin/env python3
"""Repository activity by Stage 3 outcome

Splits each verified repository into "active" vs "inactive" by whether it had a
commit within roughly the two years preceding data collection, cross-tabulated
against the exploitability outcome class.

Data source
-----------
``attack_results_merged.json``. The activity signal is the top-level
``source_last_commit_timestamp`` field captured during Stage 1/2 enumeration (an
ISO-8601 timestamp string). Repositories without this field are counted in a
separate "no timestamp" column and excluded from the %-active denominator. This
is the field the thesis uses; the GitHub REST ``pushed_at`` enrichment exists
too (see ``aggregate_enrichment.py``) but the intentionally uses the enumeration
timestamp.

Active cutoff
-------------
A repository is "active" if ``source_last_commit_timestamp`` >= ``2024-04``
(string comparison on the ISO date is sufficient and matches "at least one
commit since April 2024", ~2 years before the March-April 2026 collection).

Outcome classification
----------------------
Identical to the other results-chapter scripts: privileged
(``vulnerable_with_secret_or_write_gh_token`` true), else rce
(``repo_vulnerable``=="true" or ``act_repo_vulnerable`` true), else unconfirmed.

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

ACTIVE_CUTOFF = "2024-04"  # ISO prefix; "at least one commit since April 2024"
CLASS_ORDER = ["privileged", "rce", "unconfirmed"]
CLASS_LABEL = {"privileged": "Confirmed privileged",
               "rce": "Confirmed RCE", "unconfirmed": "Unconfirmed"}


def truthy(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def classify(r: dict) -> str:
    return _corrected_classify(r)  # 'privileged' | 'rce' | 'unconfirmed'


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True)
    ap.add_argument("--cutoff", default=ACTIVE_CUTOFF)
    ap.add_argument("--out", default="enrich_output/activity.json")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as fh:
        repos = json.load(fh)["enumeration"]["repositories"]

    active = Counter()
    inactive = Counter()
    no_ts = Counter()
    for r in repos:
        c = classify(r)
        ts = r.get("source_last_commit_timestamp")
        if not ts:
            no_ts[c] += 1
        elif str(ts) >= args.cutoff:
            active[c] += 1
        else:
            inactive[c] += 1

    print(f"{'outcome':22} {'active':>7} {'inactive':>9} {'no_ts':>7} {'%active':>8}")
    out = {}
    for c in CLASS_ORDER:
        a, i, z = active[c], inactive[c], no_ts[c]
        pct = round(100 * a / (a + i), 1) if (a + i) else 0.0
        print(f"{CLASS_LABEL[c]:22} {a:7} {i:9} {z:7} {pct:8}")
        out[c] = {"active": a, "inactive": i, "no_timestamp": z, "pct_active": pct}

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
