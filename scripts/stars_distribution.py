#!/usr/bin/env python3
"""Star distribution by Stage 3 outcome

For every repository that entered Stage 3 verification this bins the repository
by its GitHub star count and cross-tabulates against the exploitability outcome
class, producing the three series plotted in Figure 4.4 (fig:stars-dist).

Data source
-----------
``attack_results_merged.json`` (the merged Stage 3 attack dataset). The star
count is read from the top-level ``stars`` field that each repository object
carries from the Stage 1 enumeration; no GitHub API call is needed.

Outcome classification (identical across all results-chapter scripts)
--------------------------------------------------------------------
Per repository, from three boolean-ish fields:

* ``privileged``  : ``vulnerable_with_secret_or_write_gh_token`` is true.
* ``rce``         : not privileged, but ``repo_vulnerable`` == "true" OR
                    ``act_repo_vulnerable`` is true.
* ``unconfirmed`` : everything else.

"true" is matched case-insensitively for string values; booleans are honored.

Star buckets
------------
Logarithmic-ish bins matching the figure: ``0``, ``1-10``, ``11-100``,
``101-1000``, ``>1000``. A missing/non-integer star count is bucketed as
``unknown`` and reported separately (it is not plotted).

Reproduce Figure 4.4
--------------------

The printed ``\addplot`` coordinate lines can be pasted directly into the
figure; the numbers also match the prose in Section 4.4.1 (e.g. 385 repos with
>1000 stars, of which 40 privileged + 92 RCE = 132 confirmed exploitable).

Classification: the corrected privileged/rce/unconfirmed split (see
``corrected_classification.py``); this reproduces the post-correction numbers.
"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter, defaultdict
from typing import Any

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corrected_classification import classify as _corrected_classify  # single source of truth

BUCKET_ORDER = ["0", "1-10", "11-100", "101-1000", ">1000", "unknown"]
CLASS_ORDER = ["privileged", "rce", "unconfirmed"]
# pgfplots symbolic x coords used in the figure (no "unknown" bin is plotted).
PLOT_BINS = ["0", "1-10", "11-100", "101-1000", ">1000"]
PLOT_COORD = {"0": "0", "1-10": "1-10", "11-100": "11-100",
              "101-1000": "101-1000", ">1000": ">1000"}


def truthy(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def classify(r: dict) -> str:
    return _corrected_classify(r)  # 'privileged' | 'rce' | 'unconfirmed'


def star_bucket(stars: Any) -> str:
    try:
        s = int(stars)
    except (TypeError, ValueError):
        return "unknown"
    if s == 0:
        return "0"
    if s <= 10:
        return "1-10"
    if s <= 100:
        return "11-100"
    if s <= 1000:
        return "101-1000"
    return ">1000"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", default="enrich_output/stars_distribution.json")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as fh:
        repos = json.load(fh)["enumeration"]["repositories"]

    grid: dict[str, Counter] = defaultdict(Counter)  # class -> bucket -> count
    n = Counter()
    for r in repos:
        c = classify(r)
        n[c] += 1
        grid[c][star_bucket(r.get("stars"))] += 1

    # Pretty table
    print(f"{'class':12} " + " ".join(f"{b:>10}" for b in BUCKET_ORDER) + f" {'total':>8}")
    for c in CLASS_ORDER:
        row = grid[c]
        print(f"{c:12} " + " ".join(f"{row[b]:10}" for b in BUCKET_ORDER) + f" {n[c]:8}")

    # >1000 cross-check used in the prose
    big_total = sum(grid[c][">1000"] for c in CLASS_ORDER)
    big_conf = grid["privileged"][">1000"] + grid["rce"][">1000"]
    print(f"\n>1000 stars: total={big_total}, confirmed={big_conf} "
          f"(priv {grid['privileged']['>1000']} + rce {grid['rce']['>1000']}), "
          f"= {round(100 * big_conf / big_total, 1)}% of the >1000 bucket")

    # pgfplots coordinate lines for the figure
    label = {"privileged": "Confirmed privileged", "rce": "Confirmed RCE",
             "unconfirmed": "Unconfirmed"}
    print("\n--- paste into Figure 4.4 (fig:stars-dist) ---")
    for c in CLASS_ORDER:
        coords = " ".join(f"({PLOT_COORD[b]},{grid[c][b]})" for b in PLOT_BINS)
        print(f"% {label[c]}")
        print(f"\\addplot coordinates {{ {coords} }};")

    out = {
        "n_by_class": dict(n),
        "grid": {c: {b: grid[c][b] for b in BUCKET_ORDER} for c in CLASS_ORDER},
        "gt1000_total": big_total,
        "gt1000_confirmed": big_conf,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
