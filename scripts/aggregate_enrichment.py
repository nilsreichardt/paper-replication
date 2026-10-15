"""Join enriched GitHub metadata with the attack classification.

Reads:
* ``attack_results_merged.json`` -> per-repo exploitability class
  (privileged / rce_unclear / unconfirmed), using the same rule as the thesis.
* ``repo_metadata.jsonl`` (from ``enrich_repo_metadata.py``) -> ``created_at``,
  contributor count, ``pushed_at``.

Prints the statistics needed for a few sections of the thesis:
creation-date coverage and pre-February-2023 cohort by class, contributor-count
distribution and median by class, and a refreshed activity breakdown from
``pushed_at``. Also writes the full aggregate to ``enrich_output/aggregate.json``.

Usage::

    python scripts/aggregate_enrichment.py \
        --attack "/path/to/attack_results_merged.json" \
        --meta enrich_output/repo_metadata.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
from collections import Counter, defaultdict
from typing import Any

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corrected_classification import classify as _corrected_classify  # single source of truth

FEB_2023 = "2023-02"            # GitHub's default-token permission change.
ACTIVE_CUTOFF = "2024-04"       # ~2 years before data collection.
CLASS_ORDER = ["privileged", "rce_unclear", "unconfirmed"]
BUCKET_ORDER = ["0-1", "2-5", "6-10", "11-50", "51-100", ">100"]


def _truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _classify(repo: dict[str, Any]) -> str:
    c = _corrected_classify(repo)  # 'privileged' | 'rce' | 'unconfirmed'
    return "rce_unclear" if c == "rce" else c


def _load_classes(attack_path: str) -> dict[str, str]:
    with open(attack_path, encoding="utf-8") as handle:
        data = json.load(handle)
    repos = (
        data.get("enumeration", {}).get("repositories")
        if isinstance(data, dict)
        else data
    )
    classes: dict[str, str] = {}
    for repo in repos or []:
        name = repo.get("name")
        if name:
            classes[name] = _classify(repo)
    return classes


def _load_meta(meta_path: str) -> dict[str, dict[str, Any]]:
    """Latest record per repo from the JSONL (later lines win)."""
    meta: dict[str, dict[str, Any]] = {}
    with open(meta_path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            repo = record.get("repo")
            if repo:
                meta[repo] = record
    return meta


def _contrib_bucket(count: int) -> str:
    if count <= 1:
        return "0-1"
    if count <= 5:
        return "2-5"
    if count <= 10:
        return "6-10"
    if count <= 50:
        return "11-50"
    if count <= 100:
        return "51-100"
    return ">100"


def _pct(num: int, den: int) -> float:
    return round(100.0 * num / den, 1) if den else 0.0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--attack", required=True)
    parser.add_argument("--meta", default="enrich_output/repo_metadata.jsonl")
    parser.add_argument("--out", default="enrich_output/aggregate.json")
    args = parser.parse_args()

    classes = _load_classes(args.attack)
    meta = _load_meta(args.meta)
    print(f"attack repos: {len(classes)}   enriched records: {len(meta)}")

    created_known = Counter()
    created_total = Counter()
    pre_feb = Counter()
    post_feb = Counter()
    contrib_known = Counter()
    contrib_buckets: dict[str, Counter] = defaultdict(Counter)
    contrib_values: dict[str, list[int]] = defaultdict(list)
    active = Counter()
    inactive = Counter()
    push_known = Counter()
    status_breakdown = Counter()

    meta_ok = 0
    for repo, cls in classes.items():
        created_total[cls] += 1
        record = meta.get(repo)
        if not record:
            status_breakdown["missing_from_meta"] += 1
            continue
        status_breakdown[str(record.get("status"))] += 1
        if record.get("status") != "ok":
            continue
        meta_ok += 1
        created = record.get("created_at")
        if created:
            created_known[cls] += 1
            if str(created) < FEB_2023:
                pre_feb[cls] += 1
            else:
                post_feb[cls] += 1
        pushed = record.get("pushed_at")
        if pushed:
            push_known[cls] += 1
            if str(pushed) >= ACTIVE_CUTOFF:
                active[cls] += 1
            else:
                inactive[cls] += 1
        if record.get("contributors_status") == "ok" and record.get("contributors") is not None:
            count = int(record["contributors"])
            contrib_known[cls] += 1
            contrib_buckets[cls][_contrib_bucket(count)] += 1
            contrib_values[cls].append(count)

    print("\n=== META STATUS BREAKDOWN ===")
    for status, n in status_breakdown.most_common():
        print(f"  {status:20} {n}")

    print("\n=== CREATION DATE (status==ok repos) ===")
    print(f"{'class':12} {'known':>7} {'total':>7} {'cover%':>7} {'preFeb':>7} {'pre%':>6}")
    agg_creation = {}
    for cls in CLASS_ORDER:
        k, t, p = created_known[cls], created_total[cls], pre_feb[cls]
        print(f"{cls:12} {k:7} {t:7} {_pct(k, t):7} {p:7} {_pct(p, k):6}")
        agg_creation[cls] = {
            "known": k, "total": t, "coverage_pct": _pct(k, t),
            "pre_feb2023": p, "pre_feb2023_pct_of_known": _pct(p, k),
            "post_feb2023": post_feb[cls],
        }
    tot_known, tot_total, tot_pre = (
        sum(created_known.values()), sum(created_total.values()), sum(pre_feb.values())
    )
    print(f"{'ALL':12} {tot_known:7} {tot_total:7} {_pct(tot_known, tot_total):7} "
          f"{tot_pre:7} {_pct(tot_pre, tot_known):6}")
    agg_creation["ALL"] = {
        "known": tot_known, "total": tot_total, "coverage_pct": _pct(tot_known, tot_total),
        "pre_feb2023": tot_pre, "pre_feb2023_pct_of_known": _pct(tot_pre, tot_known),
    }

    print("\n=== CONTRIBUTOR COUNT (status==ok, contributors==ok) ===")
    print(f"{'class':12} {'known':>7} " + " ".join(f"{b:>7}" for b in BUCKET_ORDER)
          + f" {'median':>7} {'mean':>7} {'max':>7}")
    agg_contrib = {}
    for cls in CLASS_ORDER:
        vals = contrib_values[cls]
        med = round(statistics.median(vals), 1) if vals else 0
        mean = round(statistics.mean(vals), 1) if vals else 0
        mx = max(vals) if vals else 0
        print(f"{cls:12} {contrib_known[cls]:7} "
              + " ".join(f"{contrib_buckets[cls][b]:7}" for b in BUCKET_ORDER)
              + f" {med:7} {mean:7} {mx:7}")
        agg_contrib[cls] = {
            "known": contrib_known[cls],
            "buckets": {b: contrib_buckets[cls][b] for b in BUCKET_ORDER},
            "median": med, "mean": mean, "max": mx,
        }
    all_vals = [v for cls in CLASS_ORDER for v in contrib_values[cls]]
    if all_vals:
        print(f"{'ALL':12} {len(all_vals):7} "
              + " ".join(f"{sum(contrib_buckets[c][b] for c in CLASS_ORDER):7}" for b in BUCKET_ORDER)
              + f" {round(statistics.median(all_vals),1):7} {round(statistics.mean(all_vals),1):7} {max(all_vals):7}")
        agg_contrib["ALL"] = {
            "known": len(all_vals),
            "buckets": {b: sum(contrib_buckets[c][b] for c in CLASS_ORDER) for b in BUCKET_ORDER},
            "median": round(statistics.median(all_vals), 1),
            "mean": round(statistics.mean(all_vals), 1),
            "max": max(all_vals),
        }

    print("\n=== ACTIVITY from pushed_at (status==ok repos) ===")
    print(f"{'class':12} {'active':>7} {'inactive':>9} {'known':>7} {'%active':>8}")
    agg_activity = {}
    for cls in CLASS_ORDER:
        a, i = active[cls], inactive[cls]
        print(f"{cls:12} {a:7} {i:9} {push_known[cls]:7} {_pct(a, a + i):8}")
        agg_activity[cls] = {"active": a, "inactive": i, "pct_active": _pct(a, a + i)}

    aggregate = {
        "attack_repos": len(classes),
        "enriched_records": len(meta),
        "meta_ok": meta_ok,
        "status_breakdown": dict(status_breakdown),
        "creation": agg_creation,
        "contributors": agg_contrib,
        "activity_pushed_at": agg_activity,
    }
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(aggregate, handle, indent=2)
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
