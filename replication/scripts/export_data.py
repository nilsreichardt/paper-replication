"""Export allowlisted, non-linkable analysis views from private study records.

Inputs and any identity mapping stay outside the release. Each view is shuffled
independently and has no repository identifier or cross-view join key.
"""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
from pathlib import Path
import random
import re
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
from corrected_classification import classify, has_named_secret, highest_scope, is_write_scoped
from taxonomy_from_agent_sink import agent_sink, classify_sink, TYPE_ORDER


def stars(value):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return "unknown"
    return "0" if value == 0 else "1-10" if value <= 10 else "11-100" if value <= 100 else "101-1000" if value <= 1000 else ">1000"


def contributors(value):
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        return "unknown"
    return "0-1" if value <= 1 else "2-5" if value <= 5 else "6-10" if value <= 10 else "11-50" if value <= 50 else "51-100" if value <= 100 else ">100"


def activity(value):
    return "unknown" if not value else "active" if str(value) >= "2024-04" else "inactive"


def load_repos(path):
    data = json.loads(path.read_text())
    return data["enumeration"]["repositories"]


def export(args):
    output = args.output.resolve()
    # A private source must never be overwritten or copied into the output.
    for source in (args.search, args.enumeration, args.disclosure, args.attack, args.metadata):
        if source and source.resolve().is_relative_to(output):
            raise ValueError("Private input must be outside the public data directory")
    output.mkdir(parents=True, exist_ok=True)
    # Each view contains outcome plus one research variable, preventing joins of
    # the public attributes into a distinctive repository fingerprint.
    views = {name: [] for name in ("outcomes", "stars", "activity", "token_scope", "credential_evidence", "contributors", "creation_token", "sink_availability", "verification_status")}
    taxonomy = []
    coverage = {}
    warnings = []
    source_names = set()
    if args.search:
        source_names = {s.strip().lower() for s in args.search.read_text().splitlines() if s.strip()}
        valid = {name for name in source_names if re.fullmatch(r"[a-z0-9_.-]+/[a-z0-9_.-]+", name)}
        coverage["stage1_unique_observed"] = len(valid)
        source_names = valid
        if len(source_names) != 95584:
            warnings.append("Supplied Stage 1 list differs from paper denominator 95584; exclusion is unresolved.")
    if args.enumeration:
        enum = load_repos(args.enumeration)
        coverage["enumeration_records_observed"] = len(enum)
        coverage["enumeration_with_any_risk"] = sum(bool(r.get("risks")) for r in enum)
        coverage["enumeration_with_recorded_commit"] = sum(any(r.get(k) for k in ("source_commit_hash", "vulnerable_commit_hash", "commit_hash")) for r in enum)
        # No identities, paths or commit hashes leave this step.
        del enum
    meta = {}
    if args.metadata:
        for line in args.metadata.read_text().splitlines():
            if line.strip():
                row = json.loads(line)
                meta[row["repo"].lower()] = row
    full = bool(args.attack)
    if full:
        records = load_repos(args.attack)
    else:
        records = json.loads(args.disclosure.read_text())["repositories"]
        warnings.append("Only privileged disclosure records supplied; RCE and unconfirmed results cannot be reproduced.")
    coverage["stage3_records_observed"] = len(records)
    coverage["stage3_records_with_nonempty_commit"] = sum(bool(r.get("vulnerable_commit_hash")) for r in records) if full else None
    if full:
        disclosure = json.loads(args.disclosure.read_text())["repositories"]
        private_by_name = {r["name"].lower(): r for r in records if classify(r) == "privileged"}
        if set(private_by_name) != {r["repository"].lower() for r in disclosure}:
            raise ValueError("Disclosure membership differs from corrected merged results")
        for r in disclosure:
            original = private_by_name[r["repository"].lower()]
            if (is_write_scoped(original), has_named_secret(original)) != (r["github_token_write_scoped"], r["named_secret_exfiltrated"]):
                raise ValueError("Disclosure evidence flags differ from merged results")
        coverage["disclosure_membership_and_flags_match"] = True
        del disclosure, private_by_name
    known_contributor_values = {c: [] for c in ("privileged", "rce", "unconfirmed")}
    validation = Counter()
    for row in records:
        name = str(row.get("name") or row.get("repository")).lower()
        outcome = classify(row) if full else "privileged"
        write = is_write_scoped(row) if full else row["github_token_write_scoped"]
        secret = has_named_secret(row) if full else row["named_secret_exfiltrated"]
        scope = (highest_scope(row) if full else row["highest_github_token_scope"]) or "unknown"
        if scope not in {"write", "non-write", "read", "not-clear", "unknown"}:
            raise ValueError("Unrecognized token scope")
        validation[outcome] += 1
        if outcome == "privileged":
            validation["write_scoped_privileged"] += bool(write)
            validation["named_secret_privileged"] += bool(secret)
            validation["both_privileged"] += bool(write and secret)
        views["outcomes"].append({"outcome": outcome})
        status = "error" if full and row.get("error") else "skipped" if full and row.get("attack_skipped") else "processed" if full else "not_available"
        views["verification_status"].append({"outcome": outcome, "verification_status": status})
        if outcome in {"privileged", "rce"}:
            any_sink = any(agent_sink(risk) for risk in row.get("risks", [])) if full else any(f.get("agent_sink") for f in row.get("findings", []))
            views["sink_availability"].append({"outcome": outcome, "has_structured_sink": int(bool(any_sink))})
        views["stars"].append({"outcome": outcome, "star_bucket": stars(row.get("stars"))})
        views["activity"].append({"outcome": outcome, "activity": activity(row.get("source_last_commit_timestamp") if full else row.get("last_commit"))})
        views["token_scope"].append({"outcome": outcome, "token_scope": scope})
        views["credential_evidence"].append({"outcome": outcome, "write_scoped": int(write), "named_secret": int(secret)})
        m = meta.get(name, {})
        cv = m.get("contributors") if m.get("status") == "ok" and m.get("contributors_status") == "ok" else None
        if isinstance(cv, int) and not isinstance(cv, bool) and cv >= 0:
            known_contributor_values[outcome].append(cv)
        views["contributors"].append({"outcome": outcome, "contributor_bucket": contributors(cv)})
        created = m.get("created_at") if m.get("status") == "ok" else None
        cohort = "unknown" if not created else "pre-2023-02" if created < "2023-02" else "from-2023-02"
        views["creation_token"].append({"outcome": outcome, "creation_cohort": cohort, "write_scoped": int(write)})
        if outcome in {"privileged", "rce"}:
            # Only standardized type labels are exported, never the sink text.
            types = {classify_sink(agent_sink(risk)) for risk in row.get("risks", [])} if full else {classify_sink(f.get("agent_sink")) for f in row.get("findings", [])}
            for kind in TYPE_ORDER:
                taxonomy.append({"outcome": outcome, "type": kind, "present": int(kind in types)})
    # A separate, independently shuffled view for each type: no multi-type set.
    for kind in TYPE_ORDER:
        views["taxonomy_" + kind] = [{"outcome": r["outcome"], "present": r["present"]} for r in taxonomy if r["type"] == kind]
    del records, taxonomy
    if full and dict((k, validation[k]) for k in ("privileged", "rce", "unconfirmed")) != {"privileged": 2054, "rce": 2881, "unconfirmed": 6119}:
        warnings.append("Merged Stage 3 outcomes differ from the paper; investigate the source snapshot.")
    # Small cells remain in aggregate tables but not as microdata. Cells contain
    # only coarse categories; k is an additional precaution, not an anonymity proof.
    small_cells = {}
    manifest = {}
    for name, rows in views.items():
        fields = list(rows[0]) if rows else []
        cells = Counter(tuple(r[f] for f in fields) for r in rows)
        safe = [r for r in rows if cells[tuple(r[f] for f in fields)] >= 5]
        random.SystemRandom().shuffle(safe)
        with (output / (name + ".csv")).open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(safe)
        aggregate = [{**dict(zip(fields, key)), "count": count} for key, count in sorted(cells.items())]
        (output / (name + ".aggregate.json")).write_text(json.dumps(aggregate, indent=2) + "\n")
        small_cells[name] = {"cells": sum(v < 5 for v in cells.values()), "rows": sum(v for v in cells.values() if v < 5)}
        manifest[name] = {"source_rows": len(rows), "released_microdata_rows": len(safe), "fields": fields}
    # Contributor medians are class-level statistics; exact outlier extrema are withheld.
    import statistics
    summaries = {c: {"known": len(v), "median": statistics.median(v) if v else None, "maximum_exceeds": max((limit for limit in (0, 1, 10, 100, 1000, 3000, 20000) if max(v) > limit), default=None) if v else None} for c, v in known_contributor_values.items()}
    (output / "contributors_summary.json").write_text(json.dumps(summaries, indent=2) + "\n")
    audit = {"format_version": 1, "coverage": coverage, "validation": dict(validation), "warnings": warnings, "views": manifest, "small_cells_excluded_from_microdata": small_cells, "minimum_microdata_cell_size": 5,
             "privacy": "No source names, hashes, dates, paths, transcripts, secret names or stable join keys. Views independently shuffled. Exact marginal counts retained in aggregate files; rare cells excluded from CSVs. This reduces linkage risk and does not guarantee anonymity."}
    (output / "export_audit.json").write_text(json.dumps(audit, indent=2) + "\n")
    print(json.dumps({"coverage": coverage, "validation": dict(validation), "warnings": warnings}, indent=2))


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--search", type=Path)
    p.add_argument("--enumeration", type=Path)
    p.add_argument("--disclosure", type=Path, required=True)
    p.add_argument("--attack", type=Path)
    p.add_argument("--metadata", type=Path)
    p.add_argument("--output", type=Path, default=ROOT / "replication/data")
    export(p.parse_args())


if __name__ == "__main__":
    main()
