"""Recompute research summaries from the released categorical aggregates."""
from __future__ import annotations

import argparse
from collections import Counter
import csv
import json
from pathlib import Path

DATA = Path(__file__).resolve().parents[1] / "data"


def reproduce(data):
    audit = json.loads((data / "export_audit.json").read_text())
    grids = {}
    for name, view in audit["views"].items():
        cells = json.loads((data / (name + ".aggregate.json")).read_text())
        fields = view["fields"]
        grid = Counter()
        for row in cells:
            assert set(row) == {*fields, "count"}, f"Unexpected aggregate fields: {name}"
            assert type(row["count"]) is int and row["count"] > 0
            key = tuple(str(row[k]) for k in fields)
            assert key not in grid, f"Duplicate aggregate cell: {name}"
            grid[key] = row["count"]
        assert sum(grid.values()) == view["source_rows"], f"Aggregate total: {name}"
        # Verify released microdata against every non-suppressed aggregate cell.
        with (data / (name + ".csv")).open() as handle:
            reader = csv.DictReader(handle)
            assert reader.fieldnames == fields
            observed = Counter(tuple(row[k] for k in fields) for row in reader)
        expected = Counter({k: v for k, v in grid.items() if v >= audit["minimum_microdata_cell_size"]})
        assert observed == expected, f"Microdata differs from aggregates: {name}"
        assert sum(observed.values()) == view["released_microdata_rows"]
        grids[name] = cells
    counts = {r["outcome"]: r["count"] for r in grids["outcomes"]}
    for name, cells in grids.items():
        by_outcome = Counter()
        for row in cells:
            by_outcome[row["outcome"]] += row["count"]
        expected = {k: v for k, v in counts.items() if not (name.startswith("taxonomy_") or name == "sink_availability") or k in {"privileged", "rce"}}
        assert dict(by_outcome) == expected, f"Outcome denominator differs: {name}"
    comp = grids["credential_evidence"]
    total = lambda pred: sum(r["count"] for r in comp if r["outcome"] == "privileged" and pred(r))
    write = total(lambda r: r["write_scoped"] == 1)
    secret = total(lambda r: r["named_secret"] == 1)
    both = total(lambda r: r["write_scoped"] == 1 and r["named_secret"] == 1)
    assert write + secret - both == counts.get("privileged", 0)
    for field, value in [("write_scoped_privileged", write), ("named_secret_privileged", secret), ("both_privileged", both)]:
        assert value == audit["validation"][field]
    n = sum(counts.values())
    report = {
        "source_coverage": audit["coverage"],
        "outcomes": counts,
        "outcome_percentages": {k: round(100 * v / n, 2) for k, v in counts.items()},
        "privileged_composition": {"write_scoped": write, "named_secret": secret, "both": both, "named_secret_only": secret - both},
        "paper_stage1_denominator": 95584,
        "privileged_percent_of_paper_stage1": round(100 * counts.get("privileged", 0) / 95584, 2),
        "warnings": audit["warnings"],
        "tables": grids,
        "contributors_summary": json.loads((data / "contributors_summary.json").read_text()),
    }
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--data", type=Path, default=DATA)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    result = reproduce(args.data)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({k: v for k, v in result.items() if k != "tables"}, indent=2))


if __name__ == "__main__":
    main()
