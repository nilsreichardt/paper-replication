#!/usr/bin/env python3
"""Build the vulnerability-type taxonomy (Table 4.3) from the AGENT's sink.

Important data-model note
-------------------------
Each finding in ``attack_results_merged.json`` carries two different "sink"
fields, and they are NOT interchangeable:

* ``risks[].gato-x-sink`` - the sink guessed by the Gato-X static scanner in
  Stage 2. This is only *hint* data handed to the agent. Gato-X is tuned for low
  false negatives, so it frequently emits ``"Not Detected"`` even when an
  execution sink exists; ~41% of confirmed findings have ``gato-x-sink == "Not
  Detected"``. Classifying on this field badly overcounts "checkout-only".
* ``risks[].attack_result.attempts[].agent_output.sink`` - the sink the LLM
  agent actually identified and exploited during dynamic verification. This is
  the ground-truth sink for a confirmed repository and the field this script
  uses. (A mirror copy also appears under
  ``attack_result.execution_result.attempts[].agent_output.sink``.)

For each finding we take the sink from the attempt that confirmed the exploit
(``agent_output.vulnerable`` truthy); if no attempt is marked vulnerable we fall
back to the last attempt that recorded a non-empty sink string.

Classification
--------------
The free-text agent sink (2,700+ distinct values) is mapped to the six
execution-pathway types A-F defined in the methodology, plus two residual
buckets:

* ``other_detected`` - a sink string was recorded but does not map to A-F.
* ``no_sink_recorded`` - the agent confirmed/attempted the repo but never
  emitted a structured sink string for any finding. This is the genuine
  "checkout-only" residual (the workflow runs attacker code directly, or the
  agent simply did not name a sink), and it is far smaller than the Gato-X ``Not
  Detected`` rate.

A repository is counted under a type if at least one of its findings maps to
that type, so a repo can contribute to several types and the per-type counts sum
to more than the number of repositories.

Counting scope: confirmed-privileged + confirmed-RCE repositories, with
privileged-only figures reported alongside.

Usage::

    python scripts/taxonomy_from_agent_sink.py \
        --input "/path/to/attack_results_merged.json" \
        --out enrich_output/taxonomy.json
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

# Ordered list of (type-key, compiled-regex). First match wins, so more specific
# patterns (transitive actions) are tested before generic ones (package managers).
# Patterns are matched case-insensitively against the agent sink string.
_TYPE_PATTERNS: list[tuple[str, str]] = [
    # B: test-suite runners. Tested before A/C/F so "dotnet test", "mvn test",
    # "flutter test", "*-test-action" land in B rather than the build/PM bucket.
    ("B_test_suite",
     r"(?:pytest|conftest|tox\b|\bjest\b|vitest|mocha|npm test|yarn test|"
     r"go test|mvn (?:test|verify)|gradle(?:w)? .*test|rspec|\bnose\b|"
     r"dotnet test|flutter test|cargo test|ctest|\btestthat\b)"),
    # F: a third-party marketplace/composite action that re-checks-out and runs PR code.
    # Includes any "owner/name[@ref]" action reference, github-script, and the
    # pre-commit family (the action evaluates attacker .pre-commit-config.yaml).
    ("F_transitive_action",
     r"(?:[\w.-]+/[\w.-]+@|[\w.-]+/[\w.-]+-action\b|codesee|"
     r"pre-commit(?:/action| run|$|\b)|setup-ruby|bundler-cache|"
     r"fivem-lua-lint|sonarcloud-github-action|sonarsource/|sonar-scanner|"
     r"sonar\.scanner|actions/github-script|github-script|/action@|"
     r"\./\.github/actions/|\.github/actions/|uses:\s)"),
    # A: package-manager install / lifecycle / run scripts.
    ("A_package_manager",
     r"(?:npm (?:ci|install|run)|\bnpm\b|\bnpx\b|yarn|pnpm|\bbun (?:install|i|add)|"
     r"pip install|pip3 install|python -?m pip|pipx run|poetry (?:install|run)|"
     r"bundle (?:install|exec)|gem install|composer (?:install|update)|"
     r"cargo install|go install|nix-build|nix build|dotnet (?:restore|build|run)|"
     r"\bgo mod\b)"),
    # C: build-system invocation.
    ("C_build_system",
     r"(?:gradle|gradlew|\bmvn\b|\bmaven\b|cmake|\bmake\b|bazel|\bsbt\b|"
     r"cargo (?:build|fmt|check)|ninja|\bant\b|meson|docker (?:build|buildx)|"
     r"\bpbuilder\b|dpkg-source|debian/rules|\bterraform\b)"),
    # E: direct interpreter execution of a repo file / interpreter task.
    ("E_interpreter",
     r"(?:python3? [^-]|python3? \.|deno (?:task|run)|\bnode \b|\blua\b|"
     r"luacheck|latexmk|\bpsql\b|ansible-playbook|\bhugo\b|ruby [^/]|"
     r"\bperl\b|\bRscript\b|\bdotnet \b)"),
    # D: a shell script / local executable invoked from the workflow.
    ("D_direct_script",
     r"(?:\.sh\b|^bash\b|^sh\b| bash |/bin/sh|\./ci|\./scripts|\./\.github|"
     r"\bjust\b|sed -i|\bawk\b|^\./|\./[\w./-]+|/app/|vendor/bin|bin/[\w.-]+\.py)"),
]
_COMPILED = [(k, re.compile(p, re.IGNORECASE)) for k, p in _TYPE_PATTERNS]

TYPE_ORDER = [
    "A_package_manager", "B_test_suite", "C_build_system", "D_direct_script",
    "E_interpreter", "F_transitive_action", "other_detected", "no_sink_recorded",
]
TYPE_LABEL = {
    "A_package_manager": "A: Package manager hooks",
    "B_test_suite": "B: Test suite execution",
    "C_build_system": "C: Build system invocation",
    "D_direct_script": "D: Direct script invocation",
    "E_interpreter": "E: Interpreter execution",
    "F_transitive_action": "F: Transitive action checkout",
    "other_detected": "Other detected sink",
    "no_sink_recorded": "No sink recorded by agent (checkout-only residual)",
}


def truthy(v: Any) -> bool:
    return v is True or (isinstance(v, str) and v.strip().lower() in ("true", "yes"))


def classify_repo(r: dict) -> str:
    return {"privileged": "priv", "rce": "rce", "unconfirmed": "unc"}[_corrected_classify(r)]


def _attempts(rk: dict) -> list:
    ar = rk.get("attack_result")
    if not isinstance(ar, dict):
        return []
    a = ar.get("attempts")
    if isinstance(a, list) and a:
        return a
    er = ar.get("execution_result")
    if isinstance(er, dict) and isinstance(er.get("attempts"), list):
        return er["attempts"]
    return []


def agent_sink(rk: dict) -> str | None:
    """Sink the agent actually used: prefer the confirming attempt's sink."""
    chosen = None
    for at in _attempts(rk):
        if not isinstance(at, dict):
            continue
        ao = at.get("agent_output")
        if not isinstance(ao, dict):
            continue
        s = ao.get("sink")
        if not isinstance(s, str) or s.strip() in ("", "Not Detected", "none", "None"):
            continue
        chosen = s.strip()
        if truthy(ao.get("vulnerable")):
            return chosen
    return chosen


def classify_sink(sink: str | None) -> str:
    if not sink:
        return "no_sink_recorded"
    for key, rx in _COMPILED:
        if rx.search(sink):
            return key
    return "other_detected"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--input", required=True)
    ap.add_argument("--out", default="enrich_output/taxonomy.json")
    ap.add_argument("--examples", type=int, default=0,
                    help="print N example sink strings per type (debugging)")
    args = ap.parse_args()

    with open(args.input, encoding="utf-8") as fh:
        repos = json.load(fh)["enumeration"]["repositories"]

    # Per-repo type sets (a repo counts once per type), for three scopes.
    scopes = {"confirmed": ("priv", "rce"), "privileged": ("priv",), "rce": ("rce",)}
    repo_type = {s: Counter() for s in scopes}
    n_repos = {s: 0 for s in scopes}
    # Finding-level raw counts + examples.
    finding_type = Counter()
    examples: dict[str, list[str]] = {k: [] for k in TYPE_ORDER}
    n_findings = 0

    # Strict residual: repos where NO finding had any agent sink at all.
    no_sink_any = {s: 0 for s in scopes}

    for r in repos:
        c = classify_repo(r)
        if c not in ("priv", "rce"):
            continue
        types_in_repo = set()
        repo_has_any_sink = False
        for rk in (r.get("risks") or []):
            n_findings += 1
            sink = agent_sink(rk)
            if sink:
                repo_has_any_sink = True
            t = classify_sink(sink)
            finding_type[t] += 1
            types_in_repo.add(t)
            if args.examples and sink and len(examples[t]) < args.examples:
                examples[t].append(sink[:80])
        for s, members in scopes.items():
            if c in members:
                n_repos[s] += 1
                if not repo_has_any_sink:
                    no_sink_any[s] += 1
                for t in types_in_repo:
                    repo_type[s][t] += 1

    def block(scope: str) -> dict:
        n = n_repos[scope]
        rows = {}
        for t in TYPE_ORDER:
            cnt = repo_type[scope][t]
            rows[t] = {"count": cnt, "pct": round(100 * cnt / n, 1) if n else 0.0}
        return {
            "n_repos": n,
            "types": rows,
            "no_sink_on_any_finding": {
                "count": no_sink_any[scope],
                "pct": round(100 * no_sink_any[scope] / n, 1) if n else 0.0,
            },
        }

    out = {
        "sink_field_used": "attack_result.attempts[].agent_output.sink",
        "n_confirmed_findings": n_findings,
        "finding_level_type_counts": dict(finding_type),
        "confirmed": block("confirmed"),
        "privileged": block("privileged"),
        "rce": block("rce"),
    }

    # Pretty print
    for scope in ("confirmed", "privileged", "rce"):
        b = out[scope]
        print(f"\n=== {scope.upper()} (n={b['n_repos']} repos) ===")
        print(f"  {'type':52} {'count':>6} {'pct':>6}")
        for t in TYPE_ORDER:
            row = b["types"][t]
            print(f"  {TYPE_LABEL[t]:52} {row['count']:6} {row['pct']:6}")
    if args.examples:
        print("\n=== example sink strings per type ===")
        for t in TYPE_ORDER:
            if examples[t]:
                print(f"\n{TYPE_LABEL[t]}:")
                for e in examples[t]:
                    print(f"  - {e}")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
