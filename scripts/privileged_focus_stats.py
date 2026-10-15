"""Recompute taxonomy, token scope, and reachable-secret stats for the
CONFIRMED-PRIVILEGED subset only, plus the RCE-unclear subset separately.

Chapter 4 foregrounds confirmed privileged exploitability (the threat model of
Chapter 3); the RCE-unclear class is reported only as a chainable byproduct.
This script produces the per-class numbers needed for that framing.
"""

from __future__ import annotations

import json
import os
from collections import Counter

F = os.path.expanduser(
    "TODO"
)

SEEDING_ARTIFACTS = {"FERN_TOKEN", "SLACK_WEBHOOK_URL"}


def truthy(v):
    return v is True or (isinstance(v, str) and v.strip().lower() == "true")


def classify(r):
    if truthy(r.get("vulnerable_with_secret_or_write_gh_token")):
        return "privileged"
    if truthy(r.get("repo_vulnerable")) or truthy(r.get("act_repo_vulnerable")):
        return "rce_unclear"
    return "unconfirmed"


def classify_sink(s):
    if not s or s in ("Not Detected", "None"):
        return "checkout_only"
    t = s.lower()
    if any(k in t for k in ["pre-commit/action", "codesee", "setup-ruby", "bundler-cache",
                            "setup-node", "actions/setup", "pyenv", "rerun-job-action",
                            "/action@", "/.github/actions/"]):
        return "F_transitive_action"
    if any(k in t for k in ["npm install", "npm run", "yarn", "pnpm", "pip install",
                            "poetry install", "bundle install", "composer", "cargo install",
                            "gem install", "go install", "go run", "preinstall", "postinstall"]):
        return "A_package_manager"
    if any(k in t for k in ["pytest", "conftest", "jest", "tox", "vitest", "mocha"]):
        return "B_test_suite"
    if any(k in t for k in ["gradle", "mvn", "maven", "cmake", "make ", "make\n", "bazel",
                            "sbt", "cargo build", "cargo fmt", "ninja"]):
        return "C_build_system"
    if any(k in t for k in [".sh", "bash ", "sh ", "just ", "./ci", "./scripts", "make"]):
        return "D_direct_script"
    if any(k in t for k in ["python", "python3", "deno", "node ", "lua", "psql", "latexmk", "ruby "]):
        return "E_interpreter"
    return "other_detected"


TAX_ORDER = ["A_package_manager", "B_test_suite", "C_build_system", "D_direct_script",
             "E_interpreter", "F_transitive_action", "other_detected", "checkout_only"]


def main():
    with open(F, encoding="utf-8") as fh:
        repos = json.load(fh)["enumeration"]["repositories"]

    tax = {"privileged": Counter(), "rce_unclear": Counter()}
    secret_names = {"privileged": Counter(), "rce_unclear": Counter()}
    secret_repos = {"privileged": 0, "rce_unclear": 0}
    n = {"privileged": 0, "rce_unclear": 0}

    for r in repos:
        c = classify(r)
        if c not in ("privileged", "rce_unclear"):
            continue
        n[c] += 1
        types = set()
        repo_has_secret = False
        for risk in (r.get("risks") or []):
            types.add(classify_sink(risk.get("gato-x-sink")))
            ar = risk.get("attack_result") or {}
            for s in (ar.get("focused_workflow_secrets") or []):
                nm = s.get("name") if isinstance(s, dict) else s
                if nm and str(nm) not in SEEDING_ARTIFACTS:
                    secret_names[c][str(nm)] += 1
                    repo_has_secret = True
        for t in types:
            tax[c][t] += 1
        if repo_has_secret:
            secret_repos[c] += 1

    for c in ("privileged", "rce_unclear"):
        print(f"\n=== {c}  (n={n[c]}) ===")
        print("  taxonomy (repos with >=1 finding of type):")
        for t in TAX_ORDER:
            cnt = tax[c][t]
            print(f"    {t:20} {cnt:5}  {round(100*cnt/n[c],1)}%")
        print(f"  reachable named secret in {secret_repos[c]} repos ({round(100*secret_repos[c]/n[c],1)}%)")
        print("  top reachable secret names:")
        for nm, cnt in secret_names[c].most_common(15):
            print(f"    {nm:35} {cnt}")

    out = {
        "n": n,
        "taxonomy": {c: dict(tax[c]) for c in tax},
        "secret_repos": secret_repos,
        "top_secrets": {c: secret_names[c].most_common(15) for c in secret_names},
    }
    with open("enrich_output/privileged_focus.json", "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=2)
    print("\nwrote enrich_output/privileged_focus.json")


if __name__ == "__main__":
    main()
