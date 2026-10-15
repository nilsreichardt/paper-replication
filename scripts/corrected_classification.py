#!/usr/bin/env python3
"""Single source of truth for the corrected Stage-3 exploitability classification.

Every results-chapter number, table and figure in the thesis is computed from the
classification defined here. Run this file directly to reproduce the headline
counts and to validate the implementation against the raw dataset.

------------------------------------------------------------------------------
Why a correction was needed
------------------------------------------------------------------------------
The stored flag ``vulnerable_with_secret_or_write_gh_token`` (written by
``analyze_attack.py``) OVER-counts the privileged class:

  * ``_has_clear_exploit_job_github_token_permissions`` treats an exploit-job
    token status of ``read`` or ``non-write`` as qualifying, and
  * the hookbin secret check counts the seeded canaries (FERN_TOKEN,
    SLACK_WEBHOOK_URL).

By the thesis definition a repository is *privileged* only if a confirmed exploit
captured a WRITE-SCOPED ``GITHUB_TOKEN`` or a named (non-canary) repository
secret. 291 repositories pass the original gate but satisfy neither condition
(a read/non-write token, or only the seeded canary); they are re-labelled as the
secondary RCE class.

------------------------------------------------------------------------------
Corrected definition (this module)
------------------------------------------------------------------------------
privileged   = stored confirmed-exfiltration flag  AND  (write-scoped OR named secret)
rce          = NOT privileged  AND  (repo_vulnerable OR act_repo_vulnerable)
unconfirmed  = everything else

  * The stored flag is the confirmed-exfiltration gate: the exploit ran on the
    real GitHub-hosted fork and its memory dump reached the hookbin endpoint.
    ``recompute_stored_flag`` re-implements it from the raw fields and
    ``main()`` asserts it matches the stored value with 0 mismatches.
  * write-scoped  -> ``github_token_permissions_classification`` (highest scope
    across the repo's findings, SCOPE_RANK). This is the workflow-level explicit
    -permissions signal Figure 4.5 describes. The job-scoped
    ``exploit_job_github_token_permissions`` field is more precise per job but is
    absent for ~39 % of privileged repos (almost all secret-exfiltration repos,
    where token scope is irrelevant to classification), so using it alone would
    UNDER-count write; where both resolve they agree ~96 %.
  * named secret -> a non-canary ``"NAME":{...,"isSecret":true}`` entry in the
    hookbin logs (``github_token`` names and the FERN_TOKEN/SLACK_WEBHOOK_URL
    canaries excluded), identical to ``top_secrets.py``.

Result (Stage-2 corpus = 11,054):  privileged 2,054 / rce 2,881 / unconfirmed 6,119
  composition of the 2,054:  1,537 write-scoped + 968 named-secret - 451 both = 2,054
"""
from __future__ import annotations

import json
import os
import re
from collections import Counter
from typing import Any

DEFAULT_INPUT = os.path.expanduser(
    ".../attack_results_merged.json"
)

CLASS_ORDER = ["privileged", "rce", "unconfirmed"]
SCOPE_RANK = {"write": 4, "non-write": 3, "read": 2, "not-clear": 1, "unknown": 0}
SEEDING_ARTIFACTS = {"FERN_TOKEN", "SLACK_WEBHOOK_URL"}
GITHUB_TOKEN_NAMES = {"github_token", "system.github.token", "github.token", "GITHUB_TOKEN"}
_SECRET_RE = re.compile(
    r'"([^"]+)"\s*:\s*\{\s*"value"\s*:\s*"[^"]*"\s*,\s*"isSecret"\s*:\s*true\s*\}'
)


def truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() == "true")


def _to_bool(value: Any):
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return True if value == 1 else (False if value == 0 else None)
    if isinstance(value, str):
        n = value.strip().lower()
        if n in {"true", "yes", "y", "1"}:
            return True
        if n in {"false", "no", "n", "0"}:
            return False
    return None


# --- write-scope (Figure 4.5), via github_token_permissions_classification -----
def highest_scope(repo: dict) -> str | None:
    best = None
    for risk in repo.get("risks") or []:
        ar = risk.get("attack_result") or {}
        scope = ar.get("github_token_permissions_classification")
        if scope is None:
            gtp = risk.get("github_token_permissions") or {}
            scope = gtp.get("status") if isinstance(gtp, dict) else None
        scope = str(scope).strip().lower() if scope is not None else None
        if scope in SCOPE_RANK and (best is None or SCOPE_RANK[scope] > SCOPE_RANK[best]):
            best = scope
    return best


def is_write_scoped(repo: dict) -> bool:
    return highest_scope(repo) == "write"


# --- named (non-canary) secret in the hookbin logs (same as top_secrets.py) -----
def _hookbin_logs(risk: dict) -> list[str]:
    ar = risk.get("attack_result")
    if not isinstance(ar, dict):
        return []
    out: list[str] = []
    er = ar.get("execution_result")
    if isinstance(er, dict):
        if isinstance(er.get("hookbin_logs"), str):
            out.append(er["hookbin_logs"])
        for at in er.get("attempts") or []:
            if isinstance(at, dict) and isinstance(at.get("hookbin_logs"), str):
                out.append(at["hookbin_logs"])
    for at in ar.get("attempts") or []:
        if isinstance(at, dict) and isinstance(at.get("hookbin_logs"), str):
            out.append(at["hookbin_logs"])
    return out


def has_named_secret(repo: dict) -> bool:
    for risk in repo.get("risks") or []:
        for log in _hookbin_logs(risk):
            for match in _SECRET_RE.finditer(log):
                name = match.group(1)
                if name in GITHUB_TOKEN_NAMES or name in SEEDING_ARTIFACTS:
                    continue
                return True
    return False


# --- stored confirmed-exfiltration flag (re-implementation for validation) ------
def _hookbin_has_github_token_write(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    lowered = value.lower()
    if "github_token permissions" in lowered and "write" in lowered:
        return True
    if "github token permissions" in lowered and "write" in lowered:
        return True
    return bool(re.search(r"github[_\-\s]*token\s*permissions[\s\S]{0,200}\bwrite\b", lowered))


def _hookbin_has_secret(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    matches: list[str] = []
    for m in re.compile(r'"([^"]+)"\s*:\s*\{').finditer(value):
        name, start, depth, in_str, esc, end = m.group(1), m.end() - 1, 0, False, False, None
        for idx in range(start, len(value)):
            ch = value[idx]
            if in_str:
                if esc:
                    esc = False
                elif ch == "\\":
                    esc = True
                elif ch == '"':
                    in_str = False
                continue
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    end = idx
                    break
        if end is not None and re.search(r'"isSecret"\s*:\s*true', value[start:end + 1], re.I):
            matches.append(name)
    for name in matches:
        if name.strip().lower() not in {"github_token", "system.github.token"}:
            return True
    return "flag{" in value.lower() and not matches


def recompute_stored_flag(repo: dict) -> bool:
    """Faithful re-implementation of analyze_attack._repo_matches_... (the stored flag)."""
    if _to_bool(repo.get("repo_vulnerable")) is not True and _to_bool(repo.get("act_repo_vulnerable")) is not True:
        return False
    hookbin: list[Any] = []
    clear = False
    for risk in repo.get("risks") or []:
        if not isinstance(risk, dict):
            continue
        ar = risk.get("attack_result")
        if isinstance(ar, dict):
            perms = ar.get("exploit_job_github_token_permissions")
            if isinstance(perms, dict) and isinstance(perms.get("status"), str) \
                    and perms["status"].strip().lower() in {"write", "read", "non-write"}:
                clear = True
            er = ar.get("execution_result")
            if isinstance(er, dict) and "hookbin_logs" in er:
                hookbin.append(er.get("hookbin_logs"))
    er = repo.get("execution_result")
    if isinstance(er, dict) and "hookbin_logs" in er:
        hookbin.append(er.get("hookbin_logs"))
    if not hookbin or not any(v != "" for v in hookbin):
        return False
    return clear or any(_hookbin_has_github_token_write(v) or _hookbin_has_secret(v) for v in hookbin)


def confirmed_exfiltration(repo: dict) -> bool:
    """The original confirmed-exfiltration gate: the stored flag value."""
    return repo.get("vulnerable_with_secret_or_write_gh_token") is True


def classify(repo: dict) -> str:
    """Corrected Stage-3 class: 'privileged' | 'rce' | 'unconfirmed'."""
    if confirmed_exfiltration(repo) and (is_write_scoped(repo) or has_named_secret(repo)):
        return "privileged"
    if truthy(repo.get("repo_vulnerable")) or truthy(repo.get("act_repo_vulnerable")):
        return "rce"
    return "unconfirmed"


def load_repos(path: str = DEFAULT_INPUT) -> list[dict]:
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)["enumeration"]["repositories"]


def main() -> int:
    import argparse

    ap = argparse.ArgumentParser(description="Validate the corrected classification.")
    ap.add_argument("--input", default=DEFAULT_INPUT)
    args = ap.parse_args()

    repos = load_repos(args.input)

    # 1. Validate the stored-flag re-implementation (0 mismatches expected).
    mism = sum(1 for r in repos if recompute_stored_flag(r) != (r.get("vulnerable_with_secret_or_write_gh_token") is True))

    # 2. Corrected class counts + composition.
    n = Counter(classify(r) for r in repos)
    priv = [r for r in repos if classify(r) == "privileged"]
    write = sum(1 for r in priv if is_write_scoped(r))
    secret = sum(1 for r in priv if has_named_secret(r))
    both = sum(1 for r in priv if is_write_scoped(r) and has_named_secret(r))

    print(f"repositories (Stage-2 corpus): {len(repos)}")
    print(f"stored-flag re-implementation mismatches: {mism}  (expected 0)")
    print(f"\nCorrected classes:")
    for c in CLASS_ORDER:
        print(f"  {c:12} {n[c]:6}  {100 * n[c] / len(repos):5.2f}%  ({100 * n[c] / 95584:.2f}% of 95,584)")
    print(f"  {'TOTAL':12} {sum(n.values()):6}")
    print(f"\nPrivileged composition: write-scoped {write} ({100*write/n['privileged']:.1f}%) + "
          f"named-secret {secret} ({100*secret/n['privileged']:.1f}%) - both {both} = "
          f"{write + secret - both}  (= {n['privileged']})")
    ok = (mism == 0 and n["privileged"] == 2054 and n["rce"] == 2881 and n["unconfirmed"] == 6119)
    print(f"\n{'OK: reproduces the thesis numbers' if ok else 'MISMATCH — investigate'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
