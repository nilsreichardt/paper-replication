#!/usr/bin/env python3
"""Tables 4.1 & 4.2 and the privileged-class composition numbers.

Pipeline funnel (Table 4.1, Figure 4.1), Stage-3 outcome distribution
(Table 4.2, Figure 4.2) and the composition of the privileged class
(Section 4.2), all from the corrected classification.

Stage 1 (95,584) is the upstream Stage-1 collection count (Section 3.4 / the
collection logs: public, non-fork, non-archived repositories whose workflows use
pull_request_target). It is NOT contained in the attack dataset and is supplied
as a documented constant here. Stage 2 is the size of the verified corpus (this
dataset). Stage 3 is the corrected privileged count.

Reproduces:
  Table 4.1:  Stage1 95,584 (100%) / Stage2 11,054 (11.56%) / Stage3 2,054 (18.58% of prior, 2.15% of original)
  Table 4.2:  privileged 2,054 (18.58%) / rce 2,881 (26.06%) / unconfirmed 6,119 (55.36%); confirmed total 4,935
  Composition: 1,537 write-scoped + 968 named-secret - 451 both = 2,054
"""
from __future__ import annotations

import argparse
import os
import sys
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corrected_classification import (  # noqa: E402
    CLASS_ORDER,
    DEFAULT_INPUT,
    classify,
    has_named_secret,
    is_write_scoped,
    load_repos,
)

STAGE1 = 95584  # Stage-1 collection (public non-fork non-archived repos using pull_request_target)


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--input", default=DEFAULT_INPUT)
    args = ap.parse_args()

    repos = load_repos(args.input)
    stage2 = len(repos)
    n = Counter(classify(r) for r in repos)
    priv = n["privileged"]

    print("=== Table 4.1 / Figure 4.1: pipeline funnel ===")
    print(f"  {'Stage':8} {'N':>7} {'% prior':>9} {'% orig':>8}")
    print(f"  {'Stage 1':8} {STAGE1:7} {'---':>9} {100.0:7.2f}%")
    print(f"  {'Stage 2':8} {stage2:7} {100*stage2/STAGE1:8.2f}% {100*stage2/STAGE1:7.2f}%")
    print(f"  {'Stage 3':8} {priv:7} {100*priv/stage2:8.2f}% {100*priv/STAGE1:7.2f}%")

    print("\n=== Table 4.2 / Figure 4.2: Stage-3 outcome distribution ===")
    for c in CLASS_ORDER:
        print(f"  {c:12} {n[c]:6}  {100*n[c]/stage2:6.2f}%")
    print(f"  {'TOTAL':12} {sum(n.values()):6}  100.00%")
    print(f"  confirmed (privileged + rce) = {n['privileged'] + n['rce']}")

    pr = [r for r in repos if classify(r) == "privileged"]
    w = sum(1 for r in pr if is_write_scoped(r))
    s = sum(1 for r in pr if has_named_secret(r))
    b = sum(1 for r in pr if is_write_scoped(r) and has_named_secret(r))
    print("\n=== Section 4.2: composition of the privileged class ===")
    print(
        f"  write-scoped {w} ({100*w/priv:.1f}%) + named-secret {s} ({100*s/priv:.1f}%) "
        f"- both {b} = {w + s - b}  (= {priv})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
