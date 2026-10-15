from __future__ import annotations

import argparse
from pathlib import Path

from pwn_hunter_ai.attack_recovery import recover_attack_output


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Best-effort recovery for interrupted `pwnhunter attack` runs using "
            "input JSON + attack.log (+ optional attack-artifacts + partial output)."
        )
    )
    parser.add_argument("--input", required=True, help="Path to attack input JSON.")
    parser.add_argument("--output", required=True, help="Path to recovered output JSON.")
    parser.add_argument(
        "--log",
        help="Path to attack.log file. Recommended.",
    )
    parser.add_argument(
        "--artifacts-dir",
        help="Path to attack-artifacts directory from the same run.",
    )
    parser.add_argument(
        "--partial-output",
        help="Existing partial attack output JSON to preserve and extend.",
    )
    parser.add_argument(
        "--max-retries",
        type=int,
        help="Fallback max_retries value when unavailable in artifacts.",
    )
    parser.add_argument(
        "--use-all-artifacts-runs",
        action="store_true",
        help=(
            "By default, artifact recovery is restricted to run IDs discovered in --log. "
            "Pass this flag to disable that filter."
        ),
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if not args.log and not args.artifacts_dir and not args.partial_output:
        parser.error("At least one of --log, --artifacts-dir, or --partial-output is required.")

    output_payload = recover_attack_output(
        input_path=Path(args.input),
        output_path=Path(args.output),
        log_path=Path(args.log) if args.log else None,
        artifacts_dir=Path(args.artifacts_dir) if args.artifacts_dir else None,
        partial_output_path=Path(args.partial_output) if args.partial_output else None,
        max_retries=args.max_retries,
        restrict_artifacts_to_log_run_ids=not args.use_all_artifacts_runs,
    )
    recovered_count = len(output_payload.get("ai_enumeration", []))
    print(f"Recovered attack output written to {args.output} ({recovered_count} repositories).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

