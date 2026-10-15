"""Run harmless execution-path fixtures locally; no network or agent calls."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

import yaml

BASE = Path(__file__).resolve().parents[1] / "synthetic"


def run(base=BASE):
    results = []
    for case in json.loads((base / "manifest.json").read_text())["cases"]:
        with tempfile.TemporaryDirectory(prefix="synthetic-path-") as work:
            root = Path(work) / case["directory"]
            shutil.copytree(base / case["directory"], root)
            workflow = yaml.load((root / ".github/workflows/demo.yml").read_text(), Loader=yaml.BaseLoader)
            assert "pull_request_target" in workflow["on"]
            steps = workflow["jobs"]["demo"]["steps"]
            assert steps[0]["uses"] == "actions/checkout@v4"
            if case["type"] == "F":
                assert steps[1]["uses"] == "./.github/actions/runner"
                composite = yaml.safe_load((root / ".github/actions/runner/action.yml").read_text())
                assert composite["runs"]["using"] == "composite"
                assert composite["runs"]["steps"][0]["with"]["ref"] == "${{ github.event.pull_request.head.sha }}"
                command = composite["runs"]["steps"][1]["run"]
            else:
                assert steps[0]["with"]["ref"] == "${{ github.event.pull_request.head.sha }}"
                command = steps[-1]["run"]
            # The local harness exercises the actual command recorded in the YAML.
            # It does not simulate GitHub privileges, clone untrusted code or call LLMs.
            import os
            env = dict(os.environ, REPLICATION_CANARY="synthetic-value-no-credential")
            env["PATH"] = str(Path(sys.executable).parent) + os.pathsep + env.get("PATH", "")
            completed = subprocess.run(command, shell=True, executable="/bin/sh", cwd=root,
                                       env=env, capture_output=True, text=True, timeout=120)
            if completed.returncode != 0 or case["marker"] not in completed.stdout:
                raise RuntimeError(f"Case {case['type']} failed: {completed.stdout}\n{completed.stderr}")
            # Remove the marker payload and verify that the same workflow command
            # no longer emits it. This checks actual reachability of that file.
            (root / case["payload_file"]).write_text(case["neutral_payload"])
            neutral = subprocess.run(command, shell=True, executable="/bin/sh", cwd=root,
                                     env=env, capture_output=True, text=True, timeout=120)
            if neutral.returncode != 0 or case["marker"] in neutral.stdout:
                raise RuntimeError(f"Case {case['type']} negative control failed: {neutral.stdout}\n{neutral.stderr}")
            results.append({"type": case["type"], "marker_reached": True, "negative_control_passed": True})
    return results


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path)
    args = p.parse_args()
    results = run()
    rendered = json.dumps({"kind": "local_pathway_smoke_test", "cases": results}, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered)
    print(rendered, end="")


if __name__ == "__main__":
    main()
