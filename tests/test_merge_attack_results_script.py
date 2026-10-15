from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parent.parent / "scripts" / "merge_attack_results.py"


def _load_script_module():
    spec = importlib.util.spec_from_file_location("merge_attack_results", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_payload(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def test_merge_accepts_legacy_and_enumeration_shapes(tmp_path: Path) -> None:
    module = _load_script_module()
    _write_payload(
        tmp_path / "attack_results_part1.json",
        {
            "timestamp": "Fri Apr 03 22:57:01 2026",
            "ai_enumeration": [{"name": "org/legacy"}],
        },
    )
    _write_payload(
        tmp_path / "attack_results_part2.json",
        {
            "username": "Sharezone-Admin",
            "scopes": ["gist", "repo", "workflow"],
            "enumeration": {
                "timestamp": "Mon Mar  9 01:05:47 2026",
                "organizations": [{"login": "org"}],
                "repositories": [{"name": "org/canonical"}],
            },
        },
    )

    merged, summary = module.merge_attack_results(tmp_path)

    assert merged == {
        "username": "Sharezone-Admin",
        "scopes": ["gist", "repo", "workflow"],
        "enumeration": {
            "timestamp": "Mon Mar  9 01:05:47 2026",
            "organizations": [{"login": "org"}],
            "repositories": [{"name": "org/legacy"}, {"name": "org/canonical"}],
        },
    }
    assert summary["repositories"] == 2
    assert [source["source_shape"] for source in summary["sources"]] == [
        "ai_enumeration",
        "enumeration.repositories",
    ]


def test_main_writes_default_output_in_input_dir(tmp_path: Path) -> None:
    module = _load_script_module()
    _write_payload(
        tmp_path / "attack_results_part1.json",
        {
            "username": "tester",
            "scopes": ["repo"],
            "enumeration": {
                "timestamp": "Mon Mar  9 01:05:47 2026",
                "organizations": [],
                "repositories": [{"name": "org/repo"}],
            },
        },
    )

    exit_code = module.main(["--input-dir", str(tmp_path)])

    assert exit_code == 0
    output = tmp_path / "attack_results_merged.json"
    assert output.exists()
    merged = json.loads(output.read_text(encoding="utf-8"))
    assert merged["enumeration"]["repositories"] == [{"name": "org/repo"}]
