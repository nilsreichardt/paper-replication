from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent
    / "scripts"
    / "remove_blocked_preparation_repos.py"
)


def _load_script_module():
    spec = importlib.util.spec_from_file_location(
        "remove_blocked_preparation_repos",
        SCRIPT_PATH,
    )
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_payload(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _read_payload(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_only_blocked_preparation_repositories_are_removed(tmp_path: Path) -> None:
    module = _load_script_module()
    target = tmp_path / "result.json"
    payload = {
        "ai_enumeration": [
            {
                "name": "org/remove-me",
                "risks": [
                    {"attack_result": {"status": "blocked_preparation_error"}},
                ],
            },
            {
                "name": "org/keep-execution-error",
                "risks": [
                    {"attack_result": {"status": "execution_error"}},
                ],
            },
            {
                "name": "org/keep-ok",
                "risks": [
                    {"attack_result": {"status": "vulnerable_confirmed"}},
                ],
            },
        ]
    }
    _write_payload(target, payload)

    exit_code = module.main([str(target)])
    assert exit_code == 0

    updated = _read_payload(target)
    names = [repo["name"] for repo in updated["ai_enumeration"]]
    assert names == ["org/keep-execution-error", "org/keep-ok"]


def test_backup_is_created_with_timestamp_suffix(tmp_path: Path) -> None:
    module = _load_script_module()
    target = tmp_path / "result.json"
    _write_payload(target, {"ai_enumeration": []})

    timestamp = "20260410T113000"
    backup_path = module.create_backup_copy(target, timestamp=timestamp)

    assert backup_path == tmp_path / f"result.{timestamp}.json"
    assert backup_path.exists()
    assert _read_payload(backup_path) == {"ai_enumeration": []}


def test_dry_run_does_not_modify_input_file(tmp_path: Path) -> None:
    module = _load_script_module()
    target = tmp_path / "result.json"
    payload = {
        "ai_enumeration": [
            {
                "name": "org/remove-me",
                "risks": [
                    {"attack_result": {"status": "blocked_preparation_error"}},
                ],
            },
            {"name": "org/keep-me", "risks": []},
        ]
    }
    _write_payload(target, payload)
    before = target.read_text(encoding="utf-8")

    exit_code = module.main([str(target), "--dry-run"])
    assert exit_code == 0

    assert target.read_text(encoding="utf-8") == before
    assert list(tmp_path.glob("result.*.json")) == []
