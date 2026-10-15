from __future__ import annotations

import importlib.util
import json
from pathlib import Path


SCRIPT_PATH = (
    Path(__file__).resolve().parent.parent / "scripts" / "filter_failed_repos.py"
)


def _load_script_module():
    spec = importlib.util.spec_from_file_location("filter_failed_repos", SCRIPT_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module from {SCRIPT_PATH}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _write_payload(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _read_payload(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def test_error_based_repository_is_removed(tmp_path: Path) -> None:
    module = _load_script_module()
    target = tmp_path / "result.json"
    payload = {
        "timestamp": "2026-03-30T12:00:00Z",
        "ai_enumeration": [
            {"name": "org/ok"},
            {"name": "org/failed", "error": "Argument list too long: 'gemini'"},
        ],
    }
    _write_payload(target, payload)

    exit_code = module.main(["--file", str(target)])
    assert exit_code == 0

    updated = _read_payload(target)
    names = [repo["name"] for repo in updated["ai_enumeration"]]
    assert names == ["org/ok"]


def test_blocked_preparation_status_is_removed(tmp_path: Path) -> None:
    module = _load_script_module()
    target = tmp_path / "result.json"
    payload = {
        "timestamp": "2026-03-30T12:00:00Z",
        "ai_enumeration": [
            {
                "name": "org/blocked",
                "risks": [
                    {"attack_result": {"status": "blocked_preparation_error"}},
                ],
            },
            {
                "name": "org/ok",
                "risks": [{"attack_result": {"status": "vulnerable_confirmed"}}],
            },
        ],
    }
    _write_payload(target, payload)

    exit_code = module.main(["--file", str(target)])
    assert exit_code == 0

    updated = _read_payload(target)
    names = [repo["name"] for repo in updated["ai_enumeration"]]
    assert names == ["org/ok"]


def test_any_matching_failed_status_marks_repo_failed(tmp_path: Path) -> None:
    module = _load_script_module()
    target = tmp_path / "result.json"
    payload = {
        "timestamp": "2026-03-30T12:00:00Z",
        "ai_enumeration": [
            {
                "name": "org/mixed",
                "risks": [
                    {"attack_result": {"status": "vulnerable_confirmed"}},
                    {"attack_result": {"status": "blocked_preparation_error"}},
                ],
            },
            {
                "name": "org/ok",
                "risks": [{"attack_result": {"status": "vulnerable_confirmed"}}],
            },
        ],
    }
    _write_payload(target, payload)

    exit_code = module.main(["--file", str(target)])
    assert exit_code == 0

    updated = _read_payload(target)
    names = [repo["name"] for repo in updated["ai_enumeration"]]
    assert names == ["org/ok"]


def test_backup_naming_handles_collision(tmp_path: Path) -> None:
    module = _load_script_module()
    target = tmp_path / "result.json"
    target.write_text('{"ai_enumeration":[]}\n', encoding="utf-8")

    timestamp = "20260330T134501"
    first_candidate = tmp_path / f"result.{timestamp}.json"
    first_candidate.write_text("existing", encoding="utf-8")

    backup_path = module.create_backup_copy(target, timestamp=timestamp)
    assert backup_path == tmp_path / f"result.{timestamp}.1.json"
    assert backup_path.exists()


def test_dry_run_does_not_modify_file_or_create_backup(tmp_path: Path) -> None:
    module = _load_script_module()
    target = tmp_path / "result.json"
    payload = {
        "timestamp": "2026-03-30T12:00:00Z",
        "ai_enumeration": [
            {
                "name": "org/blocked",
                "risks": [
                    {"attack_result": {"status": "blocked_preparation_error"}},
                ],
            },
            {"name": "org/ok"},
        ],
    }
    _write_payload(target, payload)
    before = target.read_text(encoding="utf-8")

    exit_code = module.main(["--file", str(target), "--dry-run"])
    assert exit_code == 0

    after = target.read_text(encoding="utf-8")
    assert after == before
    backups = list(tmp_path.glob("result.*.json"))
    assert backups == []
