from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import pytest

BASE = Path(__file__).resolve().parents[1]


def module(name):
    spec = importlib.util.spec_from_file_location(name, BASE / "scripts" / (name + ".py"))
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


def test_export_excludes_private_fields_and_retains_suppressed_totals(tmp_path):
    exporter = module("export_data")
    private = tmp_path / "private.json"
    sensitive = "PRIVATE-IDENTITY-AND-EXPLOIT-SENTINEL"
    rows = []
    for i in range(10):
        rows.append({"repository": f"{sensitive}/{i}", "url": f"https://example.invalid/{sensitive}",
                     "classification": "confirmed_privileged", "stars": 2000 if i < 4 else 0,
                     "last_commit": "2026-01-01", "github_token_write_scoped": True,
                     "highest_github_token_scope": "write", "named_secret_exfiltrated": False,
                     "findings": [{"agent_sink": "npm install", "attempts": [{"agent_output": sensitive}],
                                   "secret_names": [sensitive], "pull_request_url": sensitive}]})
    private.write_text(json.dumps({"disclosure_metadata": {"author": sensitive}, "repositories": rows}))
    out = tmp_path / "public"
    exporter.export(argparse.Namespace(search=None, enumeration=None, disclosure=private, attack=None, metadata=None, output=out))
    assert all(sensitive not in p.read_text() for p in out.iterdir())
    aggregate = json.loads((out / "stars.aggregate.json").read_text())
    assert sum(r["count"] for r in aggregate) == 10
    assert len((out / "stars.csv").read_text().splitlines()) == 7  # header + six non-rare rows
    result = module("reproduce").reproduce(out)
    assert result["outcomes"] == {"privileged": 10}
    assert result["warnings"]  # never imply complete study coverage
    with (out / "stars.csv").open("a") as handle:
        handle.write("privileged,0\n")
    with pytest.raises(AssertionError, match="Microdata differs"):
        module("reproduce").reproduce(out)


def test_collector_configuration_matches_prompt(monkeypatch):
    from pwn_hunter_ai.attack.artifacts import _build_agent_prompt
    from pwn_hunter_ai.attack.hookbin_client import HookbinClient

    monkeypatch.setenv("PWNHUNTER_HOOKBIN_URL", "https://collector.example.invalid/")
    monkeypatch.setenv("PWNHUNTER_MEMDUMP_URL", "https://helper.example.invalid/memdump.py")
    client = HookbinClient()
    assert client.base_url == "https://collector.example.invalid"
    assert client.api_url == "https://collector.example.invalid/api"
    prompt = _build_agent_prompt({"repository_name": "synthetic-owner/demo", "vulnerable_commit_hash": "0" * 40,
                                  "attack_input_source": "gato-x", "risk": {}, "attack_result": {}})
    assert "https://collector.example.invalid/$GITHUB_RUN_ID" in prompt
    assert "https://helper.example.invalid/memdump.py" in prompt
    assert "{{hookbin_base_url}}" not in prompt


def test_released_data_consistency():
    report = module("reproduce").reproduce(BASE / "data")
    assert report["outcomes"] == {"privileged": 2054, "rce": 2881, "unconfirmed": 6119}
    assert report["privileged_composition"] == {"write_scoped": 1537, "named_secret": 968, "both": 451, "named_secret_only": 517}


def test_recovered_helper_act_mode_does_not_inspect_processes(monkeypatch):
    import os
    import runpy

    monkeypatch.setenv("IS_RUNNING_IN_ACT", "true")

    def forbidden_process_access(*args, **kwargs):
        raise AssertionError("act mode must exit before inspecting processes")

    monkeypatch.setattr(os, "listdir", forbidden_process_access)
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(BASE / "helper/memdump.py"), run_name="__main__")
    assert stopped.value.code == 0


def test_clean_checkout_uses_tracked_synthetic_secret_template(tmp_path, monkeypatch):
    from pwn_hunter_ai.attack import execution_service

    private_path = tmp_path / ".secrets"
    tracked = tmp_path / ".secrets.template"
    tracked.write_text("SYNTHETIC_VALUE=not-a-credential\n")
    monkeypatch.setattr(execution_service, "LOCAL_SECRETS_TEMPLATE_PATH", private_path)
    assert execution_service._read_local_secrets_template() == tracked.read_text()
    private_path.write_text("SYNTHETIC_VALUE=local-override\n")
    assert execution_service._read_local_secrets_template() == private_path.read_text()
