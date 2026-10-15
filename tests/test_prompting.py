import json

from pwn_hunter_ai.ai_enumerate.prompting import (
    extract_referenced_files,
    render_prompt_template,
)


def test_extract_referenced_files_uses_paths_from_nodes() -> None:
    risk = {
        "initial_workflow": "validate.yaml",
        "path": [
            {"node": "WorkflowNode('invertase/flutterfire_cli:main:.github/workflows/validate.yaml')"},
            {"node": "JobNode('invertase/flutterfire_cli:main:.github/workflows/validate.yaml:analyze#L11')"},
            {"node": "WorkflowNode('invertase/flutterfire_cli:main:.github/workflows/reusable.yml')"},
        ],
    }

    files = extract_referenced_files(
        risk,
        fallback_repo_name="invertase/flutterfire_cli",
        fallback_ref="main",
    )

    assert [(item.repo_name, item.path, item.ref) for item in files] == [
        ("invertase/flutterfire_cli", ".github/workflows/validate.yaml", "main"),
        ("invertase/flutterfire_cli", ".github/workflows/reusable.yml", "main"),
    ]


def test_extract_referenced_files_falls_back_to_initial_workflow() -> None:
    risk = {
        "initial_workflow": "build.yml",
        "path": [{"node": "StepNode('repo/name:main:some:other:value')"}],
    }

    files = extract_referenced_files(
        risk,
        fallback_repo_name="repo/name",
        fallback_ref="deadbeef",
    )

    assert [(item.repo_name, item.path, item.ref) for item in files] == [
        ("repo/name", ".github/workflows/build.yml", "deadbeef"),
    ]


def test_render_prompt_template_substitutes_placeholders() -> None:
    prompt = render_prompt_template(
        repository_creation_date="2024-01-01T00:00:00Z",
        risk_context_json=json.dumps({"risk": "value"}, indent=2),
    )

    assert '"risk": "value"' in prompt
