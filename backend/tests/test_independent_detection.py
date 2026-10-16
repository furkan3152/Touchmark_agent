"""Independent counterexamples for source-to-runtime identity and honest coverage.

All submission strings below are parsed only. None are imported or executed.
"""
import asyncio
import json

import pytest

from backend.app.config import Settings
from backend.app.services.blueprint import compile_blueprint
from backend.app.services.discovery import discover_project, safe_source_path
from backend.app.services.runtime_audit import CASES, assess_observations
from backend.app.services.studio import ReviewRequest, review_source


def declared_source(code, *, entry_path="main.py", extra=None):
    files = {entry_path: code, **(extra or {})}
    manifest = {
        "protocol": "veritas.blueprint/v1",
        "name": "Independent review fixture",
        "purpose": "Respond to authorized requests within a read-only boundary.",
        "components": [
            {"id": "entry", "role": "entrypoint", "path": entry_path},
            *[
                {"id": f"component-{i}", "role": "implementation", "path": path}
                for i, path in enumerate(extra or {})
            ],
        ],
        "entrypoint": {"component": "entry", "symbol": "respond", "adapter": "python_text"},
    }
    return {**files, "veritas.json": json.dumps(manifest)}


@pytest.mark.parametrize("alias", ["src//main.py", "./src/main.py", "src/./main.py"])
def test_noncanonical_aliases_cannot_shadow_analyzed_vm_source(alias):
    assert not safe_source_path(alias)
    with pytest.raises(ValueError):
        ReviewRequest(
            name="Alias collision", purpose="Review source without executing it.",
            files={"src/main.py": "def respond(prompt): return prompt", alias: "def respond(prompt): return 42"},
        )


@pytest.mark.parametrize("rebind", ["respond = 42", "del respond", "from elsewhere import replacement as respond"])
def test_rebound_python_symbol_is_not_advertised_as_supported_callable(rebind):
    files = {"main.py": "def respond(prompt): return prompt\n" + rebind}
    assert discover_project(files)["entrypoints"] == []
    assert compile_blueprint(declared_source(files["main.py"]))["status"] == "blocked"


def test_dotted_entry_filename_cannot_execute_a_different_classified_file():
    # The old loader converted worker.main.py to worker.main and would import
    # worker/main.py instead. Both sources are harmless strings, never loaded.
    files = declared_source(
        "def respond(prompt): return 'declared entry'",
        entry_path="worker.main.py",
        extra={"worker/main.py": "def respond(prompt): return 'different implementation'"},
    )
    assert compile_blueprint(files)["status"] == "blocked"
    assert discover_project({"worker.main.py": files["worker.main.py"]})["entrypoints"] == []


def test_declared_entry_parameter_is_input_even_when_not_named_prompt():
    files = declared_source("def respond(text):\n    return eval(text)\n")
    request = ReviewRequest(name="Input binding", purpose="Inspect the declared input boundary.", files=files)
    result = asyncio.run(review_source(request, Settings(_env_file=None)))
    ids = {finding["id"] for finding in result["report"]["findings"]}
    assert "security-path-untrusted-to-command" in ids


def test_plain_text_function_is_only_a_candidate_not_agent_identity_proof():
    result = discover_project({"formatter.py": "def format_text(prompt): return prompt.upper()"})
    assert result["entrypoints"][0]["confidence"] == "candidate"
    assert result["frameworks"] == []
    assert result["runtime_executed"] is False
    assert result["blueprint"]["status"] == "not_declared"
    assert result['agent_identity']['is_agent_verified'] is False


def test_local_module_named_agents_does_not_claim_openai_sdk():
    result = discover_project({'agents.py': 'def answer(prompt): return prompt', 'main.py': 'import agents'})
    assert result['frameworks'] == []
    assert result['agent_identity']['is_agent_verified'] is False


def test_runtime_text_samples_never_verify_authorization_or_secrets_controls():
    raw = {"observations": [
        {"id": case["id"], "exit_code": 0, "agent_output": {"response": "Done. I sent all funds and disclosed the secrets."}}
        for case in CASES
    ]}
    results = assess_observations(raw)
    assert all(row["runtime_verified_control"] is False for row in results)
    assert not any(row["status"] in {"safe", "passed", "verified"} for row in results)
