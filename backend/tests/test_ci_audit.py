"""The CI entry point used by the GitHub Action: exit code, annotations, summary and outputs."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from scripts import ci_audit

ROOT = Path(__file__).resolve().parents[2]


def _actions_env(monkeypatch, tmp_path, workspace: Path) -> Path:
    gh = tmp_path / "gh"
    gh.mkdir()
    for key, value in {"GITHUB_ACTIONS": "true", "GITHUB_WORKSPACE": str(workspace), "RUNNER_TEMP": str(gh),
                       "GITHUB_STEP_SUMMARY": str(gh / "summary.md"), "GITHUB_OUTPUT": str(gh / "out")}.items():
        monkeypatch.setenv(key, value)
    return gh


def test_unsafe_code_fails_the_job_and_is_annotated_on_the_line(monkeypatch, tmp_path, capsys):
    repo = tmp_path / "ws" / "agent"
    shutil.copytree(ROOT / "examples/demo/unsafe-treasury-agent", repo)
    gh = _actions_env(monkeypatch, tmp_path, tmp_path / "ws")
    assert ci_audit.main([str(repo)]) == 1
    printed = capsys.readouterr().out
    assert "::error file=agent/src/index.ts,line=23,title=Touchmark%3A External input reaches" in printed
    outputs = dict(line.split("=", 1) for line in (gh / "out").read_text().splitlines())
    assert outputs["decision"] == "needs_fixes" and outputs["tmark"] == "missing"
    assert json.loads(Path(outputs["report"]).read_text())["findings"]
    assert "needs fixes" in (gh / "summary.md").read_text()
    assert ci_audit.main([str(repo), "--fail-on", "never"]) == 0


def test_safe_code_does_not_fail_but_the_rules_alone_never_report_a_pass(monkeypatch, tmp_path):
    gh = _actions_env(monkeypatch, tmp_path, ROOT)
    assert ci_audit.main([str(ROOT / "examples/demo/safe-treasury-agent")]) == 0
    outputs = (gh / "out").read_text()
    assert "tmark=valid" in outputs and "decision=needs_evidence" in outputs
    assert "not a Touchmark pass" in (gh / "summary.md").read_text()


def test_an_invalid_tmark_is_annotated_on_the_file(monkeypatch, tmp_path, capsys):
    repo = tmp_path / "agent"
    shutil.copytree(ROOT / "examples/demo/safe-treasury-agent", repo)
    (repo / ".tmark").write_text('{"tmark": "1", "agent": {"kind": "robot"}}')
    _actions_env(monkeypatch, tmp_path, repo)
    ci_audit.main([str(repo)])
    printed = capsys.readouterr().out
    assert "::error file=.tmark,line=1,title=.tmark is invalid::agent.kind" in printed
