"""Scope and duplicate fixes from the second live evaluation on real repositories."""

from __future__ import annotations

from pathlib import Path

from backend.app.models import Dimension, Finding, Severity
from backend.app.services.repo_audit import select_repository
from backend.app.swarm.consolidate import consolidate


def _write(root: Path, rel: str, text: str) -> None:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def test_example_folders_that_use_a_held_key_are_reviewed_and_others_stay_out(tmp_path):
    _write(tmp_path, "src/index.ts", "export const x = 1;\n")
    _write(tmp_path, "examples/facilitator/src/server.ts",
           "const kp = Keypair.fromSecret(process.env.FACILITATOR_STELLAR_PRIVATE_KEY);\n")
    _write(tmp_path, "examples/facilitator/src/routes.ts", "export const routes = [];\n")
    _write(tmp_path, "examples/web/app.ts", "console.log('hello');\n")
    _write(tmp_path, "examples/facilitator/test/server.test.ts", "const k = Keypair.fromSecret('S');\n")
    files, meta = select_repository(tmp_path)
    assert "examples/facilitator/src/server.ts" in files and "examples/facilitator/src/routes.ts" in files
    assert "examples/web/app.ts" not in files
    assert not any("/test/" in f for f in files)
    assert meta["manifest"]["examples_with_keys_included"] == ["examples/facilitator"]


def test_new_languages_are_selected_and_their_tests_are_not(tmp_path):
    _write(tmp_path, "src/main/kotlin/Pay.kt", "fun pay() = KeyPair.fromSecretSeed(seed)\n")
    _write(tmp_path, "src/main/java/Contest.java", "class Contest {}\n")
    _write(tmp_path, "src/main/java/PayTest.java", "class PayTest {}\n")
    _write(tmp_path, "Api/Payroll.cs", "public class Payroll {}\n")
    _write(tmp_path, "Api/bin/Debug/Gen.cs", "public class Gen {}\n")
    _write(tmp_path, "crate/src/tests.rs", "fn t() {}\n")
    _write(tmp_path, "eval/run.ts", "export const r = 1;\n")
    files, _ = select_repository(tmp_path)
    assert {"src/main/kotlin/Pay.kt", "src/main/java/Contest.java", "Api/Payroll.cs"} <= set(files)
    assert not {"src/main/java/PayTest.java", "Api/bin/Debug/Gen.cs", "crate/src/tests.rs", "eval/run.ts"} & set(files)


def _f(fid: str, evidence: str, severity=Severity.HIGH) -> Finding:
    return Finding(id=fid, dimension=Dimension.SECURITY, severity=severity, title=fid, detail="d.",
                   evidence=evidence, auditor="security", confidence=0.8)


def test_one_defect_reported_per_line_or_per_rule_becomes_one_finding():
    # syronlabs: one shell injection reported at three nearby lines; asgcard: one committed
    # secret reported by three rules on the same line.
    out = consolidate([
        _f("security-ai-code-execution-1", "src/core.ts:45 `exec(cmd)`", Severity.CRITICAL),
        _f("security-ai-code-execution-2", "src/core.ts:49 `exec(cmd2)`"),
        _f("security-ai-code-execution-3", "src/core.ts:51 `exec(cmd3)`"),
        _f("stellar_native-stellar-secret-seed", "api/e2e.js:21 `SB...`", Severity.CRITICAL),
        _f("security-code-embedded-api-credential", "api/e2e.js:21 `SECRET = ...`", Severity.LOW),
        _f("security-ai-code-execution-4", "src/other.ts:45 `exec(x)`"),
    ])
    ids = [f.id for f in out]
    assert ids.count("security-ai-code-execution-1") == 1 and "security-ai-code-execution-2" not in ids
    assert "security-ai-code-execution-3" not in ids and "security-ai-code-execution-4" in ids
    assert "stellar_native-stellar-secret-seed" in ids and "security-code-embedded-api-credential" not in ids
    lead = next(f for f in out if f.id == "stellar_native-stellar-secret-seed")
    assert "Also reported as security-code-embedded-api-credential" in lead.detail


def test_a_rule_finding_absorbs_the_model_finding_of_the_same_defect_nearby():
    # syronlabs: the payment rule cites the sign call, the model the payment operation nine lines up.
    out = consolidate([
        _f("security-path-untrusted-to-financial-sink", "src/classic.ts:117 `transaction.sign(sourceKeypair);`"),
        _f("security-ai-unauthorized-payment-3", "src/classic.ts:108 `Operation.payment({` · src/classic.ts:183 `x`"),
        _f("security-ai-unauthorized-payment-4", "src/other.ts:10 `Operation.payment({`"),
    ])
    ids = [f.id for f in out]
    assert "security-ai-unauthorized-payment-3" not in ids and "security-ai-unauthorized-payment-4" in ids


def test_a_refuted_fund_rule_in_example_code_only_carries_no_weight():
    from backend.app.models import AuditorVerdict
    from backend.app.swarm.orchestrator import AuditSwarm
    f = _f("security-path-key-signs-arbitrary-bytes", "examples/charge-client-fee-bump.ts:111 `keypair.sign(`", Severity.MEDIUM)
    shipped = _f("security-path-key-signs-arbitrary-bytes-2", "src/client.ts:20 `keypair.sign(`", Severity.MEDIUM)
    shipped = shipped.model_copy(update={"id": "security-path-key-signs-arbitrary-bytes"})
    refute = lambda fid: {"results": [{"finding_id": fid, "verdict": "refuted", "quote_verified": True,  # noqa: E731
                                       "quote": "keypair.sign(Buffer.from(`${challenge.id}:${hash}`))",
                                       "file": "x.ts", "line": 1, "reason": "fixed-format message"}]}
    v = AuditorVerdict(auditor="security", dimension=Dimension.SECURITY, score=50.0, findings=[f])
    out = AuditSwarm._apply_disputes([v], refute(f.id))[0].findings[0]
    assert not out.is_risk and out.title.startswith("Disputed")
    v2 = AuditorVerdict(auditor="security", dimension=Dimension.SECURITY, score=50.0, findings=[shipped])
    kept = AuditSwarm._apply_disputes([v2], refute(shipped.id))[0].findings[0]
    assert kept.is_risk and kept.severity == Severity.LOW  # shipped fund-control rules keep the old rule: one level lower
