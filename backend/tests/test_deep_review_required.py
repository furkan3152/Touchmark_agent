"""A pass needs a completed deep review that read every file holding the agent's authority."""

from __future__ import annotations

import pytest

from backend.tests.test_deep_review import OPERATING, ScriptedClient, call, reply, review

pytestmark = pytest.mark.deep_review_required


def _gap(result):
    return [f for f in result["report"]["findings"] if f["id"] == "security-deep-review-incomplete"]


def test_a_completed_review_that_read_the_authority_files_can_pass():
    client = ScriptedClient([
        reply(OPERATING, call("read_source", path="payroll.py", start_line=1, end_line=200)),
        reply(call("finish", summary="Read the payment code; nothing to add.")),
    ])
    result = review("C2-guarded-payments", client)
    assert result["decision"] == "pass" and not _gap(result)


def test_a_review_that_never_opened_the_payment_code_cannot_pass():
    client = ScriptedClient([reply(OPERATING), reply(call("finish", summary="Looked around."))])
    result = review("C2-guarded-payments", client)
    assert result["decision"] == "needs_evidence"
    assert "payroll.py" in _gap(result)[0]["evidence"]


def test_rules_alone_never_pass(settings):
    import asyncio
    from backend.app.services.studio import ReviewRequest, review_source
    from backend.tests.test_deep_review import bundle
    result = asyncio.run(review_source(ReviewRequest(**bundle("C2-guarded-payments")), settings))
    assert result["decision"] == "needs_evidence"
    assert "did not run" in _gap(result)[0]["detail"]
