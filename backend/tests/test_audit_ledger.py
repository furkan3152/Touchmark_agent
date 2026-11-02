"""The file map and the check ledger (services/file_map.py, services/audit_ledger.py), with a
scripted model client: every file in any language is mapped, quotes are checked, the same
checks are asked of every agent and each must be answered from the code."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

from backend.app.models import AgentArtifact, SourceKind
from backend.app.services import audit_ledger as ledger
from backend.app.services import languages
from backend.app.services.deep_review import DeepReviewer, authority_files
from backend.app.services.file_map import FileMap, FileMapper, batches, segments
from backend.app.services.review_budget import Budget

KOTLIN = """package agent

import org.stellar.sdk.KeyPair
import org.stellar.sdk.Transaction

class PayoutService(private val server: Server, private val seed: String) {
    fun pay(destination: String, amount: String): String {
        val signer = KeyPair.fromSecretSeed(seed)
        val tx = buildPayment(signer, destination, amount)
        tx.sign(signer)
        return server.submitTransaction(tx).hash
    }
}
"""
ROUTES = """package agent

fun Application.routes(service: PayoutService) {
    routing {
        post("/pay") {
            val body = call.receive<PayRequest>()
            call.respond(service.pay(body.destination, body.amount))
        }
    }
}
"""
README = "# Payout agent\nPays contractors.\n"


def artifact() -> AgentArtifact:
    return AgentArtifact(name="payout", description="Pays contractors in XLM.", source_kind=SourceKind.REPO,
                         code_files={"src/main/kotlin/PayoutService.kt": KOTLIN, "src/main/kotlin/Routes.kt": ROUTES,
                                     "README.md": README})


def call(name, **args):
    return SimpleNamespace(type="tool_use", id=f"tu_{name}_{id(args)}", name=name, input=args)


def reply(*blocks, stop="tool_use"):
    return SimpleNamespace(content=list(blocks), stop_reason=stop,
                           usage=SimpleNamespace(input_tokens=100, output_tokens=50,
                                                 cache_read_input_tokens=0, cache_creation_input_tokens=0))


CARDS = [
    {"path": "src/main/kotlin/PayoutService.kt", "role": "payment", "summary": "Signs and submits payments.",
     "capabilities": [
         {"kind": "signs_transactions", "line": 10, "quote": "tx.sign(signer)"},
         {"kind": "submits_transactions", "line": 11, "quote": "server.submitTransaction(tx)"},
         {"kind": "holds_or_loads_secret", "line": 8, "quote": "KeyPair.fromSecretSeed(seed)"},
         # A quote that is not in the file: dropped and counted.
         {"kind": "moves_value", "line": 9, "quote": "Operation.payment(unbounded)"},
     ],
     "untrusted_inputs": [], "controls": [], "exposes": []},
    {"path": "src/main/kotlin/Routes.kt", "role": "http_route", "summary": "Exposes POST /pay.",
     "capabilities": [], "controls": [], "exposes": [{"name": "POST /pay", "line": 5, "quote": 'post("/pay") {'}],
     "untrusted_inputs": [{"source": "http_request", "line": 6, "quote": "call.receive<PayRequest>()"}]},
    {"path": "README.md", "role": "other", "summary": "Docs.", "capabilities": [], "untrusted_inputs": [],
     "controls": [], "exposes": []},
]


class RoutingClient:
    """Answers map requests with CARDS and review requests from a script per pass kind."""

    def __init__(self, review_turns):
        self.review_turns = list(review_turns)
        self.requests = []
        self.beta = SimpleNamespace(messages=SimpleNamespace(create=self.create))

    async def create(self, **kwargs):
        self.requests.append(kwargs)
        names = [t["name"] for t in kwargs["tools"]]
        if names == ["submit_file_cards"]:
            text = kwargs["messages"][0]["content"]
            cards = [c for c in CARDS if f"=== FILE {c['path']} " in text]
            return reply(call("submit_file_cards", cards=cards))
        if not self.review_turns:
            return reply(call("finish", summary="done"))
        return self.review_turns.pop(0)


def run(reviewer, art):
    return asyncio.run(reviewer.review(art, [], None))


def test_languages_are_named_and_rule_coverage_is_honest():
    rows = languages.coverage(["a/App.kt", "a/B.kt", "x.py", "Main.java", "lib.rs"])
    by = {r["language"]: r for r in rows}
    assert by["Kotlin"]["files"] == 2 and by["Kotlin"]["rules"] == "none"
    assert by["Python"]["rules"] == "data_flow" and by["Rust"]["rules"] == "patterns"
    assert languages.language_of("server.py.hbs") == "Python"
    assert languages.rules_blind_share(["a.kt", "b.py"]) == 0.5


def test_large_files_are_split_into_segments_and_every_segment_is_batched():
    big = "\n".join("x = 1  # " + "y" * 100 for _ in range(1500))
    files = {"big.py": big, "small.py": "a = 1\n"}
    segs = segments(files, ["big.py", "small.py"])
    assert [s for s in segs if s[0] == "big.py"][0][1] == 1 and len([s for s in segs if s[0] == "big.py"]) >= 2
    assert sum(len(b) for b in batches(files, segs)) == len(segs)


def test_file_map_keeps_only_quotes_found_in_the_source():
    art = artifact()
    client = RoutingClient([])
    mapper = FileMapper(client, model="claude-sonnet-5-5")
    saved = []

    async def save(state):
        saved.append(state)

    fmap = asyncio.run(mapper.map(art.code_files, sorted(art.code_files), Budget(), None, {}, save))
    service = fmap.cards["src/main/kotlin/PayoutService.kt"]
    assert {c["kind"] for c in service["capabilities"]} == {"signs_transactions", "submits_transactions",
                                                            "holds_or_loads_secret"}
    assert fmap.dropped_items == 1
    assert fmap.authority_files() == {"src/main/kotlin/PayoutService.kt"}
    assert fmap.done and saved and saved[-1]["done"]
    # The map request asks for the tool without forcing it (forced tool choice is a 400 on this model).
    assert client.requests[0]["tool_choice"] == {"type": "auto"}
    # Restored from saved state, the map is not run again.
    again = asyncio.run(mapper.map(art.code_files, sorted(art.code_files), Budget(), None, saved[-1], save))
    assert again.cards == fmap.cards and len(client.requests) == 1


def test_applicable_checks_follow_capabilities_not_the_model():
    assert {c.id for c in ledger.applicable(set())} == {"M4", "M5"}
    paying = {c.id for c in ledger.applicable({"moves_value", "signs_transactions"})}
    assert {"V1", "V4", "S1", "S3", "A1"} <= paying and "V7" not in paying
    assert [g for g, _ in ledger.plan({"calls_llm"})] == ["model"]
    assert ledger.agent_kinds({"payment": ["a.py:3"], "llm_call": []}, {"calls_network"}) == {"moves_value",
                                                                                            "calls_network"}


def test_ledger_review_maps_kotlin_answers_checks_and_files_failures_as_findings():
    art = artifact()
    operating = call("describe_operating_model", purpose="Pays contractors", triggers="HTTP POST /pay",
                     example_run="Client posts destination and amount; the service signs and submits.",
                     trust_boundaries=["HTTP client"], assets_at_risk=["XLM balance"])
    read = call("read_source", path="src/main/kotlin/PayoutService.kt", start_line=1, end_line=14)
    read_routes = call("read_source", path="src/main/kotlin/Routes.kt", start_line=1, end_line=10)
    fails = call("answer_check", check_id="V1", verdict="fails", file="src/main/kotlin/PayoutService.kt", line=7,
                 evidence_quote="fun pay(destination: String, amount: String): String {",
                 reason="The amount from the request is signed as is.", severity="high",
                 title="Payment amount is unbounded", attack_scenario="POST /pay with any amount drains the account.",
                 remediation="Enforce a maximum before signing.", existing_finding_id="")
    bad_quote = call("answer_check", check_id="V4", verdict="holds", file="src/main/kotlin/PayoutService.kt",
                     line=7, evidence_quote="require(destination in allowlist)", reason="allowlisted", severity="none",
                     title="", attack_scenario="", remediation="", existing_finding_id="")
    na = lambda cid: call("answer_check", check_id=cid, verdict="cannot_determine", file="", line=0,  # noqa: E731
                          evidence_quote="", reason="not in the files", severity="none", title="",
                          attack_scenario="", remediation="", existing_finding_id="")
    finish = call("finish", summary="done")
    value_checks = [c.id for g, cs in ledger.plan({"signs_transactions", "submits_transactions",
                                                    "holds_or_loads_secret"}) if g == "value" for c in cs]
    client = RoutingClient([
        reply(operating, read, read_routes), reply(finish),                        # investigate
        reply(fails, bad_quote), reply(finish),                                    # value: sent back once
        reply(*[na(c) for c in value_checks if c != "V1"]), reply(finish),
    ])
    reviewer = DeepReviewer(client, model="claude-sonnet-5-5", mode="ledger",
                            mapper=FileMapper(client, model="claude-sonnet-5-5"))
    result = run(reviewer, art)
    report = result.report()

    assert report["mode"] == "ledger"
    assert report["file_map"]["files_mapped"] == 3
    kotlin = next(r for r in report["languages"] if r["language"] == "Kotlin")
    assert kotlin == {"language": "Kotlin", "files": 2, "rules": "none", "mapped": 2, "examined": 2}
    # The map makes the Kotlin signer an authority file a passing decision requires to be examined.
    assert "src/main/kotlin/PayoutService.kt" in authority_files(art)

    rows = {r["id"]: r for r in report["ledger"]["checks"]}
    assert rows["V1"]["verdict"] == "fails" and rows["V1"]["quote_verified"]
    finding = next(f for f in result.findings if f.id == rows["V1"]["finding_id"])
    assert finding.severity.value == "high" and any("Check ledger V1" in r for r in finding.references)
    assert rows["V4"]["verdict"] != "holds"           # an unquoted "holds" is never recorded
    # The value pass tried to finish with checks open and was sent back to answer them.
    value_requests = [r for r in client.requests if r["tools"][0]["name"] != "submit_file_cards"
                      and "Check-ledger pass: Value movement" in r["messages"][0]["content"][1]["text"]]
    assert any("not answered" in str(r["messages"][-1]) or "Not finished" in str(r["messages"][-1])
               for r in value_requests)
    # Groups that were planned but whose checks got no answer are listed as unanswered, never dropped.
    assert report["ledger"]["applicable"] == len(rows)
    assert all(r["verdict"] in (*ledger.VERDICTS, "unanswered") for r in rows.values())
    # The evidence pack carries the file map and is cached across passes.
    pack_block = next(r for r in client.requests if r["tools"][0]["name"] != "submit_file_cards")["messages"][0]["content"][0]
    assert '"file_map"' in pack_block["text"] and pack_block.get("cache_control")
    assert report["coverage"]["files_examined"] == ["src/main/kotlin/PayoutService.kt", "src/main/kotlin/Routes.kt"]


def test_authority_file_the_review_never_opened_gets_a_coverage_pass():
    art = artifact()
    operating = call("describe_operating_model", purpose="p", triggers="t", example_run="e",
                     trust_boundaries=[], assets_at_risk=[])
    client = RoutingClient([reply(operating), reply(call("finish", summary="done"))])
    reviewer = DeepReviewer(client, model="claude-sonnet-5-5", mode="ledger",
                            mapper=FileMapper(client, model="claude-sonnet-5-5"))
    reviewer.max_units = 0  # without the focused file review, a coverage pass opens it
    result = run(reviewer, art)
    coverage = [p for p in result.passes if p["kind"] == "coverage"]
    assert coverage, result.passes
    asked = [r for r in client.requests if r["tools"][0]["name"] != "submit_file_cards"
             and r["messages"][0]["content"][1]["text"].startswith("Coverage pass")]
    assert "src/main/kotlin/PayoutService.kt" in asked[0]["messages"][0]["content"][1]["text"]
    # Files the map read and that hold no authority are not reopened, and are not "not reviewed".
    assert "README.md" not in asked[0]["messages"][0]["content"][1]["text"]
    assert not any(n["path"] == "README.md" for n in result.not_reviewed)


def test_each_authority_file_gets_a_focused_review_that_states_and_checks_invariants():
    art = artifact()
    operating = call("describe_operating_model", purpose="p", triggers="t", example_run="e",
                     trust_boundaries=[], assets_at_risk=[])
    holds = call("check_invariant", function="pay", invariant="amount is bounded before signing", verdict="violated",
                 file="src/main/kotlin/PayoutService.kt", line=7,
                 evidence_quote="fun pay(destination: String, amount: String): String {", reason="no cap")
    unclear = call("check_invariant", function="pay", invariant="destination is allowlisted", verdict="unclear",
                   file="", line=0, evidence_quote="", reason="config not submitted")
    bad = call("check_invariant", function="pay", invariant="x", verdict="holds",
               file="src/main/kotlin/PayoutService.kt", line=7, evidence_quote="require(amount < cap)", reason="r")
    finding = call("record_finding", category="unauthorized_payment", asset="funds", trigger="anyone",
                   network="mainnet_or_configurable", location="shipped", title="Unbounded payout",
                   file="src/main/kotlin/PayoutService.kt", line=7,
                   evidence_quote="fun pay(destination: String, amount: String): String {",
                   attack_scenario="Any amount.", stellar_impact="Drains XLM.", remediation="Cap it.")

    class UnitClient(RoutingClient):
        async def create(self, **kwargs):
            text = kwargs["messages"][0]["content"][1]["text"] if kwargs["tools"][0]["name"] != "submit_file_cards" else ""
            if text.startswith("Focused review of ONE file: src/main/kotlin/PayoutService.kt") and len(kwargs["messages"]) == 1:
                self.requests.append(kwargs)
                return reply(holds, unclear, bad, finding)
            if text.startswith("Focused review of ONE file") and len(kwargs["messages"]) > 1:
                self.requests.append(kwargs)
                return reply(call("finish", summary="done"))
            return await super().create(**kwargs)

    client = UnitClient([reply(operating), reply(call("finish", summary="done"))])
    reviewer = DeepReviewer(client, model="claude-sonnet-5-5", mode="ledger",
                            mapper=FileMapper(client, model="claude-sonnet-5-5"))
    result = run(reviewer, art)
    assert [p["kind"] for p in result.passes if p["kind"] == "units"] == ["units"]
    unit = result.units["src/main/kotlin/PayoutService.kt"]
    assert unit["status"] == "completed"
    # The unquoted "holds" is refused; the violated and the unclear invariants are kept.
    assert [i["verdict"] for i in unit["invariants"]] == ["violated", "unclear"]
    assert len(unit["findings"]) == 1
    f = next(x for x in result.findings if x.id == unit["findings"][0])
    assert f.severity.value == "critical"
    # The focused review shares the cached evidence pack and shows the file's numbered lines.
    asked = [r for r in client.requests if r["tools"][0]["name"] != "submit_file_cards"
             and r["messages"][0]["content"][1]["text"].startswith("Focused review of ONE file")]
    assert asked and asked[0]["messages"][0]["content"][0].get("cache_control")
    assert "8:         val signer = KeyPair.fromSecretSeed(seed)" in asked[0]["messages"][0]["content"][1]["text"]
    report = result.report()
    assert report["units"]["files"] >= 1 and report["units"]["violated"] == 1
    # Routes.kt holds no authority: it gets no focused review.
    assert "src/main/kotlin/Routes.kt" not in result.units


def test_a_source_file_labelled_test_by_the_map_is_still_analysed():
    from backend.app.services.file_map import is_test
    assert not is_test("src/parse.rs", {"role": "test_or_example"})
    assert is_test("tests/parse.rs", {"role": "test_or_example"})
    assert is_test("examples/client.ts", {"role": "test_or_example"})
    assert not is_test("examples/client.ts", {"role": "payment"})


def test_file_map_state_round_trips():
    fmap = FileMap(cards={"a.kt": CARDS[0]}, dropped_items=2, failed=["b.kt"], calls=3, done=True)
    assert FileMap.from_state(fmap.to_state()).to_state() == fmap.to_state()


def test_a_failing_check_linked_to_an_existing_finding_adds_its_line_to_the_evidence():
    art = artifact()
    reviewer = DeepReviewer(None, model="m", mode="ledger")
    from backend.app.services.deep_review import DeepReviewResult
    result = DeepReviewResult(mode="ledger")
    first = reviewer._add_finding({"severity": "high", "title": "Debit before submit", "file": "src/main/kotlin/PayoutService.kt",
                                   "line": 8, "evidence_quote": "KeyPair.fromSecretSeed(seed)", "attack_scenario": "s",
                                   "remediation": "r"}, "reliability_failure", result)
    reviewer._pass_checks = ["S5"]
    out = reviewer._answer_check({"check_id": "S5", "verdict": "fails", "file": "src/main/kotlin/PayoutService.kt",
                                  "line": 11, "evidence_quote": "server.submitTransaction(tx).hash", "reason": "unchecked",
                                  "severity": "medium", "title": "", "attack_scenario": "", "remediation": "",
                                  "existing_finding_id": first.id}, art, result)
    assert first.id in out and len(result.findings) == 1
    assert "PayoutService.kt:8" in result.findings[0].evidence and "PayoutService.kt:11" in result.findings[0].evidence


CHAIN = {"account": {"status": "found", "address": "GAGENT", "thresholds": {"low": 1, "medium": 2, "high": 3},
                     "multisig_required_for_payments": True, "single_key_can_administer": False,
                     "agent_key": {"key": "GKEY", "weight": 1, "is_signer": True, "can_pay_alone": False,
                                   "can_administer_alone": False}}}


def test_on_chain_thresholds_become_citable_controls_only_for_the_checks_they_enforce():
    facts = ledger.onchain_facts(CHAIN)
    assert set(facts) == {"payments_need_cosigner", "agent_key_cannot_administer"}
    assert "agent key weight 1 < medium threshold 2" in facts["payments_need_cosigner"]
    assert ledger.onchain_facts({"account": {"status": "not_supplied"}}) == {}
    solo = {"account": {**CHAIN["account"], "multisig_required_for_payments": False,
                        "agent_key": {**CHAIN["account"]["agent_key"], "weight": 2, "can_pay_alone": True}}}
    assert "payments_need_cosigner" not in ledger.onchain_facts(solo)

    art = artifact()
    reviewer = DeepReviewer(None, model="m", mode="ledger")
    reviewer._onchain = facts
    from backend.app.services.deep_review import DeepReviewResult
    result = DeepReviewResult(mode="ledger")
    reviewer._pass_checks = ["V1", "S3"]
    base = {"verdict": "holds", "file": "onchain", "line": 0, "reason": "co-signer", "severity": "none", "title": "",
            "attack_scenario": "", "remediation": "", "existing_finding_id": ""}
    out = reviewer._answer_check({**base, "check_id": "V1", "evidence_quote": facts["payments_need_cosigner"]}, art, result)
    assert "Recorded V1: holds" in out and result.ledger["V1"]["onchain"] == "payments_need_cosigner"
    # A fact that does not enforce the check, or a made-up one, is refused.
    assert "Not recorded" in reviewer._answer_check({**base, "check_id": "S3",
                                                     "evidence_quote": facts["payments_need_cosigner"]}, art, result)
    assert "Not recorded" in reviewer._answer_check({**base, "check_id": "V1",
                                                     "evidence_quote": "onchain: trust me"}, art, result)


def test_a_ledger_pass_carries_the_stellar_criteria_and_on_chain_facts_of_its_checks():
    checks = [c for c in ledger.CATALOG if c.group == "signing"]
    text = ledger.instruction("signing", checks, ["a.kt"], "- none", ledger.onchain_facts(CHAIN))
    assert "Stellar criteria for these checks" in text and "Network endpoints" in text   # S3
    assert "Signers and thresholds" in text and "Soroban authorization" in text          # S6, S7
    assert "high threshold 3" in text and "medium threshold 2" not in text               # only S6's fact
    value = ledger.instruction("value", [c for c in ledger.CATALOG if c.group == "value"], [], "- none", {})
    assert "Asset identity is code + issuer" in value and "On-chain controls" not in value


def test_severity_follows_from_stated_facts():
    from backend.app.services.severity import compute
    # A shell injection through MCP tool arguments: any content the model reads can steer it.
    assert compute("host_code_execution", "anyone", "mainnet_or_configurable", "shipped") == "critical"
    # kalepail: a committed token for a testnet service.
    assert compute("keys_or_secrets", "anyone", "testnet_only", "shipped") == "medium"
    assert compute("funds", "counterparty", "mainnet_or_configurable", "shipped") == "high"
    assert compute("funds", "operator_only", "mainnet_or_configurable", "shipped") == "medium"
    assert compute("funds", "anyone", "mainnet_or_configurable", "example_or_quickstart") == "high"
    assert compute("funds", "nobody_yet", "mainnet_or_configurable", "shipped") == "low"
    assert compute("keys_or_secrets", "anyone", "mainnet_or_configurable", "test_or_dev_tool") == "low"
    assert compute("funds_locked_or_delayed", "counterparty", "mainnet_or_configurable", "shipped") == "medium"
    assert compute("none", "anyone", "not_applicable", "shipped") == "low"


def test_failure_path_check_applies_to_value_and_signing_agents():
    assert "S8" in {c.id for c in ledger.applicable({"submits_transactions"})}
    assert "S8" not in {c.id for c in ledger.applicable({"calls_llm"})}


def test_holds_answers_on_fund_checks_are_challenged_and_can_flip():
    art = artifact()
    operating = call("describe_operating_model", purpose="p", triggers="t", example_run="e",
                     trust_boundaries=[], assets_at_risk=[])
    read = call("read_source", path="src/main/kotlin/PayoutService.kt", start_line=1, end_line=14)
    facts = {"asset": "funds", "trigger": "anyone", "network": "mainnet_or_configurable", "location": "shipped"}
    blank = {"asset": "none", "trigger": "nobody_yet", "network": "not_applicable", "location": "shipped"}

    def ans(cid, verdict, line=0, quote="", **kw):
        return call("answer_check", check_id=cid, verdict=verdict, file="src/main/kotlin/PayoutService.kt" if line else "",
                    line=line, evidence_quote=quote, reason="r", title=kw.get("title", ""), attack_scenario="s",
                    remediation="m", existing_finding_id="", **(kw.get("f") or blank))
    groups = ledger.plan({"signs_transactions", "submits_transactions", "holds_or_loads_secret"})
    turns = [reply(operating, read), reply(call("finish", summary="done"))]
    for group, checks in groups:
        turns.append(reply(*[ans(c.id, "holds", 10, "tx.sign(signer)") if c.id == "S3"
                             else ans(c.id, "cannot_determine") for c in checks]))
        turns.append(reply(call("finish", summary="done")))
    # The challenge finds a path the first answer missed.
    turns.append(reply(ans("S3", "fails", 11, "server.submitTransaction(tx).hash", title="Network chosen by caller", f=facts)))
    turns.append(reply(call("finish", summary="done")))
    client = RoutingClient(turns)
    reviewer = DeepReviewer(client, model="claude-sonnet-5-5", mode="ledger",
                            mapper=FileMapper(client, model="claude-sonnet-5-5"))
    result = run(reviewer, art)
    assert [p["kind"] for p in result.passes if p["kind"] == "ledger:challenge"] == ["ledger:challenge"]
    assert result.challenged == ["S3"]
    s3 = result.ledger["S3"]
    assert s3["verdict"] == "fails" and s3["challenged_from"] == "holds"
    finding = next(f for f in result.findings if f.id == s3["finding_id"])
    assert finding.severity.value == "critical" and "Severity basis: at risk funds" in finding.detail


def test_authentication_verification_check_applies_when_the_agent_verifies_signatures():
    # The SEP-10 miss: an agent that verifies incoming challenges, not just signs its own.
    assert "A7" in {c.id for c in ledger.applicable({"authenticates_callers"})}
    assert "A7" in {c.id for c in ledger.applicable({"verifies_incoming_payment"})}
    assert "A7" not in {c.id for c in ledger.applicable({"moves_value"})}
    text = ledger.instruction("access", [c for c in ledger.CATALOG if c.group == "access"], [], "- none", {})
    assert "SEP-10" in text and "least one required client signer" in text
    # A7 carries the web-auth Stellar criteria and is challenged.
    assert "SEP-10 / SEP-45 web authentication" in ledger.stellar_criteria([ledger.BY_ID["A7"]])
    assert "A7" in ledger.CHALLENGED


def test_a_violated_invariant_without_a_finding_is_sent_back_once():
    from backend.app.services.deep_review import DeepReviewResult
    from backend.app.models import Dimension, Finding, Severity
    unit = {"invariants": [{"function": "pay", "invariant": "amount bounded", "verdict": "violated",
                            "file": "a.kt", "line": 40},
                           {"function": "pay", "invariant": "issuer checked", "verdict": "violated",
                            "file": "a.kt", "line": 90}], "findings": []}
    result = DeepReviewResult(mode="ledger")
    result.findings.append(Finding(id="security-ai-x-1", dimension=Dimension.SECURITY, severity=Severity.HIGH,
                                   title="t", detail="d", evidence="a.kt:45 `x`", auditor="deep-review"))
    orphans = DeepReviewer._orphan_violations(unit, result)
    assert len(orphans) == 1 and "issuer checked" in orphans[0]


def test_haiku_requests_carry_no_refusal_fallback():
    from backend.app.services.deep_review import supports_fallbacks
    from backend.app.services.finding_verifier import FindingVerifier
    assert supports_fallbacks("claude-sonnet-5-5") and not supports_fallbacks("claude-haiku-5-5")
    assert not DeepReviewer(None, model="claude-haiku-5-5").fallbacks
    assert not FileMapper(None, model="claude-haiku-5-5").fallbacks
    assert not FindingVerifier(None, model="claude-haiku-5-5").fallbacks
    assert DeepReviewer(None, model="claude-sonnet-5-5").fallbacks


def test_each_focused_file_review_carries_the_lessons_and_criteria_for_what_the_file_does():
    from backend.app.stellar import lessons
    submit = {"capabilities": [{"kind": "submits_transactions"}]}
    verify = {"capabilities": [{"kind": "authenticates_callers"}]}
    topics, found = lessons.for_card(submit)
    assert "transaction_lifecycle" in topics and "feebump-rewrap" in {x.id for x in found}
    assert "sep10-client-signature" in {x.id for x in lessons.for_card(verify)[1]}
    assert "SEP-10 / SEP-45 web authentication" in lessons.prompt_block(verify)
    assert lessons.prompt_block({"capabilities": [{"kind": "calls_llm"}]}) == ""
    # A contract that moves value is told to check rounding direction, and the lesson survives the size cap.
    contract = {"capabilities": [{"kind": "moves_value"}, {"kind": "invokes_contract"}]}
    assert "round in the protocol's favour" in lessons.prompt_block(contract)
    reviewer = DeepReviewer(None, model="m", mode="ledger")
    text = reviewer._unit_instruction(artifact(), "src/main/kotlin/PayoutService.kt",
                                      {"capabilities": [{"kind": "submits_transactions"}]}, "- none")
    assert "A fee-bumped payment can land under another hash" in text
    # Every lesson names capability kinds the file map can produce.
    from backend.app.services.file_map import CAPABILITY_KINDS
    assert all(lesson.kinds <= set(CAPABILITY_KINDS) for lesson in lessons.LESSONS)


def test_a_file_review_cut_off_by_the_end_of_a_leg_is_started_again():
    units = {
        "done.go": {"status": "completed"},
        "cut.go": {"status": "partial", "attempts": 1},
        "died.go": {"status": "running", "attempts": 1},
        "never_fits.go": {"status": "partial", "attempts": DeepReviewer.unit_attempts},
        "failed.go": {"status": "failed", "attempts": 1},
    }
    targets = ["done.go", "cut.go", "died.go", "never_fits.go", "failed.go", "new.go"]
    assert DeepReviewer._unit_todo(targets, units) == ["cut.go", "died.go", "new.go"]


def test_the_operators_own_model_or_api_bill_is_not_funds():
    from backend.app.services import severity
    # A read-only agent whose chat quota can be raced costs its operator money, not an account its value.
    assert severity.compute("operator_spend", "anyone", "not_applicable", "shipped") == "medium"
    assert severity.compute("funds", "anyone", "not_applicable", "shipped") == "critical"
    assert "operator_spend" in severity.FACTOR_SCHEMA["asset"]["enum"]


def test_a_service_api_key_is_rated_below_a_signing_key_and_capabilities_are_stellar_scoped():
    from backend.app.services import severity
    from backend.app.services.file_map import SYSTEM_PROMPT as MAP_PROMPT
    assert severity.compute("service_credential", "anyone", "not_applicable", "shipped") == "high"
    assert severity.compute("service_credential", "counterparty", "not_applicable", "shipped") == "medium"
    assert severity.compute("keys_or_secrets", "anyone", "mainnet_or_configurable", "shipped") == "critical"
    # HMAC cookies and app accounts are not Stellar signing or account authority.
    assert "HMAC, JWT, cookie or webhook" in MAP_PROMPT and "application user accounts" in MAP_PROMPT


def test_a_finding_must_cite_code_not_a_comment():
    from backend.app.services.deep_review import _is_code_comment
    assert _is_code_comment("utils.ts", "* It also verifies that the transaction has been signed by the server")
    assert _is_code_comment("utils.ts", "// TODO: verify the server signature")
    assert _is_code_comment("agent.py", "# the amount is checked by the caller")
    # Code, attributes and prompts are not comments.
    assert not _is_code_comment("lib.rs", "*balance -= amount;")
    assert not _is_code_comment("lib.rs", "#[contractimpl]")
    assert not _is_code_comment("prompts/system.md", "# You may pay any address the user names")
    assert not _is_code_comment("utils.ts", "const { tx } = readChallengeTx(")


def test_a_quote_on_a_comment_line_is_refused_even_without_the_comment_marker():
    from backend.app.services.deep_review import DeepReviewer
    art = artifact()
    art.code_files["utils.ts"] = ("/**\n * It also verifies that the transaction has been signed by the server.\n */\n"
                                  "export function readChallengeTx(tx) {\n  return { tx };\n}\n")
    reviewer = DeepReviewer(None, model="m", mode="ledger")
    problem = reviewer._verify_quote(art, "utils.ts", 2, "It also verifies that the transaction has been signed")
    assert "comment" in problem
    assert reviewer._verify_quote(art, "utils.ts", 4, "export function readChallengeTx(tx) {") == ""


def test_a_tool_call_with_parameters_leaked_into_one_field_is_repaired():
    from backend.app.services.deep_review import _repair_leaked_params
    args = {"purpose": 'A pay-per-call marketplace.</purpose>\n<parameter name="triggers">A buyer LLM calling a tool',
            "triggers": "placeholder", "example_run": "A buyer pays 0.01 USDC", "trust_boundaries": []}
    fixed = _repair_leaked_params(args)
    assert fixed["purpose"] == "A pay-per-call marketplace."
    assert fixed["triggers"] == "A buyer LLM calling a tool"
    assert fixed["example_run"] == "A buyer pays 0.01 USDC"   # a real value is never overwritten
    assert _repair_leaked_params({"purpose": "plain"}) == {"purpose": "plain"}


def test_severity_facts_are_held_to_the_file_map_evidence():
    from backend.app.services import severity
    ui = {"capabilities": [{"kind": "calls_network"}]}
    payer = {"capabilities": [{"kind": "moves_value"}]}
    # A UI component that moves nothing cannot lose funds; a payment file can.
    args, notes = severity.ground({"asset": "funds", "file": "web/approval-card.tsx", "location": "shipped"}, ui)
    assert args["asset"] == "correctness" and notes
    args, notes = severity.ground({"asset": "funds", "file": "src/pay.ts", "location": "shipped"}, payer)
    assert args["asset"] == "funds" and not notes
    # A web login is not Stellar account control; a file the map never carded is left as stated.
    assert severity.ground({"asset": "account_control", "file": "auth.ts"}, {"capabilities": [
        {"kind": "authenticates_callers"}]})[0]["asset"] == "data_exposure"
    assert severity.ground({"asset": "funds", "file": "x.ts"}, None)[0]["asset"] == "funds"
    # A contract's admin is authority in itself: an initialize anyone can call first stays account control.
    oracle = {"role": "contract", "capabilities": [{"kind": "stores_shared_state"}]}
    assert severity.ground({"asset": "account_control", "file": "oracle/lib.rs"}, oracle)[0]["asset"] == "account_control"
    # Mock and test paths are not shipped code; example paths are examples.
    assert severity.ground({"asset": "funds", "file": "src/mock/mock-service.ts", "location": "shipped"},
                           payer)[0]["location"] == "test_or_dev_tool"
    assert severity.ground({"asset": "funds", "file": "examples/pay.ts", "location": "shipped"},
                           payer)[0]["location"] == "example_or_quickstart"
    # A payer charged for a call that failed is not value someone takes.
    assert severity.compute("paid_service_not_delivered", "anyone", "mainnet_or_configurable", "shipped") == "medium"


def test_installed_third_party_packages_committed_with_the_code_are_not_the_agent():
    from pathlib import Path
    from backend.app.services.repo_audit import _skipped
    assert _skipped(Path("Lib/site-packages/pip/_internal/operations/install/wheel.py"))
    assert _skipped(Path("venv/lib/python3.12/site-packages/requests/api.py"))
    assert _skipped(Path("lib/python3/dist-packages/x.py"))
    assert not _skipped(Path("src/modules/engine/smart_bot.py"))
