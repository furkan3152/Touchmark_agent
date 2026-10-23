"""Hostile inputs to the payment rules: each case was quadratic (or crashed) before, and must
finish within a time bound far below what it took then. Sizes stay well inside the ingest
limits (400 KB per file); before the fixes each case took several seconds to minutes."""

from __future__ import annotations

import time

from backend.app.models import AgentArtifact, SourceKind
from backend.app.swarm.agentic_paths import analyse_agentic_paths
from backend.app.swarm.codeflow import _CACHE, analyse_code
from backend.app.swarm.hardening import analyse_hardening, find_credentials
from backend.app.swarm.jsflow import JsProject


def lock(**versions: str) -> dict:
    return {"importers": {"": {"lockfiles": ["package-lock.json"],
                               "deps": {n: {"spec": f"^{v}", "version": v} for n, v in versions.items()}}},
            "locked": {"package-lock.json": {n: [v] for n, v in versions.items()}}}


def timed(fn, *args, **kwargs):
    _CACHE.clear()
    started = time.perf_counter()
    result = fn(*args, **kwargs)
    return result, time.perf_counter() - started


def paths(files: dict, resolved: dict | None = None) -> list:
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="agent", code_files=files,
                             raw_metadata={"resolved_versions": resolved or {}})
    return analyse_agentic_paths(artifact, "security")


def code(files: dict):
    profile = analyse_code(files)
    assert not profile.error, profile.error
    return profile


MEMORY_SERVER = ('import { stellar, Store } from "@stellar/mpp/charge/server";\n'
                 'export const m = stellar({ recipient: R, currency: C, store: Store.memory() });\n')


def test_blank_lines_do_not_make_line_anchored_patterns_quadratic():
    # Was 1.9 s at 40000 lines (28.5 s at 160000).
    _, seconds = timed(find_credentials, ".stellar/identity/agent.toml", b"\n" * 80000)
    assert seconds < 1.0
    # Was 3.7 s: the Lambda-handler search over the server's own module.
    found, seconds = timed(paths, {"src/server.ts": MEMORY_SERVER + "\n" * 60000 + "export const x = 1;\n"},
                           lock(**{"@stellar/mpp": "0.7.1"}))
    assert seconds < 2.0 and any("replay-store" in f.id for f in found)
    # Was 4.1 s: the replicas search over every compose file.
    _, seconds = timed(paths, {"src/server.ts": MEMORY_SERVER, "docker-compose.yml": "\n" * 64000},
                       lock(**{"@stellar/mpp": "0.7.1"}))
    assert seconds < 2.0


def test_one_long_word_does_not_make_the_seller_patterns_quadratic():
    # Were 4.7 s, 2.8 s and 1.4 s.
    for pattern, text in ((JsProject._SETTLES, "settle" * 20000), (JsProject._MOVES_FUNDS, "invokeContract" * 10000),
                          (JsProject._PROOF_STORE, "record" + "Payment" * 10000), (JsProject._PROOF_STORE, "is" + "Used" * 20000)):
        started = time.perf_counter()
        pattern.search(text)
        assert time.perf_counter() - started < 0.5, pattern.pattern[:40]
    paywall = ('import { verifier } from "./verifier";\n'
               'export function paywall() {\n  return async (req: any, res: any, next: any) => {\n'
               "    const xdr = req.headers['x-payment'];\n"
               '    const result = await verifier.verifyEnvelope(xdr, { payee: R });\n'
               '    if (!result.verified) return res.status(402).json(result);\n    next();\n  };\n}\n')
    # Was 4.6 s with a 60 KB comment word (38.8 s at 180 KB).
    _, seconds = timed(paths, {"src/middleware.ts": paywall + "// " + "settle" * 20000 + "\n"})
    assert seconds < 2.0


def test_many_facts_flows_and_identifier_urls_stay_linear():
    # 10000 switches: was 7.6 s (add_fact scanned every fact for each new one).
    switches = 'import { x402Client } from "@x402/core/client";\nexport const cfg = [\n' + "{spendControls:false},\n" * 10000 + "];\n"
    profile, seconds = timed(code, {"src/c.ts": switches})
    assert seconds < 3.0 and len(profile.facts_of("x402_spend_controls_disabled")) == 10000
    # 6000 sinks in one function: the flow list was scanned the same way (4.4 s at 5000).
    sinks = "export function h(req) {\n" + "".join(f"  eval(req.body.c{i});\n" for i in range(6000)) + "}\n"
    profile, seconds = timed(code, {"src/e.ts": sinks})
    assert seconds < 4.0 and len([f for f in profile.flows if f.category == "command"]) == 6000
    # 1500 fetch(identifier) calls in a seller-scope module: was 20.8 s (each call walked the module).
    body = "".join(f"  const r{i} = await fetch(u{i});\n" for i in range(1500))
    decl = "".join(f"const u{i} = BASE + '/p{i}';\n" for i in range(1500))
    _, seconds = timed(code, {"src/b.ts": "// clients send the X-PAYMENT header\n" + decl
                              + "export async function sync() {\n" + body + "}\n"})
    assert seconds < 4.0


def test_long_conditions_are_walked_once():
    # A 900-term && chain: was 2.7 s in any file, 8.5 s in a seller with a pending settlement.
    chain = " && ".join(f"a{i}.ok" for i in range(900))
    _, seconds = timed(code, {"src/a.ts": f"export function f(a) {{\n if ({chain}) return 1;\n return 2;\n}}\n"})
    assert seconds < 1.0
    success = " && ".join(f"a{i}.success" for i in range(900))
    seller = ('import { decodePaymentSignatureHeader } from "@x402/core/http";\n'
              "app.get('/q', async (req, res) => {\n"
              " const s = await facilitator.settle(decodePaymentSignatureHeader(req.header('x-payment')), R);\n"
              f" if ({chain}) res.json(1);\n x = {success} ? 1 : 2;\n}});\n")
    _, seconds = timed(code, {"src/a.ts": seller})
    assert seconds < 1.5


def test_many_mpp_servers_in_one_file():
    # 3000 Mppx.create calls: was 9.1 s (each call sliced and searched the whole file).
    source = 'import { Mppx } from "mppx/server";\nexport const all = [\n' + "Mppx.create({ secretKey: K }),\n" * 3000 + "];\n"
    artifact = AgentArtifact(source_kind=SourceKind.REPO, name="agent", code_files={"src/a.ts": source})
    started = time.perf_counter()
    analyse_hardening(artifact, "security")
    assert time.perf_counter() - started < 2.0


def test_a_deep_argument_expression_keeps_the_auto_sign_check():
    # ast.unparse recursed per nested `+` and raised past ~500 terms; the literals are now
    # collected iteratively, so the check still sees --auto-sign.
    expr = " + ".join(["'x'"] * 700)
    source = ("import subprocess\ndef run(cmd):\n"
              f"    return subprocess.run(['stellar', 'contract', 'invoke', '--id', CID, '--auto-sign', '--', 'note', {expr}])\n")
    profile, seconds = timed(code, {"a.py": source})
    assert seconds < 2.0 and profile.facts_of("cli_auto_sign")


def test_a_nested_settlement_report_is_walked_once():
    # Each nesting level judged every value twice: depth 22 took 43 s (hours at 30).
    body = "s"
    for _ in range(30):
        body = "{ a: " + body + " }"
    source = ('import { decodePaymentSignatureHeader } from "@x402/core/http";\n'
              "app.post('/q', async (req, res) => {\n"
              "  const s = await facilitator.settle(decodePaymentSignatureHeader(req.header('x-payment')), R);\n"
              f"  res.json({body});\n}});\n")
    found, seconds = timed(paths, {"src/server.ts": source})
    assert seconds < 1.0 and not [f for f in found if "x402" in f.id]  # a report of the settlement, nested


def test_mpp_facts_scan_their_package_once():
    # 100 testnet servers beside 1 MB of code: was 25 s (the package was scanned per fact).
    servers = "".join(f"export const m{i} = Mppx.create({{ methods: [stellar.charge({{ recipient: R, currency: USDC_SAC_TESTNET, "
                      f"network: STELLAR_TESTNET }})], secretKey: process.env.K }});\n" for i in range(100))
    head = ('import { Mppx } from "mppx/server";\nimport { stellar } from "@stellar/mpp/charge/server";\n'
            'import { USDC_SAC_TESTNET, STELLAR_TESTNET } from "@stellar/mpp";\n')
    filler = {f"src/f{j}.ts": "// stellar testnet notes\nexport const x = 1;\n" * 2560 for j in range(10)}
    found, seconds = timed(paths, {"src/server.ts": head + servers, **filler}, lock(**{"@stellar/mpp": "0.4.0"}))
    assert seconds < 5.0 and any("replay-store" in f.id and f.severity.value == "medium" for f in found)


def test_sequential_ifs_stay_linear():
    # 3000 ifs that reject nothing: was 30 s (each if copied and merged the whole state).
    for line in ("  if (a{i} === X{i}) metrics.c += 1;\n", "  if (a{i} === X{i} || b{i} === Y) metrics.c += 1;\n",
                 "  if (a{i} === X{i}) metrics.c += 1; else metrics.d += 1;\n"):
        source = "export function check(tx, e) {\n" + "".join(line.format(i=i) for i in range(3000)) + "}\n"
        _, seconds = timed(code, {"src/c.ts": source})
        assert seconds < 2.0, line
    # Nested branches read through a bounded chain of views: 280 nested ifs still analyse.
    nested = ("export function f(a, b) {\n" + "".join(f"if (a{i} === X{i}) {{\n" for i in range(280)) + "  pay(b);\n"
              + "}\n" * 280 + "}\n")
    _, seconds = timed(code, {"src/n.ts": nested})
    assert seconds < 1.0


def test_many_request_fields_are_looked_up_in_one_index():
    # A verifier that sets 2000 request fields, read by four modules that submit something
    # else: 53 s (every field rescanned every module and walked each function's body).
    fields = 2000
    paywall = ('import { verifier } from "./verifier";\n'
               'export function paywall() {\n  return async (req: any, res: any, next: any) => {\n'
               "    const xdr = req.headers['x-payment'];\n"
               '    const result = await verifier.verifyEnvelope(xdr, { payee: R });\n'
               '    if (!result.verified) return res.status(402).json(result);\n'
               + "".join(f"    req.f{i} = xdr;\n" for i in range(fields)) + '    next();\n  };\n}\n')
    other = ("export async function s(req) {\n  log(" + ", ".join(f"req.f{i}" for i in range(fields)) + ");\n"
             "  await server.sendTransaction(buildRefund());\n}\n")
    found, seconds = timed(paths, {"src/paywall.ts": paywall, **{f"src/o{j}.ts": other for j in range(4)}})
    assert seconds < 4.0 and any("verify-without-settle" in f.id for f in found)


def test_sequential_and_nested_loops_stay_linear():
    # 4000 loops (or switches) in a row: 10 s each (every loop copied and merged the whole
    # state); 18 nested loops: 24 s (each loop body ran twice per pass of the one around it).
    for line in ("  const v{i} = g({i});\n  for (const x of v{i}) h(x);\n",
                 "  const v{i} = g({i});\n  switch (v{i}) {{ case 1: h(); }}\n"):
        source = "export function f(a) {\n" + "".join(line.format(i=i) for i in range(4000)) + "}\n"
        _, seconds = timed(code, {"src/c.ts": source})
        assert seconds < 4.0, line
    nested = "export function f(a) {\n" + "".join(f"for (const x{i} of a{i}) {{\n" for i in range(18)) + "h(a);\n" + "}\n" * 18 + "}\n"
    _, seconds = timed(code, {"src/n.ts": nested})
    assert seconds < 1.0
