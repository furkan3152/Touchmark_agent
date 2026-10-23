"""Network binding: which value picks the network an agent signs for (swarm/network_rules.py)."""

from __future__ import annotations

import time

from backend.app.models import AgentArtifact, SourceKind
from backend.app.swarm.network_rules import _CACHE, mask, net_of, network_findings, network_hits


def found(files: dict[str, str], **metadata) -> dict[str, dict]:
    artifact = AgentArtifact(name="a", source_kind=SourceKind.REPO, source_ref="t", code_files=files,
                             raw_metadata=metadata)
    out: dict[str, dict] = {}
    for f in network_findings(artifact, "security"):
        out.setdefault(f.id.rsplit("-", 1)[0], {"severity": f.severity.value, "evidence": f.evidence,
                                                "detail": f.detail, "grade": f.evidence_grade.value})
    return out


def test_masking_keeps_offsets_and_hides_comments():
    code, skel = mask("const a = 'x{'; // b {\n/* c } */ let d = `${e}`;")
    assert len(code) == len(skel) and "b {" not in code and "c }" not in code and "'x{'" in code
    assert "{" not in skel.split(";")[0]
    assert net_of("Networks.PUBLIC") == "mainnet" and net_of("'stellar:testnet'") == "testnet"
    assert net_of("'public'") == "mainnet" and net_of("'https://horizon.stellar.org'") is None


# ----------------------------------------------------------------- N1 per-call selector
_PER_CALL = """
import { Keypair, Networks, TransactionBuilder, Horizon } from '@stellar/stellar-sdk';
import { z } from 'zod';
import { config } from './config';
const HORIZON: Record<string, string> = { mainnet: 'https://horizon.stellar.org', testnet: 'https://horizon-testnet.stellar.org' };
function passphraseFor(net: string) { return net === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET; }
function horizonFor(net: string) { return new Horizon.Server(HORIZON[net]); }
server.tool('pay', { network: z.enum(['testnet', 'mainnet']), xdr: z.string() }, async (args) => {
  const network = args.network ?? config.network;
  const tx = TransactionBuilder.fromXDR(args.xdr, passphraseFor(network));
  const kp = Keypair.fromSecret(process.env.OPERATOR_SECRET!);
  tx.sign(kp);
  return horizonFor(network).submitTransaction(tx);
});
"""


def test_a_tool_argument_that_picks_passphrase_and_endpoint_is_medium():
    finding = found({"src/pay.ts": _PER_CALL})["security-network-chosen-per-call"]
    assert finding["severity"] == "medium" and "src/pay.ts:9" in finding["evidence"]


def test_a_per_call_network_pinned_to_configuration_is_not_reported():
    pinned = _PER_CALL.replace("  const network = args.network ?? config.network;\n",
                               "  const network = args.network ?? config.network;\n"
                               "  if (args.network && args.network !== config.network) throw new Error('network');\n")
    assert "security-network-chosen-per-call" not in found({"src/pay.ts": pinned})
    # The endpoint stays on configuration: a signature for the other network fails there.
    fixed = _PER_CALL.replace("return horizonFor(network)", "return horizonFor(config.network)")
    assert "security-network-chosen-per-call" not in found({"src/pay.ts": fixed})
    # A key the caller passes in is the caller's own, not the operator's.
    callers = _PER_CALL.replace("process.env.OPERATOR_SECRET!", "args.secret")
    assert "security-network-chosen-per-call" not in found({"src/pay.ts": callers})


def test_a_helper_that_signs_and_picks_the_endpoint_from_the_tools_network_is_medium():
    helper = _PER_CALL.replace("server.tool(", """async function signAndSend(tx: any, network: string) {
  const kp = Keypair.fromSecret(process.env.OPERATOR_SECRET!);
  tx.sign(kp);
  return horizonFor(network).submitTransaction(tx);
}
server.tool(""").replace("""  const kp = Keypair.fromSecret(process.env.OPERATOR_SECRET!);
  tx.sign(kp);
  return horizonFor(network).submitTransaction(tx);
});""", """  return signAndSend(tx, network);
});""")
    assert found({"src/pay.ts": helper})["security-network-chosen-per-call"]["severity"] == "medium"
    # The helper sends to the configured network: the tool's value picks only the passphrase.
    fixed = helper.replace("async function signAndSend(tx: any, network: string)", "async function signAndSend(tx: any, net: string)") \
        .replace("return horizonFor(network).submitTransaction(tx);\n}", "return horizonFor(config.network).submitTransaction(tx);\n}")
    assert "security-network-chosen-per-call" not in found({"src/pay.ts": fixed})
    # The value handed on in another position does not reach the endpoint parameter.
    other = helper.replace("async function signAndSend(tx: any, network: string)", "async function signAndSend(network: string, tx: any)")
    assert "security-network-chosen-per-call" not in found({"src/pay.ts": other})


def test_many_tools_after_a_long_helper_cost_little():
    # Every tool sits in the region that starts at the helper: the handler test is made once per
    # region, and the helper's endpoint pick once per parameter, not once per tool (27 s before).
    helper = ("import { Keypair, Networks, TransactionBuilder, Horizon } from '@stellar/stellar-sdk';\n"
              "function passphraseFor(net: string) { return net === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET; }\n"
              "async function signAndSend(tx: any, network: string) {\n"
              + "".join(f"  const v{i} = compute{i}(tx, network);\n" for i in range(3000))
              + "  tx.sign(Keypair.fromSecret(process.env.OPERATOR_SECRET!));\n"
              "  return new Horizon.Server(network === 'mainnet' ? 'https://horizon.stellar.org' : 'x').submitTransaction(tx);\n}\n")
    tools = "".join(f"server.tool('t{i}', {{}}, async (args: any) => {{ const network = args.network; "
                    "const tx = TransactionBuilder.fromXDR(args.xdr, passphraseFor(network)); return signAndSend(tx, network); });\n"
                    for i in range(1500))
    started = time.perf_counter()
    assert found({"src/a.ts": helper + tools})["security-network-chosen-per-call"]["severity"] == "medium"
    assert time.perf_counter() - started < 5


# ----------------------------------------------------------------- N2 counterparty network
_MPP = """
import { Mppx } from 'mppx/client';
import { stellar } from '@stellar/mpp/charge/client';
export const mppx = Mppx.create({ methods: [stellar.charge({ secretKey: process.env.STELLAR_SECRET })] });
"""


def test_an_mpp_client_follows_the_servers_network():
    finding = found({"src/mpp.ts": _MPP})["security-network-chosen-by-counterparty"]
    assert finding["severity"] == "medium" and "src/mpp.ts:4" in finding["evidence"]
    assert finding["grade"] == "inferred"  # no lockfile: the installed release is unknown
    resolved = {"importers": {"": {"lockfiles": ["package-lock.json"],
                                   "deps": {"@stellar/mpp": {"spec": "^0.4.0", "version": "0.4.0"}}}},
                "locked": {"package-lock.json": {"@stellar/mpp": ["0.4.0"]}}}
    locked = found({"src/mpp.ts": _MPP}, resolved_versions=resolved)
    assert locked["security-network-chosen-by-counterparty"]["grade"] == "confirmed"


def test_an_mpp_client_with_a_pinned_rpc_or_a_network_check_is_not_reported():
    pinned = _MPP.replace("secretKey: process.env.STELLAR_SECRET", "secretKey: process.env.STELLAR_SECRET, rpcUrl: RPC_URL")
    assert "security-network-chosen-by-counterparty" not in found({"src/mpp.ts": pinned})
    checked = _MPP + ("export function onChallenge(c) { if (c.request.methodDetails?.network !== NETWORK) "
                      "throw new Error('network'); }\n")
    assert "security-network-chosen-by-counterparty" not in found({"src/mpp.ts": checked})
    # An x402 scheme registered for every Stellar network without an RPC URL refuses pubnet itself.
    x402 = ("import { ExactStellarScheme } from '@x402/stellar/exact/client';\n"
            "const client = new x402Client().register('stellar:*', new ExactStellarScheme(signer));\n")
    assert found({"src/x402.ts": x402}) == {}


# ----------------------------------------------------------------- N3 fallback
_GUESS = """
import { Networks, Horizon } from '@stellar/stellar-sdk';
export class Classic {
  constructor(serverUrl: string) {
    this.networkConfig = { testnet: { networkPassphrase: Networks.TESTNET }, public: { networkPassphrase: Networks.PUBLIC } };
    const network = serverUrl.includes('testnet') ? 'testnet' : serverUrl.includes('futurenet') ? 'futurenet' : 'public';
    this.networkPassphrase = this.networkConfig[network].networkPassphrase;
  }
}
"""


def test_a_url_guess_that_falls_back_to_mainnet_is_medium_once():
    files = {"src/classic.ts": _GUESS, "src/soroban.ts": _GUESS}
    hits = [k for k in found(files) if k == "security-network-fallback-mainnet"]
    assert hits == ["security-network-fallback-mainnet"]  # identical copies: one finding
    finding = found(files)["security-network-fallback-mainnet"]
    assert finding["severity"] == "medium" and "src/classic.ts:6" in finding["evidence"]
    assert "src/soroban.ts:6" in finding["evidence"]


def test_two_value_ternaries_and_explorer_links_are_not_fallbacks():
    two = "export const p = (network: string) => network === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET;\n"
    reverse = "const passphrase = isTestnet ? Networks.TESTNET : Networks.PUBLIC;\nbuild({ networkPassphrase: passphrase });\n"
    link = "console.log(`https://stellar.expert/explorer/${network.includes('testnet') ? 'testnet' : 'public'}/tx/${h}`);\n"
    assert found({"src/a.ts": two, "src/b.ts": reverse, "src/c.ts": link}) == {}


def test_a_switch_that_sends_unknown_names_to_mainnet_is_medium():
    switch = ("export function passphrase(net: string) {\n  switch (net) {\n    case 'testnet': return Networks.TESTNET;\n"
              "    case 'futurenet': return Networks.FUTURENET;\n    default: return Networks.PUBLIC;\n  }\n}\n")
    assert found({"src/net.ts": switch})["security-network-fallback-mainnet"]["severity"] == "medium"
    # Every declared value has its own branch: the default cannot be reached.
    declared = "export const Net = z.enum(['testnet', 'futurenet']);\n"
    assert found({"src/net.ts": switch, "src/schema.ts": declared}) == {}


def test_a_declared_value_without_a_branch_falls_to_testnet_low():
    switch = ("function resolveNetworkPassphrase(network: string): string {\n  switch (network) {\n"
              "    case 'mainnet':\n      return Networks.PUBLIC;\n    case 'testnet':\n    default:\n"
              "      return Networks.TESTNET;\n  }\n}\n")
    schema = "export const schema = z.object({ network: z.enum(['mainnet', 'testnet', 'custom']) });\n"
    files = {"src/tools/a.ts": switch, "src/tools/b.ts": switch.replace("resolveNetworkPassphrase", "passphraseOf"),
             "src/schema.ts": schema}
    finding = found(files)["security-network-fallback-testnet"]
    assert finding["severity"] == "low" and "custom" in finding["detail"]
    assert "src/tools/b.ts" in finding["evidence"]  # one finding for every copy
    handled = switch.replace("  switch (network) {", "  if (network === 'custom') return config.passphrase;\n  switch (network) {")
    assert found({"src/tools/a.ts": handled, "src/schema.ts": schema}) == {}
    assert found({"src/tools/a.ts": switch}) == {}  # nothing declares another value


def test_a_python_selector_over_two_values_is_not_a_fallback():
    py = ('class C:\n    def __init__(self, network: str = "stellar:testnet"):\n'
          '        is_testnet = "testnet" in network\n'
          '        self.passphrase = Network.TESTNET_NETWORK_PASSPHRASE if is_testnet else Network.PUBLIC_NETWORK_PASSPHRASE\n')
    assert found({"client.py": py}) == {}
    guess = py.replace('"testnet" in network', '"testnet" in rpc_url').replace("network: str", "rpc_url: str")
    assert found({"client.py": guess})["security-network-fallback-mainnet"]["severity"] == "medium"


# ----------------------------------------------------------------- N4 incoherent pairs
def test_a_network_setting_next_to_a_fixed_horizon_default_is_low():
    config = ("export const schema = z.object({\n  STELLAR_NETWORK: z.enum(['testnet', 'mainnet']).default('testnet'),\n"
              "  STELLAR_HORIZON_URL: z.string().url().default('https://horizon-testnet.stellar.org'),\n});\n"
              "export const config = schema.parse(process.env);\n")
    wallet = "export const passphrase = () => config.STELLAR_NETWORK === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET;\n"
    finding = found({"apps/mcp/config.ts": config, "apps/mcp/wallet.ts": wallet})["security-network-endpoint-mismatch"]
    assert finding["severity"] == "low" and "apps/mcp/config.ts:3" in finding["evidence"]
    # One table supplies both, or start-up checks the server's passphrase.
    table = config.replace(".default('https://horizon-testnet.stellar.org')", ".optional()")
    assert found({"apps/mcp/config.ts": table, "apps/mcp/wallet.ts": wallet}) == {}
    check = wallet + ("const net = await rpc.getNetwork();\nif (net.passphrase !== passphrase()) "
                      "throw new Error('wrong network');\n")
    assert found({"apps/mcp/config.ts": config, "apps/mcp/wallet.ts": check}) == {}


def test_a_per_call_network_that_picks_only_the_passphrase_is_low():
    tool = ("export async function handleSwap(args: Args, horizonUrl: string) {\n"
            "  const res = await fetch(`${horizonUrl}/accounts/${args.source}`);\n"
            "  const networkPassphrase = args.network === 'pubnet' ? Networks.PUBLIC : Networks.TESTNET;\n"
            "  return new TransactionBuilder(account, { fee: '100', networkPassphrase }).build().toXDR();\n}\n")
    finding = found({"src/tools/swap.ts": tool})["security-network-endpoint-mismatch"]
    assert finding["severity"] == "low" and "src/tools/swap.ts:3" in finding["evidence"]
    both = tool.replace("${horizonUrl}/accounts", "${HORIZON[args.network]}/accounts")
    assert found({"src/tools/swap.ts": both}) == {}  # unsigned and coherent: nothing to report


def test_python_pairs_fixed_on_one_side_are_low():
    server = ('import os\nHORIZON_URL = os.getenv("HORIZON_URL", "https://horizon-testnet.stellar.org")\n'
              "PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE\nhorizon = Server(HORIZON_URL)\n"
              "def pay():\n    TransactionBuilder(acct, network_passphrase=PASSPHRASE, base_fee=100)\n")
    pair = found({"server.py": server})["security-network-endpoint-mismatch"]
    assert pair["severity"] == "low" and "fixed to testnet constants" in pair["detail"]
    wallet = ('class Wallet:\n    def __init__(self, kp, network_passphrase: str = "Test SDF Network ; September 2015"):\n'
              '        self.network_passphrase = network_passphrase\n'
              '        self.server = Server("https://horizon-testnet.stellar.org")\n')
    assert "security-network-endpoint-mismatch" in found({"wallet.py": wallet})
    # Both from the environment: the operator sets them together.
    both = server.replace("Network.TESTNET_NETWORK_PASSPHRASE", 'os.getenv("NETWORK_PASSPHRASE", "Test SDF Network ; September 2015")')
    assert found({"server.py": both}) == {}


# ----------------------------------------------------------------- N5 cross-network constants
_CROSS = '''
class Client:
    def init(self, network: str = "stellar:testnet"):
        self.passphrase = (Network.TESTNET_NETWORK_PASSPHRASE if "testnet" in network
                           else Network.PUBLIC_NETWORK_PASSPHRASE)

    def pay(self, dest, amount):
        issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"
        tx = (TransactionBuilder(source_account=self.account, network_passphrase=self.passphrase, base_fee=100)
              .append_payment_op(dest, Asset("USDC", issuer), amount).build())
        return tx
'''


def test_a_testnet_issuer_in_a_payment_that_can_be_signed_for_mainnet_is_low():
    # It fails closed: the testnet issuer does not exist on mainnet, so nothing can be paid in it.
    finding = found({"sdk/client.py": _CROSS})["security-network-cross-constant"]
    assert finding["severity"] == "low" and "sdk/client.py:8" in finding["evidence"]


def test_a_network_keyed_issuer_is_not_a_cross_constant():
    keyed = _CROSS.replace('        issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"\n',
                           '        if "testnet" in self.network:\n'
                           '            issuer = "GBBD47IF6LWK7P7MDEVSCWR7DPUWV3NY3DTQEVFL4NAT4AQH3ZLLFLA5"\n'
                           '        else:\n            issuer = MAINNET_ISSUER\n')
    assert found({"sdk/client.py": keyed}) == {}
    testnet_only = _CROSS.replace("else Network.PUBLIC_NETWORK_PASSPHRASE", "else Network.TESTNET_NETWORK_PASSPHRASE")
    assert found({"sdk/client.py": testnet_only}) == {}


# ----------------------------------------------------------------- N6 Stellar CLI names
def test_an_unknown_cli_network_name_is_low_and_a_fallback_reaching_it_is_folded():
    cli = "exec(`stellar contract deploy --wasm ${wasm} --network public`);\n"
    assert found({"src/deploy.ts": cli})["security-cli-network-unknown"]["severity"] == "low"
    added = cli + "exec('stellar network add public --rpc-url https://rpc.example --network-passphrase \"x\"');\n"
    assert found({"src/deploy.ts": added}) == {}
    assert found({"src/deploy.ts": cli.replace("public", "mainnet")}) == {}
    # A fallback that also reaches the CLI is one defect: the CLI note joins the fallback finding.
    core = "exec(`stellar contract info interface --network ${args.network || 'testnet'} --id ${id}`);\n"
    result = found({"src/classic.ts": _GUESS.replace("this.networkPassphrase =", "this.network = network;\n    this.p ="),
                    "src/core.ts": core})
    assert "security-cli-network-unknown" not in result
    assert "not a built-in CLI network" in result["security-network-fallback-mainnet"]["detail"]


def test_sdk_declarations_and_examples_drop_one_level():
    switch = ("export function passphrase(net: string) {\n  switch (net) {\n    case 'testnet': return Networks.TESTNET;\n"
              "    case 'futurenet': return Networks.FUTURENET;\n    default: return Networks.PUBLIC;\n  }\n}\n")
    assert found({"examples/net.ts": switch})["security-network-fallback-mainnet"]["severity"] == "low"
    sdk = {"declared": {"agent": {"kind": "sdk", "network": "testnet"}}}
    assert found({"src/net.ts": switch}, tmark=sdk)["security-network-fallback-mainnet"]["severity"] == "low"


# ----------------------------------------------------------------- review fixes
def test_a_selector_that_never_reaches_a_passphrase_is_not_a_fallback():
    # stellar.expert names mainnet 'public': an explorer segment is not a network binding.
    head = ("import { Networks, TransactionBuilder } from '@stellar/stellar-sdk';\n"
            "const passphrase = config.network === 'mainnet' ? Networks.PUBLIC : Networks.TESTNET;\n"
            "export function txLink(hash: string) {\n"
            "  const seg = config.network === 'testnet' ? 'testnet' : config.network === 'futurenet' ? 'futurenet' : 'public';\n")
    for use in ("  logger.debug(seg);\n  return `https://stellar.expert/explorer/${seg}/tx/${hash}`;\n}\n",
                "  return links[seg] + hash;\n}\nconst links = { testnet: 'a', futurenet: 'b', public: 'c' };\n"):
        assert found({"src/links.ts": head + use}) == {}, use
    py = ("from stellar_sdk import Network\n"
          "PASS = Network.TESTNET_NETWORK_PASSPHRASE if NET == 'testnet' else Network.PUBLIC_NETWORK_PASSPHRASE\n"
          "def link(h):\n    seg = 'testnet' if NET == 'testnet' else 'futurenet' if NET == 'futurenet' else 'public'\n"
          "    return explorer(seg, h)\n")
    assert found({"links.py": py}) == {}
    # The same value handed to a passphrase function, or keying a table of passphrases, is one.
    for use in ("  return getNetworkPassphrase(seg);\n}\n",
                "  return NETWORKS[seg].networkPassphrase;\n}\n",
                "  const cfg = NETWORKS[seg];\n  return new TransactionBuilder(acct, { networkPassphrase: cfg.networkPassphrase });\n}\n"):
        assert found({"src/links.ts": head + use})["security-network-fallback-mainnet"]["severity"] == "medium", use
    table = "const T = { testnet: { networkPassphrase: Networks.TESTNET }, public: { networkPassphrase: Networks.PUBLIC } };\n"
    assert "security-network-fallback-mainnet" in found({"src/links.ts": table + head + "  return T[seg];\n}\n"})


def test_map_fallbacks_and_if_chains_to_mainnet_are_medium():
    cases = {
        "src/map.ts": "const PASS = { testnet: Networks.TESTNET, futurenet: Networks.FUTURENET };\n"
                      "export const passphrase = PASS[cfg.network] ?? Networks.PUBLIC;\n",
        "src/own.ts": "const NETS = { testnet: { networkPassphrase: Networks.TESTNET }, futurenet: { networkPassphrase: "
                      "Networks.FUTURENET }, mainnet: { networkPassphrase: Networks.PUBLIC } };\n"
                      "export const net = NETS[cfg.network] || NETS.mainnet;\n",
        "src/chain.ts": "export function pass(n: string) {\n  if (n === 'testnet') return Networks.TESTNET;\n"
                        "  else if (n === 'futurenet') { return Networks.FUTURENET; }\n  return Networks.PUBLIC;\n}\n",
        "chain.py": "def passphrase(net):\n    if net == 'testnet':\n        return Network.TESTNET_NETWORK_PASSPHRASE\n"
                    "    elif net == 'futurenet':\n        return Network.FUTURENET_NETWORK_PASSPHRASE\n"
                    "    else:\n        return Network.PUBLIC_NETWORK_PASSPHRASE\n",
        "get.py": "PASS = {'testnet': Network.TESTNET_NETWORK_PASSPHRASE, 'futurenet': Network.FUTURENET_NETWORK_PASSPHRASE}\n"
                  "def p(net):\n    return PASS.get(net, Network.PUBLIC_NETWORK_PASSPHRASE)\n",
    }
    for name, text in cases.items():
        assert found({name: text})["security-network-fallback-mainnet"]["severity"] == "medium", name
    # Over two values the fallback is the other network, not a guess.
    two = {"src/map.ts": "const PASS = { testnet: Networks.TESTNET };\nexport const p = PASS[cfg.network] ?? Networks.PUBLIC;\n",
           "src/chain.ts": "export function pass(n: string) {\n  if (n === 'testnet') return Networks.TESTNET;\n"
                           "  return Networks.PUBLIC;\n}\n",
           "get.py": "PASS = {'testnet': Network.TESTNET_NETWORK_PASSPHRASE}\n"
                     "def p(net):\n    return PASS.get(net, Network.PUBLIC_NETWORK_PASSPHRASE)\n"}
    for name, text in two.items():
        assert found({name: text}) == {}, name
    # A passphrase mapped back to a name is not a network choice.
    reverse = ("export function networkTag(passphrase: string) {\n  if (passphrase === Networks.PUBLIC) return 'mainnet';\n"
               "  if (passphrase === Networks.FUTURENET) return 'futurenet';\n  return 'testnet';\n}\n")
    assert found({"src/tag.ts": reverse, "src/schema.ts": "export const N = z.enum(['testnet', 'mainnet', 'local']);\n"}) == {}


def test_cli_names_count_only_in_commands_the_package_runs():
    assert found({"cli.py": 'HELP = "stellar contract deploy --network public  # see docs"\nprint(HELP)\n'}) == {}
    described = ("import { exec } from 'node:child_process';\n"
                 "server.tool('deploy', { description: 'stellar contract deploy --network public' }, run);\n"
                 "console.log(`stellar keys fund alice --network standalone`);\n")
    assert found({"src/tools.ts": described}) == {}
    table = "export const COMMANDS = { deploy: (a) => `stellar contract deploy --wasm ${a.wasm} --network public` };\n"
    runner = "import { exec } from 'node:child_process';\nexport const run = (c: string) => exec(c);\n"
    assert found({"src/commands.ts": table, "src/run.ts": runner})["security-cli-network-unknown"]["severity"] == "low"
    assert found({"src/commands.ts": table}) == {}


def test_long_word_runs_cost_little():
    # An embedded hex WASM or test vector: no key regex may restart inside it.
    blob = "a1" * 20_000
    for name, text in (("src/wasm.ts", f"export const WASM = '{blob}';\n"), ("src/word.ts", f"const {blob} = 1;\n"),
                       ("src/cfg.ts", f"const HORIZON_URL = process.env.H || '{blob}';\nconst NETWORK = process.env.N;\n"),
                       ("src/sw.ts", "function f(n) { switch (n) { case 'a': return '" + blob + "'; default: return Networks.PUBLIC; } }\n"),
                       ("src/tool.ts", "server.tool('x', {}, async (args) => { const network = args.network; const s = '"
                        + blob + "'; tx.sign(kp); });\n"),
                       ("w.py", f"W = '{blob}'\nseg = 'testnet' if N == 'testnet' else 'public'\n")):
        _CACHE.clear()
        started = time.perf_counter()
        network_hits({name: text})
        assert time.perf_counter() - started < 1.0, name


# ----------------------------------------------------------------- review: depth, cost and scope
_PY_TOOL = '''import os
from stellar_sdk import Keypair, Network, Server, TransactionBuilder
PASSPHRASES = {"testnet": Network.TESTNET_NETWORK_PASSPHRASE, "mainnet": Network.PUBLIC_NETWORK_PASSPHRASE}
HORIZON = {"testnet": "https://horizon-testnet.stellar.org", "mainnet": "https://horizon.stellar.org"}

@mcp.tool()
def pay(network: str, destination: str):
    banner = BANNER
    kp = Keypair.from_secret(os.environ["OPERATOR_SECRET"])
    server = Server(HORIZON[network])
    tx = TransactionBuilder(server.load_account(kp.public_key), PASSPHRASES[network], 100).build()
    tx.sign(kp)
    return server.submit_transaction(tx)
'''


def test_python_expressions_too_deep_to_unparse_neither_crash_nor_hide_a_tool():
    deep = " + ".join(['"x"'] * 1500)
    files = {"prompt.py": f"SYSTEM_PROMPT = {deep}\n",
             "pick.py": f"net = Network.PUBLIC_NETWORK_PASSPHRASE if {deep} else Network.TESTNET_NETWORK_PASSPHRASE\n",
             "attr.py": f"class A:\n    def __init__(self):\n        self.p = {deep}\n",
             "cross.py": f"def f():\n    x = {deep}\n    if {deep}:\n        y = 1\n    TransactionBuilder(a, x).append_payment_op({deep})\n"}
    _CACHE.clear()
    started = time.perf_counter()
    network_hits(files)
    assert time.perf_counter() - started < 5
    # A tool function too deep to unparse is read from its source.
    tool = _PY_TOOL.replace("BANNER", " + ".join(['"="'] * 600))
    assert found({"tools.py": tool})["security-network-chosen-per-call"]["severity"] == "medium"


def test_long_statements_and_repeated_arguments_cost_little():
    # Each `name =` used to rescan its 1,200-character window once per line (90 s for 390 KB),
    # and each `args.network` rescanned the file for its top-level declaration (62 s); at
    # 200 KB these shapes took 20 s or more each.
    size = 200_000
    shapes = {"comma.js": "x = y,\n" * (size // 7),
              "args.js": "function f(args) {\n" + "  g(args.network);\n" * (size // 19) + "}\n",
              "ternary.js": "x = a === 'futurenet' ? Networks.FUTURENET : a === 'local' ? Networks.TESTNET : Networks.PUBLIC\n" * 2000,
              "switch.js": "switch (n) { case 'a': x = Networks.PUBLIC;\n" * 4500,
              "keys.js": "const HORIZON_URL = process.env.H || 'https://horizon-testnet.stellar.org';\nconst NETWORK = process.env.N;\n" * 1500,
              "chain.py": ("def f(n):\n    if n == 'testnet':\n        return Network.TESTNET_NETWORK_PASSPHRASE\n"
                           "    return Network.PUBLIC_NETWORK_PASSPHRASE\n") * 1500}
    for name, text in shapes.items():
        _CACHE.clear()
        started = time.perf_counter()
        network_hits({f"src/{name}": text})
        assert time.perf_counter() - started < 5, name


_TWO_TOOLS = """
import { Horizon, Keypair, Networks, TransactionBuilder, Operation, Asset } from '@stellar/stellar-sdk';
import { z } from 'zod';
import { config } from './config';
const PASSPHRASES = { testnet: Networks.TESTNET, mainnet: Networks.PUBLIC };
const HORIZON_URLS = { testnet: 'https://horizon-testnet.stellar.org', mainnet: 'https://horizon.stellar.org' };
export function registerTools(server) {
  server.tool('draft_payment', { network: z.enum(['testnet', 'mainnet']), from: z.string() }, async (args) => {
    const net = args.network;
    const horizon = new Horizon.Server(HORIZON_URLS[net]);
    const source = await horizon.loadAccount(args.from);
    const tx = new TransactionBuilder(source, { fee: '100', networkPassphrase: PASSPHRASES[net] }).setTimeout(60).build();
    return { content: [{ type: 'text', text: tx.toXDR() }] };
  });
  server.tool('collect_fee', {}, async () => {
    const kp = Keypair.fromSecret(process.env.OPERATOR_SECRET);
    const horizon = new Horizon.Server(config.horizonUrl);
    const tx = new TransactionBuilder(await horizon.loadAccount(kp.publicKey()), { fee: '100', networkPassphrase: config.passphrase })
      .addOperation(Operation.payment({ destination: config.feeAccount, asset: Asset.native(), amount: '1' })).setTimeout(60).build();
    tx.sign(kp);
    return { content: [{ type: 'text', text: (await horizon.submitTransaction(tx)).hash }] };
  });
}
"""


def test_a_tool_that_signs_nothing_is_not_judged_by_another_tools_key():
    # One tool picks the network for an unsigned draft; another signs with the operator key on
    # the configured network. Neither lets a caller move a signature to mainnet.
    assert "security-network-chosen-per-call" not in found({"src/tools.ts": _TWO_TOOLS})
    # The drafting tool signing with a key loaded once for all tools is the defect.
    signing = _TWO_TOOLS.replace("export function registerTools(server) {\n",
                                 "export function registerTools(server) {\n  const operator = Keypair.fromSecret(config.secret);\n") \
        .replace("    return { content: [{ type: 'text', text: tx.toXDR() }] };", "    tx.sign(operator);\n"
                 "    return { content: [{ type: 'text', text: (await horizon.submitTransaction(tx)).hash }] };", 1)
    assert found({"src/tools.ts": signing})["security-network-chosen-per-call"]["severity"] == "medium"


def test_a_fixed_passphrase_message_names_the_network_of_its_value():
    server = ('import os\nfrom stellar_sdk import Network, Server, TransactionBuilder\n'
              "TESTNET_PASSPHRASE = Network.TESTNET_NETWORK_PASSPHRASE\nLIVE_PASSPHRASE = Network.PUBLIC_NETWORK_PASSPHRASE\n"
              'HORIZON_URL = os.getenv("HORIZON_URL", "https://horizon-testnet.stellar.org")\nserver = Server(HORIZON_URL)\n'
              "def build(source):\n    return TransactionBuilder(source, network_passphrase=TESTNET_PASSPHRASE, base_fee=100)\n")
    detail = found({"server.py": server})["security-network-endpoint-mismatch"]["detail"]
    assert "fixed to testnet constants" in detail  # the constant that reaches the builder, whatever the set order


def test_network_evidence_quotes_the_line_it_numbers():
    tool = _PER_CALL.replace("import { z } from 'zod';\n", "import { z } from 'zod';\nconst LABEL = 'a b\x0cc';\n")
    finding = found({"src/pay.ts": tool})["security-network-chosen-per-call"]
    assert "src/pay.ts:10 `const network = args.network ?? config.network;`" in finding["evidence"]


def test_python_too_complex_to_parse_is_skipped():
    # CPython raises MemoryError ("parser stack overflowed") for `a{{{...`, not SyntaxError.
    files = {"src/a.py": "x = a" + "{" * 3000 + "\nPASSPHRASE = Network.PUBLIC_NETWORK_PASSPHRASE\n",
             "src/b.py": "def f(n):\n    return Network.TESTNET_NETWORK_PASSPHRASE if n == 'testnet' else " + "(" * 50 + ")" * 50}
    _CACHE.clear()
    network_hits(files)
