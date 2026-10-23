"""Network binding: which value picks the network an agent signs for (swarm/network_rules.py)."""

from __future__ import annotations

from backend.app.models import AgentArtifact, SourceKind
from backend.app.swarm.network_rules import mask, net_of, network_findings


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
    assert found({"server.py": server})["security-network-endpoint-mismatch"]["severity"] == "low"
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


def test_a_testnet_issuer_in_a_payment_that_can_be_signed_for_mainnet_is_medium():
    finding = found({"sdk/client.py": _CROSS})["security-network-cross-constant"]
    assert finding["severity"] == "medium" and "sdk/client.py:8" in finding["evidence"]


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
