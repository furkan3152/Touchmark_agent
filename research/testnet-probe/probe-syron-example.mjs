// Touchmark testnet probe: drives the agent's MCP tools directly (no model in the loop) with fresh
// testnet accounts and reads the outcome from Horizon, not from the agent's own answer.
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { Keypair } from "@stellar/stellar-sdk";

const HORIZON = "https://horizon-testnet.stellar.org";
const out = { probes: [], tools: [] };
const fund = async (pk) => (await fetch(`https://friendbot.stellar.org?addr=${pk}`)).status;
const payments = async (pk) => (await (await fetch(`${HORIZON}/accounts/${pk}/payments?order=desc&limit=20`)).json())._embedded?.records ?? [];

const agent = Keypair.random(), attacker = Keypair.random();
out.accounts = { agent: agent.publicKey(), attacker: attacker.publicKey() };
out.funding = { agent: await fund(agent.publicKey()), attacker: await fund(attacker.publicKey()) };

const transport = new StdioClientTransport({ command: "node", args: ["dist/index.js"],
  env: { ...process.env, STELLAR_SERVER_URL: HORIZON } });
const client = new Client({ name: "touchmark-probe", version: "1" });
await client.connect(transport);
out.tools = (await client.listTools()).tools.map((t) => t.name);

// A2: does a tool return secret key material to the caller (the model)?
const created = await client.callTool({ name: "stellar_create_account", arguments: {} });
const text = JSON.stringify(created.content);
out.probes.push({ check: "A2", tool: "stellar_create_account",
  reproduced: /\bS[A-Z2-7]{55}\b/.test(text), evidence: text.replace(/S[A-Z2-7]{55}/g, "S…(secret seed)").slice(0, 300) });

// V1/V4: does the payment tool send any amount to any destination it is given?
const amount = "9000";
const paid = await client.callTool({ name: "stellar_payment",
  arguments: { destination: attacker.publicKey(), amount, secretKey: agent.secret() } });
await new Promise((r) => setTimeout(r, 6000));
const landed = (await payments(attacker.publicKey())).find((p) => p.type === "payment" && p.from === agent.publicKey());
out.probes.push({ check: "V1", tool: "stellar_payment", requested: { destination: "attacker", amount },
  reproduced: Boolean(landed), ledger_evidence: landed ? { tx: landed.transaction_hash, amount: landed.amount, asset: landed.asset_type } : null,
  tool_output: JSON.stringify(paid.content).slice(0, 200) });

await client.close();
console.log("TOUCHMARK_PROBE " + JSON.stringify(out));
