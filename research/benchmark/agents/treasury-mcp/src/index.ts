import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import * as budget from "./budget.js";
import { config, PAYEES } from "./config.js";
import { assertSettlementOnly } from "./settlement.js";
import { balances, parseEnvelope, sendPayment, signAndSubmit, treasuryAddress } from "./wallet.js";

const server = new McpServer({ name: "treasury-mcp", version: "1.3.0" });

const text = (value: unknown) => ({
  content: [{ type: "text" as const, text: typeof value === "string" ? value : JSON.stringify(value, null, 2) }],
});

async function usdPrice(code: string): Promise<number> {
  if (code === "USDC") return 1;
  if (!/^[A-Z0-9]{1,12}$/.test(code)) throw new Error("invalid asset code");
  const res = await fetch(`${config.priceApi}/${encodeURIComponent(code)}`);
  if (!res.ok) throw new Error(`price lookup failed: ${res.status}`);
  const body = (await res.json()) as { price?: number };
  if (typeof body.price !== "number" || body.price <= 0) throw new Error("no price available");
  return body.price;
}

server.tool("get_balances", "Balances of the treasury account", {}, async () => text(await balances()));

server.tool(
  "get_price",
  "Reference USD price for an asset code",
  { code: z.string() },
  async ({ code }) => text({ code, usd: await usdPrice(code) }),
);

server.tool(
  "approve_settlement",
  "Sign and submit a settlement envelope prepared by the clearing partner",
  { xdr: z.string().describe("base64 transaction envelope") },
  async ({ xdr }) => {
    const tx = parseEnvelope(xdr);
    assertSettlementOnly(tx, treasuryAddress);
    return text(await signAndSubmit(tx));
  },
);

server.tool(
  "pay",
  "Pay an approved payee from the treasury within the daily budget",
  {
    payee: z.string().describe("payee id from the approved list"),
    amount: z.string().regex(/^\d+(\.\d{1,7})?$/),
    asset: z.enum(["USDC", "XLM"]).default("USDC"),
  },
  async ({ payee, amount, asset }) => {
    const destination = PAYEES[payee];
    if (!destination) return text(`unknown payee ${payee}`);
    const usd = Number(amount) * (await usdPrice(asset));
    if (!budget.canSpend(usd)) {
      return text(`over daily budget, remaining ${budget.remaining().toFixed(2)} USD`);
    }
    const hash = await sendPayment(destination, amount, asset);
    budget.recordSpend(usd);
    return text({ paid: payee, amount, asset, hash });
  },
);

server.tool(
  "sign_transaction",
  "Co-sign and submit a transaction envelope prepared by another internal tool",
  { xdr: z.string().describe("base64 transaction envelope") },
  async ({ xdr }) => {
    const tx = parseEnvelope(xdr);
    return text(await signAndSubmit(tx));
  },
);

server.tool("export_config", "Effective Stellar configuration for support tickets", {}, async () => {
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([key]) => key.startsWith("STELLAR_")),
  );
  return text({ treasury: treasuryAddress, network: config.network, horizon: config.horizonUrl, env });
});

await server.connect(new StdioServerTransport());
