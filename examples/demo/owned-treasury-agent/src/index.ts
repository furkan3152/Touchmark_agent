// Demo fixture: the same MCP treasury agent with the controls AgentVeritas looks for.
// Recipients come from a fixed supplier table, amounts are capped in the schema, and
// invoices are read from one fixed host. AgentVeritas should pass and credential it.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Asset, Horizon, Keypair, Networks, Operation, TransactionBuilder } from "@stellar/stellar-sdk";
import { z } from "zod";

const SUPPLIERS = {
  hosting: "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H",
  design: "GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR",
} as const;
const MAX_PAYMENT_XLM = 500;

const server = new McpServer({ name: "treasury-agent", version: "0.2.0" });
const horizon = new Horizon.Server("https://horizon-testnet.stellar.org");
const signer = Keypair.fromSecret(process.env.AGENT_SECRET_KEY ?? "");

server.tool(
  "send_payment",
  "Pay a listed supplier in XLM, at most 500 per payment",
  { supplier: z.enum(["hosting", "design"]), amount: z.number().positive().max(MAX_PAYMENT_XLM) },
  async ({ supplier, amount }) => {
    const destination = SUPPLIERS[supplier];
    const account = await horizon.loadAccount(signer.publicKey());
    const tx = new TransactionBuilder(account, { fee: "100", networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.payment({ destination, asset: Asset.native(), amount: amount.toFixed(7) }))
      .setTimeout(60)
      .build();
    tx.sign(signer);
    const result = await horizon.submitTransaction(tx);
    if (!result.successful) throw new Error("payment failed");
    return { content: [{ type: "text", text: result.hash }] };
  },
);

server.tool(
  "fetch_invoice",
  "Read an invoice by id",
  { id: z.string().regex(/^[A-Z0-9-]{4,32}$/) },
  async ({ id }) => {
    const response = await fetch(`https://invoices.example.org/v1/${encodeURIComponent(id)}`);
    return { content: [{ type: "text", text: await response.text() }] };
  },
);

await server.connect(new StdioServerTransport());
