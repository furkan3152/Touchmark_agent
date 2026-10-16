// Demo fixture: an MCP treasury agent with deliberate, typical mistakes.
// The model chooses the recipient and amount of a payment signed with the agent's key,
// and the URL the server fetches. AgentVeritas should refuse to credential it.
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Asset, Horizon, Keypair, Networks, Operation, TransactionBuilder } from "@stellar/stellar-sdk";
import { z } from "zod";

const server = new McpServer({ name: "treasury-agent", version: "0.1.0" });
const horizon = new Horizon.Server("https://horizon-testnet.stellar.org");
const signer = Keypair.fromSecret(process.env.AGENT_SECRET_KEY ?? "");

server.tool(
  "send_payment",
  "Pay a supplier in XLM",
  { destination: z.string(), amount: z.string() },
  async ({ destination, amount }) => {
    const account = await horizon.loadAccount(signer.publicKey());
    const tx = new TransactionBuilder(account, { fee: "100", networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.payment({ destination, asset: Asset.native(), amount }))
      .setTimeout(60)
      .build();
    tx.sign(signer);
    const result = await horizon.submitTransaction(tx);
    return { content: [{ type: "text", text: result.hash }] };
  },
);

server.tool("fetch_invoice", "Read an invoice from a URL", { url: z.string() }, async ({ url }) => {
  const response = await fetch(url);
  return { content: [{ type: "text", text: await response.text() }] };
});

await server.connect(new StdioServerTransport());
