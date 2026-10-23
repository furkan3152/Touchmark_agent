// Demo fixture: the same MCP treasury agent with the controls Touchmark looks for.
// Recipients come from a fixed supplier table, each payment is capped, a daily budget
// is kept on disk, every payment request carries an id that is paid at most once, and
// invoices are read from one fixed host. Touchmark should pass and credential it.
import { closeSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Asset, Horizon, Keypair, Networks, Operation, TransactionBuilder } from "@stellar/stellar-sdk";
import { z } from "zod";

const SUPPLIERS = {
  hosting: "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H",
  design: "GAIH3ULLFQ4DGSECF2AR555KZ4KNDGEKN4AFI4SU2M7B43MGK3QJZNSR",
} as const;
const MAX_PAYMENT_XLM = 500;
const DAILY_BUDGET_XLM = 1000;
const LEDGER_FILE = process.env.TREASURY_LEDGER ?? "./treasury-ledger.json";
const MAX_INVOICE_BYTES = 20_000;

const secret = process.env.AGENT_SECRET_KEY;
if (!secret) throw new Error("AGENT_SECRET_KEY is not set");
const signer = Keypair.fromSecret(secret);
const server = new McpServer({ name: "treasury-agent", version: "0.3.0" });
const horizon = new Horizon.Server("https://horizon-testnet.stellar.org");

// Spending and the ids already paid, kept on disk so a restart does not reset them.
type Ledger = { day: string; spent: number; paid: Record<string, string> };
function readLedger(): Ledger {
  const today = new Date().toISOString().slice(0, 10);
  let text: string;
  try {
    text = readFileSync(LEDGER_FILE, "utf8");
  } catch (error) {
    // Only a ledger that was never written starts empty; any other read error stops payments.
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { day: today, spent: 0, paid: {} };
    throw error;
  }
  const ledger = JSON.parse(text) as Ledger; // a corrupt ledger throws: no payment without it
  if (typeof ledger.spent !== "number" || typeof ledger.paid !== "object") throw new Error("ledger is corrupt");
  return ledger.day === today ? ledger : { day: today, spent: 0, paid: ledger.paid };
}
function writeLedger(ledger: Ledger) {
  writeFileSync(LEDGER_FILE, JSON.stringify(ledger));
}
// One payment at a time, across every process that shares the ledger: an exclusive lock
// file is created before reading and removed after writing. A lock left by a crash stops
// payments until the operator checks the ledger and removes it (fails closed).
let queue: Promise<unknown> = Promise.resolve();
function serial<T>(task: () => Promise<T>): Promise<T> {
  const locked = async () => {
    const lock = openSync(`${LEDGER_FILE}.lock`, "wx"); // throws if another payment holds it
    try {
      return await task();
    } finally {
      closeSync(lock);
      unlinkSync(`${LEDGER_FILE}.lock`);
    }
  };
  const run = queue.then(locked, locked);
  queue = run.catch(() => undefined);
  return run;
}

server.tool(
  "send_payment",
  "Pay a listed supplier in XLM: at most 500 per payment and 1000 per day, once per request id",
  {
    supplier: z.enum(["hosting", "design"]),
    amount: z.number().positive().max(MAX_PAYMENT_XLM),
    request_id: z.string().regex(/^[A-Za-z0-9-]{8,64}$/),
  },
  async ({ supplier, amount, request_id }) => serial(async () => {
    const ledger = readLedger();
    if (ledger.paid[request_id]) {
      return { content: [{ type: "text" as const, text: `already paid: ${ledger.paid[request_id]}` }] };
    }
    if (ledger.spent + amount > DAILY_BUDGET_XLM) throw new Error("daily budget reached");
    // Reserve before sending, so a crash or retry cannot spend the same budget twice.
    ledger.spent += amount;
    ledger.paid[request_id] = "pending";
    writeLedger(ledger);

    const destination = SUPPLIERS[supplier];
    const account = await horizon.loadAccount(signer.publicKey());
    const tx = new TransactionBuilder(account, { fee: "100", networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.payment({ destination, asset: Asset.native(), amount: amount.toFixed(7) }))
      .setTimeout(60)
      .build();
    tx.sign(signer);
    const hash = tx.hash().toString("hex");
    ledger.paid[request_id] = hash;
    writeLedger(ledger);
    // The reservation is kept even if submission fails: the transaction may still land,
    // and its hash is recorded so the operator can check it before any new request.
    const result = await horizon.submitTransaction(tx);
    if (!result.successful) throw new Error(`payment ${hash} failed`);
    return { content: [{ type: "text" as const, text: result.hash }] };
  }),
);

server.tool(
  "fetch_invoice",
  "Read an invoice by id from the fixed invoice host",
  { id: z.string().regex(/^[A-Z0-9-]{4,32}$/) },
  async ({ id }) => {
    const response = await fetch(`https://invoices.example.org/v1/${encodeURIComponent(id)}`, { redirect: "error" });
    if (!response.ok) throw new Error(`invoice ${id}: HTTP ${response.status}`);
    const body = (await response.text()).slice(0, MAX_INVOICE_BYTES);
    // Invoice text is data from a third party: it is shown, never followed as instructions,
    // and payments are still limited to the supplier table and the budgets above.
    return { content: [{ type: "text", text: `Invoice ${id} (untrusted content):\n${body}` }] };
  },
);

await server.connect(new StdioServerTransport());
