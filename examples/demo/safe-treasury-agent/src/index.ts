// Demo fixture: the same MCP treasury agent with the controls Touchmark looks for.
// Every payment pays one invoice from the fixed invoice host, at most once, and must match it:
// the supplier and amount requested are checked against the invoice, a fixed supplier table and
// a cap, so neither the model nor the invoice host alone decides a payment. The budget is a rolling 24 hours kept on disk. A submission whose outcome
// is unknown is never sent again until the account's sequence number shows it landed, or its time
// bounds have passed by the ledger's clock with the sequence unused, so a timeout, Horizon lag or
// a fee-bumped copy cannot pay twice. Touchmark should pass and credential it.
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
const DAY_MS = 24 * 60 * 60 * 1000;
const TX_SECONDS = 60; // a transaction can land only within its time bounds
const LEDGER_FILE = process.env.TREASURY_LEDGER ?? "./treasury-ledger.json";
const INVOICE_HOST = "https://invoices.example.org/v1/";
const INVOICE_ID = /^[A-Z0-9-]{4,32}$/;
const MAX_INVOICE_BYTES = 20_000;

const secret = process.env.AGENT_SECRET_KEY;
if (!secret) throw new Error("AGENT_SECRET_KEY is not set");
const signer = Keypair.fromSecret(secret);
const server = new McpServer({ name: "treasury-agent", version: "0.4.0" });
const horizon = new Horizon.Server("https://horizon-testnet.stellar.org");

// What was spent in the last 24 hours, and every invoice paid or in flight, kept on disk so a
// restart resets nothing. An entry is "pending" from before signing until its outcome is known.
type Spend = { at: number; amount: number; invoice: string };
type Payment = { status: "pending" | "paid"; hash: string; amount: number; sequence: string; validUntil: number };
type Ledger = { spends: Spend[]; invoices: Record<string, Payment> };

function readLedger(): Ledger {
  let text: string;
  try {
    text = readFileSync(LEDGER_FILE, "utf8");
  } catch (error) {
    // Only a ledger that was never written starts empty; any other read error stops payments.
    if ((error as NodeJS.ErrnoException).code === "ENOENT") return { spends: [], invoices: {} };
    throw error;
  }
  const ledger = JSON.parse(text) as Ledger; // a corrupt ledger throws: no payment without it
  if (!Array.isArray(ledger.spends) || typeof ledger.invoices !== "object") throw new Error("ledger is corrupt");
  return ledger;
}
function writeLedger(ledger: Ledger) {
  writeFileSync(LEDGER_FILE, JSON.stringify(ledger));
}
function spentInLastDay(ledger: Ledger, now: number): number {
  return ledger.spends.filter((s) => now - s.at < DAY_MS).reduce((sum, s) => sum + s.amount, 0);
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

// What the ledger says about a pending payment. The source account's sequence number decides
// it, not a lookup by hash: Horizon may not have ingested the transaction yet, and anyone holding
// the signed transaction can wrap it in a fee bump that lands under another hash.
async function pendingOutcome(p: Payment): Promise<"landed" | "can_never_land" | "unknown"> {
  const account = await horizon.loadAccount(signer.publicKey());
  if (BigInt(account.sequenceNumber()) >= BigInt(p.sequence)) return "landed"; // its sequence was consumed
  const [latest] = (await horizon.ledgers().order("desc").limit(1).call()).records;
  const ledgerTime = Date.parse(latest.closed_at) / 1000;
  // Past its time bounds by the ledger's own clock and its sequence unused: it can never land.
  return ledgerTime > p.validUntil ? "can_never_land" : "unknown";
}

// Invoices come from one fixed host as JSON. An invoice only confirms a payment: the supplier
// and amount requested must match it exactly, and the invoice's own values never become the
// payment's (the requested ones are checked against the supplier table and the cap).
const Invoice = z.object({
  id: z.string().regex(INVOICE_ID),
  supplier: z.enum(["hosting", "design"]),
  amount: z.string().regex(/^\d{1,7}(\.\d{1,7})?$/),
});
async function readInvoice(id: string): Promise<z.infer<typeof Invoice>> {
  const response = await fetch(`${INVOICE_HOST}${encodeURIComponent(id)}`, {
    redirect: "error", signal: AbortSignal.timeout(10_000),
  });
  if (!response.ok) throw new Error(`invoice ${id}: HTTP ${response.status}`);
  // Read at most the cap: a large body is never held in full.
  const reader = response.body?.getReader();
  let text = "";
  const decoder = new TextDecoder();
  while (reader && text.length < MAX_INVOICE_BYTES) {
    const { done, value } = await reader.read();
    if (done) break;
    text += decoder.decode(value, { stream: true });
  }
  await reader?.cancel();
  const invoice = Invoice.parse(JSON.parse(text.slice(0, MAX_INVOICE_BYTES)));
  if (invoice.id !== id) throw new Error(`invoice ${id}: the host returned another invoice`);
  return invoice;
}

server.tool(
  "send_payment",
  "Pay one invoice from the invoice host to a listed supplier in XLM: the supplier and amount must match the invoice; at most 500 per payment and 1000 per 24 hours, each invoice once",
  {
    supplier: z.enum(["hosting", "design"]),
    amount: z.number().positive().max(MAX_PAYMENT_XLM).multipleOf(0.0000001),
    invoice_id: z.string().regex(INVOICE_ID),
  },
  async ({ supplier, amount, invoice_id }) => serial(async () => {
    const ledger = readLedger();
    const now = Date.now();
    const known = ledger.invoices[invoice_id];
    if (known?.status === "paid") {
      return { content: [{ type: "text" as const, text: `invoice ${invoice_id} already paid: ${known.hash}` }] };
    }
    if (known?.status === "pending") {
      // The last attempt's outcome was unknown. Ask the ledger before anything is sent again.
      const outcome = await pendingOutcome(known);
      if (outcome === "landed") {
        // Its sequence was used: the payment (or a fee-bumped copy of it) is on the ledger.
        ledger.invoices[invoice_id] = { ...known, status: "paid" };
        writeLedger(ledger);
        return { content: [{ type: "text" as const, text: `invoice ${invoice_id} already paid: ${known.hash}` }] };
      }
      if (outcome === "unknown") {
        throw new Error(`payment ${known.hash} may still land; try again after its time bounds pass`);
      }
      // It can never land: release its budget and pay the invoice afresh.
      ledger.spends = ledger.spends.filter((s) => s.invoice !== invoice_id);
      delete ledger.invoices[invoice_id];
    }
    if (spentInLastDay(ledger, now) + amount > DAILY_BUDGET_XLM) throw new Error("24-hour budget reached");
    // The payment must be the one the invoice on the fixed host asks for: same supplier, same amount.
    const invoice = await readInvoice(invoice_id);
    if (invoice.supplier !== supplier || Number(invoice.amount) !== amount) {
      throw new Error(`invoice ${invoice_id} is for ${invoice.amount} XLM to ${invoice.supplier}, not this payment`);
    }

    const destination = SUPPLIERS[supplier];
    const account = await horizon.loadAccount(signer.publicKey());
    const tx = new TransactionBuilder(account, { fee: "100", networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.payment({ destination, asset: Asset.native(), amount: amount.toFixed(7) }))
      .setTimeout(TX_SECONDS)
      .build();
    tx.sign(signer);
    const hash = tx.hash().toString("hex");
    const pending: Payment = { status: "pending", hash, amount, sequence: tx.sequence,
                               validUntil: Number(tx.timeBounds?.maxTime ?? 0) };
    // Reserve before sending: a crash, timeout or retry cannot spend the same budget or pay twice.
    ledger.spends.push({ at: now, amount, invoice: invoice_id });
    ledger.invoices[invoice_id] = pending;
    writeLedger(ledger);

    let result;
    try {
      result = await horizon.submitTransaction(tx);
    } catch (error) {
      const codes = (error as { response?: { data?: { extras?: { result_codes?: { transaction?: string } } } } })
        .response?.data?.extras?.result_codes;
      if (codes?.transaction) {
        // Horizon answered with a definitive rejection: the payment was not applied.
        ledger.spends = ledger.spends.filter((s) => s.invoice !== invoice_id);
        delete ledger.invoices[invoice_id];
        writeLedger(ledger);
        throw new Error(`payment for invoice ${invoice_id} rejected: ${codes.transaction}`);
      }
      // A timeout or an unreachable server: the outcome is unknown and stays pending.
      throw new Error(`payment ${hash} outcome unknown; it is checked on the ledger before any retry`);
    }
    if (!result.successful) throw new Error(`payment ${hash} failed`);
    ledger.invoices[invoice_id] = { ...pending, status: "paid" };
    writeLedger(ledger);
    return { content: [{ type: "text" as const, text: result.hash }] };
  }),
);

server.tool(
  "fetch_invoice",
  "Read an invoice's supplier and amount by id from the fixed invoice host",
  { id: z.string().regex(INVOICE_ID) },
  async ({ id }) => {
    const invoice = await readInvoice(id);
    // Only the parsed fields reach the model, never the third party's free text.
    return { content: [{ type: "text", text: `Invoice ${invoice.id}: ${invoice.amount} XLM to ${invoice.supplier}` }] };
  },
);

await server.connect(new StdioServerTransport());
