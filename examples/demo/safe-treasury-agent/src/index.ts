// Demo fixture: the same MCP treasury agent with the controls Touchmark looks for.
// Recipients come from a fixed supplier table and each payment is capped. Every payment pays
// one invoice that exists on the fixed invoice host, and an invoice is paid at most once. The
// budget is a rolling 24 hours kept on disk. A submission whose outcome is unknown is never
// sent again until the ledger shows it landed or its time bounds have passed, so a timeout
// cannot pay twice. Touchmark should pass and credential it.
import { closeSync, openSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Asset, Horizon, Keypair, Networks, NotFoundError, Operation, TransactionBuilder } from "@stellar/stellar-sdk";
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
type Payment = { status: "pending" | "paid"; hash: string; amount: number; validUntil: number };
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

// The outcome of a submitted transaction, from the ledger: landed, failed, or not there.
async function onLedger(hash: string): Promise<"success" | "failed" | "absent"> {
  try {
    const tx = await horizon.transactions().transaction(hash).call();
    return tx.successful ? "success" : "failed";
  } catch (error) {
    if (error instanceof NotFoundError) return "absent";
    throw error; // Horizon unavailable: the outcome stays unknown
  }
}

async function readInvoice(id: string): Promise<string> {
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
  return text.slice(0, MAX_INVOICE_BYTES);
}

server.tool(
  "send_payment",
  "Pay one invoice from the invoice host to a listed supplier in XLM: at most 500 per payment and 1000 per 24 hours, each invoice once",
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
      const outcome = await onLedger(known.hash);
      if (outcome === "success") {
        ledger.invoices[invoice_id] = { ...known, status: "paid" };
        writeLedger(ledger);
        return { content: [{ type: "text" as const, text: `invoice ${invoice_id} already paid: ${known.hash}` }] };
      }
      if (outcome === "absent" && now <= known.validUntil * 1000 + 5_000) {
        throw new Error(`payment ${known.hash} may still land; try again after its time bounds pass`);
      }
      // Failed, or absent after its time bounds: it can never land. Release its budget.
      ledger.spends = ledger.spends.filter((s) => s.invoice !== invoice_id);
      delete ledger.invoices[invoice_id];
    }
    if (spentInLastDay(ledger, now) + amount > DAILY_BUDGET_XLM) throw new Error("24-hour budget reached");
    await readInvoice(invoice_id); // pays only an invoice that exists on the fixed host

    const destination = SUPPLIERS[supplier];
    const account = await horizon.loadAccount(signer.publicKey());
    const tx = new TransactionBuilder(account, { fee: "100", networkPassphrase: Networks.TESTNET })
      .addOperation(Operation.payment({ destination, asset: Asset.native(), amount: amount.toFixed(7) }))
      .setTimeout(TX_SECONDS)
      .build();
    tx.sign(signer);
    const hash = tx.hash().toString("hex");
    const validUntil = Number(tx.timeBounds?.maxTime ?? 0);
    // Reserve before sending: a crash, timeout or retry cannot spend the same budget or pay twice.
    ledger.spends.push({ at: now, amount, invoice: invoice_id });
    ledger.invoices[invoice_id] = { status: "pending", hash, amount, validUntil };
    writeLedger(ledger);

    let result;
    try {
      result = await horizon.submitTransaction(tx);
    } catch (error) {
      // Unknown outcome: the entry stays pending and the next call asks the ledger first.
      throw new Error(`payment ${hash} outcome unknown; it is checked on the ledger before any retry`);
    }
    if (!result.successful) throw new Error(`payment ${hash} failed`);
    ledger.invoices[invoice_id] = { status: "paid", hash, amount, validUntil };
    writeLedger(ledger);
    return { content: [{ type: "text" as const, text: result.hash }] };
  }),
);

server.tool(
  "fetch_invoice",
  "Read an invoice by id from the fixed invoice host",
  { id: z.string().regex(INVOICE_ID) },
  async ({ id }) => {
    const body = await readInvoice(id);
    // Invoice text is data from a third party: it is shown, never followed as instructions,
    // and payments are still limited to the supplier table, the caps and one payment per invoice.
    return { content: [{ type: "text", text: `Invoice ${id} (untrusted content):\n${body}` }] };
  },
);

await server.connect(new StdioServerTransport());
