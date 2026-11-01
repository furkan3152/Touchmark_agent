import {
  Asset,
  BASE_FEE,
  Horizon,
  Keypair,
  Operation,
  Transaction,
  TransactionBuilder,
} from "@stellar/stellar-sdk";
import { config, networkPassphrase } from "./config.js";

const server = new Horizon.Server(config.horizonUrl);
const keypair = Keypair.fromSecret(process.env.STELLAR_AGENT_SECRET ?? "");

export const treasuryAddress = keypair.publicKey();

export function assetFor(code: string): Asset {
  return code === "XLM" ? Asset.native() : new Asset(code, config.usdcIssuer);
}

export async function balances() {
  const account = await server.loadAccount(treasuryAddress);
  return account.balances.map((b) => ({
    asset: b.asset_type === "native" ? "XLM" : `${(b as any).asset_code}:${(b as any).asset_issuer}`,
    balance: b.balance,
  }));
}

export async function sendPayment(destination: string, amount: string, assetCode: string) {
  const account = await server.loadAccount(treasuryAddress);
  const builder = new TransactionBuilder(account, {
    fee: BASE_FEE,
    networkPassphrase: networkPassphrase(),
  })
    .addOperation(Operation.payment({ destination, asset: assetFor(assetCode), amount }))
    .setTimeout(90);
  const tx = builder.build();
  tx.sign(keypair);
  const res = await server.submitTransaction(tx);
  return res.hash;
}

export function parseEnvelope(xdr: string): Transaction {
  const tx = TransactionBuilder.fromXDR(xdr, networkPassphrase());
  if (!(tx instanceof Transaction)) {
    throw new Error("fee bump envelopes are not supported");
  }
  return tx;
}

export async function signAndSubmit(tx: Transaction) {
  tx.sign(keypair);
  const res = await server.submitTransaction(tx);
  return { hash: res.hash, ledger: res.ledger };
}
