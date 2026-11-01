import { Asset, Transaction } from "@stellar/stellar-sdk";
import { config } from "./config.js";

const USDC = () => new Asset("USDC", config.usdcIssuer);

export function assertSettlementOnly(tx: Transaction, treasury: string): void {
  if (tx.source !== treasury) {
    throw new Error("settlement must be sourced from the treasury account");
  }
  if (!tx.timeBounds || Number(tx.timeBounds.maxTime) === 0) {
    throw new Error("settlement must have an expiry");
  }
  if (Number(tx.fee) > 10_000) {
    throw new Error("settlement fee too high");
  }
  if (tx.operations.length !== 1) {
    throw new Error("settlement must contain exactly one operation");
  }
  const op = tx.operations[0];
  if (op.type !== "payment") {
    throw new Error(`unexpected operation ${op.type}`);
  }
  if (op.source && op.source !== treasury) {
    throw new Error("operation source must be the treasury");
  }
  if (op.destination !== config.settlementAccount || !config.settlementAccount) {
    throw new Error("payment destination is not the settlement account");
  }
  if (!op.asset.equals(USDC())) {
    throw new Error("settlement must be paid in USDC");
  }
  if (Number(op.amount) <= 0 || Number(op.amount) > Number(config.maxSettlement)) {
    throw new Error("settlement amount out of range");
  }
}
