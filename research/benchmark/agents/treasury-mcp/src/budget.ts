import { config } from "./config.js";

let day = new Date().toISOString().slice(0, 10);
let spentUsd = 0;

function rollover() {
  const today = new Date().toISOString().slice(0, 10);
  if (today !== day) {
    day = today;
    spentUsd = 0;
  }
}

export function remaining(): number {
  rollover();
  return config.dailyBudgetUsd - spentUsd;
}

export function canSpend(usd: number): boolean {
  rollover();
  return usd > 0 && spentUsd + usd <= config.dailyBudgetUsd;
}

export function recordSpend(usd: number): void {
  rollover();
  spentUsd += usd;
}
