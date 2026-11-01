import { Networks } from "@stellar/stellar-sdk";

export const config = {
  network: process.env.STELLAR_NETWORK ?? "testnet",
  horizonUrl: process.env.STELLAR_HORIZON_URL ?? "https://horizon-testnet.stellar.org",
  settlementAccount: process.env.STELLAR_SETTLEMENT_ACCOUNT ?? "",
  usdcIssuer:
    process.env.STELLAR_USDC_ISSUER ?? "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN",
  dailyBudgetUsd: Number(process.env.TREASURY_DAILY_BUDGET ?? "2000"),
  maxSettlement: "5000",
  priceApi: "https://api.stellar.expert/explorer/public/asset",
};

export function networkPassphrase(): string {
  return config.network === "public" ? Networks.PUBLIC : Networks.TESTNET;
}

export const PAYEES: Record<string, string> = {
  "ops-contractor-ana": "GCKFBEIYV2U22IO2BJ4KVJOIP7XPWQGQFKKWXR6DOSJBV7STMAQSMTGG",
  "ops-contractor-ben": "GDJ4QEUM3XAJ6PBZNWUSYUB2EBR3IGTP7W7FSVJ3YDRWR5AULLLFNMQ6",
  "infra-vendor-cloudco": "GBVOL67TMUQBGL4TZYNMY3ZQ5WGQYFPFD5VJRWXR72VA33VFNL225PL5",
};
