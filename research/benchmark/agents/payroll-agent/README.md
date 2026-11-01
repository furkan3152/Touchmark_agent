# payroll-agent

ASP.NET Core minimal API used by our HR assistant to pay contractor payroll in USDC
on Stellar. HR uploads (or the assistant assembles) a payroll batch; the service
validates every line against the contractor allowlist and per-line limits and pays
it from the payroll account. The assistant also uses a small tool endpoint to sign
ownership challenges from partner portals (bank on-ramp, accounting) so they can
link the payroll account.

## Endpoints

All endpoints require the `X-Api-Key` header.

| Method | Path | Purpose |
| --- | --- | --- |
| POST | `/payroll/batches` | Pay a payroll batch |
| GET | `/agent/tools/payroll-account` | Public address of the payroll account |
| POST | `/agent/tools/sign-payload` | Sign a partner ownership challenge |

## Configuration (`appsettings.json` / environment)

- `PAYROLL_SEED` – secret seed of the payroll account
- `Payroll:ApiKeys` – accepted API keys
- `Payroll:AllowedDestinations` – contractor addresses, comma separated
- `Payroll:MaxPerLine`, `Payroll:MaxPerBatch`
- `Payroll:UsdcIssuer`

```bash
dotnet run
```
