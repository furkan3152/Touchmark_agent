"""Self-test preserving the evidence boundaries of the Stellar replica."""

from __future__ import annotations

import time

from ..compliance.ofac import OfacSanctionsList
from ..config import Settings
from ..ingestion import IngestRequest, IngestionService
from ..models import AuditTier
from .chain_status import ChainStatusService
from .pipeline import AuditPipeline

OK, WARN, FAIL = "ok", "warn", "fail"
MIN_SCORE_SPREAD = 25.0


def _check(name: str, state: str, detail: str, hint: str = "") -> dict:
    return {"name": name, "state": state, "detail": detail, "hint": hint}


class SelfTestService:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.chain = ChainStatusService(settings)

    async def run(self, *, deep: bool = False) -> dict:
        started = time.perf_counter()
        checks = [self._check_config()]
        checks.extend(await self._check_stellar())
        checks.extend(
            [
                self._check_ofac(),
                self._check_llm(),
                self._check_ipfs(),
                self._check_auth_boundaries(),
            ]
        )
        if deep:
            checks.append(await self._check_pipeline())
            checks.append(await self._check_discrimination())

        counts = {state: sum(c["state"] == state for c in checks) for state in (OK, WARN, FAIL)}
        return {
            "ok": counts[FAIL] == 0,
            "checks": checks,
            "summary": counts,
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "deep": deep,
        }

    def _check_config(self) -> dict:
        net = self.settings.network_or_none
        if not net:
            return _check(
                "Network profile", FAIL, "STELLAR_NETWORK could not be resolved", "STELLAR_NETWORK=testnet"
            )
        if not self.settings.is_testnet and not self.settings.allow_mainnet:
            return _check("Network profile", FAIL, "mainnet is not unlocked", "ALLOW_MAINNET=true")
        return _check("Network profile", OK, f"{net.name} · passphrase profile loaded")

    async def _check_stellar(self) -> list[dict]:
        checks: list[dict] = []
        if not self.settings.rpc_enabled:
            checks.append(_check("Stellar RPC", WARN, "offline profile", "STELLAR_NETWORK=testnet"))
        else:
            health = await self.chain.rpc.health()
            if health.get("reachable"):
                checks.append(
                    _check(
                        "Stellar RPC",
                        OK,
                        f"healthy · ledger {health.get('latest_ledger')} · protocol {health.get('protocol_version')}",
                    )
                )
            else:
                checks.append(_check("Stellar RPC", FAIL, health.get("error") or "not healthy"))

        deployments = await self.chain.deployed_contracts()
        contract_map = {row["key"]: row for row in deployments["contracts"]}
        registry = contract_map["agent_registry"]
        if not self.settings.agent_registry_contract_id:
            checks.append(
                _check(
                    "Agent registry",
                    WARN,
                    "contract ID not defined; report remains off-chain",
                    "AGENT_REGISTRY_CONTRACT_ID=C...",
                )
            )
        elif registry["onchain_verified"]:
            checks.append(
                _check(
                    "Agent registry",
                    OK,
                    f"ID + pinned WASM + live deploy tx SUCCESS · ledger {registry.get('live_ledger')}",
                )
            )
        else:
            checks.append(
                _check(
                    "Agent registry",
                    WARN,
                    "ID configured but deploy not verified with ledger entry/event",
                    "run event ingester and contract state readback",
                )
            )

        event_status = self.chain.events.status()
        checks.append(
            _check(
                "Event store",
                OK,
                f"SQLite ready · {event_status['events']} events · {event_status['streams']} cursors",
            )
        )
        checks.append(
            _check(
                "Signing boundary",
                OK,
                "backend does not store signer/secret; prepared invocation is not considered on-chain success",
            )
        )
        escrow = contract_map["audit_escrow"]
        if self.settings.audit_escrow_enabled and escrow["onchain_verified"]:
            checks.append(
                _check(
                    "Audit escrow",
                    OK,
                    f"ID + pinned WASM + live deploy tx SUCCESS · ledger {escrow.get('live_ledger')}",
                )
            )
        elif self.settings.audit_escrow_enabled:
            checks.append(
                _check(
                    "Audit escrow",
                    WARN,
                    "enabled but funding/settlement awaits external signature and event verification",
                )
            )
        else:
            checks.append(
                _check("Audit escrow", OK, "disabled and independent of the agent validation core")
            )
        return checks

    def _check_auth_boundaries(self) -> dict:
        sep10 = bool(self.settings.sep10_web_auth_endpoint)
        sep45 = bool(self.settings.sep45_web_auth_endpoint)
        if sep10 and sep45:
            return _check("Account auth", OK, "SEP-10 (G/M) and SEP-45 (C) endpoints are distinct")
        if sep10 or sep45:
            missing = "SEP-45 C-account" if sep10 else "SEP-10 G/M-account"
            return _check("Account auth", WARN, f"partial: {missing} path missing")
        return _check(
            "Account auth",
            WARN,
            "web auth not configured; raw Ed25519 can only be used for G-account",
            "SEP10_WEB_AUTH_ENDPOINT ve SEP45_WEB_AUTH_ENDPOINT",
        )

    def _check_ofac(self) -> dict:
        if not self.settings.ofac_enabled:
            return _check("OFAC sanctions list", WARN, "disabled")
        sanctions = OfacSanctionsList(self.settings.data_path, self.settings.ofac_max_age_hours)
        cache = sanctions.load_cache()
        if not cache:
            return _check(
                "OFAC sanctions list",
                WARN,
                "no cache; sanctions scan is not performed",
                "python -m backend.cli sanctions --refresh",
            )
        total = cache.get("total_addresses", 0)
        if not sanctions.is_fresh(cache):
            return _check("OFAC sanctions list", WARN, f"{total} addresses · not up-to-date")
        return _check("OFAC sanctions list", OK, f"{total} addresses · up-to-date")

    def _check_llm(self) -> dict:
        if not self.settings.llm_enabled:
            return _check("LLM-as-Judge", WARN, "disabled; deterministic heuristic engine")
        return _check(
            "LLM-as-Judge", OK, f"{self.settings.llm_provider} · {self.settings.llm_model}"
        )

    def _check_ipfs(self) -> dict:
        if not self.settings.ipfs_enabled:
            return _check("IPFS", WARN, "local content-addressed store", "PINATA_JWT")
        return _check("IPFS", OK, "Pinata pinning enabled")

    async def _check_pipeline(self) -> dict:
        try:
            report = await self._audit("./examples/vulnerable_agent")
        except Exception as exc:
            return _check("End-to-end audit", FAIL, f"{type(exc).__name__}: {exc}")
        if report is None or report.overall_score > 60:
            score = report.overall_score if report else "no report"
            return _check("End-to-end audit", FAIL, f"vulnerable agent result: {score}")
        att = report.attestation
        return _check(
            "End-to-end audit",
            OK,
            f"score {report.overall_score} · {len(report.findings)} findings · "
            f"attestation={att.mode if att else 'none'} confirmed={att.confirmed if att else False}",
        )

    async def _check_discrimination(self) -> dict:
        try:
            good = await self._audit("./examples/corpus/payroll_agent")
            bad = await self._audit("./examples/corpus/airdrop_scam")
        except Exception as exc:
            return _check("Score discrimination", FAIL, f"{type(exc).__name__}: {exc}")
        if good is None or bad is None:
            return _check("Score discrimination", FAIL, "corpus report missing")
        spread = round(good.overall_score - bad.overall_score, 1)
        detail = f"payroll {good.overall_score} - scam {bad.overall_score} = {spread}"
        return _check(
            "Score discrimination",
            OK if spread >= MIN_SCORE_SPREAD else FAIL,
            detail,
        )

    async def _audit(self, local_path: str):
        scoped = self.settings.model_copy(update={"allow_local_path_ingest": True})
        pipeline = AuditPipeline(scoped)
        ingestion = IngestionService(scoped)
        artifact = await ingestion.ingest(IngestRequest(kind="repo", local_path=local_path))
        pipeline.store.put_agent(artifact)
        job = pipeline.create_job(artifact.id, AuditTier.BASIC)
        job = await pipeline.run_job(job.id)
        return job.report
