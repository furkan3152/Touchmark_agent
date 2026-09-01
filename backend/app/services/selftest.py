"""Stellar kopyasının kanıt sınırlarını koruyan öz-denetim."""

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
                "Ağ profili", FAIL, "STELLAR_NETWORK çözümlenemedi", "STELLAR_NETWORK=testnet"
            )
        if not self.settings.is_testnet and not self.settings.allow_mainnet:
            return _check("Ağ profili", FAIL, "mainnet kilidi açık değil", "ALLOW_MAINNET=true")
        return _check("Ağ profili", OK, f"{net.name} · passphrase profili yüklü")

    async def _check_stellar(self) -> list[dict]:
        checks: list[dict] = []
        if not self.settings.rpc_enabled:
            checks.append(_check("Stellar RPC", WARN, "offline profil", "STELLAR_NETWORK=testnet"))
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
                checks.append(_check("Stellar RPC", FAIL, health.get("error") or "healthy değil"))

        deployments = await self.chain.deployed_contracts()
        contract_map = {row["key"]: row for row in deployments["contracts"]}
        registry = contract_map["agent_registry"]
        if not self.settings.agent_registry_contract_id:
            checks.append(
                _check(
                    "Agent registry",
                    WARN,
                    "contract ID tanımlı değil; rapor offchain kalır",
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
                    "ID yapılandırıldı fakat ledger entry/event ile deploy doğrulanmadı",
                    "event ingester ve contract state readback çalıştırın",
                )
            )

        event_status = self.chain.events.status()
        checks.append(
            _check(
                "Event deposu",
                OK,
                f"SQLite hazır · {event_status['events']} olay · {event_status['streams']} cursor",
            )
        )
        checks.append(
            _check(
                "İmzalama sınırı",
                OK,
                "backend signer/secret saklamıyor; prepared invocation onchain başarı sayılmıyor",
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
                    "etkin fakat fonlama/settlement dış imza ve event doğrulaması bekliyor",
                )
            )
        else:
            checks.append(
                _check("Audit escrow", OK, "kapalı ve agent validation çekirdeğinden bağımsız")
            )
        return checks

    def _check_auth_boundaries(self) -> dict:
        sep10 = bool(self.settings.sep10_web_auth_endpoint)
        sep45 = bool(self.settings.sep45_web_auth_endpoint)
        if sep10 and sep45:
            return _check("Account auth", OK, "SEP-10 (G/M) ve SEP-45 (C) uçları ayrık")
        if sep10 or sep45:
            missing = "SEP-45 C-account" if sep10 else "SEP-10 G/M-account"
            return _check("Account auth", WARN, f"kısmi: {missing} yolu eksik")
        return _check(
            "Account auth",
            WARN,
            "web auth yapılandırılmadı; raw Ed25519 yalnız G-account için kullanılabilir",
            "SEP10_WEB_AUTH_ENDPOINT ve SEP45_WEB_AUTH_ENDPOINT",
        )

    def _check_ofac(self) -> dict:
        if not self.settings.ofac_enabled:
            return _check("OFAC yaptırım listesi", WARN, "kapalı")
        sanctions = OfacSanctionsList(self.settings.data_path, self.settings.ofac_max_age_hours)
        cache = sanctions.load_cache()
        if not cache:
            return _check(
                "OFAC yaptırım listesi",
                WARN,
                "önbellek yok; yaptırım taraması yapılmıyor",
                "python -m backend.cli sanctions --refresh",
            )
        total = cache.get("total_addresses", 0)
        if not sanctions.is_fresh(cache):
            return _check("OFAC yaptırım listesi", WARN, f"{total} adres · güncel değil")
        return _check("OFAC yaptırım listesi", OK, f"{total} adres · güncel")

    def _check_llm(self) -> dict:
        if not self.settings.llm_enabled:
            return _check("LLM-as-Judge", WARN, "kapalı; deterministik heuristik motor")
        return _check(
            "LLM-as-Judge", OK, f"{self.settings.llm_provider} · {self.settings.llm_model}"
        )

    def _check_ipfs(self) -> dict:
        if not self.settings.ipfs_enabled:
            return _check("IPFS", WARN, "yerel content-addressed store", "PINATA_JWT")
        return _check("IPFS", OK, "Pinata pinleme açık")

    async def _check_pipeline(self) -> dict:
        try:
            report = await self._audit("./examples/vulnerable_agent")
        except Exception as exc:
            return _check("Uçtan uca denetim", FAIL, f"{type(exc).__name__}: {exc}")
        if report is None or report.overall_score > 60:
            score = report.overall_score if report else "rapor yok"
            return _check("Uçtan uca denetim", FAIL, f"zafiyetli ajan sonucu: {score}")
        att = report.attestation
        return _check(
            "Uçtan uca denetim",
            OK,
            f"skor {report.overall_score} · {len(report.findings)} bulgu · "
            f"attestation={att.mode if att else 'yok'} confirmed={att.confirmed if att else False}",
        )

    async def _check_discrimination(self) -> dict:
        try:
            good = await self._audit("./examples/corpus/payroll_agent")
            bad = await self._audit("./examples/corpus/airdrop_scam")
        except Exception as exc:
            return _check("Skor ayrıştırma", FAIL, f"{type(exc).__name__}: {exc}")
        if good is None or bad is None:
            return _check("Skor ayrıştırma", FAIL, "korpus raporu eksik")
        spread = round(good.overall_score - bad.overall_score, 1)
        detail = f"payroll {good.overall_score} - scam {bad.overall_score} = {spread}"
        return _check(
            "Skor ayrıştırma",
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
