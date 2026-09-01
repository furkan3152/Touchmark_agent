"""Reliability Prober — uptime, latency, hata oranı, maliyet verimliliği.

Canlı probe sonuçları CONFIRMED; kod/prompt'ta bir mekanizmanın yokluğu INFERRED.
"""

from __future__ import annotations

import asyncio
import time

import httpx

from ..models import (
    AgentArtifact,
    Dimension,
    EvidenceGrade,
    Finding,
    ScenarioResult,
    Severity,
)
from .base import BaseAuditor

PROBE_COUNT_BASIC = 3
PROBE_COUNT_DEEP = 8


class ReliabilityAuditor(BaseAuditor):
    name = "reliability-prober"
    dimension = Dimension.RELIABILITY

    async def analyse(
        self, artifact: AgentArtifact, deep: bool
    ) -> tuple[list[Finding], list[ScenarioResult], str]:
        findings: list[Finding] = []
        scenarios: list[ScenarioResult] = []

        if not artifact.endpoint_url:
            findings.append(
                self.finding(
                    "no-endpoint",
                    Severity.LOW,
                    "Canlı endpoint verilmedi",
                    "Uptime, gecikme ve başarı oranı ölçülemedi; bu boyut yalnızca statik "
                    "sinyallere dayanıyor.",
                    remediation="Sürekli izleme ve tam güvenilirlik skoru için MCP/A2A/HTTP "
                    "endpoint'i kaydedin.",
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.5,
                )
            )
            findings += self._static_reliability(artifact)
            return findings, scenarios, "Endpoint yok; yalnızca statik sinyaller değerlendirildi."

        stats = await self._probe(
            artifact.endpoint_url, PROBE_COUNT_DEEP if deep else PROBE_COUNT_BASIC
        )
        success_rate = stats["success"] / max(stats["total"], 1)

        scenarios += [
            ScenarioResult(
                scenario_id="R-01",
                name="Endpoint erişilebilir",
                passed=stats["success"] > 0,
                reason=f"{stats['success']}/{stats['total']} istek başarılı",
            ),
            ScenarioResult(
                scenario_id="R-02",
                name="Gecikme kabul edilebilir (p95 < 5s)",
                passed=bool(stats["success"]) and stats["p95_ms"] < 5000,
                reason=f"p95={stats['p95_ms']}ms",
            ),
        ]

        if success_rate == 0:
            findings.append(
                self.finding(
                    "endpoint-down",
                    Severity.HIGH,
                    "Endpoint yanıt vermiyor",
                    f"{stats['total']} denemenin hiçbiri başarılı olmadı. "
                    f"Son hata: {stats['last_error']}",
                    remediation="Servisi ayağa kaldırın ve health-check endpoint'i ekleyin.",
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.95,
                )
            )
        elif success_rate < 0.8:
            findings.append(
                self.finding(
                    "flaky-endpoint",
                    Severity.MEDIUM,
                    "Endpoint kararsız",
                    f"Başarı oranı %{success_rate * 100:.0f}. Kararsız servis iş teslim "
                    "güvenilirliğini düşürür.",
                    remediation="Yeniden deneme, devre kesici ve kapasite ölçeklemesi ekleyin.",
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.9,
                )
            )

        if stats["success"] and stats["p95_ms"] > 8000:
            findings.append(
                self.finding(
                    "high-latency",
                    Severity.MEDIUM,
                    "Yüksek gecikme",
                    f"p95 gecikme {stats['p95_ms']}ms. Agent yanıt süresi "
                    "ledger onayı öncesindeki kullanıcı deneyimini bozuyor.",
                    remediation="Model çağrılarını paralelleştirin, önbellek ve streaming ekleyin.",
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.9,
                )
            )

        if stats["auth_open"]:
            findings.append(
                self.finding(
                    "unauthenticated-endpoint",
                    Severity.HIGH,
                    "Kimlik doğrulaması olmayan endpoint",
                    "Endpoint kimlik doğrulaması istemeden istekleri kabul ediyor. Herkes agent'ı "
                    "kullanabilir; maliyet istismarı ve yetkisiz işlem riski var.",
                    evidence="probe: kimlik bilgisi olmadan 2xx yanıt alındı",
                    remediation="API anahtarı veya agent cüzdan imzası ile kimlik doğrulaması "
                    "zorunlu kılın.",
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.9,
                )
            )

        findings += self._static_reliability(artifact)
        notes = (
            f"{stats['total']} probe → başarı %{success_rate * 100:.0f}, "
            f"ortalama {stats['avg_ms']}ms, p95 {stats['p95_ms']}ms."
        )
        return findings, scenarios, notes

    def _static_reliability(self, artifact: AgentArtifact) -> list[Finding]:
        out: list[Finding] = []
        surface = artifact.text_surface().lower()

        if artifact.code_files and not any(
            k in surface for k in ("try", "except", "catch", "error", "retry")
        ):
            out.append(
                self.finding(
                    "no-error-handling",
                    Severity.MEDIUM,
                    "Hata yönetimi görünmüyor",
                    "Kod veya prompt içinde hata yakalama/yeniden deneme sinyali yok.",
                    remediation="Hata sınıflarını tanımlayın, backoff'lu yeniden deneme ekleyin.",
                    grade=EvidenceGrade.INFERRED,
                    confidence=0.7,
                )
            )

        if not any(
            k in surface for k in ("cache", "cost", "token budget", "rate limit", "throttle")
        ):
            out.append(
                self.finding(
                    "no-cost-controls",
                    Severity.LOW,
                    "Maliyet/oran kontrolü yok",
                    "Token veya gas maliyetini sınırlayan bir mekanizma bulunamadı.",
                    remediation="Önbellek, oran sınırı ve token bütçesi tanımlayın.",
                    grade=EvidenceGrade.INFERRED,
                    confidence=0.6,
                )
            )
        return out

    async def _probe(self, url: str, count: int) -> dict:
        latencies: list[float] = []
        success = 0
        last_error = ""
        auth_open = False

        async def one() -> None:
            nonlocal success, last_error, auth_open
            t0 = time.perf_counter()
            try:
                async with httpx.AsyncClient(timeout=12.0) as client:
                    resp = await client.post(
                        url.rstrip("/"),
                        json={"messages": [{"role": "user", "content": "health check: reply OK"}]},
                    )
                latencies.append((time.perf_counter() - t0) * 1000)
                if resp.status_code < 400:
                    success += 1
                    auth_open = True
                elif resp.status_code in (401, 403):
                    success += 1  # servis ayakta, kimlik doğrulaması istiyor
                else:
                    last_error = f"HTTP {resp.status_code}"
            except Exception as exc:
                last_error = type(exc).__name__

        await asyncio.gather(*(one() for _ in range(count)))

        latencies.sort()
        idx = max(0, int(len(latencies) * 0.95) - 1)
        return {
            "total": count,
            "success": success,
            "avg_ms": int(sum(latencies) / len(latencies)) if latencies else 0,
            "p95_ms": int(latencies[idx]) if latencies else 0,
            "last_error": last_error or "n/a",
            "auth_open": auth_open,
        }
