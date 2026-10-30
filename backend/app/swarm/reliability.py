"""Reliability Prober: uptime, latency, error rate, cost efficiency.

Live probe results are CONFIRMED; the absence of a mechanism in code or prompt is INFERRED.
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
                    "No live endpoint supplied",
                    "Uptime, latency and success rate could not be measured; this dimension rests "
                    "only on static signals.",
                    remediation="Register an MCP/A2A/HTTP endpoint for continuous monitoring and a "
                    "full reliability score.",
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.5,
                )
            )
            findings += self._static_reliability(artifact)
            return findings, scenarios, "No endpoint; only static signals were assessed."

        stats = await self._probe(
            artifact.endpoint_url, PROBE_COUNT_DEEP if deep else PROBE_COUNT_BASIC
        )
        success_rate = stats["success"] / max(stats["total"], 1)

        scenarios += [
            ScenarioResult(
                scenario_id="R-01",
                name="Endpoint reachable",
                passed=stats["success"] > 0,
                reason=f"{stats['success']}/{stats['total']} requests succeeded",
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
                    "Endpoint not responding",
                    f"None of {stats['total']} attempts succeeded. "
                    f"Last error: {stats['last_error']}",
                    remediation="Bring the service up and add a health-check endpoint.",
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.95,
                )
            )
        elif success_rate < 0.8:
            findings.append(
                self.finding(
                    "flaky-endpoint",
                    Severity.MEDIUM,
                    "Endpoint unstable",
                    f"Success rate is {success_rate * 100:.0f}%. An unstable service lowers delivery "
                    "reliability.",
                    remediation="Add retries, a circuit breaker and capacity scaling.",
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.9,
                )
            )

        if stats["success"] and stats["p95_ms"] > 8000:
            findings.append(
                self.finding(
                    "high-latency",
                    Severity.MEDIUM,
                    "High latency",
                    f"p95 latency is {stats['p95_ms']}ms. The agent's response time "
                    "degrades the user experience before ledger confirmation.",
                    remediation="Parallelise model calls and add caching and streaming.",
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.9,
                )
            )

        if stats["auth_open"]:
            findings.append(
                self.finding(
                    "unauthenticated-endpoint",
                    Severity.HIGH,
                    "Unauthenticated endpoint",
                    "The endpoint accepts requests without authentication. Anyone can use the agent; "
                    "there is a risk of cost abuse and unauthorized transactions.",
                    evidence="probe: 2xx response without credentials",
                    remediation="Require authentication with an API key or an agent wallet "
                    "signature.",
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.9,
                )
            )

        findings += self._static_reliability(artifact)
        notes = (
            f"{stats['total']} probes → {success_rate * 100:.0f}% success, "
            f"average {stats['avg_ms']}ms, p95 {stats['p95_ms']}ms."
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
                    "No visible error handling",
                    "There is no error-handling or retry signal in the code or prompt.",
                    remediation="Define error classes and add retries with backoff.",
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
                    "No cost or rate control",
                    "No mechanism that bounds token or gas cost was found.",
                    remediation="Define caching, a rate limit and a token budget.",
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
                    success += 1  # service is up and requires authentication
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
