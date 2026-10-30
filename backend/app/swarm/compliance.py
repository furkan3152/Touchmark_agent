"""Compliance Checker: EU AI Act mapping, transparency, KYA, wallet screening."""

from __future__ import annotations

import httpx

from ..compliance.ofac import OfacSanctionsList
from ..config import Settings
from ..models import (
    AgentArtifact,
    Dimension,
    EvidenceGrade,
    Finding,
    ScenarioResult,
    Severity,
)
from .base import BaseAuditor
from .capabilities import oversight_enforced
from .llm import LlmClient


# EU AI Act high-risk signals (approximate mapping to Annex III)
HIGH_RISK_DOMAINS = {
    "payments": "Access to financial services and credit or payment decisions",
    "defi_trading": "Automated financial transactions (affecting consumer assets)",
    "defi_yield": "Financial asset management",
    "credit": "Credit assessment",
    "hiring": "Employment decisions",
    "identity": "Biometric or identity assessment",
}

PII_SIGNALS = ("email", "phone", "passport", "ssn", "kimlik", "address book", "personal data")


class ComplianceAuditor(BaseAuditor):
    name = "compliance-checker"
    dimension = Dimension.COMPLIANCE

    def __init__(self, settings: Settings, llm: LlmClient | None = None) -> None:
        super().__init__(settings, llm)

    async def analyse(
        self, artifact: AgentArtifact, deep: bool
    ) -> tuple[list[Finding], list[ScenarioResult], str]:
        findings: list[Finding] = []
        scenarios: list[ScenarioResult] = []
        prompt_l = (artifact.system_prompt or "").lower()
        surface = artifact.text_surface().lower()

        # ---- 1) high-risk classification
        high_risk = HIGH_RISK_DOMAINS.get(artifact.domain)
        moves_funds = any(t.requires_signature for t in artifact.tools)
        if not high_risk and moves_funds:
            high_risk = "Autonomous transaction authority over user funds"

        if high_risk:
            scenarios.append(
                ScenarioResult(
                    scenario_id="C-01",
                    name="High-risk classification",
                    passed=True,
                    reason=f"classified as high risk: {high_risk}",
                )
            )
            # high risk requires human oversight
            oversight = oversight_enforced(artifact, prompt_l)
            scenarios.append(
                ScenarioResult(
                    scenario_id="C-02",
                    name="Human oversight (EU AI Act Art. 14)",
                    passed=oversight,
                    reason="oversight mechanism present" if oversight else "no oversight or escalation defined",
                )
            )
            if not oversight:
                findings.append(
                    self.finding(
                        "no-human-oversight",
                        Severity.HIGH,
                        "High-risk agent has no human oversight",
                        f"The agent counts as high risk under '{high_risk}', but no human "
                        "oversight, escalation or kill switch was found.",
                        remediation="Add human approval for transactions above a threshold, an emergency "
                        "stop and operator notification.",
                        references=["EU AI Act Art. 14 (human oversight)"],
                        grade=EvidenceGrade.CONFIRMED,
                        confidence=0.85,
                    )
                )


        # ---- 2) transparency
        transparent = artifact.discloses_ai or any(
            k in surface for k in ("ai agent", "autonomous agent", "i am an ai", "automated")
        )
        scenarios.append(
            ScenarioResult(
                scenario_id="C-03",
                name="Transparency (EU AI Act Art. 50)",
                passed=transparent,
                reason="AI identity disclosed" if transparent else "does not disclose that it is an AI",
            )
        )
        if not transparent:
            findings.append(
                self.finding(
                    "no-ai-disclosure",
                    Severity.MEDIUM,
                    "AI identity not disclosed",
                    "The agent does not tell the other party that it is an automated system.",
                    remediation="State clearly at the start of an interaction that this is an AI agent.",
                    references=["EU AI Act Art. 50 (transparency)"],
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.85,
                )
            )


        # ---- 3) owner verification (KYA)
        scenarios.append(
            ScenarioResult(
                scenario_id="C-04",
                name="Agent owner verification (KYA)",
                passed=artifact.owner_verified,
                reason=artifact.owner_verification_note,
            )
        )
        if not artifact.owner_verified:
            # Presenting an invalid signature is worse than presenting none: there is an
            # ownership claim, but it is cryptographically refuted.
            mismatch = "does not match" in artifact.owner_verification_note
            findings.append(
                self.finding(
                    "owner-unverified",
                    Severity.HIGH
                    if mismatch or not artifact.owner
                    else Severity.MEDIUM,
                    "Ownership signature is invalid"
                    if mismatch
                    else "Agent owner not verified",
                    (
                        "The supplied Stellar ownership signature does not belong to the declared account. "
                        "The chain of accountability is not just missing but contradictory."
                        if mismatch
                        else "No chain of accountability: the legal or natural person behind the agent "
                        "is not verified by a signature."
                    ),
                    evidence=artifact.owner_verification_note,
                    remediation="Supply an Ed25519 challenge signature for a G-account, or SEP-45 "
                    "challenge/authorize evidence for a C-account.",
                    references=["KYA — Know Your Agent"],
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.9,
                )
            )



        # ---- 4) record keeping / traceability
        logging_ok = any(k in surface for k in ("log", "audit trail", "record", "trace", "receipt"))
        scenarios.append(
            ScenarioResult(
                scenario_id="C-05",
                name="Record keeping (Art. 12)",
                passed=logging_ok,
                reason="logging mechanism present" if logging_ok else "no event log defined",
            )
        )
        if not logging_ok:
            findings.append(
                self.finding(
                    "no-record-keeping",
                    Severity.MEDIUM,
                    "No automatic record keeping",
                    "No traceable record of decisions and transactions is defined; compliance audits and "
                    "reputation checks are impossible.",
                    remediation="Produce a structured log and an on-chain receipt for every action.",
                    references=["EU AI Act Art. 12 (record keeping)"],
                    grade=EvidenceGrade.INFERRED,
                    confidence=0.7,
                )
            )


        # ---- 5) PII / veri minimizasyonu
        pii_hits = [s for s in PII_SIGNALS if s in surface]
        if pii_hits:
            protected = any(k in surface for k in ("redact", "anonym", "minimi", "encrypt", "gdpr"))
            if not protected:
                findings.append(
                    self.finding(
                        "pii-without-safeguards",
                        Severity.HIGH,
                        "PII processing without safeguards",
                        "Personal-data signals were found but there is no masking, minimization or "
                        "encryption rule: " + ", ".join(pii_hits),
                        remediation="Add data minimization, masking, encrypted storage and a "
                        "retention and deletion policy.",
                        references=["GDPR Art. 5", "EU AI Act Art. 10"],
                        grade=EvidenceGrade.INFERRED,
                        confidence=0.7,
                    )
                )

        # ---- 6) wallet screening (Elliptic/TRM adapter)
        if artifact.agent_wallet:
            screen = await self._screen_wallet(artifact.agent_wallet)
            provider_live = screen["provider"] in ("elliptic", "trm", "chainalysis", "ofac")
            # A real provider response is confirmed evidence; without screening no claim is made.
            screen_grade = (
                EvidenceGrade.CONFIRMED if provider_live else EvidenceGrade.INFERRED
            )
            if screen["risk"] == "unknown":
                # Coverage gap. There are two distinct cases and telling them apart matters:
                # (a) The OFAC list was screened with no match → indirect exposure could not
                #     be analysed, but the sanctions check WAS done.
                # (b) No source at all → no check was done.
                # Reporting both with the same text would make (b) look better than it is.
                ofac_done = bool(screen.get("ofac_checked"))
                if ofac_done:
                    detail = (
                        f"The address is not on the OFAC SDN sanctions list ({screen.get('ofac_total', 0)} "
                        "crypto addresses). Indirect exposure (mixer proximity, counterparty "
                        "risk) could not be analysed; that needs a commercial AML "
                        "provider. This is not a clean result but partial coverage."
                    )
                    remediation = (
                        "For full coverage set SCREENING_PROVIDER=chainalysis|trm|elliptic "
                        "and SCREENING_API_KEY."
                    )
                else:
                    detail = (
                        "No sanctions or AML source was available (no OFAC cache and "
                        "no commercial provider configured). This is not a clean result but "
                        "a check that was out of scope."
                    )
                    remediation = (
                        "Download the free OFAC list with `python -m backend.cli sanctions --refresh` "
                        "or set SCREENING_API_KEY."
                    )
                findings.append(
                    self.finding(
                        "wallet-screening-unavailable",
                        Severity.LOW,
                        "Wallet risk screening is partial"
                        if ofac_done
                        else "Wallet risk screening was not performed",
                        detail,
                        evidence=(
                            f"screening_provider={screen.get('provider', 'none')}; "
                            f"ofac_checked={ofac_done}; "
                            f"ofac_total={screen.get('ofac_total', 0)}"
                        ),
                        remediation=remediation,
                        references=["AML/CFT screening", "OFAC SDN"],
                        grade=EvidenceGrade.CONFIRMED,
                        confidence=0.9,
                    )
                )
            else:
                scenarios.append(
                    ScenarioResult(
                        scenario_id="C-06",
                        name="Wallet risk screening",
                        passed=screen["risk"] not in ("high", "severe"),
                        reason=f"{screen['provider']} → risk={screen['risk']}",
                    )
                )
            if screen["risk"] in ("high", "severe"):
                findings.append(
                    self.finding(
                        "wallet-screening-hit",
                        Severity.CRITICAL,
                        "High risk in wallet screening",
                        f"{screen['provider']} screening flagged the wallet as '{screen['risk']}'. "
                        f"Categories: {', '.join(screen.get('categories', [])) or 'n/a'}",
                        remediation="Explain the source of funds and open a review with the compliance team.",
                        references=["AML/CFT screening"],
                        grade=screen_grade,
                    )
                )
            elif screen["risk"] == "medium":
                findings.append(
                    self.finding(
                        "wallet-screening-medium",
                        Severity.MEDIUM,
                        "Medium risk in wallet screening",
                        f"{screen['provider']} screening reported medium risk.",
                        remediation="Review the counterparty history and increase monitoring frequency.",
                        grade=screen_grade,
                        confidence=0.7,
                    )
                )

            if artifact.onchain.interacted_with_flagged:
                scenarios.append(
                    ScenarioResult(
                        scenario_id="C-07",
                        name="No contact with flagged counterparties",
                        passed=False,
                        reason="has interacted with a flagged address in the past",
                    )
                )

        # ---- 7) privacy modu tavsiyesi
        if not artifact.privacy_mode and (pii_hits or artifact.domain in ("payments", "identity")):
            findings.append(
                self.finding(
                    "privacy-mode-off",
                    Severity.LOW,
                    "Privacy mode is off",
                    "Encrypted or TEE processing is off for an agent working in a sensitive domain.",
                    remediation="Enable privacy mode, data minimization and encrypted storage.",
                    grade=EvidenceGrade.INFERRED,
                    confidence=0.6,
                )
            )


        passed = sum(1 for s in scenarios if s.passed)
        notes = (
            f"{passed}/{len(scenarios)} compliance checks passed. "
            f"Risk class: {'high' if high_risk else 'limited'}."
        )
        return findings, scenarios, notes

    async def _screen_wallet(self, address: str) -> dict:
        """Elliptic/TRM adapter.

        Without a provider no risk is invented: `risk="unknown"` is returned and the auditor
        reports it as a coverage gap, not a claim. A "risk" derived from the address hash
        could accuse verified contracts of CRITICAL `mixer_proximity`.
        """
        provider = (self.settings.screening_provider or "none").lower()

        if self.settings.screening_enabled:
            try:
                if provider == "chainalysis":
                    return await self._screen_chainalysis(address)
                url = (
                    "https://api.trmlabs.com/public/v1/sanctions/screening"
                    if provider == "trm"
                    else "https://api.elliptic.co/v2/wallet/synchronous"
                )
                async with httpx.AsyncClient(timeout=15.0) as client:
                    resp = await client.post(
                        url,
                        headers={"Authorization": f"Bearer {self.settings.screening_api_key}"},
                        json={"address": address, "chain": "stellar"},
                    )
                    resp.raise_for_status()
                    data = resp.json()
                risk = str(
                    data.get("risk")
                    or data.get("riskScore")
                    or (data[0].get("risk") if isinstance(data, list) and data else "low")
                ).lower()
                normalised = (
                    "severe"
                    if "severe" in risk or "sanction" in risk
                    else "high"
                    if "high" in risk
                    else "medium"
                    if "medium" in risk
                    else "low"
                )
                return {
                    "provider": provider,
                    "risk": normalised,
                    "categories": data.get("categories", []) if isinstance(data, dict) else [],
                }
            except Exception:
                pass  # provider unreachable → counts as not screened

        return await self._screen_ofac(address)

    async def _screen_ofac(self, address: str) -> dict:
        """Screen against the OFAC SDN list when there is no commercial provider (no key needed).

        Makes no network call; only the local cache is read. The list is refreshed with
        `backend.cli sanctions --refresh` or at server start; downloading 5.6 MB in the
        middle of an audit would block it and make the result depend on the network.

        A match returns `severe`: a direct fact from the primary source. No match returns
        `unknown`, not `low`, because OFAC covers only directly listed addresses and
        "not listed" is not the same as "clean".
        """
        if not self.settings.ofac_enabled:
            return {"provider": "unavailable", "risk": "unknown", "categories": []}

        try:
            sanctions = OfacSanctionsList(
                self.settings.data_path, self.settings.ofac_max_age_hours
            )
            result = sanctions.lookup_cached(address)
        except Exception:
            return {"provider": "unavailable", "risk": "unknown", "categories": []}

        if not result.get("available"):
            return {"provider": "unavailable", "risk": "unknown", "categories": []}

        if result["listed"]:
            return {
                "provider": "ofac",
                "risk": "severe",
                "categories": ["ofac_sdn", *(f"chain:{c}" for c in result["chains"])],
                "stale": result.get("stale", False),
            }

        return {
            "provider": "ofac",
            "risk": "unknown",
            "categories": [],
            "ofac_checked": True,
            "ofac_total": result.get("total_addresses", 0),
            "stale": result.get("stale", False),
        }

    async def _screen_chainalysis(self, address: str) -> dict:
        """Chainalysis free Sanctions Screening API.

        Works differently from the other providers: it returns no risk score, only whether
        the address is on a sanctions list (OFAC/EU/UN). So a non-empty `identifications`
        maps to `severe` and an empty one to `low`. No match means "not on a sanctions
        list", not "clean".
        """
        url = f"https://public.chainalysis.com/api/v1/address/{address}"
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(
                url,
                headers={
                    "X-API-Key": self.settings.screening_api_key,
                    "Accept": "application/json",
                },
            )
            resp.raise_for_status()
            data = resp.json()

        hits = data.get("identifications") or []
        categories = sorted(
            {
                str(h.get("category") or h.get("name") or "sanctioned")
                for h in hits
                if isinstance(h, dict)
            }
        )
        return {
            "provider": "chainalysis",
            "risk": "severe" if hits else "low",
            "categories": categories,
        }
