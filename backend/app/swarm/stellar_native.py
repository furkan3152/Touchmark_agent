"""Stellar/Soroban'a özgü agent ve entegrasyon denetçisi."""

from __future__ import annotations

import re

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, ScenarioResult, Severity
from .base import BaseAuditor


class StellarNativeAuditor(BaseAuditor):
    name = "stellar-native-auditor"
    dimension = Dimension.STELLAR_NATIVE

    async def analyse(
        self, artifact: AgentArtifact, deep: bool
    ) -> tuple[list[Finding], list[ScenarioResult], str]:
        findings: list[Finding] = []
        surface = artifact.text_surface()
        rust = "\n".join(
            content for name, content in artifact.code_files.items() if name.endswith(".rs")
        )
        lower = surface.lower()

        if re.search(r"\bS[A-Z2-7]{55}\b", surface):
            findings.append(
                self.finding(
                    "stellar-secret-seed",
                    Severity.CRITICAL,
                    "Stellar secret seed kaynakta görünüyor",
                    "S... secret seed doğrudan kod/manifest yüzeyinde bulundu.",
                    remediation="Seed'i derhal döndürün; haricî signer/HSM kullanın ve geçmişten temizleyin.",
                    confidence=0.99,
                )
            )

        mutating = bool(re.search(r"pub\s+fn\s+(?:set|reg|upd|fund|submit|complete|refund)", rust))
        if mutating and "require_auth" not in rust:
            findings.append(
                self.finding(
                    "soroban-auth-missing",
                    Severity.CRITICAL,
                    "Soroban yazma işlevlerinde require_auth kanıtı yok",
                    "Durum değiştiren entrypoint'ler bulundu ancak Address.require_auth görünmüyor.",
                    remediation="Her rolü state'ten okuyun, eşleştirin ve ilgili Address için require_auth çağırın.",
                    confidence=0.94,
                )
            )

        if "storage().persistent()" in rust and "extend_ttl" not in rust:
            findings.append(
                self.finding(
                    "persistent-ttl",
                    Severity.HIGH,
                    "Persistent state TTL yenilemesi görünmüyor",
                    "Agent/validation state arşivlenebilir; uygulama state'i kalıcı sanabilir.",
                    remediation="Okuma/yazma yollarında kontrollü extend_ttl politikası ve arşiv geri-yükleme testi ekleyin.",
                    confidence=0.9,
                )
            )

        if "storage().temporary()" in rust and re.search(r"agent|valid|escrow|balance", lower):
            findings.append(
                self.finding(
                    "temporary-critical-state",
                    Severity.HIGH,
                    "Kritik kayıt temporary storage kullanıyor olabilir",
                    "Agent, validation veya escrow state'i süresi dolduğunda silinebilir.",
                    remediation="Kritik kayıtları persistent storage'a taşıyın; temporary yalnız cache/idempotency penceresi olsun.",
                    confidence=0.82,
                )
            )

        if "getevents" in lower and not re.search(r"cursor|pagingtoken|sqlite|dedup|unique", lower):
            findings.append(
                self.finding(
                    "event-cursor-missing",
                    Severity.HIGH,
                    "Soroban event ingestion cursor/dedup kanıtı yok",
                    "RPC event geçmişi kalıcı indeks değildir; restart veya retention boşluğu kayıt kaybettirebilir.",
                    remediation="Cursor'u dayanıklı DB'de tutun, event ID'yi unique yapın ve boşluk alarmı ekleyin.",
                    grade=EvidenceGrade.INFERRED,
                    confidence=0.86,
                )
            )

        if "contract account" in lower or re.search(r"\bC[A-Z2-7]{55}\b", surface):
            if "sep-45" not in lower and "sep45" not in lower:
                findings.append(
                    self.finding(
                        "sep45-boundary",
                        Severity.MEDIUM,
                        "C-account auth için SEP-45 sınırı görünmüyor",
                        "Raw Ed25519 veya SEP-10, contract account sahipliğini tek başına kanıtlamaz.",
                        remediation="C-account oturumlarında SEP-45 challenge/authorize akışı kullanın.",
                        grade=EvidenceGrade.INFERRED,
                        confidence=0.8,
                    )
                )

        if "sep-24" in lower and "payout" in lower and "sep-31" not in lower:
            findings.append(
                self.finding(
                    "sep24-payout-confusion",
                    Severity.HIGH,
                    "SEP-24 kullanıcı çekimi, üçüncü taraf payout gibi kullanılıyor olabilir",
                    "Recipient payout için SEP-31 sınırı görünmüyor.",
                    remediation="Kullanıcının kendi withdrawal akışını SEP-24, alıcı payout'unu SEP-31 ile ayırın.",
                    confidence=0.84,
                )
            )

        if re.search(r"tx[_ -]?hash.*(?:success|complete|confirmed)", lower):
            findings.append(
                self.finding(
                    "hash-is-not-confirmation",
                    Severity.HIGH,
                    "Transaction hash başarı kanıtı sayılıyor olabilir",
                    "Hash üretimi/yayın, ledger inclusion ve beklenen contract state/event anlamına gelmez.",
                    remediation="getTransaction sonucu, success status ve contract state/event readback birlikte doğrulansın.",
                    grade=EvidenceGrade.INFERRED,
                    confidence=0.78,
                )
            )

        scenarios = [
            ScenarioResult(
                scenario_id="ST-001",
                name="Soroban role auth",
                passed=not mutating or "require_auth" in rust,
                reason="Durum değiştiren fonksiyonlarda require_auth aranır.",
            ),
            ScenarioResult(
                scenario_id="ST-002",
                name="Persistent TTL",
                passed="storage().persistent()" not in rust or "extend_ttl" in rust,
                reason="Arşivlenebilir state için TTL politikası aranır.",
            ),
            ScenarioResult(
                scenario_id="ST-003",
                name="Event durability",
                passed="getevents" not in lower
                or bool(re.search(r"cursor|pagingtoken|sqlite|dedup|unique", lower)),
                reason="RPC retention yerine durable cursor/dedup aranır.",
            ),
        ]
        if deep:
            scenarios.append(
                ScenarioResult(
                    scenario_id="ST-004",
                    name="Contract-account web auth",
                    passed="contract account" not in lower
                    or "sep-45" in lower
                    or "sep45" in lower,
                    reason="C-account desteği ilan ediliyorsa SEP-45 aranır.",
                )
            )
        source = artifact.onchain.data_source
        return findings, scenarios, f"Stellar/Soroban yüzeyi denetlendi; onchain kaynak={source}."
