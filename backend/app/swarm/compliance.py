"""Compliance Checker — EU AI Act eşlemesi, şeffaflık, KYA, cüzdan taraması."""

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
from .llm import LlmClient


# EU AI Act yüksek-risk sinyalleri (Annex III'e yaklaşık eşleme)
HIGH_RISK_DOMAINS = {
    "payments": "Finansal hizmet erişimi ve kredi/ödeme kararları",
    "defi_trading": "Finansal işlem otomasyonu (tüketici varlıkları üzerinde etki)",
    "defi_yield": "Finansal varlık yönetimi",
    "credit": "Kredi değerlendirmesi",
    "hiring": "İstihdam kararları",
    "identity": "Biyometrik/kimlik değerlendirmesi",
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

        # ---- 1) yüksek risk sınıflandırması
        high_risk = HIGH_RISK_DOMAINS.get(artifact.domain)
        moves_funds = any(t.requires_signature for t in artifact.tools)
        if not high_risk and moves_funds:
            high_risk = "Kullanıcı fonları üzerinde otonom işlem yetkisi"

        if high_risk:
            scenarios.append(
                ScenarioResult(
                    scenario_id="C-01",
                    name="Yüksek-risk sınıflandırması",
                    passed=True,
                    reason=f"yüksek risk olarak sınıflandırıldı: {high_risk}",
                )
            )
            # yüksek risk ise insan gözetimi zorunlu
            oversight = artifact.human_oversight or any(
                k in prompt_l for k in ("human", "confirm", "approval", "escalate", "operator")
            )
            scenarios.append(
                ScenarioResult(
                    scenario_id="C-02",
                    name="İnsan gözetimi (EU AI Act Art. 14)",
                    passed=oversight,
                    reason="gözetim mekanizması var" if oversight else "gözetim/eskalasyon tanımı yok",
                )
            )
            if not oversight:
                findings.append(
                    self.finding(
                        "no-human-oversight",
                        Severity.HIGH,
                        "Yüksek riskli agent'ta insan gözetimi yok",
                        f"Agent '{high_risk}' kapsamında yüksek riskli sayılır ancak insan "
                        "gözetimi, eskalasyon veya devre kesici (kill switch) tanımı bulunamadı.",
                        remediation="Eşik üstü işlemler için insan onayı, acil durdurma ve "
                        "operatör bildirimi ekleyin.",
                        references=["EU AI Act Art. 14 (human oversight)"],
                        grade=EvidenceGrade.CONFIRMED,
                        confidence=0.85,
                    )
                )


        # ---- 2) şeffaflık
        transparent = artifact.discloses_ai or any(
            k in surface for k in ("ai agent", "autonomous agent", "i am an ai", "automated")
        )
        scenarios.append(
            ScenarioResult(
                scenario_id="C-03",
                name="Şeffaflık (EU AI Act Art. 50)",
                passed=transparent,
                reason="AI kimliği açıklanıyor" if transparent else "AI olduğu bildirilmiyor",
            )
        )
        if not transparent:
            findings.append(
                self.finding(
                    "no-ai-disclosure",
                    Severity.MEDIUM,
                    "AI kimliği açıklanmıyor",
                    "Agent karşı tarafa otomatik bir sistem olduğunu bildirmiyor.",
                    remediation="Etkileşim başında AI agent olduğunu açıkça bildirin.",
                    references=["EU AI Act Art. 50 (transparency)"],
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.85,
                )
            )


        # ---- 3) sahip doğrulaması (KYA)
        scenarios.append(
            ScenarioResult(
                scenario_id="C-04",
                name="Agent sahibi doğrulaması (KYA)",
                passed=artifact.owner_verified,
                reason=artifact.owner_verification_note,
            )
        )
        if not artifact.owner_verified:
            # Geçersiz imza sunmak, hiç sunmamaktan daha ağırdır: sahiplik
            # iddiası var ama kriptografik olarak çürütülmüş.
            mismatch = "uyuşmuyor" in artifact.owner_verification_note
            findings.append(
                self.finding(
                    "owner-unverified",
                    Severity.HIGH
                    if mismatch or not artifact.owner
                    else Severity.MEDIUM,
                    "Sahiplik imzası geçersiz"
                    if mismatch
                    else "Agent sahibi doğrulanmamış",
                    (
                        "Sunulan Stellar sahiplik imzası beyan edilen hesaba ait değil. "
                        "Sorumluluk zinciri yalnızca eksik değil, çelişkili."
                        if mismatch
                        else "Sorumluluk zinciri kurulamıyor: agent'ın arkasındaki tüzel/gerçek "
                        "kişi imza ile doğrulanmamış."
                    ),
                    evidence=artifact.owner_verification_note,
                    remediation="G-account için Ed25519 challenge imzası, C-account için SEP-45 "
                    "challenge/authorize kanıtı sunun.",
                    references=["KYA — Know Your Agent"],
                    grade=EvidenceGrade.CONFIRMED,
                    confidence=0.9,
                )
            )



        # ---- 4) kayıt tutma / izlenebilirlik
        logging_ok = any(k in surface for k in ("log", "audit trail", "record", "trace", "receipt"))
        scenarios.append(
            ScenarioResult(
                scenario_id="C-05",
                name="Kayıt tutma (Art. 12)",
                passed=logging_ok,
                reason="kayıt mekanizması var" if logging_ok else "olay kaydı tanımsız",
            )
        )
        if not logging_ok:
            findings.append(
                self.finding(
                    "no-record-keeping",
                    Severity.MEDIUM,
                    "Otomatik kayıt tutma yok",
                    "Kararların ve işlemlerin izlenebilir kaydı tanımlı değil; uyum denetimi ve "
                    "itibar doğrulaması yapılamaz.",
                    remediation="Her aksiyon için yapılandırılmış log ve zincir üstü makbuz üretin.",
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
                        "Koruma önlemi olmadan PII işleme",
                        "Kişisel veri sinyalleri bulundu ancak maskeleme/minimizasyon/şifreleme "
                        "kuralı yok: " + ", ".join(pii_hits),
                        remediation="Veri minimizasyonu, maskeleme, şifreli saklama ve silme "
                        "süresi politikası ekleyin.",
                        references=["GDPR Art. 5", "EU AI Act Art. 10"],
                        grade=EvidenceGrade.INFERRED,
                        confidence=0.7,
                    )
                )

        # ---- 6) cüzdan taraması (Elliptic/TRM adaptörü)
        if artifact.agent_wallet:
            screen = await self._screen_wallet(artifact.agent_wallet)
            provider_live = screen["provider"] in ("elliptic", "trm", "chainalysis", "ofac")
            # Gerçek sağlayıcı yanıtı doğrulanmış kanıttır; tarama yoksa iddia üretilmez.
            screen_grade = (
                EvidenceGrade.CONFIRMED if provider_live else EvidenceGrade.INFERRED
            )
            if screen["risk"] == "unknown":
                # Kapsam boşluğu. İki ayrı durum var ve ayırt etmek önemli:
                # (a) OFAC listesi tarandı, eşleşme yok → dolaylı maruziyet
                #     analizi yapılamadı ama yaptırım kontrolü YAPILDI.
                # (b) Hiçbir kaynak yok → hiçbir kontrol yapılmadı.
                # İkisini aynı metinle raporlamak (b)'yi olduğundan iyi gösterir.
                ofac_done = bool(screen.get("ofac_checked"))
                if ofac_done:
                    detail = (
                        f"Adres OFAC SDN yaptırım listesinde ({screen.get('ofac_total', 0)} "
                        "kripto adresi) bulunamadı. Ancak dolaylı maruziyet (mixer yakınlığı, "
                        "karşı taraf riski) analiz edilemedi; bunun için ticari bir AML "
                        "sağlayıcısı gerekir. Bu bir temiz sonuç değil, kısmi kapsamdır."
                    )
                    remediation = (
                        "Tam kapsam için SCREENING_PROVIDER=chainalysis|trm|elliptic "
                        "ve SCREENING_API_KEY tanımlayın."
                    )
                else:
                    detail = (
                        "Hiçbir yaptırım/AML kaynağı kullanılamadı (OFAC önbelleği yok ve "
                        "ticari sağlayıcı yapılandırılmadı). Bu bir temiz sonuç değil, "
                        "kapsam dışı kalan bir kontroldür."
                    )
                    remediation = (
                        "`python -m backend.cli sanctions --refresh` ile ücretsiz OFAC "
                        "listesini indirin veya SCREENING_API_KEY tanımlayın."
                    )
                findings.append(
                    self.finding(
                        "wallet-screening-unavailable",
                        Severity.LOW,
                        "Cüzdan risk taraması kısmi"
                        if ofac_done
                        else "Cüzdan risk taraması yapılmadı",
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
                        name="Cüzdan risk taraması",
                        passed=screen["risk"] not in ("high", "severe"),
                        reason=f"{screen['provider']} → risk={screen['risk']}",
                    )
                )
            if screen["risk"] in ("high", "severe"):
                findings.append(
                    self.finding(
                        "wallet-screening-hit",
                        Severity.CRITICAL,
                        "Cüzdan taramasında yüksek risk",
                        f"{screen['provider']} taraması cüzdanı '{screen['risk']}' olarak "
                        f"işaretledi. Kategoriler: {', '.join(screen.get('categories', [])) or 'n/a'}",
                        remediation="Fon kaynağını açıklayın; uyum ekibiyle inceleme başlatın.",
                        references=["AML/CFT screening"],
                        grade=screen_grade,
                    )
                )
            elif screen["risk"] == "medium":
                findings.append(
                    self.finding(
                        "wallet-screening-medium",
                        Severity.MEDIUM,
                        "Cüzdan taramasında orta risk",
                        f"{screen['provider']} taraması orta seviye risk bildirdi.",
                        remediation="Karşı taraf geçmişini gözden geçirin ve izleme sıklığını artırın.",
                        grade=screen_grade,
                        confidence=0.7,
                    )
                )

            if artifact.onchain.interacted_with_flagged:
                scenarios.append(
                    ScenarioResult(
                        scenario_id="C-07",
                        name="İşaretli karşı taraf teması yok",
                        passed=False,
                        reason="geçmişte işaretli adresle etkileşim var",
                    )
                )

        # ---- 7) privacy modu tavsiyesi
        if not artifact.privacy_mode and (pii_hits or artifact.domain in ("payments", "identity")):
            findings.append(
                self.finding(
                    "privacy-mode-off",
                    Severity.LOW,
                    "Gizlilik modu kapalı",
                    "Hassas alanda çalışan agent için şifreli/TEE işleme kapalı.",
                    remediation="Privacy mode, veri minimizasyonu ve şifreli saklamayı etkinleştirin.",
                    grade=EvidenceGrade.INFERRED,
                    confidence=0.6,
                )
            )


        passed = sum(1 for s in scenarios if s.passed)
        notes = (
            f"{passed}/{len(scenarios)} uyum kontrolü geçti. "
            f"Risk sınıfı: {'yüksek' if high_risk else 'sınırlı'}."
        )
        return findings, scenarios, notes

    async def _screen_wallet(self, address: str) -> dict:
        """Elliptic/TRM adaptörü.

        **Sağlayıcı yoksa risk uydurulmaz.** Eskiden adresin sha256'sından
        deterministik bir "risk" türetiliyordu; bu, doğrulanmış kontratları
        CRITICAL `mixer_proximity` ile suçlayabiliyordu — saf
        yanlış pozitif. Artık sağlayıcı yoksa `risk="unknown"` dönülür ve denetçi
        bunu bir iddia değil, *kapsam boşluğu* olarak raporlar.
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
                pass  # sağlayıcı erişilemedi → tarama yapılmamış sayılır

        return await self._screen_ofac(address)

    async def _screen_ofac(self, address: str) -> dict:
        """Ticari sağlayıcı yoksa OFAC SDN listesiyle tarar (anahtar gerektirmez).

        **Ağa çıkmaz**: yalnızca yerel önbelleği okur. Liste `backend.cli sanctions
        --refresh` ile veya sunucu açılışında güncellenir; denetimin ortasında
        5.6 MB indirmek denetimi bloklar ve sonucu ağ durumuna bağımlı kılar.

        Eşleşme varsa `severe` — bu birincil kaynaktan doğrudan bir olgudur.
        Eşleşme yoksa **`low` değil `unknown`** döner: OFAC yalnızca doğrudan
        listelenmiş adresleri kapsar, dolaylı maruziyet analizi yapmaz. "Listede
        yok" ile "temiz" aynı şey olmadığı için burada iddia üretmiyoruz.
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
        """Chainalysis ücretsiz Sanctions Screening API'si.

        Diğer sağlayıcılardan farklı çalışır: risk skoru döndürmez, yalnızca adresin
        bir yaptırım listesinde (OFAC/EU/UN) olup olmadığını söyler. Bu yüzden
        `identifications` doluysa **severe**, boşsa **low** olarak eşlenir — arada
        gri bölge yoktur. Bu netlik yanlış pozitif riskini sıfırlar: eşleşme yoksa
        "temiz" değil, "yaptırım listesinde değil" demektir.
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
