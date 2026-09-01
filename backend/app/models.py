"""Domain modelleri: normalize edilmiş agent artifact, bulgular, denetim raporu, job."""

from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


# --------------------------------------------------------------------------- enums
class SourceKind(str, Enum):
    ONCHAIN_ADDRESS = "onchain_address"
    REPO = "repo"
    ENDPOINT = "endpoint"
    WIZARD = "wizard"
    UPLOAD = "upload"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def weight(self) -> float:
        return {
            "critical": 30.0,
            "high": 14.0,
            "medium": 6.0,
            "low": 2.0,
            "info": 0.0,
        }[self.value]

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]

    def downgrade(self, steps: int = 1) -> "Severity":
        """Kanıt gücü zayıfsa ciddiyeti kademe kademe indirir."""
        order = [
            Severity.INFO,
            Severity.LOW,
            Severity.MEDIUM,
            Severity.HIGH,
            Severity.CRITICAL,
        ]
        return order[max(0, self.rank - steps)]


class EvidenceGrade(str, Enum):
    """Bulgunun kanıt gücü. Skor cezası ve badge tavanı buna göre ölçeklenir.

    Bu ayrım kritik: "kodda gömülü özel anahtar" doğrudan kanıttır, ama
    "prompt'ta savunma cümlesi yok" yalnızca bir çıkarımdır. İkisini aynı
    ağırlıkta cezalandırmak yanlış pozitif üretir.
    """

    CONFIRMED = "confirmed"  # doğrudan kanıt: kod eşleşmesi, canlı probe, açık config
    INFERRED = "inferred"  # savunma kanıtının yokluğu (statik çıkarım)
    SIMULATED = "simulated"  # gerçek indexer yok, türetilmiş zincir verisi

    @property
    def penalty_multiplier(self) -> float:
        return {"confirmed": 1.0, "inferred": 0.6, "simulated": 0.35}[self.value]

    @property
    def blocks_badge(self) -> bool:
        """Yalnızca doğrulanmış kanıt badge tavanını zorlar."""
        return self is EvidenceGrade.CONFIRMED


class AssuranceLevel(str, Enum):
    """Rapor girdilerinin Stellar kimlik ve ledger verisine bağlılık seviyesi."""

    VERIFIED = "verified"
    PARTIAL = "partial"
    SIMULATED = "simulated"


class Dimension(str, Enum):
    INTENT = "intent"
    SECURITY = "security"
    ECONOMIC = "economic"
    COMPLIANCE = "compliance"
    RELIABILITY = "reliability"
    #: Stellar'a özgü riskler: Soroban auth, TTL, events, trustlines, SEP sınırları.
    STELLAR_NATIVE = "stellar_native"
    #: Kaynak, bağımlılık, build ve release izlenebilirliği.
    PROVENANCE = "provenance"


DIMENSION_WEIGHTS: dict[Dimension, float] = {
    Dimension.INTENT: 0.18,
    Dimension.SECURITY: 0.24,
    Dimension.ECONOMIC: 0.14,
    Dimension.COMPLIANCE: 0.11,
    Dimension.RELIABILITY: 0.09,
    Dimension.STELLAR_NATIVE: 0.10,
    Dimension.PROVENANCE: 0.14,
}


class Badge(str, Enum):
    SAFE = "SAFE"
    CAUTION = "CAUTION"
    HIGH_RISK = "HIGH_RISK"
    BLOCKLIST = "BLOCKLIST"


class JobState(str, Enum):
    CREATED = "created"
    AWAITING_SIGNATURE = "awaiting_signature"
    FUNDED = "funded"
    RUNNING = "running"
    DELIVERED = "delivered"
    SETTLED = "settled"
    COMPLETED = "completed"
    REFUNDED = "refunded"
    INDETERMINATE = "indeterminate"
    FAILED = "failed"


class AuditTier(str, Enum):
    BASIC = "basic"
    DEEP = "deep"


# --------------------------------------------------------------------------- artifact
class ToolSpec(BaseModel):
    name: str
    description: str = ""
    # yetki sinyalleri
    scopes: list[str] = Field(default_factory=list)
    requires_signature: bool = False
    spend_limit_usdc: float | None = None
    network_access: bool = False


class OnchainActivity(BaseModel):
    """Ajanın Stellar account/contract davranış özeti.

    `data_source` bulgunun kanıt gücünü belirler:
      - "indexer"   : davranış alanlarını gerçekten hesaplayan kalıcı indexer
      - "horizon_account": yalnız account/balance kaydı; davranış kanıtı değildir
      - "rpc"       : belirli Soroban state/event readback'i
      - "simulated" : RPC yok, deterministik türetilmiş veri → ciddiyet bir kademe düşer
      - "none"      : veri yok, ekonomik boyut denetlenemez
    """

    address: str = ""
    data_source: str = "none"

    #: Stellar account'taki XLM ve varsa USDC güven hattı bakiyesi.
    balance_xlm: float | None = None
    balance_usdc: float | None = None
    fee_runway_txs: int | None = None  # yalnız ölçüldüyse; varsayım üretilmez
    is_contract: bool | None = None

    tx_count: int = 0

    unique_counterparties: int = 0
    top_counterparty_share: float = 0.0  # 0..1 konsantrasyon
    total_outflow_usdc: float = 0.0
    largest_single_outflow_usdc: float = 0.0
    failed_tx_ratio: float = 0.0
    avg_slippage_bps: float = 0.0
    unbounded_trustlines: int = 0
    interacted_with_flagged: bool = False
    first_seen_days: int = 0
    night_activity_ratio: float = 0.0  # ani/otomatik davranış sinyali


class AgentArtifact(BaseModel):
    """Tüm yükleme yollarının normalize edildiği tek gösterim."""

    id: str = Field(default_factory=lambda: f"agent_{uuid.uuid4().hex[:12]}")
    created_at: float = Field(default_factory=time.time)

    source_kind: SourceKind
    source_ref: str = ""

    name: str = "unnamed-agent"
    description: str = ""
    declared_capabilities: list[str] = Field(default_factory=list)
    system_prompt: str = ""
    tools: list[ToolSpec] = Field(default_factory=list)
    code_files: dict[str, str] = Field(default_factory=dict)
    dependencies: list[str] = Field(default_factory=list)

    endpoint_url: str = ""
    endpoint_protocol: str = ""  # mcp | a2a | http

    agent_wallet: str = ""
    agent_contract_id: str = ""
    owner: str = ""
    owner_verified: bool = False
    #: Sahiplik doğrulamasının **neden** başarılı/başarısız olduğu. Rapor bunu kanıt
    #: olarak yazar; "imza verilmedi" ile "imza uyuşmuyor" ayırt edilebilir olmalı.
    owner_verification_note: str = "sahiplik imzası verilmedi"


    human_oversight: bool = False
    discloses_ai: bool = False
    privacy_mode: bool = False
    domain: str = "general"

    onchain: OnchainActivity = Field(default_factory=OnchainActivity)
    raw_metadata: dict[str, Any] = Field(default_factory=dict)

    def text_surface(self) -> str:
        """Denetçilerin tarayacağı birleşik metin yüzeyi."""
        parts = [self.name, self.description, self.system_prompt]
        parts += self.declared_capabilities
        parts += [f"{t.name} {t.description} {' '.join(t.scopes)}" for t in self.tools]
        parts += list(self.code_files.values())
        return "\n".join(p for p in parts if p)


# --------------------------------------------------------------------------- findings
class Finding(BaseModel):
    id: str
    dimension: Dimension
    severity: Severity
    title: str
    detail: str
    evidence: str = ""
    evidence_grade: EvidenceGrade = EvidenceGrade.CONFIRMED
    remediation: str = ""
    references: list[str] = Field(default_factory=list)
    auditor: str = ""
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)

    @property
    def penalty(self) -> float:
        """Skordan düşülecek etkin ceza."""
        return self.severity.weight * self.evidence_grade.penalty_multiplier * max(0.4, self.confidence)


class ScenarioResult(BaseModel):

    scenario_id: str
    name: str
    passed: bool
    reason: str = ""
    evidence_grade: EvidenceGrade = EvidenceGrade.INFERRED
    evidence: str = ""


class AuditorVerdict(BaseModel):
    auditor: str
    dimension: Dimension
    score: float  # 0..100
    findings: list[Finding] = Field(default_factory=list)
    scenarios: list[ScenarioResult] = Field(default_factory=list)
    notes: str = ""
    stake_usdc: float = 0.0
    duration_ms: int = 0
    llm_assisted: bool = False
    llm_consulted: bool = False
    rule_set: str = ""
    coverage: dict[str, int] = Field(default_factory=dict)
    status: str = "completed"  # completed | error
    error: str = ""


class DimensionScore(BaseModel):
    dimension: Dimension
    score: float
    weight: float
    weighted: float


class Attestation(BaseModel):
    mode: str  # unavailable | prepared | onchain
    registry_contract_id: str = ""
    request_id: str = ""
    invocation_json: str = ""
    report_hash: str = ""
    tx_hash: str = ""
    ledger: int | None = None
    network: str = ""
    explorer_url: str = ""
    validator_address: str = ""
    confirmed: bool = False
    note: str = ""
    submitted_at: float = Field(default_factory=time.time)


class EscrowRecord(BaseModel):
    job_id: str
    tier: AuditTier
    amount_usdc: float
    funded: bool = False
    funder: str = ""
    platform_fee_usdc: float = 0.0
    swarm_payout_usdc: float = 0.0
    payouts: dict[str, float] = Field(default_factory=dict)
    settled: bool = False
    tx_ref: str = ""
    #: not_required | prepared | onchain | indeterminate
    mode: str = "not_required"
    #: Aşama → tx hash; yalnız RPC state/event doğrulamasından sonra dolar.
    tx_hashes: dict[str, str] = Field(default_factory=dict)
    #: Zincir akışı denenip başarısız olduysa sebep.
    note: str = ""
    #: Bir tx yayınlanmış olabilir fakat güvenli nihai durum belirlenememiştir.
    indeterminate: bool = False
    failure_stage: str = ""


class AuditReport(BaseModel):
    job_id: str
    agent_id: str
    agent_name: str
    tier: AuditTier
    created_at: float = Field(default_factory=time.time)
    duration_ms: int = 0

    overall_score: float = 0.0
    badge: Badge = Badge.CAUTION
    dimension_scores: list[DimensionScore] = Field(default_factory=list)
    verdicts: list[AuditorVerdict] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    judge_notes: list[str] = Field(default_factory=list)
    disagreement_index: float = 0.0
    completed_dimensions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    policy_version: str = ""
    input_hash: str = ""
    finding_set_hash: str = ""
    assurance_level: AssuranceLevel = AssuranceLevel.PARTIAL
    evidence_summary: dict[str, int] = Field(default_factory=dict)
    # Deep audit reports include nested per-surface evidence coverage, while
    # auditor verdict coverage above remains a strict integer counter map.
    coverage: dict[str, Any] = Field(default_factory=dict)
    deterministic: bool = True
    external_processors: list[str] = Field(default_factory=list)

    report_cid: str = ""
    report_uri: str = ""
    attestation: Attestation | None = None

    def counts(self) -> dict[str, int]:
        out = {s.value: 0 for s in Severity}
        for f in self.findings:
            out[f.severity.value] += 1
        return out


class Job(BaseModel):
    id: str = Field(default_factory=lambda: f"job_{uuid.uuid4().hex[:12]}")
    agent_id: str
    tier: AuditTier = AuditTier.BASIC
    state: JobState = JobState.CREATED
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)
    requester: str = ""
    validation_request_hash: str = ""
    escrow: EscrowRecord | None = None
    report: AuditReport | None = None
    error: str = ""
    logs: list[str] = Field(default_factory=list)

    def log(self, msg: str) -> None:
        self.logs.append(f"{time.strftime('%H:%M:%S')} {msg}")
        self.updated_at = time.time()


class MonitorSubscription(BaseModel):
    id: str = Field(default_factory=lambda: f"sub_{uuid.uuid4().hex[:10]}")
    agent_id: str
    interval_minutes: int = 30
    balance_usdc: float = 0.0
    active: bool = True
    ticks: int = 0
    last_tick_at: float | None = None
    last_score: float | None = None
    last_badge: str = ""
    last_finding_set_hash: str = ""
    last_confirmed_risk_ids: list[str] = Field(default_factory=list)
    last_assurance_level: str = ""
    alerts: list[str] = Field(default_factory=list)


class SwarmMemberStats(BaseModel):
    name: str
    dimension: Dimension
    elo: float = 1200.0
    stake_usdc: float = 0.0
    audits: int = 0
    agreements: int = 0
    adjudicated_findings: int = 0
    correct_findings: int = 0
    slashed_usdc: float = 0.0
    earned_usdc: float = 0.0

    @property
    def accuracy(self) -> float | None:
        """Yalnız appeal-final ground truth varsa kalibrasyon doğruluğu döner."""
        if not self.adjudicated_findings:
            return None
        return round(self.correct_findings / self.adjudicated_findings, 3)
