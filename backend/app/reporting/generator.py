"""Rapor üretimi: JSON (zincir/IPFS için kanonik) + Markdown (insan için)."""

from __future__ import annotations

import json
import time
from hashlib import sha256

from ..models import AgentArtifact, AuditReport, Severity
from ..swarm.policy import AUDIT_SCHEMA_VERSION

SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
SEVERITY_LABEL = {
    Severity.CRITICAL: "KRİTİK",
    Severity.HIGH: "YÜKSEK",
    Severity.MEDIUM: "ORTA",
    Severity.LOW: "DÜŞÜK",
    Severity.INFO: "BİLGİ",
}
GRADE_LABEL = {
    "confirmed": "doğrulanmış (doğrudan kanıt)",
    "inferred": "çıkarım (savunma kanıtı yok)",
    "simulated": "simüle (indexer bağlı değil)",
}
BADGE_LABEL = {

    "SAFE": "✅ SAFE",
    "CAUTION": "⚠️ CAUTION",
    "HIGH_RISK": "⛔ HIGH RISK",
    "BLOCKLIST": "🚫 BLOCKLIST",
}


def _mask(text: str, privacy: bool) -> str:
    if not privacy or not text:
        return text
    digest = sha256(text.encode()).hexdigest()[:16]
    return f"[privacy-mode: içerik maskelendi, sha256:{digest}]"


def report_to_dict(report: AuditReport, artifact: AgentArtifact) -> dict:
    """IPFS'e yazılan kanonik JSON gösterimi."""
    privacy = artifact.privacy_mode
    return {
        "schema": AUDIT_SCHEMA_VERSION,
        "policy_version": report.policy_version,
        "input_hash": report.input_hash,
        "finding_set_hash": report.finding_set_hash,
        "job_id": report.job_id,
        "generated_at": report.created_at,
        "duration_ms": report.duration_ms,
        "tier": report.tier.value,
        "agent": {
            "id": artifact.id,
            "name": artifact.name,
            "source_kind": artifact.source_kind.value,
            "source_ref": _mask(artifact.source_ref, privacy),
            "wallet": artifact.agent_wallet,
            "agent_contract_id": artifact.agent_contract_id,
            "owner": artifact.owner,
            "owner_verified": artifact.owner_verified,
            "owner_verification": artifact.owner_verification_note,

            "domain": artifact.domain,
            "declared_capabilities": artifact.declared_capabilities,
            "tools": [t.model_dump() for t in artifact.tools],
            "privacy_mode": privacy,
            "system_prompt_sha256": sha256((artifact.system_prompt or "").encode()).hexdigest(),
            "code_file_count": len(artifact.code_files),
            "dependency_count": len(artifact.dependencies),
            "onchain": artifact.onchain.model_dump(),
        },
        "result": {
            "overall_score": report.overall_score,
            "badge": report.badge.value,
            "severity_counts": report.counts(),
            "disagreement_index": report.disagreement_index,
            "dimension_scores": [d.model_dump(mode="json") for d in report.dimension_scores],
            "assurance_level": report.assurance_level.value,
            "evidence_summary": report.evidence_summary,
            "coverage": report.coverage,
            "completed_dimensions": report.completed_dimensions,
            "limitations": report.limitations,
            "deterministic": report.deterministic,
            "external_processors": report.external_processors,
        },
        "findings": [
            {
                **f.model_dump(mode="json"),
                "evidence": _mask(f.evidence, privacy),
            }
            for f in report.findings
        ],
        "auditors": [
            {
                "auditor": v.auditor,
                "dimension": v.dimension.value,
                "score": v.score,
                "stake_usdc": v.stake_usdc,
                "duration_ms": v.duration_ms,
                "llm_assisted": v.llm_assisted,
                "llm_consulted": v.llm_consulted,
                "rule_set": v.rule_set,
                "coverage": v.coverage,
                "status": v.status,
                "notes": v.notes,
                "scenarios": [s.model_dump() for s in v.scenarios],
            }
            for v in report.verdicts
        ],
        "judge_notes": report.judge_notes,
        "attestation": report.attestation.model_dump(mode="json") if report.attestation else None,
    }


def canonical_json(payload: dict) -> str:
    return json.dumps(payload, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def render_markdown(report: AuditReport, artifact: AgentArtifact) -> str:
    privacy = artifact.privacy_mode
    counts = report.counts()
    created = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(report.created_at))

    lines: list[str] = []
    add = lines.append

    add(f"# AgentVeritas Denetim Raporu — {report.agent_name}")
    add("")
    add(f"**Trust Score: {report.overall_score}/100 · Badge: {BADGE_LABEL[report.badge.value]}**")
    add("")
    add(f"| Alan | Değer |")
    add("|---|---|")
    add(f"| Job ID | `{report.job_id}` |")
    add(f"| Agent ID | `{report.agent_id}` |")
    visible_source = _mask(artifact.source_ref, privacy) if artifact.source_ref else "n/a"
    add(f"| Kaynak | {artifact.source_kind.value} — `{visible_source}` |")
    add(f"| Cüzdan | `{artifact.agent_wallet or 'bildirilmedi'}` |")
    add(f"| Stellar agent contract | `{artifact.agent_contract_id or 'kayıtlı değil'}` |")
    add(
        f"| Sahip doğrulaması | "
        f"{'✅ ' if artifact.owner_verified else '❌ '}{artifact.owner_verification_note} |"
    )

    add(f"| Alan (domain) | {artifact.domain} |")
    add(f"| Seviye | {report.tier.value} |")
    add(f"| Süre | {report.duration_ms} ms |")
    add(f"| Oluşturuldu | {created} |")
    add(f"| Anlaşmazlık endeksi | σ={report.disagreement_index} |")
    add(f"| Kanıt güvencesi | `{report.assurance_level.value}` |")
    add(f"| Policy | `{report.policy_version}` |")
    add(f"| Audit input hash | `{report.input_hash}` |")
    add(f"| Finding set hash | `{report.finding_set_hash}` |")
    add(f"| Deterministik | {'evet' if report.deterministic else 'hayır'} |")
    if report.report_cid:
        label = "Yerel CAS" if report.report_uri.startswith("local-cas://") else "IPFS"
        add(f"| {label} | `{report.report_cid}` |")
    if report.attestation:
        att = report.attestation
        add(
            f"| Attestation | {att.mode} · confirmed={att.confirmed} · "
            f"tx `{att.tx_hash[:18] + '…' if att.tx_hash else 'yok'}` |"
        )
    add("")

    add("## Kanıt ve kapsam")
    add("")
    add(
        f"- kanıt: confirmed={report.evidence_summary.get('confirmed', 0)} · "
        f"inferred={report.evidence_summary.get('inferred', 0)} · "
        f"simulated={report.evidence_summary.get('simulated', 0)}"
    )
    add(
        f"- quorum: {report.coverage.get('completed_auditors', 0)}/"
        f"{report.coverage.get('expected_auditors', 0)} auditor · "
        f"{report.coverage.get('completed_dimensions', 0)}/"
        f"{report.coverage.get('expected_dimensions', 0)} boyut"
    )
    if report.external_processors:
        add(f"- harici işleyiciler: {', '.join(report.external_processors)}")
    for limitation in report.limitations:
        add(f"- sınır: {limitation}")
    add("")

    add("## Boyut skorları")
    add("")
    add("| Boyut | Skor | Ağırlık | Katkı |")
    add("|---|---:|---:|---:|")
    for d in report.dimension_scores:
        add(f"| {d.dimension.value} | {d.score} | %{d.weight * 100:.0f} | {d.weighted} |")
    add("")

    add("## Özet")
    add("")
    add(
        "| KRİTİK | YÜKSEK | ORTA | DÜŞÜK | BİLGİ |\n|---:|---:|---:|---:|---:|\n"
        f"| {counts['critical']} | {counts['high']} | {counts['medium']} | "
        f"{counts['low']} | {counts['info']} |"
    )
    add("")
    for note in report.judge_notes:
        add(f"- {note}")
    add("")

    add("## Bulgular")
    add("")
    if not report.findings:
        add("Bulgu yok.")
    for sev in SEVERITY_ORDER:
        group = [f for f in report.findings if f.severity == sev]
        if not group:
            continue
        add(f"### {SEVERITY_LABEL[sev]} ({len(group)})")
        add("")
        for f in group:
            add(f"#### {f.title}")
            add("")
            add(f"- **id**: `{f.id}` · **boyut**: {f.dimension.value} · **denetçi**: {f.auditor}")
            add(
                f"- **kanıt**: {GRADE_LABEL[f.evidence_grade.value]} · "
                f"**güven**: {f.confidence:.2f} · **etkin ceza**: {f.penalty:.1f}"
            )

            if f.references:
                add(f"- **referans**: {', '.join(f.references)}")
            add("")
            add(f.detail)
            if f.evidence:
                add("")
                add("```")
                add(_mask(f.evidence, privacy))
                add("```")
            if f.remediation:
                add("")
                add(f"**Çözüm:** {f.remediation}")
            add("")

    add("## Denetçi detayları")
    add("")
    for v in report.verdicts:
        add(f"### {v.auditor} — {v.score}/100 ({v.dimension.value})")
        add("")
        add(
            f"- stake: {v.stake_usdc} USDC · süre: {v.duration_ms} ms · "
            f"LLM bulgusu: {'evet' if v.llm_assisted else 'hayır'} · "
            f"LLM'e veri gitti: {'evet' if v.llm_consulted else 'hayır'}"
        )
        add(f"- rule set: `{v.rule_set}` · coverage: {v.coverage}")
        if v.notes:
            add(f"- not: {v.notes}")
        if v.scenarios:
            passed = sum(1 for s in v.scenarios if s.passed)
            add(f"- senaryo: {passed}/{len(v.scenarios)} geçti")
            add("")
            add("| # | Senaryo | Sonuç | Gerekçe |")
            add("|---|---|---|---|")
            for s in v.scenarios:
                mark = "✅" if s.passed else "❌"
                add(f"| {s.scenario_id} | {s.name} | {mark} | {s.reason} |")
        add("")

    add("---")
    add("")
    add(
        "_AgentVeritas Stellar · Soroban agent validation. Prepared invocation veya hash tek "
        "başına zincir başarısı değildir; confirmed alanı ledger/state kanıtını gösterir._"
    )
    return "\n".join(lines)
