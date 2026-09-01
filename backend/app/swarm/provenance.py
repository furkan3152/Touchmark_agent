"""Kaynak ve build provenance denetçisi.

Bu boyut kodun güvenli olduğunu iddia etmez. İncelenen kaynak, kilitli
bağımlılık ve yayımlanan artefakt arasında yeniden üretilebilir bir bağ olup
olmadığını ölçer.
"""

from __future__ import annotations

import re

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, ScenarioResult, Severity
from .base import BaseAuditor


class ProvenanceAuditor(BaseAuditor):
    name = "provenance-auditor"
    dimension = Dimension.PROVENANCE

    async def analyse(
        self, artifact: AgentArtifact, deep: bool
    ) -> tuple[list[Finding], list[ScenarioResult], str]:
        findings: list[Finding] = []
        names = {name.lower() for name in artifact.code_files}
        joined = "\n".join(artifact.code_files.values())

        lock_markers = (
            "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "cargo.lock",
            "poetry.lock", "uv.lock", "pipfile.lock", "go.sum",
        )
        if artifact.source_kind.value in {"repo", "upload"} and not any(
            any(name.endswith(marker) for name in names) for marker in lock_markers
        ):
            findings.append(self.finding(
                "missing-lockfile",
                Severity.MEDIUM,
                "Bağımlılık kilidi kanıtlanmadı",
                "İncelenen dosya setinde desteklenen bir lockfile yok; aynı kaynak farklı bağımlılıklarla farklı davranabilir.",
                remediation="Runtime ve build bağımlılıklarını lockfile ile sabitleyin; CI'da yalnız locked/frozen kurulum kullanın.",
                grade=EvidenceGrade.INFERRED,
                confidence=0.78,
            ))

        workflow = any(".github/workflows/" in name or name.endswith("gitlab-ci.yml") for name in names)
        if not workflow:
            findings.append(self.finding(
                "no-release-pipeline",
                Severity.LOW,
                "Doğrulanabilir release pipeline görünmüyor",
                "Kaynak→test→artefakt zincirini yeniden üreten bir CI tanımı denetim yüzeyinde bulunamadı.",
                remediation="Pinlenmiş toolchain ile test/build yapan ve hash/provenance yayımlayan CI ekleyin.",
                grade=EvidenceGrade.INFERRED,
                confidence=0.68,
            ))

        if not any(name.endswith(("license", "license.md", "license.txt")) for name in names):
            findings.append(self.finding(
                "license-missing",
                Severity.INFO,
                "Lisans dosyası görünmüyor",
                "Kaynağın yeniden kullanım ve dağıtım şartları belirlenemedi.",
                remediation="Kök dizine açık bir LICENSE dosyası ekleyin.",
                grade=EvidenceGrade.INFERRED,
                confidence=0.65,
            ))

        floating = re.findall(
            r"(?im)^\s*(?:FROM\s+\S+:latest|[^#\n]+(?:>=|\*|latest)[^\n]*)$", joined
        )
        if floating:
            findings.append(self.finding(
                "floating-dependencies",
                Severity.MEDIUM,
                "Değişken bağımlılık/build girdileri bulundu",
                "`latest`, wildcard veya alt sınır-only sürümler yeniden üretilebilirliği zayıflatıyor.",
                evidence="\n".join(floating[:5]),
                remediation="Doğrudan bağımlılıkları ve container image'larını değişmez sürüm/digest ile sabitleyin.",
                confidence=0.82,
            ))

        if deep and not any("sbom" in name or name.endswith(("cyclonedx.json", "spdx.json")) for name in names):
            findings.append(self.finding(
                "sbom-missing",
                Severity.LOW,
                "SBOM kanıtı yok",
                "Derin denetimde dağıtılan bileşen envanteri doğrulanamadı.",
                remediation="Release sırasında CycloneDX veya SPDX SBOM üretin ve artefakt hash'iyle bağlayın.",
                grade=EvidenceGrade.INFERRED,
                confidence=0.7,
            ))

        scenarios = [
            ScenarioResult(
                scenario_id="P-001",
                name="Kaynak→artefakt izlenebilirliği",
                passed=workflow and not floating,
                reason="CI ve değişmez build girdileri birlikte aranır.",
            )
        ]
        return findings, scenarios, "Kaynak, dependency ve release provenance yüzeyi denetlendi."
