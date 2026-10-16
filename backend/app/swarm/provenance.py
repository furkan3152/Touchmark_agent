"""Kaynak ve build provenance denetçisi.

Bu boyut kodun güvenli olduğunu iddia etmez. İncelenen kaynak, kilitli
bağımlılık ve yayımlanan artefakt arasında yeniden üretilebilir bir bağ olup
olmadığını ölçer.
"""

from __future__ import annotations

import json
import re

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, ScenarioResult, Severity
from .base import BaseAuditor


MANIFEST_NAMES = ("package.json", "requirements.txt", "requirements.in", "pyproject.toml", "setup.cfg",
                  "cargo.toml", "go.mod", "dockerfile", "pipfile", "gemfile")


def _is_manifest(name: str) -> bool:
    base = name.lower().rsplit("/", 1)[-1]
    return (base in MANIFEST_NAMES or base.startswith(("requirements", "dockerfile"))
            or base.endswith((".dockerfile", ".hbs.dockerfile")) or base.startswith("dockerfile.")
            or (("/.github/workflows/" in "/" + name.lower()) and base.endswith((".yml", ".yaml"))))


def _is_workflow(name: str) -> bool:
    return "/.github/workflows/" in "/" + name.lower() or name.lower().endswith("gitlab-ci.yml")


def _is_build_file(name: str) -> bool:
    base = name.lower().rsplit("/", 1)[-1]
    return "dockerfile" in base or "/.github/workflows/" in "/" + name.lower()


def _manifest_text(name: str, text: str) -> str:
    """Version-bearing lines only. In package.json that is the dependency sections:
    `engines` and `scripts` (globs such as `src/**/*.ts`) are not dependencies."""
    if not name.lower().endswith("package.json"):
        return text
    try:
        data = json.loads(text)
    except ValueError:
        return text
    sections = ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies")
    return "\n".join(f'"{dep}": "{version}"' for section in sections
                     for dep, version in sorted((data.get(section) or {}).items()) if isinstance(version, str))


class ProvenanceAuditor(BaseAuditor):
    name = "provenance-auditor"
    dimension = Dimension.PROVENANCE

    async def analyse(
        self, artifact: AgentArtifact, deep: bool
    ) -> tuple[list[Finding], list[ScenarioResult], str]:
        findings: list[Finding] = []
        names = {name.lower() for name in artifact.code_files} | {n.lower() for n in artifact.lockfiles}
        lock_markers = (
            "package-lock.json", "pnpm-lock.yaml", "yarn.lock", "cargo.lock",
            "poetry.lock", "uv.lock", "pipfile.lock", "go.sum", "bun.lock", "bun.lockb",
        )
        # Version ranges live in manifests and build files, not in application source:
        # `/**` comments and `a >= b` comparisons in code are not floating dependencies.
        locked = any(any(name.endswith(marker) for name in names) for marker in lock_markers)
        # With a lockfile, manifest ranges are pinned; only build inputs (base images,
        # tools fetched at build time) can still float.
        joined = "\n".join(_manifest_text(name, text) for name, text in artifact.code_files.items()
                           if _is_manifest(name) and not _is_workflow(name)
                           and not (locked and not _is_build_file(name)))
        if artifact.source_kind.value in {"repo", "upload"} and not locked:
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
        # CI workflows float through actions referenced by tag or branch and through
        # `:latest` images; runner labels (ubuntu-latest) and trigger filters do not.
        for name, text in artifact.code_files.items():
            if _is_workflow(name):
                floating += [m.group(0).strip() for m in re.finditer(
                    r"(?m)^\s*-?\s*uses:\s*(?!\./)[\w.-]+/[\w./-]+@(?![0-9a-f]{40}\b)\S+.*$|"
                    r"^\s*(?:image|container):\s*\S+:latest\b.*$", text)]
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
