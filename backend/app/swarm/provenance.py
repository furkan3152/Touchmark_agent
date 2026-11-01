"""Source and build provenance auditor.

This dimension does not claim the code is safe. It measures whether there is a
reproducible link between the reviewed source, the locked dependencies and the
published artifact.
"""

from __future__ import annotations

import json
import re

from ..models import AgentArtifact, Dimension, EvidenceGrade, Finding, ScenarioResult, Severity
from .base import BaseAuditor


MANIFEST_NAMES = ("package.json", "requirements.txt", "requirements.in", "pyproject.toml", "setup.cfg",
                  "cargo.toml", "go.mod", "dockerfile", "pipfile", "gemfile",
                  # JVM, .NET, PHP, Swift, Dart, Elixir and Scala builds
                  "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
                  "composer.json", "package.swift", "pubspec.yaml", "mix.exs", "build.sbt")


def _is_manifest(name: str) -> bool:
    base = name.lower().rsplit("/", 1)[-1]
    return (base in MANIFEST_NAMES or base.startswith(("requirements", "dockerfile"))
            or base.endswith((".dockerfile", ".hbs.dockerfile", ".csproj", ".fsproj")) or base.startswith("dockerfile.")
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
            "gradle.lockfile", "packages.lock.json", "composer.lock", "gemfile.lock", "package.resolved",
            "pubspec.lock", "mix.lock",
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
                "Dependency lock not established",
                "The reviewed file set has no supported lockfile; the same source can behave differently with different dependencies.",
                remediation="Pin runtime and build dependencies with a lockfile; use only locked/frozen installs in CI.",
                grade=EvidenceGrade.INFERRED,
                confidence=0.78,
            ))

        workflow = any(".github/workflows/" in name or name.endswith("gitlab-ci.yml") for name in names)
        if not workflow:
            findings.append(self.finding(
                "no-release-pipeline",
                Severity.LOW,
                "No verifiable release pipeline",
                "No CI definition that reproduces the source→test→artifact chain was found in the audit surface.",
                remediation="Add CI that tests and builds with a pinned toolchain and publishes hashes and provenance.",
                grade=EvidenceGrade.INFERRED,
                confidence=0.68,
            ))

        if not any(name.endswith(("license", "license.md", "license.txt")) for name in names):
            findings.append(self.finding(
                "license-missing",
                Severity.INFO,
                "No license file",
                "The reuse and distribution terms of the source could not be determined.",
                remediation="Add an explicit LICENSE file at the repository root.",
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
            # With dependencies locked, actions pinned by tag alone are a supply-chain hygiene
            # point (a retagged action), not unpinned runtime code.
            only_ci_tags = all(re.match(r"-?\s*uses:", line.strip()) for line in floating)
            # A drifting dependency matters most where it runs with keys or the power to pay.
            caps = artifact.code_profile.get("capabilities", {})
            holds_authority = any(c in caps for c in ("key_custody", "stellar_signing", "tx_submission", "payment"))
            findings.append(self.finding(
                "floating-dependencies",
                Severity.LOW if only_ci_tags or not holds_authority else Severity.MEDIUM,
                "Mutable dependency or build inputs found",
                "`latest`, wildcard or lower-bound-only versions weaken reproducibility.",
                evidence="\n".join(floating[:5]),
                remediation="Pin direct dependencies and container images to immutable versions or digests.",
                confidence=0.82,
            ))

        if deep and not any("sbom" in name or name.endswith(("cyclonedx.json", "spdx.json")) for name in names):
            findings.append(self.finding(
                "sbom-missing",
                Severity.LOW,
                "No SBOM evidence",
                "The deep audit could not verify the inventory of deployed components.",
                remediation="Generate a CycloneDX or SPDX SBOM at release time and bind it to the artifact hash.",
                grade=EvidenceGrade.INFERRED,
                confidence=0.7,
            ))

        scenarios = [
            ScenarioResult(
                scenario_id="P-001",
                name="Source→artifact traceability",
                passed=workflow and not floating,
                reason="CI and immutable build inputs are checked together.",
            )
        ]
        return findings, scenarios, "Source, dependency and release provenance surface audited."
