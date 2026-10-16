"""Stellar/Soroban'a özgü agent ve entegrasyon denetçisi."""

from __future__ import annotations

import re

from ..models import FindingKind, AgentArtifact, Dimension, EvidenceGrade, Finding, ScenarioResult, Severity
from .base import BaseAuditor


def _rust_code(source: str) -> str:
    """Mask Rust comments/literals, retaining offsets; this is not a Rust parser."""
    result = list(source)
    i = 0
    while i < len(source):
        end = None
        if source.startswith('//', i):
            end = source.find('\n', i)
            if end < 0: end = len(source)
        elif source.startswith('/*', i):
            depth, end = 1, i + 2
            while end < len(source) and depth:
                if source.startswith('/*', end): depth += 1; end += 2
                elif source.startswith('*/', end): depth -= 1; end += 2
                else: end += 1
        else:
            raw = re.match(r'(?:br|r)(#{0,255})"', source[i:])
            if raw:
                closing = '"' + raw.group(1)
                found = source.find(closing, i + len(raw.group()))
                end = len(source) if found < 0 else found + len(closing)
            elif source[i] == '"':
                end = i + 1
                while end < len(source):
                    if source[end] == '\\': end += 2
                    elif source[end] == '"': end += 1; break
                    else: end += 1
            elif source[i] == "'":
                # Do not consume lifetimes such as &'a Address.
                char = re.match(r"'(?:\\(?:u\{[0-9A-Fa-f_]+\}|x[0-9A-Fa-f]{2}|.)|[^\\'\n])'", source[i:])
                if char: end = i + len(char.group())
        if end is not None:
            for pos in range(i, min(end, len(source))):
                if result[pos] != '\n': result[pos] = ' '
            i = end
        else:
            i += 1
    return ''.join(result)


_FUNCTION = re.compile(r'\b(?P<public>pub(?:\s*\([^)]*\))?\s+)?(?:(?:async|unsafe|const)\s+)*fn\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\b')
_PERSISTENT = r'\.\s*storage\s*\(\s*\)\s*\.\s*persistent\s*\(\s*\)'
_MUTATION = re.compile(r'\.\s*(?:set|remove|update|try_update|transfer|transfer_from|mint|burn|approve)\s*\(')
_MUTATING_NAME = re.compile(r'^(?:set|reg|upd|fund|submit|complete|refund|initialize|init|mint|burn|transfer|approve|revoke|publish|issue|pause|withdraw|deposit|bind|add|remove)')
_AUTH = re.compile(r'\.\s*require_auth(?:_for_args)?\s*\(')


def _rust_functions(source: str, include_private: bool = False) -> list[dict]:
    """Bound public function bodies conservatively, without resolving Rust types/macros."""
    code = _rust_code(source)
    functions = []
    for match in _FUNCTION.finditer(code):
        start = code.find('{', match.end())
        semicolon = code.find(';', match.end())
        if start < 0 or 0 <= semicolon < start: continue
        depth, end = 1, start + 1
        while end < len(code) and depth:
            if code[end] == '{': depth += 1
            elif code[end] == '}': depth -= 1
            end += 1
        if depth: continue
        functions.append({'name': match['name'], 'public': bool(match['public']),
                          'start': match.start(), 'body_start': start + 1, 'end': end,
                          'line': code.count('\n', 0, match.start()) + 1})
    results = []
    for fn in functions:
        if not fn['public'] and not include_private: continue
        # Merely defining a protected nested function does not guard its parent.
        body = list(code[fn['body_start']:fn['end'] - 1])
        for nested in functions:
            if fn['body_start'] <= nested['start'] < nested['end'] < fn['end']:
                for i in range(nested['start'] - fn['body_start'], nested['end'] - fn['body_start']):
                    if body[i] != '\n': body[i] = ' '
        results.append({**fn, 'body': ''.join(body)})
    return results


def _has_persistent_ttl(body: str) -> bool:
    if re.search(_PERSISTENT + r'\s*\.\s*extend_ttl\s*\(', body): return True
    # Recognize a local storage binding, but do not mistake instance TTL for
    # persistent-entry TTL. Key matching/path reachability still need review.
    aliases = re.findall(r'\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*[A-Za-z_][A-Za-z0-9_]*' + _PERSISTENT + r'\s*;', body)
    return any(re.search(r'\b' + re.escape(alias) + r'\s*\.\s*extend_ttl\s*\(', body) for alias in aliases)


def _providers(functions: list[dict], direct) -> set[str]:
    """Names of functions that perform a check directly or through a helper they call."""
    names = {fn['name'] for fn in functions}
    providing = {fn['name'] for fn in functions if direct(fn['body'])}
    for _ in range(4):  # helpers of helpers; bounded, no full call graph
        grew = {fn['name'] for fn in functions if fn['name'] not in providing and any(
            re.search(r'(?:\bSelf::|\bself\.|(?<![\w.:]))' + re.escape(h) + r'\s*\(', fn['body'])
            for h in providing if h in names)}
        if not grew:
            break
        providing |= grew
    return providing


def _calls_any(body: str, names: set[str]) -> bool:
    return any(re.search(r'(?:\bSelf::|\bself\.|(?<![\w.:]))' + re.escape(n) + r'\s*\(', body) for n in names)


class StellarNativeAuditor(BaseAuditor):
    name = "stellar-native-auditor"
    dimension = Dimension.STELLAR_NATIVE

    async def analyse(
        self, artifact: AgentArtifact, deep: bool
    ) -> tuple[list[Finding], list[ScenarioResult], str]:
        findings: list[Finding] = []
        surface = artifact.text_surface()
        rust_files = {name: content for name, content in artifact.code_files.items() if name.endswith('.rs')}
        rust = '\n'.join(_rust_code(content) for content in rust_files.values())
        functions = [{**fn, 'file': name} for name, content in rust_files.items() for fn in _rust_functions(content)]
        lower = surface.lower()

        from stellar_sdk import StrKey
        sources = {**artifact.code_files, "<system prompt>": artifact.system_prompt or ""}
        seeds = [
            (name, content[:m.start()].count(chr(10)) + 1, m.group(0))
            for name, content in sources.items()
            for m in re.finditer(r"\bS[A-Z2-7]{55}\b", content)
            if StrKey.is_valid_ed25519_secret_seed(m.group(0))  # placeholders fail the checksum
        ]
        seed_locations = [f"{n}:{line} (S{s[1:5]}…redacted)" for n, line, s in seeds][:5]
        test_only = bool(seeds) and all(
            re.search(r"(^|/)(tests?|spec|fixtures?|examples?|scripts)/|test|spec|smoke|example|fixture", n, re.I)
            for n, _, _ in seeds)
        if seeds:
            findings.append(
                self.finding(
                    "stellar-secret-seed",
                    Severity.MEDIUM if test_only else Severity.CRITICAL,
                    "Stellar secret seed kaynakta görünüyor",
                    "S... secret seed doğrudan kod/manifest yüzeyinde bulundu."
                    + (" Yalnızca test/örnek dosyalarında; yine de commit edilmiş anahtarlar döndürülmelidir." if test_only else ""),
                    evidence="; ".join(seed_locations) or "secret seed pattern in submitted manifest text",
                    remediation="Seed'i derhal döndürün; haricî signer/HSM kullanın ve geçmişten temizleyin.",
                    confidence=0.99,
                )
            )

        # Constructor deployment authorization and custom-account __check_auth
        # are separate boundaries; requiring require_auth inside them is unsound.
        mutating = [fn for fn in functions if fn['name'] not in {'__constructor', '__check_auth'}
                    and (_MUTATING_NAME.search(fn['name']) or _MUTATION.search(fn['body']))]
        # Authorization and TTL renewal are often done in a helper (`Self::create_task`,
        # `extend_persistent_ttl`); a call to a helper that performs them counts.
        everything = [{**fn, 'file': name} for name, content in rust_files.items()
                      for fn in _rust_functions(content, include_private=True)]
        auth_helpers = _providers(everything, lambda body: bool(_AUTH.search(body)))
        ttl_helpers = _providers(everything, lambda body: bool(re.search(r'\.\s*extend_ttl\s*\(', body)))
        # Conservative: a gap stays a gap unless the check is in the function's own body.
        # Severity separates "no check anywhere" (high) from "only through a helper, or a
        # read that cannot create state" (medium, needs review).
        auth_gaps = [fn for fn in mutating if not _AUTH.search(fn['body'])]
        auth_hard = [fn for fn in auth_gaps if not _calls_any(fn['body'], auth_helpers)]
        persistent = [fn for fn in functions if re.search(_PERSISTENT, fn['body'])]
        ttl_gaps = [fn for fn in persistent if not _has_persistent_ttl(fn['body'])]
        ttl_hard = [fn for fn in ttl_gaps
                    if _MUTATION.search(fn['body']) and not _calls_any(fn['body'], ttl_helpers)]
        def locations(items):
            return '; '.join(f"{fn['file']}:{fn['line']} {fn['name']}" for fn in items)
        if auth_gaps:
            finding = self.finding(
                "soroban-auth-missing",
                Severity.HIGH if auth_hard else Severity.MEDIUM,
                "Soroban authorization paths require review",
                "Potentially mutating public functions lack a direct require_auth call in their own body. Authorization may exist in a helper or caller; this lexical review does not establish an exploitable authorization bypass.",
                evidence=locations(auth_hard + [fn for fn in auth_gaps if fn not in auth_hard]),
                remediation="Trace each entrypoint's actual authorization path, including helpers and invocation context, and run unauthorized-caller tests bound to the exact action arguments.",
                grade=EvidenceGrade.INFERRED,
                confidence=0.75,
            )
            # Every gap reaches a helper that calls require_auth: nothing is shown to be
            # missing, only unverified. That is an evidence gap, not a risk.
            findings.append(finding if auth_hard else finding.model_copy(update={"kind": FindingKind.EVIDENCE_GAP}))

        if ttl_gaps:
            finding = self.finding(
                "persistent-ttl",
                Severity.HIGH if ttl_hard else Severity.MEDIUM,
                "Persistent state lifetime paths require review",
                "These public functions reference persistent storage without a recognized persistent-entry extend_ttl call in the same body. A helper or external maintenance policy may handle lifetime; its effectiveness was not verified.",
                evidence=locations(ttl_hard + [fn for fn in ttl_gaps if fn not in ttl_hard]),
                remediation="Trace the lifetime policy for each affected key, distinguish instance TTL from persistent-entry TTL, and test archival, restoration and missing-state behavior.",
                grade=EvidenceGrade.INFERRED,
                confidence=0.75,
            )
            findings.append(finding if ttl_hard else finding.model_copy(update={"kind": FindingKind.EVIDENCE_GAP}))

        # Temporary storage is right for counters, allowances, nonces and caches. Report
        # only keys whose names say they hold state that must not silently expire.
        temporary_keys = re.findall(r'\.\s*temporary\s*\(\s*\)\s*\.\s*set\s*\(\s*&?\s*(?:DataKey::)?([A-Za-z_]\w*)', rust)
        critical_keys = [k for k in temporary_keys
                         if re.search(r"balance|escrow|owner|admin|limit|deposit|vault|task|grant|valid|signer|policy", k, re.I)
                         and not re.search(r"allowance|spent|nonce|cache|session|lock|count|seen", k, re.I)]
        if critical_keys:
            findings.append(
                self.finding(
                    "temporary-critical-state",
                    Severity.MEDIUM,
                    "Kritik kayıt temporary storage kullanıyor olabilir",
                    "Agent, validation veya escrow state'i süresi dolduğunda silinebilir.",
                    evidence="temporary keys: " + ", ".join(sorted(set(critical_keys))),
                    remediation="Kritik kayıtları persistent storage'a taşıyın; temporary yalnız cache/idempotency penceresi olsun.",
                    grade=EvidenceGrade.INFERRED,
                    confidence=0.7,
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

        # SEP-45 is web authentication for contract accounts. A contract id alone (a token
        # SAC, a policy contract) is not a contract-account login, so require both.
        contract_accounts = "contract account" in lower or "smart account" in lower or "smart wallet" in lower
        web_auth = re.search(r"sep-?10\b|\bweb[ _-]?auth\b|challenge transaction|challenge_transaction|"
                             r"build_challenge|read_challenge|/auth\b", lower)
        if contract_accounts and web_auth:
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

        # Payment verification by transaction hash must check that the transaction succeeded:
        # Horizon returns failed transactions (and their operations) by hash too.
        unchecked = []
        for name, content in artifact.code_files.items():
            if not name.lower().endswith((".py", ".js", ".mjs", ".cjs", ".ts", ".tsx")):
                continue
            looks_up = re.search(r"\.transactions\(\)\s*\.\s*transaction\(|forTransaction\(|for_transaction\(|"
                                 r"/transactions/\$\{|/transactions/\{|get_transaction\(|getTransaction\(", content)
            pays = re.search(r"\bamount\b", content) and re.search(r"destination|payTo|pay_to|\.to\b|recipient", content)
            verifies = re.search(r"verif|validat", name + content[:4000], re.I)
            checks = re.search(r"\.successful\b|\[[\"']successful[\"']\]|[\"']SUCCESS[\"']|transaction_successful", content)
            if looks_up and pays and verifies and not checks:
                line = content[:looks_up.start()].count("\n") + 1
                unchecked.append(f"{name}:{line}")
        if unchecked:
            findings.append(self.finding(
                "payment-success-unchecked", Severity.HIGH,
                "Payment verification does not check that the transaction succeeded",
                "The code looks a payment transaction up by hash and checks its fields, but never checks `successful`. "
                "Horizon and RPC return failed transactions by hash, with their memo and operations, so a transaction "
                "that failed on chain (fee paid, no transfer) can pass as payment.",
                evidence="; ".join(unchecked[:5]),
                remediation="Require `successful === true` (Horizon) or `status === 'SUCCESS'` (RPC) before reading the "
                            "operations, and verify the payment operation itself.",
                grade=EvidenceGrade.INFERRED, confidence=0.8))


        # `successful`, a SUCCESS comparison); a comment alone is weak evidence.
        confirms = re.search(r"gettransaction\s*\(|get_transaction\s*\(|\.successful\b|"
                             r"[\"']success[\"']|status\s*===?\s*[\"']success", lower)
        if re.search(r"tx[_ -]?hash.*(?:success|complete|confirmed)", lower) and not confirms:
            findings.append(
                self.finding(
                    "hash-is-not-confirmation",
                    Severity.MEDIUM,
                    "Transaction hash başarı kanıtı sayılıyor olabilir",
                    "Hash üretimi/yayın, ledger inclusion ve beklenen contract state/event anlamına gelmez.",
                    remediation="getTransaction sonucu, success status ve contract state/event readback birlikte doğrulansın.",
                    grade=EvidenceGrade.INFERRED,
                    confidence=0.78,
                )
            )

        scenarios = []
        if mutating:
            scenarios.append(ScenarioResult(
                scenario_id="ST-001",
                name="Soroban authorization call presence",
                passed=not auth_gaps,
                reason="Per-function lexical call presence only; signer identity, control flow, helper authorization and runtime enforcement remain unverified.",
                evidence=locations(mutating),
            ))
        if persistent:
            scenarios.append(ScenarioResult(
                scenario_id="ST-002",
                name="Persistent-entry TTL call presence",
                passed=not ttl_gaps,
                reason="Per-function lexical call presence only; key binding, execution paths, helper policies and restoration remain unverified.",
                evidence=locations(persistent),
            ))
        scenarios.extend([
            ScenarioResult(
                scenario_id="ST-003",
                name="Event durability",
                passed="getevents" not in lower
                or bool(re.search(r"cursor|pagingtoken|sqlite|dedup|unique", lower)),
                reason="RPC retention yerine durable cursor/dedup aranır.",
            ),
        ])
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
        findings += self._authority_findings(artifact)
        return findings, scenarios, f"Stellar/Soroban source review; onchain source={source}. Rust checks are bounded lexical evidence, not a compiler, call graph, authorization proof or runtime test. Constructor and custom-account authorization need separate verification."

    # ------------------------------------------------------------ ledger authority
    def _authority_findings(self, artifact: AgentArtifact) -> list[Finding]:
        """Findings from public ledger state: signers, thresholds, trustlines, SEP-1, SEP-29."""
        facts = artifact.chain_authority or {}
        out: list[Finding] = []
        account = facts.get("account", {})
        address = account.get("address", "")
        signs = any(t.requires_signature for t in artifact.tools)
        if account.get("status") == "not_found":
            out.append(self.finding("onchain-account-missing", Severity.MEDIUM,
                "The supplied agent account does not exist on this network",
                "Horizon has no account for the supplied address, so its authority cannot be verified.",
                evidence=f"{facts.get('network')}: {address} not found",
                remediation="Supply the funded account the agent signs with, on the network it runs on."))
        if account.get("status") == "found":
            agent = account.get("agent_key")
            if agent and agent.get("can_administer_alone"):
                out.append(self.finding("onchain-agent-key-administers-account", Severity.HIGH,
                    "The agent key alone can change signers or merge the account",
                    "Its weight meets the high threshold. Whoever controls the agent (including through prompt "
                    "injection) can add a signer, change thresholds or merge the account and take every asset.",
                    evidence=f"{address}: agent key weight {agent['weight']} >= high threshold "
                             f"{account['thresholds']['high']}",
                    remediation="Give the agent key a weight below the high threshold (and ideally below medium), "
                                "with administration reserved to an offline key."))
            elif agent and not agent.get("is_signer"):
                out.append(self.finding("onchain-agent-key-not-signer", Severity.MEDIUM,
                    "The declared agent key is not a signer of the agent account",
                    "Transactions signed with it will fail, or the agent signs for a different account than declared.",
                    evidence=f"{address}: {agent['key']} not in signers",
                    remediation="Declare the key the agent actually signs with, or add it as a scoped signer."))
            elif not agent and signs and account.get("single_key_can_pay"):
                out.append(self.finding("onchain-agent-key-undeclared", Severity.MEDIUM,
                    "The agent's signing key is not declared",
                    "A single signer on this account can pay alone. Without the agent's public key the audit cannot "
                    "tell whether the agent holds that authority.",
                    evidence=f"{address}: single-key payment authority present",
                    remediation="Declare the agent's public signing key so its on-chain weight can be verified."))
            if agent and agent.get("is_signer") and not agent.get("can_pay_alone"):
                out.append(self.finding("onchain-cosigner-required", Severity.INFO,
                    "Payments require a co-signer on the ledger",
                    "The agent key's weight is below the medium threshold, so no payment executes without another "
                    "signer. This is an enforced control, independent of the agent's code.",
                    evidence=f"{address}: agent weight {agent['weight']} < medium threshold {account['thresholds']['medium']}",
                    remediation="Keep the co-signer independent of the agent's runtime."))
            for line in account.get("trustlines", []):
                if line.get("unlimited"):
                    out.append(self.finding(f"onchain-unlimited-trustline-{len(out)}", Severity.LOW,
                        "A trustline has no holding limit",
                        "The account will accept any amount of this asset, including spam or assets the issuer can freeze.",
                        evidence=f"{address}: {line['asset']} limit {line['limit']}",
                        remediation="Set trustline limits to what the agent needs."))
            sep1 = facts.get("sep1")
            if not account.get("home_domain") or (sep1 and not sep1.get("account_listed")):
                out.append(self.finding("onchain-identity-unbound", Severity.LOW,
                    "The account is not bound to a published SEP-1 identity",
                    "No home domain lists this account in its stellar.toml ACCOUNTS, so users cannot tie it to an operator.",
                    evidence=f"{address}: home_domain={account.get('home_domain') or 'none'}; "
                             f"sep1={sep1.get('status') if sep1 else 'not_checked'}",
                    remediation="Set home_domain and list the account in https://<domain>/.well-known/stellar.toml."))
        for dest in facts.get("destinations", []):
            if dest.get("status") == "found" and dest.get("memo_required") and not dest.get("code_attaches_memo"):
                out.append(self.finding(f"onchain-memo-required-{len(out)}", Severity.HIGH,
                    "Payments go to an account that requires a memo, but the code never sets one",
                    "The destination publishes SEP-29 config.memo_required (typical for exchanges and custodians). "
                    "Payments without a memo are not credited to any customer and are usually unrecoverable.",
                    evidence=f"{dest['location']}: {dest['address']} memo_required=true",
                    remediation="Attach the destination's required memo, and refuse to pay memo-required accounts without one."))
            elif dest.get("status") == "not_found":
                # A payment to a missing account fails; it does not lose funds.
                out.append(self.finding(f"onchain-destination-missing-{len(out)}", Severity.LOW,
                    "A hard-coded payment destination does not exist on this network",
                    "Payments to it fail; create_account would be needed, which sends a different amount semantics.",
                    evidence=f"{dest['location']}: {dest['address']} not found on {facts.get('network')}",
                    remediation="Verify destinations on the target network before deployment."))
        contract = facts.get("contract") or {}
        if contract.get("status") == "found" and contract.get("executable") == "wasm":
            if contract.get("upgradeable"):
                out.append(self.finding("onchain-contract-upgradeable", Severity.LOW,
                    "The deployed contract can replace its own code",
                    "The contract exposes an upgrade entry point, so its administrator can swap the WASM after this "
                    "review. The review applies to the WASM hash recorded below only.",
                    evidence=f"{contract.get('contract_id')}: wasm {contract.get('wasm_hash')}",
                    remediation="Bind credentials to the WASM hash, gate upgrade behind a timelock or multisig, "
                                "and re-review after every upgrade."))
            if contract.get("code") in {"archived_or_missing", "too_large"}:
                out.append(self.finding("onchain-contract-code-unavailable", Severity.MEDIUM,
                    "The deployed contract code could not be read",
                    "The ledger references a WASM that is archived or too large to fetch, so its functions were not inspected.",
                    evidence=f"{contract.get('contract_id')}: {contract.get('code')}",
                    remediation="Restore the contract code entry or supply the source and build attestation."
                    ).model_copy(update={"kind": FindingKind.EVIDENCE_GAP}))
        binding = facts.get("source_binding") or {}
        if binding.get("onchain") and not binding.get("verified"):
            how = {"wasm_metadata": "only named in the WASM metadata", "unbound_card": "named in an unregistered card",
                   "registry_card": "named in the registry card by branch, not by commit",
                   "user_supplied": "supplied by the requester", "none": "not identified"}.get(binding.get("binding"), "not proven")
            out.append(self.finding("onchain-source-unbound", Severity.MEDIUM,
                "The reviewed source is not proven to be the deployed agent",
                f"The source repository is {how}. Nothing ties the reviewed commit to the code or identity on chain, "
                "so a pass would describe the repository, not the deployed agent.",
                evidence=f"binding={binding.get('binding')}",
                remediation="Publish a GitHub build attestation for the WASM hash (SEP-55 style), or register the agent "
                            "with a card that pins the commit and whose hash the registry records."
                ).model_copy(update={"kind": FindingKind.EVIDENCE_GAP}))
        return out
