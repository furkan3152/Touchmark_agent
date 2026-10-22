"""Stellar/Soroban'a özgü agent ve entegrasyon denetçisi."""

from __future__ import annotations

import re

from ..models import FindingKind, AgentArtifact, Dimension, EvidenceGrade, Finding, ScenarioResult, Severity, SourceKind
from ..stellar.wasm_profile import (AUTH, AUTH_CALLS, CALL, DELEGATED_SIGNERS, EXECUTABLE_TAG, EXTERNAL_REF,
                                    HOST_ENTRY_POINTS, PUT_DATA, SDK_EXPORTS, UPGRADE)
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
        # A .rs file outside every crate is not built or deployed: a sample or fixture (an
        # auditor's test inputs, a stray draft). Only crate sources are judged as contracts.
        crates = {name.rsplit('/', 1)[0] if '/' in name else '' for name, text in artifact.code_files.items()
                  if name.endswith('Cargo.toml') and re.search(r'soroban-sdk|\[workspace\]', text)}
        if crates or artifact.source_kind == SourceKind.REPO:
            # A repository with no Soroban crate builds no contract from its loose .rs files, and
            # in a Rust workspace only the files that use soroban_sdk are contract code: a CLI or
            # wallet crate next to the contracts is not.
            rust_files = {name: content for name, content in rust_files.items()
                          if any(c == '' or name.startswith(c + '/') for c in crates)
                          and re.search(r'\bsoroban_sdk\b|#\[contract', content)}
        rust = '\n'.join(_rust_code(content) for content in rust_files.values())
        # Entry points are the public functions of a #[contractimpl] block; a crate's client or
        # helper modules that only use soroban_sdk types expose none.
        functions = [{**fn, 'file': name} for name, content in rust_files.items()
                     if artifact.source_kind != SourceKind.REPO or '#[contractimpl' in content
                     for fn in _rust_functions(content)]
        lower = surface.lower()

        from stellar_sdk import StrKey
        sources = {**artifact.code_files, "<system prompt>": artifact.system_prompt or ""}
        seeds = [
            (name, content[:m.start()].count(chr(10)) + 1, m.group(0))
            for name, content in sources.items()
            for m in re.finditer(r"\bS[A-Z2-7]{55}\b", content)
            if StrKey.is_valid_ed25519_secret_seed(m.group(0))  # placeholders fail the checksum
        ]
        # Seeds in committed files outside the analysed source (key files, notes), located
        # during repository selection; only their redacted locations are passed on.
        committed = list(artifact.raw_metadata.get("committed_seeds") or [])
        seed_locations = ([f"{n}:{line} (S{s[1:5]}…redacted)" for n, line, s in seeds] + committed)[:5]
        test_only = bool(seeds or committed) and all(
            re.search(r"(^|/)(tests?|spec|fixtures?|examples?|scripts)/|test|spec|smoke|example|fixture", n, re.I)
            for n in [n for n, _, _ in seeds] + [c.split(":", 1)[0] for c in committed])
        seeds = seeds or committed
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
                # Hand audits rated these medium or low: a lexical gap, not a shown bypass.
                Severity.MEDIUM if auth_hard else Severity.LOW,
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

        # Per-record entries (a key with an id: Channel(id), Balance(addr)) in instance storage:
        # the instance is one ledger entry, loaded on every call and size-limited, so records
        # that grow with use make every call costlier and can lock the contract.
        records = [f"{name}:{content[:m.start()].count(chr(10)) + 1}"
                   for name, content in rust_files.items() if '#[contractimpl' in content
                   for m in re.finditer(r"\.instance\(\)\s*\.set\(\s*&\s*(?:\w+::)?\w+\(\s*[^)\s]", _rust_code(content))]
        if records:
            findings.append(self.finding(
                "instance-storage-records",
                Severity.MEDIUM,
                "Per-record state is kept in instance storage",
                "Entries keyed by an id or address are written to the contract instance. The instance is a single "
                "ledger entry that every call loads and that has a size limit, so records that grow with use raise the "
                "cost of every call and can make the contract unusable; they also share the instance's lifetime.",
                evidence="; ".join(records[:6]),
                remediation="Keep per-user and per-record data in persistent storage, each entry with its own TTL "
                            "extension, and keep instance storage for small contract-wide configuration.",
                grade=EvidenceGrade.CONFIRMED,
                confidence=0.85,
            ))

        if ttl_gaps:
            finding = self.finding(
                "persistent-ttl",
                # Archived entries can be restored: a liveness and cost risk, not a loss of funds.
                Severity.MEDIUM if ttl_hard else Severity.LOW,
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

        # Only an ingestion loop loses events: polling getEvents and acting on what it returns.
        # A tool that answers one query with getEvents keeps no state to lose.
        code_l = "\n".join(artifact.code_files.values()).lower()
        polls = re.search(r"getevents[\s\S]{0,1500}?(?:setinterval|while\s*\(|while\s+true|asyncio\.sleep|cron|schedule|subscribe)|"
                          r"(?:setinterval|while\s*\(|while\s+true|cron|schedule)[\s\S]{0,1500}?getevents", code_l)
        if "getevents" in lower and polls and not re.search(r"cursor|pagingtoken|sqlite|dedup|unique", lower):
            findings.append(
                self.finding(
                    "event-cursor-missing",
                    Severity.MEDIUM,
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
        # "Smart wallet" and "/auth" are generic (ERC-4337 wallets, any login route); the
        # boundary only exists when the code itself is Stellar code.
        stellar_code = re.search(r"stellar[-_]sdk|@stellar/|soroban|\bsep-?10\b|challenge_transaction|horizon\.server|"
                                 r"new\s+horizon\b|horizon[-.\w]*\.stellar\.org|freighter|stellar-wallets-kit",
                                 "\n".join(artifact.code_files.values()).lower())
        if contract_accounts and web_auth and stellar_code:
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

        # Only a real SEP-24 client counts: the interactive endpoints or the anchor's SEP-24 server.
        sep24_code = re.search(r"transactions/(?:deposit|withdraw)/interactive|TRANSFER_SERVER_SEP0024|sep24",
                               "\n".join(artifact.code_files.values()), re.I)
        if sep24_code and "payout" in lower and "sep-31" not in lower and "sep31" not in lower:
            findings.append(
                self.finding(
                    "sep24-payout-confusion",
                    Severity.MEDIUM,
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
            # A raw /transactions/{id} URL counts only on a Horizon base: anchors (SEP-6/24) expose
            # the same path for their own transfer records.
            looks_up = re.search(r"\.transactions\(\)\s*\.\s*transaction\(|forTransaction\(|for_transaction\(|"
                                 r"horizon[^\n]{0,80}/transactions/(?:\$\{|\{)|get_transaction\(|getTransaction\(", content, re.I)
            pays = re.search(r"\bamount\b", content) and re.search(r"destination|payTo|pay_to|\.to\b|recipient", content)
            verifies = re.search(r"verif|validat", name + content[:4000], re.I)
            checks = re.search(r"\.successful\b|\[[\"']successful[\"']\]|[\"']SUCCESS[\"']|transaction_successful|"
                               r"status\s*[!=]==?\s*[\"']success[\"']|[\"']success[\"']\s*[!=]==?\s*[\w.]*status", content)
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
            # A literal missing on the audited network is usually an asset issuer, a documentation
            # example or a mainnet address checked on testnet; a payment to it fails without loss.
        out += self._contract_findings(artifact, facts.get("contract") or {})
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

    # ------------------------------------------------------------ deployed contract code
    def _contract_findings(self, artifact: AgentArtifact, contract: dict) -> list[Finding]:
        """Findings from the deployed executable: who can replace it, and what its bytecode lets
        a caller reach without authentication (wasm_profile call graph)."""
        cid = contract.get("contract_id", "")
        if contract.get("status") == "unreadable" or contract.get("executable") == "unknown":
            return [_gap(self.finding("onchain-contract-code-unresolved", Severity.MEDIUM,
                "The deployed contract's executable could not be read",
                "The contract instance on the ledger could not be decoded, so the code it runs is unknown.",
                evidence=f"{cid}: {contract.get('error') or 'executable ' + str(contract.get('executable'))}",
                remediation="Re-run the review when the instance can be read, or supply the WASM and its hash."))]
        if contract.get("status") != "found" or contract.get("executable") not in {"wasm", "external_ref"}:
            return []
        out: list[Finding] = []
        if contract.get("executable") == "external_ref":
            out += self._external_ref_findings(artifact, contract)
            if contract["external_ref"].get("status") != "resolved":
                return out
        profile = contract.get("profile") or {}
        exports: dict = profile.get("exports") or {}
        where = f"{cid}: wasm {contract.get('wasm_hash')}"
        risks, notes = _upgrade_risks(profile, contract.get("functions"))
        if risks:
            out.append(self._unauthenticated_upgrade(risks, where))
        elif contract.get("upgradeable"):
            paths = [p for r in exports.values() for c, p in sorted(r["paths"].items()) if c in UPGRADE]
            if paths:
                how = "; ".join(paths[:4])
            elif profile:
                how = "imports " + ", ".join(sorted(set(profile.get("imports", [])) & UPGRADE))
            else:
                how = "an upgrade entry point is named in the spec (the imports could not be read)"
            out.append(self.finding("onchain-contract-upgradeable", Severity.LOW,
                "The deployed contract can replace its own code",
                "The contract can call update_current_contract_wasm or update_current_contract_executable_ref, so "
                "whoever controls its upgrade path can swap the WASM after this review. The review applies to the "
                "WASM hash recorded below only."
                + (" Not proven from the bytecode: " + "; ".join(notes[:3]) + "." if notes else ""),
                evidence=f"{where}; {how}",
                remediation="Bind credentials to the WASM hash, gate upgrade behind a timelock or multisig, "
                            "and re-review after every upgrade."))
        if contract.get("code") in {"archived_or_missing", "too_large"}:
            out.append(_gap(self.finding("onchain-contract-code-unavailable", Severity.MEDIUM,
                "The deployed contract code could not be read",
                "The ledger references a WASM that is archived or too large to fetch, so its functions were not inspected.",
                evidence=f"{cid}: {contract.get('code')}",
                remediation="Restore the contract code entry or supply the source and build attestation.")))
        if not profile:
            return out
        if profile.get("manages_external_refs"):
            out.append(self.finding("onchain-contract-manages-external-refs", Severity.INFO,
                "The contract publishes executable references (CAP-85)",
                "It imports create_executable_tag or create_external_ref_contract, so other contracts can run code "
                "this contract names, and it can deploy contracts whose code it controls.",
                evidence=f"{where}; imports " + ", ".join(i for i in profile.get("imports", []) if i in EXTERNAL_REF),
                remediation="Declare which contracts run code from this contract's entries and who may change them."))
        out += self._interface_findings(profile, exports, where, {name for _, name, _ in risks})
        check = exports.get("__check_auth")
        if (check and profile.get("delegates_read", DELEGATED_SIGNERS in check["reaches"])
                and not set(check["reaches"]) & AUTH_CALLS and not check["indirect"]):
            out.append(self.finding("onchain-contract-delegates-unauthenticated", Severity.HIGH,
                "The custom account reads delegated signers but never authenticates them",
                "__check_auth calls get_delegated_signers_for_current_auth_check, whose addresses come from whoever "
                "submits the transaction, and no call path reaches delegate_account_auth or require_auth. If the "
                "account counts those signers toward authorization, anyone can name a signer it trusts.",
                evidence=f"{where}; {check['paths'].get(DELEGATED_SIGNERS)}",
                remediation="Call delegate_account_auth for every delegated signer, after checking that it belongs "
                            "to the account.", grade=EvidenceGrade.INFERRED))
        return out

    def _external_ref_findings(self, artifact: AgentArtifact, contract: dict) -> list[Finding]:
        cid, ref = contract.get("contract_id", ""), contract["external_ref"]
        owner, tag, status = ref.get("owner", ""), ref.get("tag", ""), ref.get("status")
        out: list[Finding] = []
        if status != "resolved":
            why = {"missing": "the owner has no entry for this tag (or it was never published)",
                   "malformed": "the entry does not hold a 32-byte WASM hash",
                   "unavailable": "the RPC could not read the entry"}.get(status, str(status))
            out.append(_gap(self.finding("onchain-contract-code-unresolved", Severity.MEDIUM,
                "The code this contract runs could not be resolved",
                f"Its executable is a CAP-85 reference to tag {tag!r} of {owner or 'an unreadable owner'}, and {why}. "
                "The contract runs whatever WASM that entry names when it is called, so its code was not reviewed.",
                evidence=f"{cid}: external_ref owner={owner} tag={tag!r} status={status}",
                remediation="Publish the entry (or restore it), or deploy the agent with its own WASM executable.")))
        if not owner:
            return out
        declared = owner == cid or owner in _declared_addresses(artifact)
        owner_facts = ref.get("owner_contract") or {}
        owner_profile = contract.get("profile") if owner == cid else owner_facts.get("profile")
        notes = []
        if not declared and owner_facts.get("executable") == "external_ref":
            nested = owner_facts.get("external_ref") or {}
            notes.append(f"the owner's own code is a reference to tag {nested.get('tag')!r} of {nested.get('owner')}, "
                         "which was not followed")
        if not declared and (owner_profile or {}).get("can_upgrade"):
            notes.append("the owner can also replace its own code")
        if owner_facts.get("status") in {"unavailable", "unreadable", "not_a_contract", "not_found"}:
            notes.append(f"the owner could not be inspected ({owner_facts['status']})")
        severity, grade = (Severity.LOW if declared else Severity.MEDIUM), EvidenceGrade.CONFIRMED
        writer = _unauthenticated_tag_writer(owner_profile)
        if writer:
            severity, grade = Severity.HIGH, EvidenceGrade.INFERRED
            notes.append("an owner entry point can write executable entries with no authentication on its call "
                         f"paths, so anyone may be able to repoint this contract: {writer} (an owner that refuses to "
                         "overwrite a published tag would be safe; the bytecode does not show that)")
        owner_risks = _upgrade_risks(owner_profile, owner_facts.get("functions"))[0] if owner != cid else []
        if owner_risks:
            severity, grade = Severity.HIGH, EvidenceGrade.INFERRED
            notes.append("the owner's own upgrade needs no authentication, so anyone may be able to replace the "
                         f"owner's code and then rewrite its entries: {owner_risks[0][2]}")
        who = ("the contract itself" if owner == cid else "the declared authority" if declared
               else "a contract the .tmark does not declare")
        out.append(self.finding("onchain-contract-code-externally-controlled", severity,
            "The contract runs code that another contract's entry names" if owner != cid
            else "The contract runs code named by its own executable entry",
            f"Its executable is a CAP-85 external reference: each call runs the WASM named by tag {tag!r} in the "
            f"storage of {owner}, which is {who}. Whoever can rewrite that entry changes this agent's code for every "
            "later call, with no action by the agent. The review applies to the WASM the entry named when it was read."
            + (" Also: " + "; ".join(notes) + "." if notes else ""),
            evidence=f"{cid}: external_ref owner={owner} tag={tag!r} resolved wasm {ref.get('resolved_wasm_hash', '-')} "
                     f"(entry last modified at ledger {ref.get('tag_last_modified_ledger')})",
            remediation="Declare the executable owner and who controls its entries, bind credentials to the resolved "
                        "WASM hash and re-review when the entry changes, or deploy the agent with its own WASM.",
            grade=grade))
        return out

    def _unauthenticated_upgrade(self, risks: list[tuple[Severity, str, str]], where: str) -> Finding:
        severity = max((s for s, _, _ in risks), key=lambda s: s.rank)
        critical = severity is Severity.CRITICAL
        return self.finding("onchain-contract-upgrade-unauthenticated", severity,
            "Anyone can replace the deployed contract's code" if critical
            else "The contract's upgrade can be steered without authentication",
            "An exported function reaches update_current_contract_wasm or update_current_contract_executable_ref, and "
            "none of its call paths reaches require_auth, a signature check, another contract or an indirect call. "
            + ("It installs the WASM hash its caller passes and nothing checks that hash, so anyone can install "
               "their own code and take whatever the contract holds or controls." if critical else
               "The code it installs is read from storage or checked against a stored value, and an export with no "
               "authentication either stores a caller-supplied value of that kind, so anyone may be able to choose "
               "the code. Check whether that export writes the entry the upgrade reads."),
            evidence=f"{where}; " + "; ".join(text for _, _, text in risks[:4]),
            remediation="Require the administrator's authorization (require_auth) in every upgrade path, or a "
                        "timelock whose schedule step is authenticated.",
            grade=EvidenceGrade.CONFIRMED if critical else EvidenceGrade.INFERRED)

    def _interface_findings(self, profile: dict, exports: dict, where: str, upgrade_reported: set[str]) -> list[Finding]:
        """The exports compared with the contract spec (contractspecv0) the WASM publishes."""
        out: list[Finding] = []
        hidden = profile.get("hidden_exports") or []
        callable_exports = [n for n in profile.get("function_exports", []) if n not in SDK_EXPORTS]
        if "hidden_exports" not in profile and callable_exports:
            out.append(_gap(self.finding("onchain-contract-spec-missing", Severity.LOW,
                "The deployed contract publishes no interface spec",
                "The WASM has no readable contractspecv0 functions, so its exports cannot be compared with a "
                "published interface and hidden entry points cannot be ruled out.",
                evidence=f"{where}; exports " + ", ".join(callable_exports[:10]),
                remediation="Build with the Soroban SDK so the spec is embedded, and keep it in the deployed WASM.")))
        if hidden:
            # An unlisted export that writes storage, calls out or upgrades with no authentication on its
            # paths is HIGH; one whose upgrade is already reported, or that authenticates, is MEDIUM.
            risky = {n: p for n in hidden if n not in upgrade_reported
                     and not set((exports.get(n) or {}).get("reaches", [])) & AUTH
                     for c, p in sorted((exports.get(n) or {}).get("paths", {}).items()) if c in UPGRADE | CALL | {PUT_DATA}}
            reported = [n for n in hidden if n in upgrade_reported]
            out.append(self.finding("onchain-contract-hidden-export", Severity.HIGH if risky else Severity.MEDIUM,
                "The deployed contract exports functions its published interface does not list",
                "Wallets, clients and reviewers see the contractspecv0 interface; these exports are not in it but "
                "anyone can still invoke them by name."
                + (" With no authentication on their call paths, they can write storage, call other contracts or "
                   "replace the code." if risky else "")
                + (f" The unauthenticated upgrade in {', '.join(reported)} is reported separately." if reported else ""),
                evidence=f"{where}; hidden: {', '.join(hidden[:10])}"
                         + (f"; {'; '.join(list(risky.values())[:3])}" if risky else ""),
                remediation="Remove the unlisted exports or publish them in the spec, and explain why they exist."))
        if profile.get("spec_only"):
            out.append(self.finding("onchain-contract-spec-only", Severity.INFO,
                "The contract spec lists functions the code does not export",
                "Calls to them fail: the published interface does not match the deployed code.",
                evidence=f"{where}; spec only: {', '.join(profile['spec_only'][:10])}",
                remediation="Publish the spec generated from the deployed source."))
        return out


def _gap(finding: Finding) -> Finding:
    return finding.model_copy(update={"kind": FindingKind.EVIDENCE_GAP})


def _declared_addresses(artifact: AgentArtifact) -> set[str]:
    """Addresses the .tmark names for the agent: its owner account and its agent account."""
    declared = ((artifact.raw_metadata or {}).get("tmark") or {}).get("declared") or {}
    return {a for a in ((declared.get("owner") or {}).get("stellar_account"),
                        (declared.get("authority") or {}).get("agent_account"), artifact.agent_contract_id) if a}


#: Exports that write their arguments once before the contract is used (old-style initialisers).
_INITIALIZER = re.compile(r"^_*init(?:iali[sz]e)?(?:_|$)", re.IGNORECASE)
#: Spec input types the code an upgrade installs can be stored as: the WASM hash for
#: update_current_contract_wasm, the owner or tag for update_current_contract_executable_ref.
_CODE_TYPES = {"l.6": frozenset({"bytes32", "bytes"}), "l.j": frozenset({"address", "string"})}


def _open(reach: dict) -> bool:
    """No authentication, signature check, contract call or indirect call on any call path."""
    return not set(reach["reaches"]) & (AUTH | CALL) and not reach["indirect"]


def _upgrade_risks(profile: dict | None, functions: list[dict] | None) -> tuple[list[tuple[Severity, str, str]], list[str]]:
    """Upgrade exports the bytecode shows anyone can steer, as (severity, export, evidence),
    and notes on unauthenticated upgrade exports it cannot decide (those raise no risk).

    CRITICAL: the WASM hash (or executable owner) comes from the caller's argument and no host
    function that could check it sees that argument. HIGH: the code comes from storage, or
    the argument is checked against something, and another unauthenticated export stores a
    caller-supplied value of a type the code is stored as. Anything else is a note."""
    exports = (profile or {}).get("exports") or {}
    inputs = {f["name"]: f.get("inputs", []) for f in functions or []}
    risks: list[tuple[Severity, str, str]] = []
    notes: list[str] = []
    for name, reach in sorted(exports.items()):
        upgrades = set(reach["reaches"]) & UPGRADE
        if name in HOST_ENTRY_POINTS or not upgrades or set(reach["reaches"]) & AUTH:
            continue
        if not _open(reach):
            notes.append(f"{name} has no authentication of its own, and another contract or an indirect call "
                         "may hold the check")
            continue
        flows = reach.get("flows")
        if flows is None:
            notes.append(f"{name} needs no authentication, and where the code it installs comes from was not traced")
            continue
        path = "; ".join(reach["paths"][c] for c in sorted(upgrades))
        args = inputs.get(name)
        named = ", ".join(_argument(args, i) for i in flows["upgrade_code"])
        if flows["upgrade_code"] and not flows.get("upgrade_code_checked"):
            risks.append((Severity.CRITICAL, name, f"{path} (installs the {named} its caller passes, unchecked)"))
            continue
        writers = _code_writers(exports, inputs, upgrades)
        if flows["upgrade_code"]:
            how = f"installs the {named} its caller passes after passing it to a host function that can check it"
        elif flows["upgrade_tag"]:
            how = "installs the owner's tag its caller names"
        elif flows["upgrade_from_storage"]:
            how = "installs code read from storage"
        else:
            how = "installs code that does not come from its arguments"
        if writers and (flows["upgrade_code"] or flows["upgrade_from_storage"]):
            risks.append((Severity.HIGH, name, f"{path} ({how}; {', '.join(writers[:3])} without authentication)"))
        else:
            notes.append(f"{name} needs no authentication and {how}; no unauthenticated export stores a value it "
                         "could install")
    return risks, notes


def _argument(args: list[dict] | None, index: int) -> str:
    if args and index < len(args):
        return f"argument {args[index]['name']} ({args[index]['type']})"
    return f"argument {index}"


def _code_writers(exports: dict, inputs: dict, upgrades: set[str]) -> list[str]:
    """Unauthenticated exports (not initialisers) that store one of their own arguments, of a
    type the upgrade's code can be stored as (any type when the export is not in the spec).
    The upgrade export itself counts only this way: writing a constant (an operation marked
    done) is not choosing code."""
    kinds = frozenset().union(*(_CODE_TYPES[c] for c in upgrades))
    out = []
    for name, reach in sorted(exports.items()):
        if name in HOST_ENTRY_POINTS or _INITIALIZER.match(name) or not _open(reach):
            continue
        args = inputs.get(name)
        stored = [i for i in (reach.get("flows") or {}).get("stores", [])
                  if args is None or (i < len(args) and args[i]["type"] in kinds)]
        if stored:
            out.append(f"{name} stores its {', '.join(_argument(args, i) for i in stored)}")
    return out


def _unauthenticated_tag_writer(profile: dict | None) -> str:
    """An owner entry point (not an initialiser) that writes a caller-supplied value under a
    create_executable_tag key, with no authentication, contract call or indirect call on its
    paths. Without a data flow the reach alone counts; without a call graph, the imports."""
    if not profile:
        return ""
    exports = profile.get("exports")
    if exports is not None:
        for name, reach in exports.items():
            flows = reach.get("flows")
            if (name not in HOST_ENTRY_POINTS and not _INITIALIZER.match(name)
                    and {EXECUTABLE_TAG, PUT_DATA} <= set(reach["reaches"]) and _open(reach)
                    and (flows is None or flows["tag_writes"])):
                return f"{reach['paths'][EXECUTABLE_TAG]}; {reach['paths'][PUT_DATA]}"
        return ""
    imports = set(profile.get("imports", []))
    if {EXECUTABLE_TAG, PUT_DATA} <= imports and not imports & (AUTH | CALL):
        return ("the owner imports create_executable_tag and put_contract_data and no authentication, signature "
                "check or contract call")
    return ""
