"""English presentation for legacy rule messages; original source evidence is retained."""
from ..models import Finding

# Rule IDs are stable. This wording describes scope rather than claiming exploit success.
MESSAGES = {
"security-no-auditable-surface": ("No auditable security surface", "No instructions, implementation or endpoint were supplied; security checks lack sufficient evidence.", "Supply the agent instructions, source and tool manifest."),
"security-no-isolation": ("Sandbox evidence missing", "The supplied material does not show execution isolation. Absence of a signal is not proof of an exploitable runtime.", "Isolate tool execution and provide resource, filesystem and network restrictions."),
"security-unbounded-spend": ("Spending tools have no declared limit", "One or more financial tools lack an explicit spending ceiling in their submitted configuration.", "Enforce per-action and cumulative limits outside the model, using integer asset units."),
"security-dangerous-tools": ("Code or command execution tools", "The manifest exposes tools capable of executing code or host commands.", "Restrict command arguments and execute in an isolated runtime with minimal authority."),
"security-broad-scopes": ("Overly broad tool permissions", "The submitted scopes grant broad authority that may exceed the intended task.", "Replace wildcard scopes with explicit permitted actions and resources."),
"security-all-tools-networked": ("All tools declare network access", "Every declared tool has network access, increasing the potential exfiltration surface.", "Disable network access where unnecessary and enforce destination allowlists."),
"security-unpinned-deps": ("Unpinned dependencies", "Some dependency specifications do not identify an exact reproducible version.", "Pin versions and commit a lockfile with integrity hashes."),
"security-typosquat-suspect": ("Potentially deceptive package name", "A package name matches the rule's suspicious-name list. This is a review signal, not a verified malware determination.", "Verify package ownership, provenance and integrity before installation."),
"security-vcs-deps": ("Dependencies fetched from a URL or VCS", "A dependency is obtained outside a normal pinned registry release.", "Pin a reviewed commit and verify source and build integrity."),
"reliability-no-endpoint": ("Runtime endpoint not supplied", "Availability, latency and runtime behavior could not be measured.", "Provide an authorized isolated staging target for runtime testing."),
"reliability-endpoint-down": ("Endpoint could not be reached", "The configured endpoint did not provide the expected response during the check.", "Inspect endpoint availability and reproduce the failure from the deployment network."),
"reliability-high-latency": ("High observed latency", "The endpoint check exceeded the auditor's latency threshold.", "Measure latency under representative load and enforce timeouts."),
"reliability-unauthenticated-endpoint": ("Endpoint authentication evidence missing", "The endpoint configuration does not demonstrate required authentication.", "Require scoped authentication for sensitive actions and test unauthorized access."),
"reliability-no-error-handling": ("Error handling evidence missing", "The submitted source lacks recognized error-handling signals.", "Add bounded retries, explicit failure states and dependency-failure tests."),
"reliability-no-cost-controls": ("Resource budget evidence missing", "No recognized execution-cost or rate-control signal was found.", "Bound tokens, steps, recursion, concurrency and execution time."),
"reliability-flaky-endpoint": ("Inconsistent endpoint responses", "Endpoint checks produced inconsistent availability results.", "Investigate failures and add resilience tests with explicit success criteria."),
"provenance-missing-lockfile": ("Dependency lockfile missing", "The supplied evidence does not contain a recognized dependency lockfile.", "Include a complete lockfile and verify it against the deployed build."),
"provenance-no-release-pipeline": ("Release provenance not established", "A verifiable build and release pipeline was not found in the supplied scope.", "Provide CI configuration, artifact digests and signed release provenance."),
"provenance-license-missing": ("License evidence missing", "No recognized license file was found in the supplied files.", "Include the project license and dependency license inventory."),
"provenance-floating-dependencies": ("Mutable build inputs", "Some dependency or build inputs can change without an agent source change.", "Pin dependencies and images to immutable digests."),
"provenance-sbom-missing": ("Software inventory missing", "No software bill of materials was supplied.", "Generate an SBOM for the exact release artifact and include it with the audit."),
"intent-no-system-prompt": ("System instructions missing", "The agent's instruction hierarchy was not supplied, limiting intent review.", "Provide the actual system instructions and permitted and prohibited actions."),
"intent-capability-tool-gap": ("Claimed capability has no declared tool", "The stated behavior and declared tool inventory do not fully align.", "Document how each capability maps to an executable tool and its permissions."),
"intent-no-planning-structure": ("Planning controls not evidenced", "The instructions lack a recognized structure for bounded multi-step execution.", "Define bounded steps, stop conditions and checks before consequential actions."),
"intent-no-uncertainty-guard": ("Uncertainty handling not evidenced", "The instructions do not show a recognized verification or uncertainty boundary.", "Require evidence checks and escalation when inputs or intent are ambiguous."),
"intent-no-scope-boundary": ("Task scope not bounded", "The supplied instructions do not clearly delimit the agent's allowed work.", "Define permitted goals, forbidden actions and execution-time authorization."),
"intent-conflicting-instructions": ("Conflicting instruction signals", "The submitted instructions contain signals that may conflict during decision-making.", "Resolve the instruction hierarchy and test conflicting goals with adversarial inputs."),
"intent-full-autonomy-over-funds": ("Autonomous authority over funds", "The declared behavior combines financial authority with insufficient oversight signals.", "Enforce independent approval and bounded transaction authority outside the model."),
"intent-scenario-failures": ("Behavioral defense signals missing", "One or more static behavioral checks found no recognized defense signal. These are not executed attacks.", "Test the listed scenarios in an authorized isolated environment and record observed actions."),
"intent-no-declared-intent": ("Intended behavior not declared", "There is insufficient description of the agent's purpose and permitted actions.", "Specify concrete tasks, boundaries and prohibited effects."),
"intent-thin-system-prompt": ("Instructions provide limited detail", "The supplied instruction text provides little evidence of behavioral boundaries.", "Document authority, data handling, failure behavior and escalation rules."),
"intent-undeclared-financial-capability": ("Financial authority is not disclosed", "Tool or source signals indicate financial capability not reflected in the declared intent.", "Disclose the capability and enforce explicit transaction limits and approvals."),
"economic-no-wallet": ("Agent wallet not supplied", "Financial history cannot be associated with a public account in this review.", "Supply a public address and a version-bound ownership proof; never supply a signing secret."),
"economic-no-chain-data": ("Behavioral chain history unavailable", "Account presence or balances alone do not establish transaction behavior.", "Provide indexed transaction history and evidence of its relationship to this agent."),
"economic-high-realised-slippage": ("High realized slippage", "Supplied transaction history exceeds the slippage threshold.", "Review execution quality and enforce slippage constraints before settlement."),
"economic-counterparty-concentration": ("Concentrated counterparties", "The supplied activity shows concentrated interaction with a small number of counterparties.", "Review concentration, related parties and counterparty limits."),
"economic-unbounded-trustlines": ("Trustline limits need review", "The activity summary identifies unbounded or unverified trustlines.", "Verify asset issuers, authorization, limits and revocation policy."),
"economic-flagged-counterparty": ("Flagged counterparty interaction", "The supplied activity reports interaction with a flagged counterparty.", "Validate the source and timestamp of the flag and investigate the transactions."),
"economic-high-failure-rate": ("High transaction failure ratio", "The activity summary exceeds the auditor's transaction failure threshold.", "Investigate failures and enforce bounded retries with idempotency."),
"economic-young-wallet": ("Limited wallet history", "The supplied account history covers a short observation period.", "Collect a longer representative history; do not interpret youth as misconduct."),
"economic-no-spend-policy": ("Spending policy not established", "An enforced spending policy is not demonstrated by the supplied evidence.", "Enforce recipient, amount, asset and cumulative budget constraints outside prompts."),
"economic-no-mev-protection": ("Execution-price protection missing", "The applicable trading surface lacks recognized slippage or execution-price controls.", "Use explicit minimum outputs, deadlines and simulation; assess the actual venue's ordering risks."),
"economic-single-large-outflow": ("Large single outflow", "A single outflow in the supplied history exceeds the auditor's concentration threshold.", "Review the payment and enforce transaction caps and independent approval."),
"compliance-no-ai-disclosure": ("AI identity not disclosed", "The submitted material does not demonstrate disclosure that the service is automated.", "Make the agent's automated nature and authority clear to affected users."),
"compliance-owner-unverified": ("Owner identity not verified", "A valid ownership binding has not been established for this agent and review.", "Provide a valid public-address ownership proof bound to this agent version."),
"compliance-no-record-keeping": ("Audit logging not evidenced", "The supplied source lacks recognized record-keeping signals.", "Record redacted, attributable actions with integrity, retention and access controls."),
"compliance-privacy-mode-off": ("Privacy mode not enabled", "The persistent audit pipeline's privacy masking mode is not enabled.", "Assess sensitive content before publishing reports and enable appropriate masking."),
"compliance-no-human-oversight": ("High-risk actions lack oversight evidence", "The declared high-risk use case does not establish independent human oversight.", "Bind approval to exact consequential actions and provide an emergency stop."),
"compliance-pii-without-safeguards": ("Personal data safeguards not evidenced", "Personal-data processing signals appear without recognized safeguards.", "Minimize data, isolate tenants, restrict egress and test redaction and deletion."),
"compliance-wallet-screening-unavailable": ("Wallet screening incomplete", "The configured checks do not provide complete wallet risk screening. No clearance is implied.", "Use appropriate current screening evidence and disclose coverage limitations."),
"compliance-wallet-screening-hit": ("High-risk wallet screening result", "A configured screening source returned a high-risk result; inspect the source evidence and timestamp.", "Validate the match and escalate for appropriate review before granting financial authority."),
"compliance-wallet-screening-medium": ("Wallet screening requires review", "A configured screening source returned an intermediate risk result.", "Investigate the source evidence and apply the relevant operating policy."),
"stellar_native-stellar-secret-seed": ("Stellar signing secret in source", "A source pattern matches a Stellar secret seed. Treat exposed signing authority as compromised.", "Rotate the key, remove it from source and history, and use an isolated signer."),
"stellar_native-persistent-ttl": ("Persistent storage TTL renewal missing", "The submitted contract does not show renewal for relevant persistent state. Since Protocol 23 an archived entry is restored automatically when a transaction next touches it, so a lapsed lifetime costs a restore fee, not the state.", "Implement and test TTL renewal and archived-entry restoration."),
"stellar_native-temporary-critical-state": ("Critical state may use temporary storage", "Storage signals suggest important records may disappear when temporary entries expire.", "Use appropriate persistent storage and test expiration and restoration behavior."),
"stellar_native-event-cursor-missing": ("Event cursor or deduplication missing", "The source lacks recognized durable cursor and replay-handling signals for Soroban events.", "Persist cursors and deduplicate by stable event identifiers."),
"stellar_native-sep24-payout-confusion": ("Interactive withdrawal may be used as payout", "The code may conflate interactive user withdrawals with third-party payout semantics.", "Verify the appropriate SEP flow and the anchor's supported operation."),
"stellar_native-hash-is-not-confirmation": ("Transaction hash may be treated as success", "A transaction identifier alone does not establish successful execution or the expected state change.", "Verify successful ledger inclusion and matching contract state or event readback."),
"stellar_native-sep45-boundary": ("Contract-account web authentication unclear", "The submitted material does not establish the contract-account authentication boundary.", "Use appropriate contract-account authorization and explicitly document web-session authentication."),
}


ATTACK_LABELS = [
    ("Direct prompt injection", "Instruction disclosure or override"),
    ("Indirect tool-output injection", "Instructions hidden in untrusted tool output"),
    ("Role manipulation", "Attempts to replace the agent's instruction hierarchy"),
    ("Secret extraction", "Attempts to extract credentials or environment secrets"),
    ("Privilege escalation", "Attempts to increase the agent's financial authority"),
    ("Resource exhaustion", "Unbounded retries or execution consuming the available budget"),
    ("Fund-drain path", "Transfers without validated recipients and amount ceilings"),
    ("Unsafe tool chaining", "Untrusted external content influencing code execution"),
    ("Owner impersonation", "Requests claiming owner authority without verification"),
    ("Long-context drift", "Loss of instruction or policy enforcement across a long session"),
]
for number, (title, risk) in enumerate(ATTACK_LABELS, 1):
    MESSAGES[f"security-a-{number:02}"] = (
        title, f"{risk}: the static defense-signal check did not find the expected protection. No attack was executed.",
        "Enforce this boundary outside the model and validate it with an authorized isolated negative test.")
MESSAGES.update({
"security-systemic-code-execution-wallet": ("Code execution and Stellar signing share authority", "The same agent combines command execution and wallet signing, increasing the consequence of tool compromise.", "Separate the signer from the execution sandbox and require narrowly scoped, independently approved transactions."),
"security-systemic-network-to-execution": ("Network input and execution authority combined", "The agent can consume external content and execute code. This combination creates a potential injection path even when individual tools appear acceptable.", "Treat external content as data; isolate execution and reject unapproved commands and arguments."),
"security-path-unenforced-financial-controls": ("Stellar financial controls not evidenced", "Signing tools are declared, but implementation-level financial controls are not demonstrated in the supplied source.", "Enforce authorization, recipient allowlists, limits and replay protection, and test rejection paths."),
})
CODE_MESSAGES = {
"Soroban authorization paths require review": ("Soroban authorization not evidenced", "A write-capable contract surface lacks recognized require_auth enforcement.", "Require authorization for the exact action arguments and add negative authorization tests."),
"eval() kullanımı": ("Dynamic eval() execution", "Dynamic evaluation can interpret untrusted input as executable code.", "Remove dynamic evaluation or isolate execution with strictly bounded input."),
"exec() kullanımı": ("Dynamic exec() execution", "Dynamic execution may allow untrusted content to become code.", "Remove dynamic execution and use explicit, typed operations."),
"shell=True ile subprocess": ("Subprocess invokes a shell", "Shell invocation increases command-injection risk if any argument is attacker-influenced.", "Use argument arrays with shell=False, validate each argument and isolate the process."),
"os.system() kullanımı": ("Host shell command execution", "A host shell command is executed. Inspect how command input is constructed.", "Use fixed executable paths and validated argument arrays in an isolated runtime."),
"TLS doğrulaması kapalı": ("TLS verification disabled", "The request configuration disables certificate verification.", "Enable certificate verification and use a trusted CA bundle."),
"Kodda gömülü özel anahtar": ("Signing secret embedded in source", "A source pattern resembles a hardcoded private key or mnemonic.", "Rotate exposed credentials and move signing authority into an isolated signer."),
"Kodda gömülü API anahtarı": ("API credential embedded in source", "A source pattern resembles a hardcoded API credential.", "Rotate the credential and load it from a secret manager with least privilege."),
"Doğrulanmamış varlık yetkisi": ("Untrusted asset or administrative authority", "An asset or administrative action appears to consume untrusted input.", "Require exact authorization and validate the asset, issuer and permitted action."),
"Aşırı yüksek slippage toleransı": ("Excessive slippage tolerance", "A trading parameter permits large adverse price movement.", "Set bounded slippage and validate the actual execution venue and minimum output."),
"Çıkışsız sonsuz döngü": ("Loop without an evident exit", "The source pattern contains an indefinite loop without a nearby recognized stop condition.", "Add iteration, time and resource bounds and test cancellation."),
"Kullanıcı girdisiyle birleştirilmiş URL": ("URL constructed from external input", "Input-derived URL construction may allow server-side request forgery.", "Allowlist destinations and reject private addresses, redirects and rebinding."),
}

# Support stable rule IDs and legacy code-pattern identifiers.
def english_finding(finding: Finding) -> Finding:
    message = MESSAGES.get(finding.id) or CODE_MESSAGES.get(finding.title)
    if message:
        title, detail, remediation = message
        return finding.model_copy(update={"title": title, "detail": detail, "remediation": remediation})
    return finding


def english_report(report) -> None:
    """Translate findings in place and keep the score breakdown's titles in step."""
    report.findings = [english_finding(f) for f in report.findings]
    titles = {f.id: f.title for f in report.findings}
    for item in (report.score_breakdown or {}).get("deductions", []):
        item["title"] = titles.get(item["id"], item.get("title", ""))
