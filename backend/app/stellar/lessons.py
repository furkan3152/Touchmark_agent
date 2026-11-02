"""Lessons learned from defects the audit missed, and the Stellar criteria a file needs.

The review used to be offered the Stellar reference as a tool it could call; on real defects
fixed upstream it often did not, and missed bugs the reference describes. Now each file the
focused review examines gets, in its prompt, the reference topics and the lessons that match
what the file map says the file does. A file that verifies signatures gets the SEP-10 lesson; a
file that submits transactions gets the fee-bump lesson; and so on.

To add a lesson after a new miss: one entry in LESSONS with the capability kinds it applies to
(services/file_map.py CAPABILITY_KINDS), a short title, and what to check. Keep lessons general
Stellar behaviour, never a description of one repository.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import knowledge

#: file-map capability kind -> Stellar reference topics (stellar/knowledge.py).
TOPICS_BY_KIND = {
    "moves_value": ("payments",),
    "verifies_incoming_payment": ("payments", "transaction_lifecycle", "anchors"),
    "signs_transactions": ("transaction_lifecycle", "endpoints"),
    "submits_transactions": ("transaction_lifecycle", "endpoints"),
    "builds_from_external_xdr": ("transaction_lifecycle", "soroban_auth"),
    "signs_raw_bytes": ("key_management",),
    "holds_or_loads_secret": ("key_management",),
    "changes_account_authority": ("multisig", "trustlines_and_assets"),
    "invokes_contract": ("soroban_auth",),
    "authenticates_callers": ("web_auth", "multisig"),
}


@dataclass(frozen=True)
class Lesson:
    id: str
    kinds: frozenset
    title: str
    check: str


def _l(id, kinds, title, check):
    return Lesson(id, frozenset(kinds), title, check)


LESSONS: tuple[Lesson, ...] = (
    _l("feebump-rewrap", {"submits_transactions", "signs_transactions"},
       "A fee-bumped payment can land under another hash",
       "Anyone holding the signed inner transaction can wrap it in a new fee bump. If the code treats a 404 or "
       "timeout for the hash it submitted as 'did not land' and rebuilds or re-signs, the payment can be made twice. "
       "Reconciliation must use the inner hash or whether the source sequence number was consumed."),
    _l("unknown-outcome-unlock", {"submits_transactions", "moves_value"},
       "An unknown submission outcome must not release the payment for retry",
       "On a timeout, 504 or error after sending, the transaction may still land. Unlocking the job, the channel "
       "account or the payment record for a new attempt before the outcome is known pays twice."),
    _l("sep10-client-signature", {"authenticates_callers"},
       "SEP-10/45 verification must require a real client signature",
       "Attribute each signature to exactly one expected signer, require at least one client signer, never count "
       "the server's own signature, reject duplicates and unmatched signatures. A default account (thresholds 0) "
       "must not authenticate with no signature at all."),
    _l("signed-params-boundary", {"authenticates_callers", "builds_from_external_xdr"},
       "Only what was signed is verified",
       "When a signed URI, message or request is verified, every parameter the code then uses must be covered by "
       "the signature. Parameters appended after the signature, or parsed from a different copy, are attacker data."),
    _l("soroban-invoker-auth", {"invokes_contract", "authenticates_callers"},
       "require_auth passes without a signature for the direct invoker",
       "In __check_auth or a policy, a delegated or contract signer authenticated with require_auth is satisfied "
       "when that contract is the invoker. Self-delegation or two accounts delegating to each other authorize "
       "without a key; reject a delegated signer that is the invoker or the contract of an authorized context."),
    _l("sponsored-contract-authorizer", {"builds_from_external_xdr", "invokes_contract"},
       "A sponsor must check contract authorizers too",
       "When the agent pays the fees of an invocation someone else built, check every auth entry's credential, "
       "including contract addresses (their __check_auth runs on the sponsor's fees), the invoked contract and "
       "function, and bound the resource fee."),
    _l("issuer-and-amount-received", {"verifies_incoming_payment", "moves_value"},
       "Credit what was received, in the asset that was received",
       "A deposit, swap or path payment must be credited with the amount actually received (path payments: the "
       "destination amount) in the asset matched by code AND issuer, not the requested or quoted amount."),
    _l("failure-path-state", {"submits_transactions", "moves_value", "verifies_incoming_payment"},
       "Every failure path must leave state consistent",
       "After a rejection, a FAILED result or an exception, check what each branch leaves: a debit with no refund, "
       "a 'pending' or 'settling' marker that blocks all later requests, a record marked paid that was not."),
    _l("rounding-direction", {"moves_value", "invokes_contract"},
       "Fees, shares and swap amounts must round in the protocol's favour",
       "Integer division truncates. A fee computed as floor(amount * rate / base) is zero for small amounts, so a "
       "swap split into small pieces pays no fee; shares minted with floor() can be zero while the deposit is "
       "taken. Check the rounding direction of every fee, share, price and invariant calculation, and that a "
       "result of zero is rejected where it would give value away."),
    _l("cross-tenant-lookup", {"authenticates_callers", "moves_value"},
       "Every lookup is scoped to the caller",
       "A transaction, account or API key read by id must be checked against the authenticated caller and tenant; "
       "caches keyed without the tenant and headers that select the tenant are cross-user access."),
)


def for_card(card: dict) -> tuple[list[str], list[Lesson]]:
    """(reference topics, lessons) for a file-map card."""
    kinds = {c.get("kind") for c in (card or {}).get("capabilities", [])}
    topics = list(dict.fromkeys(t for k in kinds for t in TOPICS_BY_KIND.get(k, ())))
    lessons = [lesson for lesson in LESSONS if lesson.kinds & kinds]
    return topics, lessons


def prompt_block(card: dict, *, max_chars: int = 9000) -> str:
    """The Stellar criteria and lessons to place in a focused file review, or "" when none apply."""
    topics, lessons = for_card(card)
    if not topics and not lessons:
        return ""
    parts = []
    if lessons:
        parts.append("Lessons from real Stellar defects that this file's capabilities make relevant (check each):\n"
                     + "\n".join(f"- {lesson.title}: {lesson.check}" for lesson in lessons))
    if topics:
        parts.append("Stellar criteria for this file:\n" + "\n\n".join(knowledge.reference(t) for t in topics))
    return "\n\n".join(parts)[:max_chars]
