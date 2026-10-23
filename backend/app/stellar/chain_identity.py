"""The on-chain identity an audit reviewed, as committed in its input hash.

A credential binds to the code and authority that were reviewed. For a contract agent that is
its executable: the WASM hash, or for a CAP-85 external reference the owner, tag and the hash
the tag named when read. For an account agent it is the signers, thresholds and flags. Both
carry the network passphrase.

The hash binds that identity, not one read of it. The ledger the facts were read at, and the
last-modified ledgers of the instance, the tag entry and the account, move with every counter
the contract writes and every payment the account receives, so they are left out (they stay
in the report's chain facts), as are balances and TTLs. An unchanged agent keeps its
commitment across audits; a new executable, tag target, signer, threshold or flag changes it.
"""

from __future__ import annotations

from .networks import NETWORKS

#: Fields whose change means a different agent: report_diff flags them on re-audit.
DRIFT_FIELDS = ("contract.executable", "contract.wasm_hash", "contract.external_ref.owner",
                "contract.external_ref.tag", "contract.external_ref.resolved_wasm_hash",
                "account.signers", "account.thresholds")


def chain_identity(chain: dict | None) -> dict:
    """The identity fields of chain_authority facts; empty when no agent was read on chain."""
    chain = chain or {}
    out: dict = {}
    contract = chain.get("contract") or {}
    if contract.get("status") in {"found", "unreadable"}:
        record = {k: contract.get(k) for k in ("contract_id", "status", "executable")}
        if contract.get("executable") == "wasm":
            record["wasm_hash"] = contract.get("wasm_hash")
        ref = contract.get("external_ref")
        if ref:
            record["external_ref"] = {k: ref.get(k) for k in ("owner", "tag", "status", "resolved_wasm_hash")}
        out["contract"] = record
    account = chain.get("account") or {}
    if account.get("status") == "found":
        out["account"] = {
            "address": account.get("address"),
            "signers": sorted([s.get("key"), s.get("type"), s.get("weight")] for s in account.get("signers", [])),
            "thresholds": account.get("thresholds"), "flags": account.get("flags")}
    if out:
        network = chain.get("network") or contract.get("network")
        out["network_passphrase"] = NETWORKS[network].passphrase if network in NETWORKS else network
    return out


def identity_changes(before: dict | None, after: dict | None) -> list[dict]:
    """DRIFT_FIELDS whose value differs between two chain_authority records."""
    old, new = chain_identity(before), chain_identity(after)
    changes = []
    for path in DRIFT_FIELDS:
        a, b = _get(old, path), _get(new, path)
        if a != b:
            changes.append({"field": path, "before": a, "after": b})
    return changes


def _get(record: dict, path: str):
    for part in path.split("."):
        record = record.get(part) if isinstance(record, dict) else None
    return record
