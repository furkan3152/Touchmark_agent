"""Published advisories for Stellar libraries, and deployed contract code known to be unsafe.

A vulnerable library version is only a risk when the code uses the affected feature: the
soroban-sdk macro bug needs a trait function and an inherent function with the same name, the
MPP hash-push flaw needs a charge server without a fee payer. Each row therefore names the code
condition that makes it exploitable (swarm/advisory_check.py tests it), and a version that
matches without that condition is reported as a fact to verify, not as a risk.

Versions come from lockfiles or exact pins (services/lockfiles.py), never from a range. Each
row records the day it was last checked against its source; a table that is not kept up to
date says so in the report (dep-advisory-table-stale).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

from ..services.lockfiles import version_key

#: Rows older than this many days are reported as a stale table.
STALE_AFTER_DAYS = 90


@dataclass(frozen=True)
class Advisory:
    id: str
    ecosystem: str
    package: str
    #: Affected versions as half-open ranges [introduced, fixed).
    affected: tuple[tuple[str, str], ...]
    fixed: str
    vendor_severity: str
    url: str
    #: The day this row was last checked against ``url``.
    reviewed_at: str
    #: The code condition that makes an affected version exploitable (advisory_check.py).
    condition: str
    summary: str

    def affects(self, version: str) -> bool:
        key = version_key(version)
        return key is not None and any(version_key(lo) <= key < version_key(hi) for lo, hi in self.affected)

    def stale(self, today: date | None = None) -> bool:
        return ((today or date.today()) - date.fromisoformat(self.reviewed_at)).days > STALE_AFTER_DAYS


ADVISORIES: tuple[Advisory, ...] = (
    Advisory(
        "GHSA-4chv-4c6w-w254", "cargo", "soroban-sdk-macros",
        (("0.0.0", "22.0.10"), ("23.0.0", "23.5.2"), ("25.0.0", "25.1.1")), "22.0.10, 23.5.2, 25.1.1", "high",
        "https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-4chv-4c6w-w254", "2026-10-22",
        "contractimpl_name_collision",
        "#[contractimpl] on `impl Trait for T` exports a call to `T::f`, which runs an inherent `impl T` function "
        "of the same name instead of the trait function, skipping the checks the trait function makes."),
    # The fix is read from the published crates (0.7.3 adds the SelfDelegatedSigner and
    # DelegatedSignerIsContextContract errors, 0.7.2 has neither); no advisory record was
    # retrievable when this row was written, so the row carries no GHSA id.
    Advisory(
        "STELLAR-ACCOUNTS-DELEGATED-SIGNER", "cargo", "stellar-accounts",
        (("0.0.0", "0.7.3"),), "0.7.3, 0.8.0", "moderate",
        "https://crates.io/crates/stellar-accounts/0.7.3", "2026-10-22",
        "delegated_contract_signer",
        "A Signer::Delegated whose address is a contract in the call stack (the account itself, or an account that "
        "delegates back) is approved by the host without any signature; 0.7.3 rejects self-delegation and a "
        "delegated signer that is the context contract."),
    Advisory(
        "GHSA-96xm-fv9w-pf3f", "cargo", "soroban-sdk",
        (("0.0.0", "22.0.9"), ("23.0.0", "23.5.1"), ("25.0.0", "25.0.2")), "22.0.9, 23.5.1, 25.0.2", "moderate",
        "https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-96xm-fv9w-pf3f", "2026-10-22",
        "unchecked_range_arithmetic",
        "Bytes::slice, Vec::slice and Prng::gen_range wrap on boundary values when overflow checks are off, so a "
        "range can silently select different data."),
    Advisory(
        "GHSA-x2hw-px52-wp4m", "cargo", "soroban-sdk",
        (("0.0.0", "22.0.11"), ("23.0.0", "23.5.3"), ("25.0.0", "25.3.0")), "22.0.11, 23.5.3, 25.3.0", "moderate",
        "https://github.com/stellar/rs-soroban-sdk/security/advisories/GHSA-x2hw-px52-wp4m", "2026-10-22",
        "fr_equality",
        "BN254 and BLS12-381 Fr values compare their unreduced representation, so equal field elements can "
        "compare unequal and a crafted input passes or fails an equality check."),
    Advisory(
        "MPP-UNSIGNED-HASH-PUSH", "npm", "@stellar/mpp",
        (("0.0.0", "0.7.0"),), "0.7.0", "",
        "https://www.npmjs.com/package/@stellar/mpp/v/0.7.0", "2026-10-22",
        "charge_server_without_fee_payer",
        "Before 0.7.0 a charge server without a fee payer accepts a push credential that is only a transaction "
        "hash, unsigned: whoever presents another payer's hash first is served on that payment. 0.3 binds no payer; "
        "from 0.4 the server compares the transfer's sender with the credential's source DID, which the presenter "
        "writes and nothing signs. 0.7.0 accepts unsigned hashes only with allowUnsignedPush."),
    Advisory(
        "PASSKEY-KIT-POLICY-SIGNER", "npm", "passkey-kit",
        (("0.0.0", "0.16.3"),), "0.16.3", "",
        "https://www.npmjs.com/package/passkey-kit/v/0.16.3", "2026-10-22",
        "policy_signers",
        "Smart wallets deployed by earlier kits run contract code from before the 0.16.3 fix, where a policy "
        "signer could be removed without its own policy check; deployed wallets do not upgrade by themselves."),
)

#: Smart-wallet WASM whose update_signer has no authorization check: anyone who knows a signer's
#: key id can overwrite that signer. Listed in passkey-kit 0.19.1 (SECURITY.md and
#: KNOWN_VULNERABLE_WALLET_WASM_HASHES in dist/constants.js).
KNOWN_BAD_WASM = Advisory(
    "PASSKEY-KIT-UPDATE-SIGNER", "wasm", "smart-wallet", (), "upgrade to the legacy-line target", "",
    "https://www.npmjs.com/package/passkey-kit/v/0.19.1", "2026-10-22", "deployed_hash",
    "The wallet's update_signer has no require_auth: anyone can replace a signer and take the wallet.")
KNOWN_BAD_WASM_HASHES = frozenset({
    "0c0a264d4cc0b3e79b8533e2a2e1f0ed21501a5a3f9f2455d2f18c232940b865",
    "19868df3653d427cafa1c30bdb6cec1ca5c8c815eeabab8a8bae6d83efb1fedd",
    "b62f62217ff256d557513793e9e44317b25b14401a8a6b6149a04d38d72d6c7c",
    "c5509dfa5f022deb8ae621f073adac5fd788feca0b24d15b5f392ab22c2ff222",
})


def for_package(package: str) -> list[Advisory]:
    return [a for a in ADVISORIES if a.package == package]


def stale_rows(today: date | None = None) -> list[Advisory]:
    return [a for a in (*ADVISORIES, KNOWN_BAD_WASM) if a.stale(today)]
