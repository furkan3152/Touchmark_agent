"""Stellar RPC, Soroban contract yapılandırması ve event-ingestion durumu."""

from __future__ import annotations

import json

import httpx

from ..config import Settings
from ..models import Attestation
from ..stellar.events import StellarEventIngester, StellarEventStore
from ..stellar.identity import is_valid_stellar_address
from ..stellar.rpc import StellarRpc


class ChainStatusService:
    def __init__(self, settings: Settings, rpc: StellarRpc | None = None) -> None:
        self.settings = settings
        self.rpc = rpc or StellarRpc(settings)
        self.events = StellarEventStore(settings.event_database_path)
        self.ingester = StellarEventIngester(self.rpc, self.events)

    async def status(self) -> dict:
        health = await self.rpc.health() if self.settings.rpc_enabled else {
            "reachable": False,
            "error": "offline profile",
        }
        blockers: list[str] = []
        if self.settings.rpc_enabled and not health.get("reachable"):
            blockers.append(f"RPC sağlıksız: {health.get('error') or health.get('status')}")
        deployments = await self.deployed_contracts()
        contract_map = {row["key"]: row for row in deployments["contracts"]}
        response_entries = self.events.confirmed_responses(
            self.settings.agent_registry_contract_id, limit=1
        )
        response_proof: dict = {"confirmed": False}
        if response_entries:
            entry = response_entries[0]
            tx_hash = str(entry.get("tx_hash") or "")
            if tx_hash and self.settings.rpc_enabled:
                try:
                    transaction = await self.rpc.get_transaction(tx_hash)
                    response_proof = {
                        "confirmed": transaction.get("status") == "SUCCESS",
                        "tx_hash": tx_hash,
                        "ledger": entry.get("ledger"),
                        "event_id": entry.get("event_id"),
                        "live_tx_status": transaction.get("status"),
                    }
                except Exception as exc:
                    response_proof = {"confirmed": False, "error": str(exc)}
        if not self.settings.agent_registry_contract_id:
            blockers.append("AGENT_REGISTRY_CONTRACT_ID tanımlı değil")
        elif not contract_map["agent_registry"]["onchain_verified"]:
            blockers.append("AgentRegistry deploy transaction/hash kanıtı canlı doğrulanmadı")
        return {
            "network": self.settings.network_summary(),
            "rpc": health,
            "contracts": contract_map,
            "event_ingestion": self.events.status(),
            "submission": {
                "backend_signing": False,
                "external_signing_required": True,
                "mode": "external_signer",
                **response_proof,
            },
            "validation_ready": not blockers,
            "blockers": blockers,
        }

    def contracts(self) -> dict:
        net = self.settings.network_or_none
        values = {
            "agent_registry": self.settings.agent_registry_contract_id,
            "audit_escrow": self.settings.audit_escrow_contract_id,
            "sac": self.settings.sac_contract_id,
        }
        return {
            key: {
                "key": key,
                "contract_id": value,
                "configured": bool(value),
                "onchain_verified": False,
                "explorer_url": net.explorer_contract(value) if net and value else "",
                "note": "RPC ledger-entry/event verification required",
            }
            for key, value in values.items()
        }

    def _deployment_manifest(self) -> dict:
        path = self.settings.deployment_manifest_path
        try:
            data = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError):
            return {}
        if data.get("schema") != "agentveritas.stellar.testnet-deployment.v1":
            return {}
        if data.get("network", {}).get("passphrase") != self.settings.network_passphrase:
            return {}
        return data

    async def deployed_contracts(self) -> dict:
        """Release manifestini canlı deploy tx readback'iyle birlikte doğrular.

        Yapılandırılmış bir C... kimliği tek başına deployment kanıtı değildir. Kod
        kontratları için ID eşliği, release anındaki local/on-chain WASM hash eşliği
        ve deploy transaction'ının canlı RPC'de ``SUCCESS`` olması birlikte gerekir.
        """
        rows = self.contracts()
        manifest = self._deployment_manifest()
        evidence = manifest.get("contracts", {})
        mapping = {
            "agent_registry": "agent_registry",
            "audit_escrow": "audit_escrow",
        }
        for key, evidence_key in mapping.items():
            row = rows[key]
            item = evidence.get(evidence_key, {})
            deploy = item.get("deploy", {})
            tx_hash = str(deploy.get("tx_hash") or "")
            id_match = bool(row["contract_id"] and row["contract_id"] == item.get("contract_id"))
            hash_match = bool(
                item.get("hash_match") is True
                and item.get("local_wasm_sha256")
                and item.get("local_wasm_sha256") == item.get("onchain_wasm_sha256")
            )
            live_success = False
            live_ledger = None
            live_status = "NOT_CHECKED"
            if id_match and hash_match and tx_hash and self.settings.rpc_enabled:
                try:
                    transaction = await self.rpc.get_transaction(tx_hash)
                    live_status = str(transaction.get("status") or "UNKNOWN")
                    live_success = live_status == "SUCCESS"
                    live_ledger = transaction.get("ledger")
                except Exception as exc:
                    live_status = f"ERROR: {exc}"
            row.update(
                manifest_id_match=id_match,
                wasm_hash_match=hash_match,
                deploy_tx_hash=tx_hash,
                live_tx_status=live_status,
                live_ledger=live_ledger,
                onchain_verified=id_match and hash_match and live_success,
                note=(
                    "configured ID + pinned WASM hash + live deploy tx SUCCESS"
                    if id_match and hash_match and live_success
                    else "ID, pinned WASM hash ve canlı deploy tx SUCCESS birlikte gerekli"
                ),
            )

        asset = manifest.get("asset", {})
        sac = rows["sac"]
        sac_match = bool(
            sac["contract_id"]
            and sac["contract_id"] == asset.get("contract_id")
            and asset.get("kind") == "native_xlm_sac"
        )
        sac.update(
            manifest_id_match=sac_match,
            deterministic_native_sac=sac_match,
            note=(
                "Testnet native XLM SAC kimliği release manifestiyle eşleşiyor"
                if sac_match
                else "native SAC kimliği doğrulanmadı"
            ),
        )
        verified = sum(bool(row["onchain_verified"]) for row in rows.values())
        return {
            "contracts": list(rows.values()),
            "verified_code_contracts": verified,
            "manifest_loaded": bool(manifest),
            "note": "configured tek başına deployed değildir; canlı tx ve pinned hash birlikte aranır",
        }

    async def onchain_attestations(self, limit: int = 20) -> dict:
        entries = self.events.confirmed_responses(
            self.settings.agent_registry_contract_id, limit=limit
        )
        return {
            "registry": self.settings.agent_registry_contract_id,
            "count": len(entries),
            "entries": entries,
            "confirmed": bool(entries),
            "event_store": self.events.status(),
            "note": (
                "Successful responded events were decoded from the configured registry."
                if entries
                else "Event sync has not established successful registry response events."
            ),
        }

    async def sync_registry_events(self, start_ledger: int) -> dict:
        contract_id = self.settings.agent_registry_contract_id
        if not contract_id:
            raise ValueError("AGENT_REGISTRY_CONTRACT_ID gerekli")
        return await self.ingester.sync("agent-registry", [contract_id], start_ledger)

    async def confirm_attestation(self, attestation: Attestation) -> dict:
        """Event eşleşmesini ve transaction SUCCESS durumunu birlikte doğrular."""
        if not self.settings.agent_registry_contract_id:
            return {"confirmed": False, "reason": "registry contract ID tanımsız"}
        event = self.events.find_response(
            self.settings.agent_registry_contract_id,
            attestation.request_id,
            attestation.report_hash,
        )
        if not event:
            return {"confirmed": False, "reason": "eşleşen responded event bulunamadı"}
        tx_hash = str(event.get("tx_hash") or "")
        if not tx_hash:
            return {"confirmed": False, "reason": "event transaction hash taşımıyor"}
        try:
            transaction = await self.rpc.get_transaction(tx_hash)
        except Exception as exc:
            return {"confirmed": False, "reason": f"transaction readback başarısız: {exc}"}
        if transaction.get("status") != "SUCCESS":
            return {
                "confirmed": False,
                "reason": f"transaction status SUCCESS değil: {transaction.get('status')}",
            }
        net = self.settings.network_or_none
        return {
            "confirmed": True,
            "tx_hash": tx_hash,
            "ledger": event.get("ledger"),
            "event_id": event.get("event_id"),
            "explorer_url": net.explorer_transaction(tx_hash) if net else "",
        }

    async def escrow_status(self) -> dict:
        return {
            "enabled": self.settings.audit_escrow_enabled,
            "contract_id": self.settings.audit_escrow_contract_id,
            "sac_contract_id": self.settings.sac_contract_id,
            "asset_code": self.settings.resolved_escrow_asset_code,
            "backend_signing": False,
            "confirmed": False,
            "mode": "external_signature_required" if self.settings.audit_escrow_enabled else "disabled",
            "note": "Escrow agent validation çekirdeğinden bağımsızdır.",
        }

    async def probe_address(self, address: str) -> dict:
        out = {"address": address, "source": "none", "account": None, "contract": None}
        if not is_valid_stellar_address(address):
            out["error"] = "geçersiz Stellar StrKey/checksum; G... veya C... bekleniyor"
            return out
        net = self.settings.network_or_none
        if address.startswith("G") and self.settings.horizon_url:
            try:
                async with httpx.AsyncClient(timeout=10.0, follow_redirects=False) as client:
                    response = await client.get(f"{self.settings.horizon_url}/accounts/{address}")
                    response.raise_for_status()
                    data = response.json()
                out.update(
                    source="horizon",
                    account=True,
                    sequence=data.get("sequence"),
                    subentry_count=data.get("subentry_count"),
                )
            except (httpx.HTTPError, ValueError) as exc:
                out["error"] = str(exc)
        elif address.startswith("C"):
            out.update(source="rpc-required", contract=True)
            out["note"] = "Contract ledger entry verification adapter is pending."
        else:
            out["error"] = "G... account veya C... contract bekleniyor"
        if net:
            out["explorer_url"] = (
                net.explorer_account(address)
                if address.startswith("G")
                else net.explorer_contract(address)
            )
        return out
