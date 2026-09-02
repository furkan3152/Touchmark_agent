"""AgentVeritas Stellar ağ, Soroban ve audit ayarları."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import ClassVar

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .stellar.networks import TESTNET, NetworkGuardError, StellarNetwork, resolve_network


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "AgentVeritas Stellar"
    version: str = "0.3.0-stellar"
    admin_api_key: str = ""
    admin_rate_limit_per_minute: int = 60

    # LLM; privacy-mode için ayrıca opt-in gerekir.
    llm_provider: str = ""
    llm_api_key: str = ""
    llm_model: str = "claude-sonnet-4-20250514"
    llm_base_url: str = ""
    allow_external_llm_for_private_audits: bool = False
    # Gerçek endpoint'e adversarial payload yalnız izole hedefte açık opt-in ile gönderilir.
    enable_active_agent_probes: bool = False

    # Stellar ağ ve Soroban kontratları.
    stellar_network: str = TESTNET
    allow_mainnet: bool = False
    stellar_rpc_url: str = ""
    stellar_horizon_url: str = ""
    agent_registry_contract_id: str = ""
    audit_escrow_contract_id: str = ""
    sac_contract_id: str = ""
    # Boş bırakılırsa deployment manifestindeki asset türünden çözülür.
    escrow_asset_code: str = ""
    enable_audit_escrow: bool = False
    # Backend tx imzalamaz; bu değer yalnız hazırlanmış çağrıları görünür kılar.
    external_signing_required: bool = True

    # SEP web-session/anchor modülleri çekirdekten bağımsızdır.
    sep1_domain: str = ""
    sep10_web_auth_endpoint: str = ""
    sep45_web_auth_endpoint: str = ""
    enable_anchor_payments: bool = False
    sep24_transfer_server: str = ""
    sep31_transfer_server: str = ""
    sep38_quote_server: str = ""

    # Rapor yayınlama ve compliance.
    pinata_jwt: str = ""
    ipfs_gateway: str = "https://gateway.pinata.cloud/ipfs/"
    screening_provider: str = "none"
    screening_api_key: str = ""
    enable_ofac_screening: bool = True
    ofac_max_age_hours: float = 24.0

    # Ekonomi yalnız opsiyonel escrow için kullanılır.
    platform_fee_bps: int = 1500
    price_basic_usdc: float = 2.0
    price_deep_usdc: float = 25.0
    # İzleme çekirdek doğrulama akışında ücretli değildir. Ücretli bir ürün
    # eklenecekse ayrı bir imzalı ödeme modülü ve zincir kanıtı gerekir.
    monitor_tick_price_usdc: float = 0.0
    swarm_stake_usdc: float = 5.0
    auditor_timeout_seconds: float = Field(default=30.0, ge=0.1, le=300.0)

    database_url: str = "sqlite:///./data/agentveritas-stellar.db"
    data_dir: str = "./data"
    event_database: str = "./data/stellar-events.db"
    deployment_manifest: str = "./deployments/stellar-testnet.json"
    ingest_root: str = ""
    allow_local_path_ingest: bool = False
    max_ingest_bytes: int = 8_000_000

    @property
    def network(self) -> StellarNetwork:
        return resolve_network(self.stellar_network, allow_mainnet=self.allow_mainnet)

    @property
    def network_or_none(self) -> StellarNetwork | None:
        try:
            return self.network
        except NetworkGuardError:
            return None

    @property
    def rpc_url(self) -> str:
        return self.stellar_rpc_url or (self.network_or_none.rpc_url if self.network_or_none else "")

    @property
    def horizon_url(self) -> str:
        return self.stellar_horizon_url or (
            self.network_or_none.horizon_url if self.network_or_none else ""
        )

    @property
    def network_passphrase(self) -> str:
        return self.network_or_none.passphrase if self.network_or_none else ""

    @property
    def explorer(self) -> str:
        return self.network_or_none.explorer if self.network_or_none else ""

    @property
    def is_testnet(self) -> bool:
        return bool(self.network_or_none and self.network_or_none.is_testnet)

    @property
    def rpc_enabled(self) -> bool:
        return bool(self.rpc_url)

    @property
    def chain_enabled(self) -> bool:
        """Backend signing yoktur; prepared invocation zincir başarısı değildir."""
        return False

    @property
    def audit_escrow_enabled(self) -> bool:
        return bool(
            self.enable_audit_escrow
            and self.audit_escrow_contract_id
            and self.sac_contract_id
        )

    @property
    def resolved_escrow_asset_code(self) -> str:
        """Aktif escrow birimini yapılandırma veya release manifestinden çöz.

        Kalıcı model alanları geriye uyumluluk için ``*_usdc`` adını taşıyor.
        Bu nedenle gerçek SAC native XLM olduğunda kullanıcı yüzeyinde yanlış
        bir USDC settlement iddiası üretmemek için ayrı bir kanıtlı etiket gerekir.
        """
        if self.escrow_asset_code.strip():
            return self.escrow_asset_code.strip().upper()
        try:
            manifest = json.loads(self.deployment_manifest_path.read_text())
            asset = manifest.get("asset") or {}
            if (
                asset.get("contract_id") == self.sac_contract_id
                and asset.get("kind") == "native_xlm_sac"
            ):
                return "XLM"
        except (OSError, json.JSONDecodeError):
            pass
        return "SAC"

    @property
    def llm_enabled(self) -> bool:
        return bool(self.llm_provider and self.llm_provider != "none" and self.llm_api_key)

    @property
    def ipfs_enabled(self) -> bool:
        return bool(self.pinata_jwt)

    @property
    def screening_enabled(self) -> bool:
        return bool(
            self.screening_provider.lower() in ("trm", "elliptic", "chainalysis")
            and self.screening_api_key
        )

    @property
    def ofac_enabled(self) -> bool:
        return self.enable_ofac_screening

    LLM_BASES: ClassVar[dict[str, str]] = {
        "openai": "https://api.openai.com/v1",
        "openrouter": "https://openrouter.ai/api/v1",
        "deepseek": "https://api.deepseek.com/v1",
        "groq": "https://api.groq.com/openai/v1",
        "together": "https://api.together.xyz/v1",
    }

    @property
    def llm_api_base(self) -> str:
        if self.llm_base_url:
            return self.llm_base_url.rstrip("/")
        return self.LLM_BASES.get(self.llm_provider.lower(), self.LLM_BASES["openai"])

    def integrations(self) -> list[dict]:
        return [
            {
                "key": "AGENT_REGISTRY_CONTRACT_ID",
                "enabled": bool(self.agent_registry_contract_id),
                "value": self.agent_registry_contract_id,
                "unlocks": "Soroban validation invocation hazırlığı ve event doğrulaması",
                "fallback": "rapor yalnız offchain; zincir başarısı iddia edilmez",
            },
            {
                "key": "AUDIT_ESCROW_CONTRACT_ID",
                "enabled": self.audit_escrow_enabled,
                "value": "Soroban escrow" if self.audit_escrow_enabled else "",
                "unlocks": "opsiyonel SAC tabanlı audit escrow çağrısı hazırlığı",
                "fallback": "agent validation ödeme gerektirmeden tamamlanır",
            },
            {
                "key": "LLM_API_KEY",
                "enabled": self.llm_enabled,
                "value": self.llm_provider,
                "unlocks": "heuristiklere bağlamsal ikinci görüş",
                "fallback": "deterministik heuristik motor",
            },
            {
                "key": "(anahtarsız)",
                "enabled": self.ofac_enabled,
                "value": "OFAC SDN",
                "unlocks": "yerel yaptırım listesi kontrolü",
                "fallback": "kontrol çalıştırılmaz ve raporda kapsam boşluğu yazılır",
            },
            {
                "key": "SCREENING_API_KEY",
                "enabled": self.screening_enabled,
                "value": self.screening_provider if self.screening_enabled else "",
                "unlocks": "desteklenen sağlayıcıyla adres risk taraması",
                "fallback": "risk sonucu unknown; temiz adres iddiası üretilmez",
            },
            {
                "key": "PINATA_JWT",
                "enabled": self.ipfs_enabled,
                "value": "",
                "unlocks": "raporun IPFS'e pinlenmesi",
                "fallback": "yerel content-addressed store",
            },
            {
                "key": "SEP10/SEP45 endpoints",
                "enabled": bool(self.sep10_web_auth_endpoint or self.sep45_web_auth_endpoint),
                "value": "web auth",
                "unlocks": "G/M ve C account web session sahipliği",
                "fallback": "G-account için imzalı challenge; C-account kabul edilmez",
            },
        ]

    def network_summary(self) -> dict:
        net = self.network_or_none
        return {
            "key": self.stellar_network,
            "name": net.name if net else "invalid",
            "passphrase": self.network_passphrase,
            "rpc_url": self.rpc_url,
            "horizon_url": self.horizon_url,
            "is_testnet": self.is_testnet,
            "explorer": self.explorer,
            "external_signing_required": self.external_signing_required,
        }

    @property
    def data_path(self) -> Path:
        path = Path(self.data_dir)
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(path, 0o700)
        except OSError:
            # Salt-okunur/container dosya sistemlerinde asıl yazma işlemi de
            # fail-closed olur; sırf chmod desteği yok diye health importu çökmesin.
            pass
        return path

    @property
    def event_database_path(self) -> Path:
        return Path(self.event_database)

    @property
    def deployment_manifest_path(self) -> Path:
        return Path(self.deployment_manifest)

    @property
    def ingest_root_path(self) -> Path:
        if self.ingest_root:
            return Path(self.ingest_root).expanduser().resolve()
        return Path(__file__).resolve().parents[2]


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
