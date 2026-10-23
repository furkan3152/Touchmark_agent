"""AgentVeritas Stellar ağ, Soroban ve audit ayarları."""

from __future__ import annotations

import json
import os
from functools import lru_cache
from pathlib import Path
from typing import ClassVar

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from .stellar.networks import TESTNET, NetworkGuardError, StellarNetwork, resolve_network


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    stateless_studio: bool = False
    app_name: str = "AgentVeritas Stellar"
    version: str = "0.3.0-stellar"
    admin_api_key: str = ""
    admin_rate_limit_per_minute: int = 60

    # LLM; privacy-mode için ayrıca opt-in gerekir.
    enable_sandbox_runtime: bool = False
    enable_brokered_runtime: bool = False
    audit_testnet_funding_secret: str = Field(default="", repr=False, exclude=True)
    runtime_api_key: str = ""
    checkout_quote_signing_key: str = ""
    # Official Testnet fulfillment is a separate opt-in persistent service.
    # Never enable the SQLite order worker on ephemeral serverless storage.
    enable_official_orders: bool = False
    official_orders_database: str = "./data/official-orders.db"
    official_orders_storage_durable: bool = False
    official_orders_local_pilot: bool = False
    enable_testnet_order_settlement: bool = False
    official_provider_secret: str = Field(default="", repr=False, exclude=True)
    official_evaluator_secret: str = Field(default="", repr=False, exclude=True)
    official_report_base_url: str = ""
    blob_read_write_token: str = Field(default="", repr=False, exclude=True)
    blob_store_id: str = ""
    sandbox_image: str = "vercel/sandbox/universal@sha256:c77f7436b9bc0a8b01ef7b09dbcea2de6a18a9fe2aafa89996d2da193da72cf0"
    enable_public_ai_review: bool = False
    llm_provider: str = ""
    llm_api_key: str = Field(default="", repr=False, exclude=True)
    ai_gateway_api_key: str = Field(default="", repr=False, exclude=True)
    vercel_oidc_token: str = Field(default="", repr=False, exclude=True)
    ai_review_api_key: str = Field(default="", repr=False, exclude=True)
    llm_model: str = "claude-sonnet-4-20250514"
    llm_base_url: str = ""
    llm_max_input_bytes: int = Field(default=28_000, ge=1_000, le=64_000)
    llm_max_output_tokens: int = Field(default=1800, ge=64, le=4096)
    llm_max_response_bytes: int = Field(default=128_000, ge=4096, le=256_000)
    llm_timeout_seconds: float = Field(default=20.0, ge=1.0, le=60.0)
    allow_external_llm_for_private_audits: bool = False
    # Deep review: grounded, tool-using Claude investigation (services/deep_review.py).
    # Runs only with per-request consent; the key comes from ANTHROPIC_API_KEY.
    # Read public ledger state (signers, thresholds, SEP-1, SEP-29) for supplied addresses.
    enable_onchain_verification: bool = False
    enable_deep_review: bool = False
    anthropic_api_key: str = Field(default="", repr=False, exclude=True,
                                   validation_alias=AliasChoices("anthropic_api_key", "anthropic_ai_key"))
    deep_review_model: str = "claude-sonnet-5-5"
    deep_review_effort: str = Field(default="high", pattern="^(low|medium|high|xhigh|max)$")
    deep_review_max_turns: int = Field(default=24, ge=4, le=60)
    # 2 = an investigation pass plus a challenger pass that hunts for what the first missed.
    deep_review_passes: int = Field(default=2, ge=1, le=3)
    deep_review_timeout_seconds: float = Field(default=240.0, ge=30.0, le=900.0)
    # Independent re-check of each finding by a second model (services/finding_verifier.py).
    # On by default (it still needs an API key): a medium payment bypass that no verifier
    # checked holds back a pass, so without it a model-reviewed agent can never pass.
    enable_finding_verification: bool = True
    verifier_model: str = "claude-sonnet-5-5"
    verifier_effort: str = Field(default="medium", pattern="^(low|medium|high|xhigh|max)$")
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
        # Configuration is not proof of provider connectivity or available credit.
        return bool(self.llm_api_base and self.llm_model.strip() and self.llm_credential)

    @property
    def llm_credential(self) -> str:
        if self.llm_provider.lower() == "vercel":
            explicit = self.ai_gateway_api_key or self.llm_api_key
            if explicit:
                return explicit
            if os.getenv("VERCEL") == "1":
                # Functions receive a rotating request-context token; builds use
                # the environment. Resolve at call time, never cache or export it.
                try:
                    from vercel.oidc import get_vercel_oidc_token
                    return get_vercel_oidc_token()
                except Exception:
                    return ""
            return os.getenv("VERCEL_OIDC_TOKEN", "") or self.vercel_oidc_token
        return self.llm_api_key

    @property
    def llm_auth_mode(self) -> str:
        if not self.llm_credential:
            return "unconfigured"
        if self.llm_provider.lower() == "vercel" and not (self.ai_gateway_api_key or self.llm_api_key):
            return "vercel_oidc"
        return "api_key"

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
        "anthropic": "https://api.anthropic.com/v1",
        "vercel": "https://ai-gateway.vercel.sh/v1",
        "openai": "https://api.openai.com/v1",
        "openrouter": "https://openrouter.ai/api/v1",
        "deepseek": "https://api.deepseek.com/v1",
        "groq": "https://api.groq.com/openai/v1",
        "together": "https://api.together.xyz/v1",
    }

    @property
    def llm_api_base(self) -> str:
        expected = self.LLM_BASES.get(self.llm_provider.lower(), "")
        # No arbitrary URLs, redirects, localhost or silently substituted provider.
        if self.llm_base_url and self.llm_base_url.rstrip("/") != expected:
            return ""
        return expected

    def llm_status(self) -> dict:
        return {
            "configured": self.llm_enabled, "connection_verified": False,
            "provider": self.llm_provider, "model": self.llm_model,
            "auth_mode": self.llm_auth_mode,
            "max_input_bytes": self.llm_max_input_bytes,
            "max_output_tokens": self.llm_max_output_tokens,
            "max_requests_per_review": 1, "automatic_retries": 0,
            "billing_note": "Token limits bound each request, not account-wide spend. Set a provider-side budget.",
        }

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
