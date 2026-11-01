from functools import lru_cache

from pydantic import Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="SETTLER_")

    horizon_url: str = "https://horizon.stellar.org"
    network_passphrase: str = "Public Global Stellar Network ; September 2015"
    signing_secret: SecretStr = Field(..., description="Seed of the settlement account")
    api_keys: str = ""
    webhook_secret: SecretStr = Field(..., description="HMAC key shared with accounting")
    usdc_code: str = "USDC"
    usdc_issuer: str = "GA5ZSEJYB37JRC5AVCIA5MOP4RHTM335X2KGX3IHOJAPP5RE34K4KZVN"
    max_invoice_amount: str = "25000"
    base_fee: int = 200

    def operator_keys(self) -> set[str]:
        return {k.strip() for k in self.api_keys.split(",") if k.strip()}


@lru_cache
def get_settings() -> Settings:
    return Settings()
