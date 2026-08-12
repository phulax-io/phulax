from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    phulax_env: str = "dev"
    gateway_signing_key: str = "fake-dev-key-change-me-not-a-secret-0001"
    control_plane_url: str = "http://127.0.0.1:8000"
    token_audience: str = "phulax-gateway"
    # Ed25519 public key for verifying policy bundles (base64, raw 32 bytes).
    # Configured out-of-band by design — never fetched over the same channel
    # as the bundles it verifies (T08). No default: unset means every bundle
    # fails verification and the gateway fails closed.
    policy_public_key: str = ""
    # How long a verified bundle serves decisions before the gateway asks
    # for a newer one. Refresh failure never evicts: cached enforcement
    # keeps working through a control-plane outage (T14).
    policy_refresh_seconds: float = 30.0


@lru_cache
def get_settings() -> Settings:
    return Settings()
