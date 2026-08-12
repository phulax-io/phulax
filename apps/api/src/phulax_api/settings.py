from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict

DEFAULT_DATABASE_URL = "postgresql://phulax:phulax-dev-only@localhost:5432/phulax"


def normalize_database_url(url: str) -> str:
    """Force the psycopg (v3) driver: bare postgresql:// URLs default to psycopg2."""
    if url.startswith("postgresql://"):
        return url.replace("postgresql://", "postgresql+psycopg://", 1)
    return url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(extra="ignore")

    phulax_env: str = "dev"
    database_url: str = DEFAULT_DATABASE_URL
    gateway_signing_key: str = "fake-dev-key-change-me-not-a-secret-0001"
    # Ed25519 seed for signing policy bundles (base64, raw 32 bytes).
    # No default, even for dev — a checked-in signing key would let anyone
    # forge policy for deployments that forgot to override it (T08).
    # `make bootstrap` generates a local pair into .env.
    policy_signing_key: str = ""
    token_ttl_seconds: int = 900  # short-lived by design (plan §7, T06)
    token_audience: str = "phulax-gateway"
    token_issuer: str = "phulax-control-plane"

    @property
    def sqlalchemy_url(self) -> str:
        return normalize_database_url(self.database_url)


@lru_cache
def get_settings() -> Settings:
    return Settings()
