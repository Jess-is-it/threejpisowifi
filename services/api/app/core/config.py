from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    cw_env: str = "production"
    cw_public_base_url: str = "http://127.0.0.1"

    database_url: str
    redis_url: str = "redis://redis:6379/0"

    jwt_issuer: str = "centralwifi"
    jwt_secret: str
    jwt_expires_seconds: int = 86400

    admin_username: str = "admin"
    admin_password: str

    radius_shared_secret: str
    active_session_grace_seconds: int = 180

    vendo_seconds_per_coin: int = 300
    vendo_event_tolerance_seconds: int = 600
    device_token_enc_key: str

    sms_provider: str = "mock"
    payment_provider: str = "mock"


settings = Settings()  # singleton

