"""
FrothIQ Control Center — configuration

All settings are loaded from environment variables (and optionally a .env file).
Secrets are never hard-coded; the defaults here are development-safe only.
"""

from __future__ import annotations

import secrets
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="CC_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -----------------------------------------------------------------
    # Application
    # -----------------------------------------------------------------
    app_name: str = "FrothIQ Control Center"
    app_version: str = "1.0.0"
    environment: Literal["development", "staging", "production"] = "development"
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 8002

    # -----------------------------------------------------------------
    # Security
    # -----------------------------------------------------------------
    secret_key: str = Field(
        default_factory=lambda: secrets.token_urlsafe(64),
        description="JWT signing key — MUST be set in production",
    )
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 60
    refresh_token_expire_days: int = 7
    # Comma-separated list of CIDR blocks or IPs allowed to hit /admin endpoints
    admin_ip_allowlist: str = ""  # empty = allow all (dev default)

    # -----------------------------------------------------------------
    # Database (MariaDB)
    # -----------------------------------------------------------------
    database_url: str = "mysql+aiomysql://frothiq:frothiq_cc_pass@localhost:3306/frothiq_cc"

    # -----------------------------------------------------------------
    # Redis
    # -----------------------------------------------------------------
    redis_url: str = "redis://localhost:6379/2"
    redis_pubsub_url: str = "redis://localhost:6379/3"

    # -----------------------------------------------------------------
    # frothiq-core connection
    # -----------------------------------------------------------------
    core_base_url: str = "http://127.0.0.1:8001"
    # Service token — signed HS256 JWT issued by the Control Center itself
    # frothiq-core must be configured to accept this in a future integration step.
    # For now, uses the core's internal API key for trusted internal calls.
    core_service_api_key: str = ""
    core_timeout_seconds: float = 10.0
    core_max_connections: int = 50

    # -----------------------------------------------------------------
    # CORS
    # -----------------------------------------------------------------
    cors_origins: str = "http://localhost:3000,http://localhost:3001"

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors(cls, v: str) -> str:
        return v

    @property
    def cors_origins_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def admin_ip_allowlist_parsed(self) -> list[str]:
        return [ip.strip() for ip in self.admin_ip_allowlist.split(",") if ip.strip()]

    # -----------------------------------------------------------------
    # WebSocket
    # -----------------------------------------------------------------
    ws_heartbeat_interval: int = 30  # seconds
    ws_max_connections: int = 500

    # -----------------------------------------------------------------
    # Gateway integration
    # -----------------------------------------------------------------
    gateway_url: str = "http://127.0.0.1:8000"
    # Shared HMAC key for signing commands forwarded to the gateway
    gateway_signing_key: str = "changeme-gateway-signing-key"

    # -----------------------------------------------------------------
    # Billing sync
    # -----------------------------------------------------------------
    # Shared HMAC-SHA256 secret between ERPNext billing bridge and MC3.
    # Must match CC_BILLING_WEBHOOK_SECRET in both environments.
    billing_webhook_secret: str = ""

    # -----------------------------------------------------------------
    # Rate limiting
    # -----------------------------------------------------------------
    rate_limit_default: str = "120/minute"
    rate_limit_admin: str = "30/minute"
    rate_limit_auth: str = "10/minute"

    # -----------------------------------------------------------------
    # Audit
    # -----------------------------------------------------------------
    audit_log_to_db: bool = True
    audit_log_to_redis: bool = True


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings()
