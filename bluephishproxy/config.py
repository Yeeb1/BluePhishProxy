"""Runtime configuration for BluePhishProxy.

All settings are overridable via environment variables so the same image can be
redeployed across engagements without code changes.
"""

from __future__ import annotations

import json
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


def _env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        return default


def _env_json_list(name: str) -> list[Any]:
    raw = os.environ.get(name)
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, list):
            return parsed
        return [parsed]
    except json.JSONDecodeError:
        return [raw]


def _env_json_dict(name: str) -> dict[str, Any]:
    raw = os.environ.get(name)
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass
    return {}


@dataclass(slots=True)
class Config:
    """Immutable-ish runtime configuration."""

    # --- network / server -------------------------------------------------
    host: str = field(default_factory=lambda: os.environ.get("BPP_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("BPP_PORT", 5000))
    debug: bool = field(default_factory=lambda: _env_bool("BPP_DEBUG", False))
    trusted_proxies: int = field(default_factory=lambda: _env_int("BPP_TRUSTED_PROXIES", 1))

    # --- campaign defaults ------------------------------------------------
    safe_redirect_url: str = field(
        default_factory=lambda: os.environ.get(
            "BPP_SAFE_REDIRECT_URL", "https://www.microsoft.com/en-us/security"
        )
    )
    flagged_redirect_url: str = field(
        default_factory=lambda: os.environ.get(
            "BPP_FLAGGED_REDIRECT_URL", "https://www.microsoft.com/en-us/security"
        )
    )
    brand_name: str = field(default_factory=lambda: os.environ.get("BPP_BRAND", "Microsoft"))
    default_template: str = field(
        default_factory=lambda: os.environ.get("BPP_DEFAULT_TEMPLATE", "safelinks")
    )

    # --- detection tuning -------------------------------------------------
    bot_threshold: int = field(default_factory=lambda: _env_int("BPP_BOT_THRESHOLD", 50))
    suspicious_threshold: int = field(
        default_factory=lambda: _env_int("BPP_SUSPICIOUS_THRESHOLD", 25)
    )

    # --- enrichment -------------------------------------------------------
    enable_ip_enrichment: bool = field(
        default_factory=lambda: _env_bool("BPP_IP_ENRICHMENT", True)
    )
    ipinfo_token: str | None = field(default_factory=lambda: os.environ.get("BPP_IPINFO_TOKEN"))
    ipinfo_timeout: float = field(
        default_factory=lambda: float(os.environ.get("BPP_IPINFO_TIMEOUT", "3.0"))
    )

    # --- storage ----------------------------------------------------------
    data_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("BPP_DATA_DIR", "data"))
    )
    analytics_dir: Path = field(
        default_factory=lambda: Path(os.environ.get("BPP_ANALYTICS_DIR", "analytics"))
    )
    log_file: Path = field(
        default_factory=lambda: Path(os.environ.get("BPP_LOG_FILE", "access.log"))
    )

    # --- session ----------------------------------------------------------
    secret_key: str = field(
        default_factory=lambda: os.environ.get("BPP_SECRET_KEY") or ""
    )
    session_max_age: int = field(default_factory=lambda: _env_int("BPP_SESSION_MAX_AGE", 3600))

    # --- webhooks ---------------------------------------------------------
    webhook_urls: list[Any] = field(default_factory=lambda: _env_json_list("BPP_WEBHOOK_URLS"))
    webhook_min_level: str = field(
        default_factory=lambda: os.environ.get("BPP_WEBHOOK_MIN_LEVEL", "suspicious")
    )

    # --- operator API -----------------------------------------------------
    operator_token: str = field(
        default_factory=lambda: os.environ.get("BPP_OPERATOR_TOKEN") or ""
    )
    rate_limit: int = field(
        default_factory=lambda: _env_int("BPP_RATE_LIMIT", 60)
    )

    # --- cloudflare -------------------------------------------------------
    behind_cloudflare: bool = field(
        default_factory=lambda: _env_bool("BPP_BEHIND_CLOUDFLARE", False)
    )

    # --- TLS --------------------------------------------------------------
    tls_cert: str = field(
        default_factory=lambda: os.environ.get("BPP_TLS_CERT") or ""
    )
    tls_key: str = field(
        default_factory=lambda: os.environ.get("BPP_TLS_KEY") or ""
    )

    # --- database ---------------------------------------------------------
    database_path: str = field(
        default_factory=lambda: os.environ.get("BPP_DATABASE", "data/bluephishproxy.db")
    )

    # --- redirect chains --------------------------------------------------
    redirect_chains: dict[str, Any] = field(
        default_factory=lambda: _env_json_dict("BPP_REDIRECT_CHAINS")
    )

    # --- encryption -------------------------------------------------------
    encryption_key: str = field(
        default_factory=lambda: os.environ.get("BPP_ENCRYPTION_KEY") or ""
    )

    # --- templates --------------------------------------------------------
    templates_dir: str = field(
        default_factory=lambda: os.environ.get("BPP_TEMPLATES_DIR") or ""
    )

    # --- single-campaign auto-setup ---------------------------------------
    campaign_name: str = field(
        default_factory=lambda: os.environ.get("BPP_CAMPAIGN_NAME") or ""
    )
    campaign_template: str = field(
        default_factory=lambda: os.environ.get("BPP_CAMPAIGN_TEMPLATE") or ""
    )

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        self.analytics_dir = Path(self.analytics_dir)
        self.log_file = Path(self.log_file)

    @property
    def secret_key_is_ephemeral(self) -> bool:
        return not os.environ.get("BPP_SECRET_KEY")

    def resolved_secret_key(self) -> str:
        return self.secret_key or secrets.token_hex(32)

    @property
    def tls_enabled(self) -> bool:
        return bool(self.tls_cert and self.tls_key)
