"""Campaign management — SQLite-backed with JSON file fallback.

Each campaign has its own ID, template, redirect URLs, and visit history.
Campaigns are referenced by URL path prefix (e.g. /c/<campaign_id>/...).
"""

from __future__ import annotations

import secrets
import datetime
from dataclasses import dataclass, field, asdict
from typing import Any

from .config import Config
from .database import (
    save_campaign_db,
    load_campaign_db,
    list_campaigns_db,
    delete_campaign_db,
)


@dataclass(slots=True)
class Campaign:
    id: str
    name: str
    template: str = "safelinks"
    created_at: str = ""
    active: bool = True
    safe_redirect_url: str = ""
    flagged_redirect_url: str = ""
    brand_name: str = "Microsoft"
    description: str = ""
    custom_params: dict[str, Any] = field(default_factory=dict)
    redirect_chains: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()


def create_campaign(
    name: str,
    template: str,
    cfg: Config,
    *,
    safe_redirect_url: str = "",
    flagged_redirect_url: str = "",
    brand_name: str = "",
    description: str = "",
    custom_params: dict[str, Any] | None = None,
    redirect_chains: dict[str, Any] | None = None,
) -> Campaign:
    cid = secrets.token_urlsafe(8)
    c = Campaign(
        id=cid,
        name=name,
        template=template,
        safe_redirect_url=safe_redirect_url or cfg.safe_redirect_url,
        flagged_redirect_url=flagged_redirect_url or cfg.flagged_redirect_url,
        brand_name=brand_name or cfg.brand_name,
        description=description,
        custom_params=custom_params or {},
        redirect_chains=redirect_chains or {},
    )
    save_campaign(c, cfg)
    return c


def save_campaign(campaign: Campaign, cfg: Config) -> None:
    save_campaign_db(asdict(campaign), cfg)


def load_campaign(campaign_id: str | None, cfg: Config) -> Campaign | None:
    if not campaign_id:
        return None
    data = load_campaign_db(campaign_id, cfg)
    if not data:
        return None
    return Campaign(
        id=data["id"],
        name=data["name"],
        template=data.get("template", "safelinks"),
        created_at=data.get("created_at", ""),
        active=data.get("active", True),
        safe_redirect_url=data.get("safe_redirect_url", ""),
        flagged_redirect_url=data.get("flagged_redirect_url", ""),
        brand_name=data.get("brand_name", "Microsoft"),
        description=data.get("description", ""),
        custom_params=data.get("custom_params", {}),
        redirect_chains=data.get("redirect_chains", {}),
    )


def list_campaigns(cfg: Config) -> list[Campaign]:
    rows = list_campaigns_db(cfg)
    campaigns: list[Campaign] = []
    for data in rows:
        campaigns.append(Campaign(
            id=data["id"],
            name=data["name"],
            template=data.get("template", "safelinks"),
            created_at=data.get("created_at", ""),
            active=data.get("active", True),
            safe_redirect_url=data.get("safe_redirect_url", ""),
            flagged_redirect_url=data.get("flagged_redirect_url", ""),
            brand_name=data.get("brand_name", "Microsoft"),
            description=data.get("description", ""),
            custom_params=data.get("custom_params", {}),
            redirect_chains=data.get("redirect_chains", {}),
        ))
    return campaigns


def delete_campaign(campaign_id: str, cfg: Config) -> bool:
    return delete_campaign_db(campaign_id, cfg)
