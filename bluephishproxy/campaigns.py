"""Campaign management for multi-engagement tracking.

Each campaign has its own ID, template, redirect URLs, and visit history.
Campaigns are stored as JSON files in the campaigns directory and referenced
by URL path prefix (e.g. /c/<campaign_id>/...).
"""

from __future__ import annotations

import json
import secrets
import datetime
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any

from .config import Config


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

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()


def _campaigns_dir(cfg: Config) -> Path:
    d = cfg.data_dir.parent / "campaigns"
    d.mkdir(parents=True, exist_ok=True)
    return d


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
    )
    save_campaign(c, cfg)
    return c


def save_campaign(campaign: Campaign, cfg: Config) -> Path:
    d = _campaigns_dir(cfg)
    path = d / f"{campaign.id}.json"
    path.write_text(json.dumps(asdict(campaign), indent=2))
    return path


def load_campaign(campaign_id: str, cfg: Config) -> Campaign | None:
    path = _campaigns_dir(cfg) / f"{campaign_id}.json"
    if not path.exists():
        return None
    try:
        data = json.loads(path.read_text())
        return Campaign(**data)
    except (json.JSONDecodeError, TypeError, OSError):
        return None


def list_campaigns(cfg: Config) -> list[Campaign]:
    d = _campaigns_dir(cfg)
    campaigns: list[Campaign] = []
    for f in sorted(d.glob("*.json")):
        try:
            data = json.loads(f.read_text())
            campaigns.append(Campaign(**data))
        except (json.JSONDecodeError, TypeError, OSError):
            continue
    return campaigns


def delete_campaign(campaign_id: str, cfg: Config) -> bool:
    path = _campaigns_dir(cfg) / f"{campaign_id}.json"
    if path.exists():
        path.unlink()
        return True
    return False
