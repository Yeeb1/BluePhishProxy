"""Real-time webhook notifications for visit events.

Sends notifications to configured endpoints (Slack, Discord, Teams, or
generic HTTP) whenever a visit is recorded. Notifications include
classification, score, vendor info, and key signals — giving operators
instant visibility into who is probing their links.
"""

from __future__ import annotations

import json
import logging
import threading
from typing import Any

import requests as http_lib

from .config import Config

logger = logging.getLogger("bluephishproxy")


def _format_slack(record: dict[str, Any], cfg: Config) -> dict[str, Any]:
    classification = record.get("classification", "clean").upper()
    score = record.get("detection_score", 0)
    ip = record.get("ip_address", "?")
    org = record.get("org", "?")
    country = record.get("country", "?")
    vendor = record.get("vendor_name")
    path = record.get("path", "/")
    browser = record.get("browser", "?")
    os_ = record.get("os", "?")
    campaign = record.get("campaign_id", "default")
    signals = record.get("detection_signals", [])

    emoji = {"BOT": "⚠️", "SUSPICIOUS": "⚡", "CLEAN": "✅"}.get(
        classification, "❓"
    )

    signal_text = ""
    if signals:
        top = sorted(signals, key=lambda s: s.get("weight", 0), reverse=True)[:5]
        signal_text = "\n".join(
            f"  • `{s['tag']}` (weight={s['weight']}) {s.get('detail', '')}"
            for s in top
        )

    text = (
        f"{emoji} *{classification}* (score={score})\n"
        f"*IP:* `{ip}` | *Org:* {org} | *Country:* {country}\n"
        f"*Browser:* {browser} on {os_} | *Path:* `{path}`\n"
        f"*Campaign:* {campaign}"
    )
    if vendor:
        text += f"\n*Vendor:* {vendor}"
    if signal_text:
        text += f"\n*Signals:*\n{signal_text}"

    return {"text": text}


def _format_discord(record: dict[str, Any], cfg: Config) -> dict[str, Any]:
    classification = record.get("classification", "clean").upper()
    score = record.get("detection_score", 0)
    ip = record.get("ip_address", "?")
    org = record.get("org", "?")
    country = record.get("country", "?")
    vendor = record.get("vendor_name")
    path = record.get("path", "/")
    campaign = record.get("campaign_id", "default")
    signals = record.get("detection_signals", [])

    color = {"BOT": 0xFF4444, "SUSPICIOUS": 0xFFAA00, "CLEAN": 0x44FF44}.get(
        classification, 0x888888
    )

    fields = [
        {"name": "IP", "value": f"`{ip}`", "inline": True},
        {"name": "Org", "value": org, "inline": True},
        {"name": "Country", "value": country, "inline": True},
        {"name": "Score", "value": str(score), "inline": True},
        {"name": "Path", "value": f"`{path}`", "inline": True},
        {"name": "Campaign", "value": campaign, "inline": True},
    ]
    if vendor:
        fields.append({"name": "Vendor", "value": vendor, "inline": True})
    if signals:
        top = sorted(signals, key=lambda s: s.get("weight", 0), reverse=True)[:5]
        sig_lines = "\n".join(
            f"`{s['tag']}` w={s['weight']}" for s in top
        )
        fields.append({"name": "Top Signals", "value": sig_lines, "inline": False})

    return {
        "embeds": [{
            "title": f"{classification} Visit Detected",
            "color": color,
            "fields": fields,
            "timestamp": record.get("timestamp"),
        }]
    }


def _format_teams(record: dict[str, Any], cfg: Config) -> dict[str, Any]:
    classification = record.get("classification", "clean").upper()
    score = record.get("detection_score", 0)
    ip = record.get("ip_address", "?")
    org = record.get("org", "?")

    return {
        "@type": "MessageCard",
        "summary": f"BluePhishProxy: {classification} visit from {ip}",
        "themeColor": {"BOT": "FF4444", "SUSPICIOUS": "FFAA00", "CLEAN": "44FF44"}.get(
            classification, "888888"
        ),
        "title": f"BluePhishProxy: {classification} (score={score})",
        "text": f"**IP:** {ip}  \n**Org:** {org}  \n**Score:** {score}",
    }


def _format_generic(record: dict[str, Any], cfg: Config) -> dict[str, Any]:
    return {
        "event": "visit",
        "classification": record.get("classification"),
        "score": record.get("detection_score"),
        "ip": record.get("ip_address"),
        "org": record.get("org"),
        "country": record.get("country"),
        "vendor": record.get("vendor_name"),
        "path": record.get("path"),
        "campaign_id": record.get("campaign_id"),
        "session_id": record.get("session_id"),
        "timestamp": record.get("timestamp"),
        "signals": record.get("detection_signals"),
        "user_agent": record.get("user_agent"),
    }


_FORMATTERS = {
    "slack": _format_slack,
    "discord": _format_discord,
    "teams": _format_teams,
    "generic": _format_generic,
}


def _send_webhook(url: str, payload: dict[str, Any], timeout: float = 5.0) -> None:
    try:
        r = http_lib.post(url, json=payload, timeout=timeout)
        if r.status_code >= 400:
            logger.warning("Webhook %s returned %d", url[:60], r.status_code)
    except Exception as exc:
        logger.warning("Webhook %s failed: %s", url[:60], exc)


def notify(record: dict[str, Any], cfg: Config) -> None:
    hooks = cfg.webhook_urls
    if not hooks:
        return

    min_level = cfg.webhook_min_level
    classification = record.get("classification", "clean")
    levels = {"bot": 3, "suspicious": 2, "clean": 1}
    if levels.get(classification, 0) < levels.get(min_level, 1):
        return

    for hook_def in hooks:
        if isinstance(hook_def, str):
            url = hook_def
            hook_type = "generic"
        else:
            url = hook_def.get("url", "")
            hook_type = hook_def.get("type", "generic")

        if not url:
            continue

        formatter = _FORMATTERS.get(hook_type, _format_generic)
        payload = formatter(record, cfg)

        threading.Thread(
            target=_send_webhook,
            args=(url, payload),
            daemon=True,
        ).start()
