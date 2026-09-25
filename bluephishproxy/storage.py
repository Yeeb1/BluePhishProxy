"""Visit logging and daily analytics persistence."""

from __future__ import annotations

import datetime
import json
import logging
from pathlib import Path
from typing import Any

from .config import Config

logger = logging.getLogger("bluephishproxy")


def save_visit(record: dict[str, Any], cfg: Config) -> Path:
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S%f")
    sid = record.get("session_id", "unknown")
    fname = cfg.data_dir / f"{sid}-{ts}.json"
    fname.write_text(json.dumps(record, indent=2, default=str))
    return fname


def update_analytics(record: dict[str, Any], cfg: Config) -> None:
    cfg.analytics_dir.mkdir(parents=True, exist_ok=True)
    today = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")
    fname = cfg.analytics_dir / f"daily-{today}.json"

    analytics: dict[str, Any] = {
        "date": today,
        "total_visits": 0,
        "bots": 0,
        "suspicious": 0,
        "clean": 0,
        "browsers": {},
        "os": {},
        "countries": {},
        "asns": {},
        "orgs": {},
        "paths": {},
        "classifications": {},
        "vendors_seen": {},
        "top_signals": {},
        "hourly": {str(h): 0 for h in range(24)},
    }

    if fname.exists():
        try:
            analytics = json.loads(fname.read_text())
        except (json.JSONDecodeError, OSError):
            pass

    analytics["total_visits"] += 1

    classification = record.get("classification", "clean")
    analytics.setdefault("classifications", {})
    analytics["classifications"][classification] = (
        analytics["classifications"].get(classification, 0) + 1
    )

    if record.get("is_bot"):
        analytics["bots"] = analytics.get("bots", 0) + 1
    elif classification == "suspicious":
        analytics["suspicious"] = analytics.get("suspicious", 0) + 1
    else:
        analytics["clean"] = analytics.get("clean", 0) + 1

    for key, field in [
        ("browsers", "browser"),
        ("os", "os"),
        ("countries", "country"),
        ("asns", "asn"),
        ("orgs", "org"),
        ("paths", "path"),
    ]:
        val = record.get(field, "Unknown")
        analytics.setdefault(key, {})
        analytics[key][val] = analytics[key].get(val, 0) + 1

    vendor = record.get("vendor_name")
    if vendor:
        analytics.setdefault("vendors_seen", {})
        analytics["vendors_seen"][vendor] = (
            analytics["vendors_seen"].get(vendor, 0) + 1
        )

    top_sig = record.get("top_signal", "none")
    analytics.setdefault("top_signals", {})
    analytics["top_signals"][top_sig] = (
        analytics["top_signals"].get(top_sig, 0) + 1
    )

    hour = datetime.datetime.now(datetime.timezone.utc).hour
    analytics.setdefault("hourly", {str(h): 0 for h in range(24)})
    analytics["hourly"][str(hour)] = analytics["hourly"].get(str(hour), 0) + 1

    fname.write_text(json.dumps(analytics, indent=2, default=str))


def log_visit(record: dict[str, Any]) -> None:
    classification = record.get("classification", "clean").upper()
    ip = record.get("ip_address", "?")
    org = record.get("org", "?")
    country = record.get("country", "?")
    browser = record.get("browser", "?")
    version = record.get("browser_version", "")
    os_ = record.get("os", "?")
    score = record.get("detection_score", 0)
    sid = record.get("session_id", "?")

    msg = (
        f"{classification} (score={score}): SID={sid}, IP={ip}, "
        f"ORG={org}, Country={country}, UA={browser} {version} on {os_}"
    )
    vendor = record.get("vendor_name")
    if vendor:
        msg += f", VENDOR={vendor}"

    if classification == "BOT":
        logger.warning(msg)
    elif classification == "SUSPICIOUS":
        logger.info(msg)
    else:
        logger.info(msg)
