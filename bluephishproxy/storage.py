"""Visit logging — console/file output only.

Database persistence is handled by database.py. This module retains the
structured log output for operator visibility.
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("bluephishproxy")


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

    ja3 = record.get("ja3_hash")
    if ja3:
        msg += f", JA3={ja3[:16]}"

    http_ver = record.get("http_version")
    if http_ver:
        msg += f", PROTO={http_ver}"

    if classification == "BOT":
        logger.warning(msg)
    elif classification == "SUSPICIOUS":
        logger.info(msg)
    else:
        logger.info(msg)
