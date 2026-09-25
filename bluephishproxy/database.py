"""SQLite database backend for BluePhishProxy.

Replaces JSON file storage with a proper relational database for scalability.
Uses Python's built-in sqlite3 module — no external dependencies.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Generator

from .config import Config

_local = threading.local()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    ip_address TEXT NOT NULL,
    user_agent TEXT,
    org TEXT,
    asn TEXT,
    country TEXT,
    region TEXT,
    city TEXT,
    hostname TEXT,
    browser TEXT,
    browser_version TEXT,
    os TEXT,
    device TEXT,
    path TEXT,
    method TEXT,
    referrer TEXT,
    campaign_id TEXT,
    campaign_name TEXT,
    template TEXT,
    classification TEXT NOT NULL DEFAULT 'clean',
    detection_score INTEGER NOT NULL DEFAULT 0,
    is_bot INTEGER NOT NULL DEFAULT 0,
    top_signal TEXT,
    vendor_name TEXT,
    vendor_category TEXT,
    headers_json TEXT,
    cookies_json TEXT,
    args_json TEXT,
    signals_json TEXT,
    metrics_json TEXT,
    ja3_hash TEXT,
    http_version TEXT,
    cf_bot_score INTEGER,
    cf_country TEXT,
    cf_ray TEXT,
    recipient_id INTEGER,
    tracking_token TEXT,
    device_id TEXT,
    is_prefetch INTEGER NOT NULL DEFAULT 0,
    prefetch_reason TEXT,
    timestamp TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_visits_campaign ON visits(campaign_id);
CREATE INDEX IF NOT EXISTS idx_visits_classification ON visits(classification);
CREATE INDEX IF NOT EXISTS idx_visits_timestamp ON visits(timestamp);
CREATE INDEX IF NOT EXISTS idx_visits_ip ON visits(ip_address);
CREATE INDEX IF NOT EXISTS idx_visits_session ON visits(session_id);
CREATE INDEX IF NOT EXISTS idx_visits_token ON visits(tracking_token);
CREATE INDEX IF NOT EXISTS idx_visits_device ON visits(device_id);
CREATE INDEX IF NOT EXISTS idx_visits_recipient ON visits(recipient_id);

CREATE TABLE IF NOT EXISTS campaigns (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    template TEXT NOT NULL DEFAULT 'safelinks',
    created_at TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 1,
    safe_redirect_url TEXT,
    flagged_redirect_url TEXT,
    brand_name TEXT DEFAULT 'Microsoft',
    description TEXT,
    custom_params_json TEXT DEFAULT '{}',
    redirect_chains_json TEXT DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS analytics_daily (
    date TEXT NOT NULL,
    key TEXT NOT NULL,
    value INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (date, key)
);

CREATE TABLE IF NOT EXISTS recipients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    campaign_id TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT,
    department TEXT,
    token TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'pending',
    first_click_at TEXT,
    last_click_at TEXT,
    click_count INTEGER NOT NULL DEFAULT 0,
    device_ids TEXT DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_recipients_token ON recipients(token);
CREATE INDEX IF NOT EXISTS idx_recipients_campaign ON recipients(campaign_id);
CREATE INDEX IF NOT EXISTS idx_recipients_email ON recipients(email);

CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    name TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'admin',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used TEXT,
    active INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
"""


def _get_db_path(cfg: Config) -> str:
    path = Path(cfg.database_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    return str(path)


@contextmanager
def get_db(cfg: Config) -> Generator[sqlite3.Connection, None, None]:
    db_path = _get_db_path(cfg)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db(cfg: Config) -> None:
    with get_db(cfg) as conn:
        conn.executescript(_SCHEMA)


# --- Visit storage --------------------------------------------------------

def save_visit_db(record: dict[str, Any], cfg: Config) -> int:
    with get_db(cfg) as conn:
        cur = conn.execute(
            """INSERT INTO visits (
                session_id, ip_address, user_agent, org, asn, country, region,
                city, hostname, browser, browser_version, os, device, path,
                method, referrer, campaign_id, campaign_name, template,
                classification, detection_score, is_bot, top_signal,
                vendor_name, vendor_category, headers_json, cookies_json,
                args_json, signals_json, metrics_json, ja3_hash,
                http_version, cf_bot_score, cf_country, cf_ray,
                recipient_id, tracking_token, device_id,
                is_prefetch, prefetch_reason, timestamp
            ) VALUES (
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                ?, ?, ?, ?, ?, ?
            )""",
            (
                record.get("session_id", ""),
                record.get("ip_address", ""),
                record.get("user_agent", ""),
                record.get("org", ""),
                record.get("asn", ""),
                record.get("country", ""),
                record.get("region", ""),
                record.get("city", ""),
                record.get("hostname", ""),
                record.get("browser", ""),
                record.get("browser_version", ""),
                record.get("os", ""),
                record.get("device", ""),
                record.get("path", ""),
                record.get("method", ""),
                record.get("referrer", ""),
                record.get("campaign_id"),
                record.get("campaign_name"),
                record.get("template"),
                record.get("classification", "clean"),
                record.get("detection_score", 0),
                1 if record.get("is_bot") else 0,
                record.get("top_signal", ""),
                record.get("vendor_name"),
                record.get("vendor_category"),
                json.dumps(record.get("headers", {}), default=str),
                json.dumps(record.get("cookies", {}), default=str),
                json.dumps(record.get("args", {}), default=str),
                json.dumps(record.get("detection_signals", []), default=str),
                json.dumps(record.get("advanced_metrics", {}), default=str),
                record.get("ja3_hash"),
                record.get("http_version"),
                record.get("cf_bot_score"),
                record.get("cf_country"),
                record.get("cf_ray"),
                record.get("recipient_id"),
                record.get("tracking_token"),
                record.get("device_id"),
                1 if record.get("is_prefetch") else 0,
                record.get("prefetch_reason"),
                record.get("timestamp", datetime.now(timezone.utc).isoformat()),
            ),
        )
        return cur.lastrowid or 0


def query_visits(
    cfg: Config,
    *,
    campaign_id: str | None = None,
    classification: str | None = None,
    ip_address: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[dict[str, Any]]:
    conditions: list[str] = []
    params: list[Any] = []

    if campaign_id:
        conditions.append("campaign_id = ?")
        params.append(campaign_id)
    if classification:
        conditions.append("classification = ?")
        params.append(classification)
    if ip_address:
        conditions.append("ip_address = ?")
        params.append(ip_address)

    where = f"WHERE {' AND '.join(conditions)}" if conditions else ""
    params.extend([limit, offset])

    with get_db(cfg) as conn:
        rows = conn.execute(
            f"SELECT * FROM visits {where} ORDER BY id DESC LIMIT ? OFFSET ?",
            params,
        ).fetchall()
        return [dict(row) for row in rows]


def get_visit(cfg: Config, session_id: str) -> dict[str, Any] | None:
    with get_db(cfg) as conn:
        row = conn.execute(
            "SELECT * FROM visits WHERE session_id = ? ORDER BY id DESC LIMIT 1",
            (session_id,),
        ).fetchone()
        return dict(row) if row else None


def get_visit_stats(cfg: Config, campaign_id: str | None = None) -> dict[str, Any]:
    condition = "WHERE campaign_id = ?" if campaign_id else ""
    params = [campaign_id] if campaign_id else []

    with get_db(cfg) as conn:
        row = conn.execute(
            f"""SELECT
                COUNT(*) as total,
                SUM(CASE WHEN classification = 'bot' THEN 1 ELSE 0 END) as bots,
                SUM(CASE WHEN classification = 'suspicious' THEN 1 ELSE 0 END) as suspicious,
                SUM(CASE WHEN classification = 'clean' THEN 1 ELSE 0 END) as clean,
                COUNT(DISTINCT ip_address) as unique_ips
            FROM visits {condition}""",
            params,
        ).fetchone()
        return dict(row) if row else {}


def get_vendor_stats(cfg: Config, campaign_id: str | None = None) -> list[dict[str, Any]]:
    condition = "WHERE vendor_name IS NOT NULL"
    params: list[Any] = []
    if campaign_id:
        condition += " AND campaign_id = ?"
        params.append(campaign_id)

    with get_db(cfg) as conn:
        rows = conn.execute(
            f"""SELECT vendor_name, vendor_category, COUNT(*) as count
            FROM visits {condition}
            GROUP BY vendor_name ORDER BY count DESC""",
            params,
        ).fetchall()
        return [dict(row) for row in rows]


# --- Campaign storage -----------------------------------------------------

def save_campaign_db(campaign_data: dict[str, Any], cfg: Config) -> None:
    with get_db(cfg) as conn:
        conn.execute(
            """INSERT OR REPLACE INTO campaigns
            (id, name, template, created_at, active, safe_redirect_url,
             flagged_redirect_url, brand_name, description,
             custom_params_json, redirect_chains_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                campaign_data["id"],
                campaign_data["name"],
                campaign_data.get("template", "safelinks"),
                campaign_data.get("created_at", datetime.now(timezone.utc).isoformat()),
                1 if campaign_data.get("active", True) else 0,
                campaign_data.get("safe_redirect_url", ""),
                campaign_data.get("flagged_redirect_url", ""),
                campaign_data.get("brand_name", "Microsoft"),
                campaign_data.get("description", ""),
                json.dumps(campaign_data.get("custom_params", {})),
                json.dumps(campaign_data.get("redirect_chains", {})),
            ),
        )


def load_campaign_db(campaign_id: str, cfg: Config) -> dict[str, Any] | None:
    with get_db(cfg) as conn:
        row = conn.execute(
            "SELECT * FROM campaigns WHERE id = ?", (campaign_id,)
        ).fetchone()
        if not row:
            return None
        d = dict(row)
        d["active"] = bool(d["active"])
        d["custom_params"] = json.loads(d.pop("custom_params_json", "{}"))
        d["redirect_chains"] = json.loads(d.pop("redirect_chains_json", "{}"))
        return d


def list_campaigns_db(cfg: Config) -> list[dict[str, Any]]:
    with get_db(cfg) as conn:
        rows = conn.execute(
            "SELECT * FROM campaigns ORDER BY created_at DESC"
        ).fetchall()
        results = []
        for row in rows:
            d = dict(row)
            d["active"] = bool(d["active"])
            d["custom_params"] = json.loads(d.pop("custom_params_json", "{}"))
            d["redirect_chains"] = json.loads(d.pop("redirect_chains_json", "{}"))
            results.append(d)
        return results


def delete_campaign_db(campaign_id: str, cfg: Config) -> bool:
    with get_db(cfg) as conn:
        cur = conn.execute("DELETE FROM campaigns WHERE id = ?", (campaign_id,))
        return cur.rowcount > 0


# --- Analytics ------------------------------------------------------------

def update_analytics_db(record: dict[str, Any], cfg: Config) -> None:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    hour = str(datetime.now(timezone.utc).hour)

    increments = [
        (today, "total_visits"),
        (today, f"classification:{record.get('classification', 'clean')}"),
        (today, f"browser:{record.get('browser', 'Unknown')}"),
        (today, f"os:{record.get('os', 'Unknown')}"),
        (today, f"country:{record.get('country', 'Unknown')}"),
        (today, f"hour:{hour}"),
    ]
    vendor = record.get("vendor_name")
    if vendor:
        increments.append((today, f"vendor:{vendor}"))

    top_sig = record.get("top_signal")
    if top_sig:
        increments.append((today, f"signal:{top_sig}"))

    with get_db(cfg) as conn:
        for date, key in increments:
            conn.execute(
                """INSERT INTO analytics_daily (date, key, value)
                VALUES (?, ?, 1)
                ON CONFLICT(date, key) DO UPDATE SET value = value + 1""",
                (date, key),
            )


def get_analytics_db(cfg: Config, days: int = 30) -> list[dict[str, Any]]:
    with get_db(cfg) as conn:
        rows = conn.execute(
            """SELECT date, key, value FROM analytics_daily
            ORDER BY date DESC, value DESC
            LIMIT ?""",
            (days * 100,),
        ).fetchall()

        by_date: dict[str, dict[str, Any]] = {}
        for row in rows:
            d = row["date"]
            if d not in by_date:
                by_date[d] = {"date": d}
            by_date[d][row["key"]] = row["value"]
        return list(by_date.values())


# --- API key management ---------------------------------------------------

def _hash_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_api_key(cfg: Config, name: str, role: str = "admin") -> str:
    key = f"bpp_{secrets.token_urlsafe(32)}"
    key_hash = _hash_key(key)
    prefix = key[:12]

    with get_db(cfg) as conn:
        conn.execute(
            "INSERT INTO api_keys (key_hash, key_prefix, name, role) VALUES (?, ?, ?, ?)",
            (key_hash, prefix, name, role),
        )
    return key


def validate_api_key(cfg: Config, key: str) -> dict[str, Any] | None:
    key_hash = _hash_key(key)
    with get_db(cfg) as conn:
        row = conn.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND active = 1",
            (key_hash,),
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE api_keys SET last_used = datetime('now') WHERE id = ?",
                (row["id"],),
            )
            return dict(row)
    return None


def list_api_keys(cfg: Config) -> list[dict[str, Any]]:
    with get_db(cfg) as conn:
        rows = conn.execute(
            "SELECT id, key_prefix, name, role, created_at, last_used, active "
            "FROM api_keys ORDER BY created_at DESC"
        ).fetchall()
        return [dict(row) for row in rows]


# --- Recipient / tracking token management --------------------------------

def _generate_token(length: int = 8) -> str:
    return secrets.token_urlsafe(length)[:length]


def import_recipients(
    cfg: Config,
    campaign_id: str,
    recipients: list[dict[str, str]],
) -> list[dict[str, str]]:
    results = []
    with get_db(cfg) as conn:
        for r in recipients:
            token = _generate_token()
            conn.execute(
                """INSERT INTO recipients (campaign_id, email, name, department, token)
                VALUES (?, ?, ?, ?, ?)""",
                (campaign_id, r["email"], r.get("name", ""), r.get("department", ""), token),
            )
            results.append({"email": r["email"], "token": token})
    return results


def get_recipient_by_token(cfg: Config, token: str) -> dict[str, Any] | None:
    with get_db(cfg) as conn:
        row = conn.execute(
            "SELECT * FROM recipients WHERE token = ?", (token,)
        ).fetchone()
        return dict(row) if row else None


def list_recipients(
    cfg: Config,
    campaign_id: str | None = None,
) -> list[dict[str, Any]]:
    if campaign_id:
        sql = "SELECT * FROM recipients WHERE campaign_id = ? ORDER BY created_at"
        params: list[Any] = [campaign_id]
    else:
        sql = "SELECT * FROM recipients ORDER BY created_at"
        params = []
    with get_db(cfg) as conn:
        rows = conn.execute(sql, params).fetchall()
        return [dict(row) for row in rows]


def record_recipient_click(
    cfg: Config,
    token: str,
    device_id: str | None = None,
) -> None:
    now = datetime.now(timezone.utc).isoformat()
    with get_db(cfg) as conn:
        row = conn.execute(
            "SELECT id, device_ids, first_click_at FROM recipients WHERE token = ?",
            (token,),
        ).fetchone()
        if not row:
            return

        device_ids: list[str] = json.loads(row["device_ids"] or "[]")
        if device_id and device_id not in device_ids:
            device_ids.append(device_id)

        updates = {
            "status": "clicked",
            "last_click_at": now,
            "click_count": "click_count + 1",
            "device_ids": json.dumps(device_ids),
        }
        if not row["first_click_at"]:
            updates["first_click_at"] = now

        conn.execute(
            """UPDATE recipients SET
                status = 'clicked',
                first_click_at = COALESCE(first_click_at, ?),
                last_click_at = ?,
                click_count = click_count + 1,
                device_ids = ?
            WHERE token = ?""",
            (now, now, json.dumps(device_ids), token),
        )


def get_recipient_stats(cfg: Config, campaign_id: str | None = None) -> dict[str, Any]:
    condition = "WHERE campaign_id = ?" if campaign_id else ""
    params = [campaign_id] if campaign_id else []
    with get_db(cfg) as conn:
        row = conn.execute(
            f"""SELECT
                COUNT(*) as total,
                SUM(CASE WHEN status = 'clicked' THEN 1 ELSE 0 END) as clicked,
                SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending,
                SUM(click_count) as total_clicks,
                COUNT(DISTINCT CASE WHEN status = 'clicked' THEN email END) as unique_clickers
            FROM recipients {condition}""",
            params,
        ).fetchone()
        return dict(row) if row else {}


def delete_recipient(cfg: Config, recipient_id: int) -> bool:
    with get_db(cfg) as conn:
        cur = conn.execute("DELETE FROM recipients WHERE id = ?", (recipient_id,))
        return cur.rowcount > 0


def revoke_api_key(cfg: Config, key_id: int) -> bool:
    with get_db(cfg) as conn:
        cur = conn.execute(
            "UPDATE api_keys SET active = 0 WHERE id = ?", (key_id,)
        )
        return cur.rowcount > 0
