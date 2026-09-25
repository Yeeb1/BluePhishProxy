"""Individual detection signal producers.

Each function examines one facet of a request and returns a list of Signal
objects. The detection module aggregates all signals into a scored verdict.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from typing import Any

import requests as http_lib

from .config import Config
from .vendors import (
    GENERIC_BOT_TOKENS,
    HEADLESS_TOKENS,
    HTTP_LIBRARY_TOKENS,
    SCANNER_TOOL_TOKENS,
    is_hosting_org,
    match_org,
    match_scanner_ua,
)


@dataclass(frozen=True, slots=True)
class Signal:
    source: str
    tag: str
    weight: int
    detail: str = ""


# ---------------------------------------------------------------------------
# IP / ASN enrichment
# ---------------------------------------------------------------------------

_ip_cache: dict[str, dict[str, str]] = {}


def enrich_ip(ip: str, cfg: Config) -> dict[str, str]:
    if ip in _ip_cache:
        return _ip_cache[ip]

    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"asn": "Invalid", "org": "Invalid", "country": "Unknown"}

    if addr.is_private or addr.is_loopback:
        data = {"asn": "Private", "org": "Private Network", "country": "Local"}
        _ip_cache[ip] = data
        return data

    if not cfg.enable_ip_enrichment:
        return {"asn": "Disabled", "org": "Disabled", "country": "Unknown"}

    url = f"https://ipinfo.io/{ip}/json"
    params: dict[str, str] = {}
    if cfg.ipinfo_token:
        params["token"] = cfg.ipinfo_token

    try:
        r = http_lib.get(url, params=params, timeout=cfg.ipinfo_timeout)
        if r.status_code == 200:
            raw = r.json()
            org_val = raw.get("org", "Unknown")
            parts = org_val.split(" ", 1)
            data = {
                "asn": parts[0] if parts else "Unknown",
                "org": parts[1] if len(parts) > 1 else "Unknown",
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

    _ip_cache[ip] = data
    return data


# ---------------------------------------------------------------------------
# User-Agent parsing
# ---------------------------------------------------------------------------

_BROWSER_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Edge", re.compile(r"Edg[e]?/(\d+[\.\d]*)")),
    ("Opera", re.compile(r"(?:OPR|Opera)[/ ](\d+[\.\d]*)")),
    ("Chrome", re.compile(r"Chrome/(\d+[\.\d]*)")),
    ("Firefox", re.compile(r"Firefox/(\d+[\.\d]*)")),
    ("Safari", re.compile(r"Version/(\d+[\.\d]*).*Safari")),
    ("MSIE", re.compile(r"MSIE (\d+[\.\d]*)")),
    ("Trident", re.compile(r"rv:(\d+[\.\d]*)")),
]


def parse_user_agent(ua: str) -> dict[str, str]:
    result: dict[str, str] = {
        "browser": "Unknown",
        "browser_version": "Unknown",
        "os": "Unknown",
        "device": "Desktop",
    }

    if not ua:
        return result

    if "Mobile" in ua or "Android" in ua:
        result["device"] = "Mobile"
    elif "Tablet" in ua or "iPad" in ua:
        result["device"] = "Tablet"

    for name, pat in _BROWSER_PATTERNS:
        m = pat.search(ua)
        if m:
            result["browser"] = name
            result["browser_version"] = m.group(1)
            break

    ua_l = ua.lower()
    if "windows" in ua_l:
        result["os"] = "Windows"
    elif "mac os x" in ua_l or "macintosh" in ua_l:
        result["os"] = "macOS"
    elif "iphone" in ua_l or "ipad" in ua_l:
        result["os"] = "iOS"
    elif "android" in ua_l:
        result["os"] = "Android"
    elif "linux" in ua_l:
        result["os"] = "Linux"
    elif "cros" in ua_l:
        result["os"] = "ChromeOS"

    return result


# ---------------------------------------------------------------------------
# Signal producers
# ---------------------------------------------------------------------------

def signals_from_ua(ua: str) -> list[Signal]:
    signals: list[Signal] = []
    if not ua:
        signals.append(Signal("ua", "missing-ua", 40, "No User-Agent header"))
        return signals

    ua_l = ua.lower()

    vendor = match_scanner_ua(ua_l)
    if vendor:
        signals.append(Signal("ua", "scanner-vendor", 80,
                              f"{vendor.name} ({vendor.category})"))
        return signals

    for token in HEADLESS_TOKENS:
        if token in ua_l:
            signals.append(Signal("ua", "headless", 70, f"Token: {token}"))
            return signals

    for token in SCANNER_TOOL_TOKENS:
        if token in ua_l:
            signals.append(Signal("ua", "scanner-tool", 75, f"Token: {token}"))
            return signals

    for token in HTTP_LIBRARY_TOKENS:
        if token in ua_l:
            signals.append(Signal("ua", "http-library", 65, f"Token: {token}"))
            return signals

    for token in GENERIC_BOT_TOKENS:
        if token in ua_l:
            signals.append(Signal("ua", "generic-bot", 55, f"Token: {token}"))
            return signals

    return signals


def signals_from_headers(headers: dict[str, str]) -> list[Signal]:
    signals: list[Signal] = []

    if not headers.get("Accept-Language"):
        signals.append(Signal("header", "no-accept-language", 15,
                              "Missing Accept-Language"))

    if not headers.get("Accept-Encoding"):
        signals.append(Signal("header", "no-accept-encoding", 10,
                              "Missing Accept-Encoding"))

    accept = headers.get("Accept", "")
    if accept and "text/html" not in accept and "application/xhtml" not in accept:
        signals.append(Signal("header", "non-browser-accept", 20,
                              f"Accept: {accept[:80]}"))

    conn = headers.get("Connection", "").lower()
    if conn == "close":
        signals.append(Signal("header", "connection-close", 10,
                              "Connection: close (typical of scripts)"))

    via = headers.get("Via", "")
    if via:
        signals.append(Signal("header", "via-header", 15,
                              f"Via: {via[:80]}"))

    xff = headers.get("X-Forwarded-For", "")
    if xff and "," in xff:
        signals.append(Signal("header", "multi-hop-xff", 10,
                              f"Multi-hop XFF: {xff[:80]}"))

    for hdr in ("X-Scanner", "X-Virus-Scanned", "X-Antivirus",
                "X-Spam-Flag", "X-Spam-Status"):
        if headers.get(hdr):
            signals.append(Signal("header", "security-header", 30,
                                  f"{hdr}: {headers[hdr][:40]}"))

    ua = headers.get("User-Agent", "")
    if ua:
        parsed = parse_user_agent(ua)
        claimed_device = parsed["device"]
        claimed_os = parsed["os"]
        sec_ch_mobile = headers.get("Sec-CH-UA-Mobile", "")
        sec_ch_platform = headers.get("Sec-CH-UA-Platform", "")

        if sec_ch_mobile == "?0" and claimed_device == "Mobile":
            signals.append(Signal("header", "ch-mobile-mismatch", 25,
                                  "Claims mobile UA but Sec-CH-UA-Mobile=?0"))
        if sec_ch_platform:
            plat = sec_ch_platform.strip('"').lower()
            if plat == "linux" and claimed_os == "Windows":
                signals.append(Signal("header", "ch-platform-mismatch", 25,
                                      f"UA says Windows, CH says {plat}"))

    return signals


def signals_from_ip(ip_info: dict[str, str]) -> list[Signal]:
    signals: list[Signal] = []
    org = ip_info.get("org", "")

    vendor = match_org(org)
    if vendor:
        signals.append(Signal("ip", "security-vendor-org", 70,
                              f"{vendor.name} ({vendor.category})"))

    if is_hosting_org(org):
        signals.append(Signal("ip", "hosting-provider", 30,
                              f"Datacenter/hosting: {org}"))

    hostname = ip_info.get("hostname", "")
    if hostname and hostname != "Unknown":
        vendor = match_org(hostname)
        if vendor:
            signals.append(Signal("ip", "security-vendor-ptr", 65,
                                  f"PTR: {hostname} => {vendor.name}"))

    return signals


def signals_from_js(metrics: dict[str, Any] | None) -> list[Signal]:
    signals: list[Signal] = []
    if metrics is None:
        signals.append(Signal("js", "no-js-metrics", 25,
                              "No JS fingerprint collected"))
        return signals

    if metrics.get("webdriver"):
        signals.append(Signal("js", "webdriver-true", 80,
                              "navigator.webdriver is true"))

    mouse_moves = metrics.get("mouseMoves", 0)
    if mouse_moves < 1:
        signals.append(Signal("js", "no-mouse-movement", 35,
                              "Zero mouse/touch events"))
    elif mouse_moves < 3:
        signals.append(Signal("js", "minimal-mouse", 15,
                              f"Only {mouse_moves} mouse events"))

    if metrics.get("automationAPIs"):
        signals.append(Signal("js", "automation-apis", 75,
                              "Automation APIs detected (phantom/selenium/etc)"))

    plugins = metrics.get("pluginCount", -1)
    if plugins == 0:
        signals.append(Signal("js", "no-plugins", 15,
                              "Zero navigator.plugins"))

    if metrics.get("touchSupport") and not metrics.get("hasTouchEvents"):
        signals.append(Signal("js", "touch-mismatch", 20,
                              "Touch API present but no touch events fired"))

    if metrics.get("canvasBlocked"):
        signals.append(Signal("js", "canvas-blocked", 20,
                              "Canvas fingerprint returned blank"))

    if metrics.get("audioBlocked"):
        signals.append(Signal("js", "audio-blocked", 15,
                              "AudioContext fingerprint failed"))

    lang_count = metrics.get("languageCount", -1)
    if lang_count == 0:
        signals.append(Signal("js", "no-languages", 20,
                              "navigator.languages is empty"))

    if metrics.get("notificationPermission") == "denied" and \
       metrics.get("cookiesEnabled") is False:
        signals.append(Signal("js", "privacy-lockdown", 15,
                              "Notifications denied + cookies disabled"))

    wo = metrics.get("windowOuter")
    if wo is not None and wo == [0, 0]:
        signals.append(Signal("js", "zero-outer-window", 30,
                              "outerWidth/Height are 0 (headless)"))

    screen = metrics.get("screenSize", [0, 0])
    window = metrics.get("windowSize", [0, 0])
    if screen and window and screen[0] > 0 and window[0] > 0:
        if window[0] > screen[0] or window[1] > screen[1]:
            signals.append(Signal("js", "window-exceeds-screen", 25,
                                  "Window larger than screen (spoofed)"))

    color_depth = metrics.get("colorDepth", 0)
    if color_depth and color_depth not in (24, 30, 32, 48):
        signals.append(Signal("js", "unusual-color-depth", 10,
                              f"colorDepth={color_depth}"))

    raf_delta = metrics.get("rafDelta")
    if raf_delta is not None and raf_delta < 2:
        signals.append(Signal("js", "instant-raf", 30,
                              f"requestAnimationFrame delta={raf_delta}ms (headless)"))

    perf = metrics.get("performanceTiming")
    if perf:
        dom_load = perf.get("domContentLoaded", 0)
        if dom_load > 0 and dom_load < 5:
            signals.append(Signal("js", "instant-dom-load", 25,
                                  f"DOMContentLoaded in {dom_load}ms"))

    return signals


def signals_from_timing(elapsed_ms: float | None) -> list[Signal]:
    signals: list[Signal] = []
    if elapsed_ms is not None and elapsed_ms < 500:
        signals.append(Signal("timing", "instant-arrival", 20,
                              f"Arrived at final page in {elapsed_ms:.0f}ms"))
    return signals
