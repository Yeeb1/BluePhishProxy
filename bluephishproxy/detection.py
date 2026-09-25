"""Scoring engine that aggregates signals into a classification verdict.

The engine collects Signal objects from all fingerprint producers, sums their
weights, and maps the total to one of three verdicts:

    bot          - very likely automated / defensive infra
    suspicious   - possibly automated, warrants caution
    clean        - appears to be a real human browser

Thresholds are drawn from Config so operators can tune per-engagement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .config import Config
from .fingerprint import (
    Signal,
    compute_device_id,
    detect_prefetch,
    enrich_ip,
    parse_user_agent,
    signals_from_cloudflare,
    signals_from_headers,
    signals_from_http_version,
    signals_from_ip,
    signals_from_js,
    signals_from_timing,
    signals_from_tls,
    signals_from_ua,
)
from .vendors import Vendor, match_org, match_scanner_ua


@dataclass(slots=True)
class Verdict:
    score: int = 0
    classification: str = "clean"
    signals: list[Signal] = field(default_factory=list)
    vendor: Vendor | None = None

    @property
    def is_bot(self) -> bool:
        return self.classification == "bot"

    @property
    def is_suspicious(self) -> bool:
        return self.classification in ("bot", "suspicious")

    def summary_tags(self) -> list[str]:
        return sorted({s.tag for s in self.signals})

    def top_signal(self) -> str:
        if not self.signals:
            return "none"
        best = max(self.signals, key=lambda s: s.weight)
        return f"{best.source}:{best.tag}"


def evaluate(
    *,
    ip: str,
    user_agent: str,
    headers: dict[str, str],
    js_metrics: dict[str, Any] | None,
    elapsed_ms: float | None,
    cfg: Config,
    http_version: str | None = None,
) -> Verdict:
    all_signals: list[Signal] = []

    all_signals.extend(signals_from_ua(user_agent))

    ip_info = enrich_ip(ip, cfg)
    all_signals.extend(signals_from_ip(ip_info))

    all_signals.extend(signals_from_headers(headers))

    all_signals.extend(signals_from_js(js_metrics))

    all_signals.extend(signals_from_timing(elapsed_ms))

    if cfg.behind_cloudflare:
        all_signals.extend(signals_from_cloudflare(headers))

    all_signals.extend(signals_from_tls(headers))
    all_signals.extend(signals_from_http_version(http_version, user_agent))

    total = sum(s.weight for s in all_signals)

    if total >= cfg.bot_threshold:
        classification = "bot"
    elif total >= cfg.suspicious_threshold:
        classification = "suspicious"
    else:
        classification = "clean"

    vendor = match_scanner_ua(user_agent) or match_org(
        ip_info.get("org", "")
    )

    return Verdict(
        score=total,
        classification=classification,
        signals=all_signals,
        vendor=vendor,
    )


def build_visit_record(
    *,
    ip: str,
    user_agent: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    path: str,
    method: str,
    args: dict[str, str],
    referrer: str | None,
    session_id: str,
    js_metrics: dict[str, Any] | None,
    elapsed_ms: float | None,
    cfg: Config,
    http_version: str | None = None,
) -> dict[str, Any]:
    import datetime

    ip_info = enrich_ip(ip, cfg)
    ua_info = parse_user_agent(user_agent)
    verdict = evaluate(
        ip=ip,
        user_agent=user_agent,
        headers=headers,
        js_metrics=js_metrics,
        elapsed_ms=elapsed_ms,
        cfg=cfg,
        http_version=http_version,
    )

    record: dict[str, Any] = {
        "ip_address": ip,
        "user_agent": user_agent,
        **ip_info,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "headers": headers,
        "cookies": cookies,
        "path": path,
        "method": method,
        "args": args,
        "referrer": referrer,
        **ua_info,
        "session_id": session_id,
        "is_bot": verdict.is_bot,
        "classification": verdict.classification,
        "detection_score": verdict.score,
        "detection_signals": [
            {"source": s.source, "tag": s.tag, "weight": s.weight,
             "detail": s.detail}
            for s in verdict.signals
        ],
        "top_signal": verdict.top_signal(),
    }

    if verdict.vendor:
        record["vendor_name"] = verdict.vendor.name
        record["vendor_category"] = verdict.vendor.category

    device_id = compute_device_id(js_metrics, user_agent, headers)
    if device_id:
        record["device_id"] = device_id

    is_prefetch, prefetch_reason = detect_prefetch(
        user_agent, headers, js_metrics, elapsed_ms
    )
    if is_prefetch:
        record["is_prefetch"] = True
        record["prefetch_reason"] = prefetch_reason

    if js_metrics:
        record["advanced_metrics"] = js_metrics

    ja3 = headers.get("X-Ja3-Fingerprint") or headers.get("X-Ja3-Hash")
    if ja3:
        record["ja3_hash"] = ja3.strip()

    if http_version:
        record["http_version"] = http_version

    if cfg.behind_cloudflare:
        cf_country = headers.get("Cf-Ipcountry")
        if cf_country:
            record["cf_country"] = cf_country
            record["country"] = cf_country
        cf_ray = headers.get("Cf-Ray")
        if cf_ray:
            record["cf_ray"] = cf_ray
        cf_bot = headers.get("Cf-Bot-Score")
        if cf_bot:
            try:
                record["cf_bot_score"] = int(cf_bot)
            except ValueError:
                pass

    return record
