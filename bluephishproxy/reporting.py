"""Engagement report generation — SQLite-backed.

Reads visit data from the SQLite database to produce a summary report
in Markdown that operators can hand to customers.
"""

from __future__ import annotations

import datetime
from collections import Counter
from pathlib import Path
from typing import Any

from .config import Config
from .database import query_visits, get_visit_stats, get_vendor_stats


def _load_visits_db(cfg: Config, limit: int = 5000) -> list[dict[str, Any]]:
    return query_visits(cfg, limit=limit)


def _section_stats(visits: list[dict[str, Any]], heading: str) -> list[str]:
    if not visits:
        return []

    total = len(visits)
    bots = [v for v in visits if v.get("is_bot") or v.get("classification") == "bot"]
    suspicious = [v for v in visits if v.get("classification") == "suspicious"]
    clean = [v for v in visits if v.get("classification") == "clean"]

    vendor_counter: Counter[str] = Counter()
    org_counter: Counter[str] = Counter()
    country_counter: Counter[str] = Counter()
    signal_counter: Counter[str] = Counter()
    ip_set: set[str] = set()

    for v in visits:
        vendor = v.get("vendor_name")
        if vendor:
            vendor_counter[vendor] += 1
        org_counter[v.get("org", "Unknown")] += 1
        country_counter[v.get("country", "Unknown")] += 1
        ip_set.add(v.get("ip_address", "?"))
        top_sig = v.get("top_signal", "")
        if top_sig:
            signal_counter[top_sig] += 1

    lines = [
        f"## {heading}",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total visits | {total} |",
        f"| Unique IPs | {len(ip_set)} |",
        f"| Classified as bot | {len(bots)} |",
        f"| Classified as suspicious | {len(suspicious)} |",
        f"| Classified as clean | {len(clean)} |",
        f"| Unique security vendors seen | {len(vendor_counter)} |",
        "",
    ]

    if vendor_counter:
        lines += [
            "### Security Vendors Detected", "",
            "| Vendor | Hits |", "|--------|------|",
        ]
        for vendor, count in vendor_counter.most_common():
            lines.append(f"| {vendor} | {count} |")
        lines.append("")

    if org_counter:
        lines += [
            "### Top Organisations (by IP)", "",
            "| Organisation | Hits |", "|-------------|------|",
        ]
        for org, count in org_counter.most_common(20):
            lines.append(f"| {org} | {count} |")
        lines.append("")

    if country_counter:
        lines += [
            "### Countries", "",
            "| Country | Hits |", "|---------|------|",
        ]
        for country, count in country_counter.most_common(15):
            lines.append(f"| {country} | {count} |")
        lines.append("")

    if signal_counter:
        lines += [
            "### Top Detection Signals", "",
            "| Signal | Occurrences |", "|--------|-------------|",
        ]
        for sig, count in signal_counter.most_common(20):
            lines.append(f"| {sig} | {count} |")
        lines.append("")

    if bots:
        lines += ["### Bot / Scanner Visit Details", ""]
        for v in bots[:50]:
            ip = v.get("ip_address", "?")
            org = v.get("org", "?")
            vendor = v.get("vendor_name", "N/A")
            score = v.get("detection_score", 0)
            ts = v.get("timestamp", "?")
            ua = (v.get("user_agent") or "?")[:80]
            lines.append(f"- **{ip}** ({org}) score={score} vendor={vendor}")
            lines.append(f"  - {ts} — `{ua}`")
        if len(bots) > 50:
            lines.append(f"\n_...and {len(bots) - 50} more bot visits._")
        lines.append("")

    return lines


def generate_markdown(cfg: Config) -> str:
    visits = _load_visits_db(cfg)
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    if not visits:
        return "# BluePhishProxy Engagement Report\n\nNo visits recorded.\n"

    lines = [
        "# BluePhishProxy Engagement Report",
        f"\nGenerated: {now}",
        "",
    ]

    lines.extend(_section_stats(visits, "Overall Summary"))

    by_campaign: dict[str, list[dict[str, Any]]] = {}
    for v in visits:
        cid = v.get("campaign_id") or "default"
        by_campaign.setdefault(cid, []).append(v)

    if len(by_campaign) > 1 or "default" not in by_campaign:
        for cid, cvisits in sorted(by_campaign.items()):
            cname = cvisits[0].get("campaign_name") or cid
            template = cvisits[0].get("template") or "?"
            heading = f"Campaign: {cname} ({cid}) — template: {template}"
            lines.extend(_section_stats(cvisits, heading))

    return "\n".join(lines)


def write_report(cfg: Config, out_dir: Path | None = None) -> Path:
    content = generate_markdown(cfg)
    dest = (out_dir or cfg.analytics_dir) / "engagement-report.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content)
    return dest
