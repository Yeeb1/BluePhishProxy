"""Engagement report generation.

Reads stored visit JSON files and daily analytics to produce a summary report
in Markdown (and optionally HTML) that operators can hand to customers.
"""

from __future__ import annotations

import json
import datetime
from collections import Counter
from pathlib import Path
from typing import Any

from .config import Config


def _load_visits(cfg: Config) -> list[dict[str, Any]]:
    visits: list[dict[str, Any]] = []
    if not cfg.data_dir.exists():
        return visits
    for f in sorted(cfg.data_dir.glob("*.json")):
        try:
            visits.append(json.loads(f.read_text()))
        except (json.JSONDecodeError, OSError):
            continue
    return visits


def generate_markdown(cfg: Config) -> str:
    visits = _load_visits(cfg)
    if not visits:
        return "# BluePhishProxy Engagement Report\n\nNo visits recorded.\n"

    total = len(visits)
    bots = [v for v in visits if v.get("is_bot")]
    suspicious = [v for v in visits if v.get("classification") == "suspicious"]
    clean = [v for v in visits if v.get("classification") == "clean"]

    vendor_counter: Counter[str] = Counter()
    org_counter: Counter[str] = Counter()
    country_counter: Counter[str] = Counter()
    signal_counter: Counter[str] = Counter()

    for v in visits:
        vendor = v.get("vendor_name")
        if vendor:
            vendor_counter[vendor] += 1
        org_counter[v.get("org", "Unknown")] += 1
        country_counter[v.get("country", "Unknown")] += 1
        for sig in v.get("detection_signals", []):
            signal_counter[sig.get("tag", "?")] += 1

    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines = [
        "# BluePhishProxy Engagement Report",
        f"\nGenerated: {now}",
        "",
        "## Summary",
        "",
        f"| Metric | Count |",
        f"|--------|-------|",
        f"| Total visits | {total} |",
        f"| Classified as bot | {len(bots)} |",
        f"| Classified as suspicious | {len(suspicious)} |",
        f"| Classified as clean | {len(clean)} |",
        f"| Unique security vendors seen | {len(vendor_counter)} |",
        "",
    ]

    if vendor_counter:
        lines.append("## Security Vendors Detected")
        lines.append("")
        lines.append("| Vendor | Hits |")
        lines.append("|--------|------|")
        for vendor, count in vendor_counter.most_common():
            lines.append(f"| {vendor} | {count} |")
        lines.append("")

    if org_counter:
        lines.append("## Top Organisations (by IP)")
        lines.append("")
        lines.append("| Organisation | Hits |")
        lines.append("|-------------|------|")
        for org, count in org_counter.most_common(20):
            lines.append(f"| {org} | {count} |")
        lines.append("")

    if country_counter:
        lines.append("## Countries")
        lines.append("")
        lines.append("| Country | Hits |")
        lines.append("|---------|------|")
        for country, count in country_counter.most_common(15):
            lines.append(f"| {country} | {count} |")
        lines.append("")

    if signal_counter:
        lines.append("## Top Detection Signals")
        lines.append("")
        lines.append("| Signal | Occurrences |")
        lines.append("|--------|-------------|")
        for sig, count in signal_counter.most_common(20):
            lines.append(f"| {sig} | {count} |")
        lines.append("")

    if bots:
        lines.append("## Bot / Scanner Visit Details")
        lines.append("")
        for v in bots[:50]:
            ip = v.get("ip_address", "?")
            org = v.get("org", "?")
            vendor = v.get("vendor_name", "N/A")
            score = v.get("detection_score", 0)
            ts = v.get("timestamp", "?")
            ua = v.get("user_agent", "?")[:80]
            lines.append(f"- **{ip}** ({org}) score={score} vendor={vendor}")
            lines.append(f"  - {ts} — `{ua}`")
        if len(bots) > 50:
            lines.append(f"\n_...and {len(bots) - 50} more bot visits._")
        lines.append("")

    return "\n".join(lines)


def write_report(cfg: Config, out_dir: Path | None = None) -> Path:
    content = generate_markdown(cfg)
    dest = (out_dir or cfg.analytics_dir) / "engagement-report.md"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content)
    return dest
