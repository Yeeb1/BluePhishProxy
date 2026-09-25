# BluePhishProxy — The Phish is the Bait

BluePhishProxy is a reconnaissance proxy for authorized red team engagements.
It generates links that intentionally look suspicious and are meant to be
probed by automated scanners, security gateways, and Blue Team analysts.
The goal is to fingerprint these systems **before delivering the actual payload**.

<p align="center">
    <img src="https://github.com/user-attachments/assets/846fd2a9-f8f4-4cc9-b052-03c90927da18" width="400">
</p>

## Purpose

This tool addresses a common challenge in red team exercises: how to identify
which security systems are inspecting phishing links. By deploying
BluePhishProxy first, you can:

- Identify email gateway scanning behavior and vendor (Proofpoint, Mimecast, Microsoft ATP, …)
- Detect URL sandbox services (urlscan.io, VirusTotal, ANY.RUN, …)
- Map Blue Team infrastructure, IP ranges, and response patterns
- Discover internet breakout points of the target organization
- Document security systems' fingerprints with a scored detection engine
- Build allowlists/blocklists for your actual payload delivery

## Architecture

```
bluephishproxy/
  config.py        # env-driven runtime configuration
  vendors.py       # fingerprint data for known security vendors
  fingerprint.py   # signal producers (IP, UA, headers, JS metrics, timing)
  detection.py     # weighted scoring engine → bot / suspicious / clean
  storage.py       # visit logging + daily analytics (JSON)
  reporting.py     # engagement report generation (Markdown)
  templates.py     # decoy scan page + advanced JS fingerprint collector
  app.py           # Flask application factory and routes
BluePhishProxy.py  # CLI entry point
```

## How It Works

1. Deploy BluePhishProxy and generate phishing-style links
   (e.g. `https://prestaged-phish.com/foo/bar`).
2. Visitors see a branded "Safe Links" scanning interstitial.
3. While the spinner runs, JavaScript silently collects 30+ browser signals:
   - Canvas and WebGL fingerprints
   - AudioContext fingerprint
   - Navigator properties (webdriver, plugins, languages, platform)
   - Mouse/touch/keyboard/scroll interaction counters
   - Screen geometry and window sizing consistency
   - requestAnimationFrame and performance timing
   - Automation API detection (Selenium, Puppeteer, Phantom, …)
   - Connection type, hardware concurrency, device memory
4. The server combines JS signals with server-side signals:
   - IP/ASN enrichment and security vendor org matching
   - User-Agent parsing and scanner token matching
   - HTTP header anomaly analysis (missing Accept-Language, Client Hints mismatches, …)
   - Hosting/datacenter origin detection
   - Request timing analysis
5. A weighted scoring engine classifies each visit as **bot**, **suspicious**,
   or **clean**.
6. Results are logged per-visit as JSON, aggregated into daily analytics, and
   can be exported as an engagement report.

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run the server
python BluePhishProxy.py serve --port 5000

# Or with environment variables
BPP_PORT=8443 BPP_SAFE_REDIRECT_URL=https://example.com python BluePhishProxy.py serve

# Generate an engagement report from collected data
python BluePhishProxy.py report --out ./reports
```

### Production (gunicorn)

```bash
BPP_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))") \
gunicorn "bluephishproxy.app:create_app()" \
    --bind 0.0.0.0:8443 \
    --workers 4 \
    --access-logfile -
```

### Docker

```bash
docker build -t bluephishproxy .
docker run -p 8443:8443 \
    -e BPP_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))") \
    -e BPP_SAFE_REDIRECT_URL=https://example.com \
    -v $(pwd)/data:/app/data \
    bluephishproxy
```

## Configuration

All settings are driven by environment variables — no code changes needed
between engagements:

| Variable | Default | Description |
|----------|---------|-------------|
| `BPP_HOST` | `0.0.0.0` | Bind address |
| `BPP_PORT` | `5000` | Bind port |
| `BPP_DEBUG` | `false` | Flask debug mode |
| `BPP_TRUSTED_PROXIES` | `1` | Proxy hops for X-Forwarded-For |
| `BPP_SAFE_REDIRECT_URL` | microsoft.com/security | Redirect for clean visitors |
| `BPP_FLAGGED_REDIRECT_URL` | microsoft.com/security | Redirect for suspicious visitors |
| `BPP_BRAND` | `Microsoft` | Brand shown on the interstitial |
| `BPP_BOT_THRESHOLD` | `50` | Score at or above → classified as bot |
| `BPP_SUSPICIOUS_THRESHOLD` | `25` | Score at or above → suspicious |
| `BPP_IP_ENRICHMENT` | `true` | Enable ipinfo.io lookups |
| `BPP_IPINFO_TOKEN` | _(none)_ | Optional ipinfo.io API token |
| `BPP_SECRET_KEY` | _(ephemeral)_ | Flask session signing key |
| `BPP_DATA_DIR` | `data/` | Per-visit JSON log directory |
| `BPP_ANALYTICS_DIR` | `analytics/` | Daily analytics directory |
| `BPP_SESSION_MAX_AGE` | `3600` | Session cookie lifetime (seconds) |

## Detection Signals

The scoring engine evaluates signals across five categories:

| Category | Signals | Weight Range |
|----------|---------|-------------|
| **User-Agent** | Scanner vendor tokens, headless browsers, HTTP libraries, generic bot tokens | 55–80 |
| **IP / ASN** | Known security vendor orgs, datacenter/hosting origins, PTR records | 30–70 |
| **Headers** | Missing Accept-Language, Client Hints mismatches, security proxy headers, non-browser Accept | 10–30 |
| **JavaScript** | webdriver flag, automation APIs, zero interaction, canvas/audio blocks, instant RAF, window geometry anomalies | 10–80 |
| **Timing** | Instant page transition (< 500ms from scan page to final) | 20 |

Scores are summed. Visits scoring ≥ `BPP_BOT_THRESHOLD` (default 50) are
classified **bot**; ≥ `BPP_SUSPICIOUS_THRESHOLD` (default 25) are
**suspicious**; below that are **clean**.

## Example Log Entry

```json
{
  "ip_address": "88.84.250.151",
  "user_agent": "Mozilla/5.0 ...",
  "asn": "AS14061",
  "org": "DigitalOcean, LLC",
  "country": "DE",
  "timestamp": "2025-04-14T14:15:43.689133+00:00",
  "classification": "bot",
  "detection_score": 100,
  "detection_signals": [
    {"source": "ip", "tag": "hosting-provider", "weight": 30, "detail": "Datacenter/hosting: DigitalOcean, LLC"},
    {"source": "js", "tag": "webdriver-true", "weight": 80, "detail": "navigator.webdriver is true"}
  ],
  "top_signal": "js:webdriver-true",
  "vendor_name": null,
  "advanced_metrics": {
    "mouseMoves": 0,
    "webdriver": true,
    "canvasHash": "a3f29bc1",
    "webglRenderer": "ANGLE (Intel, ...)",
    "rafDelta": 0,
    "automationAPIs": true
  }
}
```

## Engagement Report

```bash
python BluePhishProxy.py report
```

Produces a Markdown report in `analytics/engagement-report.md` with:
- Visit summary (total / bot / suspicious / clean)
- Security vendors detected and hit counts
- Top organisations by IP
- Countries
- Most frequent detection signals
- Detailed bot visit listing

## License

For authorized security testing and red team engagements only.
