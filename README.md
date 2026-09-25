# BluePhishProxy — The Phish is the Bait

BluePhishProxy is an enterprise reconnaissance proxy for authorized red team
engagements. It generates links that intentionally look suspicious and are
meant to be probed by automated scanners, security gateways, and Blue Team
analysts. The goal is to fingerprint defensive infrastructure **before
delivering the actual payload**.

<p align="center">
    <img src="https://github.com/user-attachments/assets/846fd2a9-f8f4-4cc9-b052-03c90927da18" width="400">
</p>

## What's New in v2.0

- **8 configurable lure templates** — Safe Links, ClickFix, CAPTCHA, OAuth consent, MFA push, document viewer, voicemail, SharePoint sharing
- **Campaign management** — create multiple campaigns with different templates, brands, and redirect URLs; track visits per campaign
- **Real-time webhook notifications** — Slack, Discord, Teams, or generic HTTP webhooks fire on every visit with classification, score, vendor info
- **Live operator dashboard** — SSE-powered real-time feed with stats, vendor detection, and campaign overview
- **Operator REST API** — full CRUD for campaigns, visit queries, analytics export, template previews
- **30+ JS fingerprint signals** — canvas, WebGL, AudioContext, automation API detection, interaction tracking, timing analysis
- **Weighted scoring engine** — signals produce a numeric score, not just binary bot/not-bot
- **Campaign-aware reporting** — Markdown reports with per-campaign breakdowns

## Architecture

```
bluephishproxy/
  config.py        # env-driven runtime configuration
  vendors.py       # fingerprint data for 60+ security vendors & hosting providers
  fingerprint.py   # signal producers (IP, UA, headers, JS metrics, timing)
  detection.py     # weighted scoring engine → bot / suspicious / clean
  lures.py         # 8 configurable lure template renderers + JS fingerprint payload
  campaigns.py     # campaign management (create, list, load, delete)
  webhooks.py      # real-time notifications (Slack, Discord, Teams, HTTP)
  storage.py       # visit logging + daily analytics (JSON)
  reporting.py     # engagement report generation (Markdown, campaign-aware)
  dashboard.py     # operator monitoring dashboard (SSE-powered)
  app.py           # Flask application factory, routes, operator API
BluePhishProxy.py  # CLI entry point
```

## How It Works

1. **Create a campaign** with a chosen lure template (ClickFix, CAPTCHA, etc.)
2. **Deploy** and distribute campaign links (`https://your-server.com/c/<id>/path`)
3. Visitors see the lure page; JS silently collects **30+ browser signals**
4. The server combines JS signals with **server-side analysis** (IP/ASN, headers, vendor matching)
5. A **weighted scoring engine** classifies each visit as `bot`, `suspicious`, or `clean`
6. **Webhooks fire** in real-time to Slack/Discord/Teams
7. The **operator dashboard** shows a live feed of all visits
8. **Reports** document which defensive systems probed your links

### Detection Signals

| Category | Signals | Weight |
|----------|---------|--------|
| **User-Agent** | 60+ scanner vendor tokens, headless browsers, HTTP libraries | 55–80 |
| **IP / ASN** | Security vendor orgs, datacenter/hosting origins, PTR records | 30–70 |
| **Headers** | Missing Accept-Language, Client Hints mismatches, proxy headers | 10–30 |
| **JavaScript** | webdriver, automation APIs, canvas/WebGL/audio fingerprints, interaction counters, RAF timing, window geometry | 10–80 |
| **Timing** | Instant page transition (< 500ms) | 20 |

## Quick Start

```bash
pip install -r requirements.txt

# Start the server
python BluePhishProxy.py serve --port 5000

# List available templates
python BluePhishProxy.py templates

# Create a ClickFix campaign
python BluePhishProxy.py campaign create \
    --name "Q4 Assessment" \
    --template clickfix \
    --brand "IT Support" \
    --redirect "https://target-corp.com/portal"

# Create a CAPTCHA campaign
python BluePhishProxy.py campaign create \
    --name "Recon Phase" \
    --template captcha

# Create an OAuth consent campaign
python BluePhishProxy.py campaign create \
    --name "OAuth Test" \
    --template oauth \
    --params '{"app_name": "Document Portal", "permissions": ["Read your email", "Access files"]}'

# List campaigns
python BluePhishProxy.py campaign list

# Generate engagement report
python BluePhishProxy.py report
```

## Lure Templates

| Template | Description | Use Case |
|----------|-------------|----------|
| `safelinks` | Microsoft Safe Links / ATP scanning page | Email link scanning pretext |
| `clickfix` | "Fix Issue" action-required prompt | ClickFix-style social engineering |
| `captcha` | Google reCAPTCHA checkbox verification | Human verification pretext |
| `oauth` | OAuth consent / app permissions page | OAuth consent phishing recon |
| `mfa` | MFA push notification approval | MFA fatigue / push verification |
| `docviewer` | Document preview loading page | File sharing pretexts |
| `voicemail` | Voicemail notification player | Voice message pretexts |
| `sharepoint` | SharePoint file sharing notification | Internal file sharing pretexts |

All templates include the full JS fingerprinting payload and are customizable via `custom_params`.

## Campaign Management

### CLI

```bash
# Create
python BluePhishProxy.py campaign create --name "Name" --template clickfix

# List
python BluePhishProxy.py campaign list

# Delete
python BluePhishProxy.py campaign delete <campaign_id>
```

### REST API

```bash
# List campaigns
curl http://localhost:5000/api/operator/campaigns

# Create campaign
curl -X POST http://localhost:5000/api/operator/campaigns \
  -H "Content-Type: application/json" \
  -d '{"name": "Test", "template": "captcha"}'

# Update campaign
curl -X PUT http://localhost:5000/api/operator/campaigns/<id> \
  -H "Content-Type: application/json" \
  -d '{"active": false}'

# List visits (with filters)
curl "http://localhost:5000/api/operator/visits?classification=bot&limit=20"

# Preview a template
curl http://localhost:5000/api/operator/templates/clickfix/preview

# Get analytics
curl http://localhost:5000/api/operator/analytics
```

## Real-Time Monitoring

### Operator Dashboard

Access at `/api/operator/dashboard` — shows:
- Live visit feed (SSE-powered, no polling)
- Running totals (visits, bots, suspicious, clean)
- Security vendors detected
- Active campaigns

### Webhook Notifications

Configure via environment variables:

```bash
# Single webhook
BPP_WEBHOOK_URLS='["https://hooks.slack.com/services/xxx"]'

# Multiple webhooks with types
BPP_WEBHOOK_URLS='[{"url": "https://hooks.slack.com/services/xxx", "type": "slack"}, {"url": "https://discord.com/api/webhooks/xxx", "type": "discord"}]'

# Minimum classification level to notify (bot, suspicious, or clean)
BPP_WEBHOOK_MIN_LEVEL=suspicious
```

Supported webhook types: `slack`, `discord`, `teams`, `generic` (raw JSON)

### SSE Live Feed

```javascript
const es = new EventSource("/api/operator/feed");
es.onmessage = (e) => {
    const visit = JSON.parse(e.data);
    console.log(`${visit.classification}: ${visit.ip} (${visit.org}) score=${visit.score}`);
};
```

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `BPP_HOST` | `0.0.0.0` | Bind address |
| `BPP_PORT` | `5000` | Bind port |
| `BPP_DEBUG` | `false` | Flask debug mode |
| `BPP_TRUSTED_PROXIES` | `1` | Proxy hops for X-Forwarded-For |
| `BPP_SAFE_REDIRECT_URL` | microsoft.com/security | Default clean redirect |
| `BPP_FLAGGED_REDIRECT_URL` | microsoft.com/security | Default bot/suspicious redirect |
| `BPP_BRAND` | `Microsoft` | Default brand for templates |
| `BPP_DEFAULT_TEMPLATE` | `safelinks` | Default lure template |
| `BPP_BOT_THRESHOLD` | `50` | Score ≥ this → bot |
| `BPP_SUSPICIOUS_THRESHOLD` | `25` | Score ≥ this → suspicious |
| `BPP_IP_ENRICHMENT` | `true` | Enable ipinfo.io lookups |
| `BPP_IPINFO_TOKEN` | _(none)_ | ipinfo.io API token |
| `BPP_SECRET_KEY` | _(ephemeral)_ | Flask session signing key |
| `BPP_WEBHOOK_URLS` | _(none)_ | Webhook endpoints (JSON array) |
| `BPP_WEBHOOK_MIN_LEVEL` | `suspicious` | Min classification for webhooks |
| `BPP_OPERATOR_TOKEN` | _(none)_ | Bearer token for operator API |
| `BPP_DATA_DIR` | `data/` | Per-visit JSON log directory |
| `BPP_ANALYTICS_DIR` | `analytics/` | Daily analytics directory |

## Production Deployment

### Gunicorn

```bash
BPP_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))") \
BPP_OPERATOR_TOKEN=$(python -c "import secrets; print(secrets.token_hex(16))") \
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
    -e BPP_OPERATOR_TOKEN=your-token-here \
    -e BPP_WEBHOOK_URLS='[{"url": "https://hooks.slack.com/services/xxx", "type": "slack"}]' \
    -v $(pwd)/data:/app/data \
    -v $(pwd)/campaigns:/app/campaigns \
    bluephishproxy
```

## License

For authorized security testing and red team engagements only.
