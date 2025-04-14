# BluePhishProxy - The Phish is the Bait

BluePhishProxy is a lightweight web proxy used in phishing campaign pre-staging. It generates links that intentionally look suspicious and are meant to be probed by automated scanners, security gateways, early-stage defenses or most interestingly manual inspections of the Blue Team. The goal is to fingerprint these systems and processes **before delivering the actual payload**.


<p align="center">
    <img src="https://github.com/user-attachments/assets/846fd2a9-f8f4-4cc9-b052-03c90927da18" width="400">

## Purpose
This tool addresses a common challenge in red team exercises: how to identify which security systems are inspecting phishing links. By deploying BluePhishProxy first, you can:

- Identify email gateway scanning behavior
- Detect URL scanning services and their characteristics
- Map Blue Team infrastructure and response patterns
- Discover Internet breakout points of the target organization
- Document security systems' IP addresses and fingerprints
- Test potential evasion techniques

## How It Works

1. You deploy BluePhishProxy on a server and generate phishing-style links (e.g. `http://prestragedphish.com/foo/bar`).
2. These links serve a fake MS "Safe Links" style scanning page.
3. Visitors are profiled using:
   - IP + ASN lookup
   - HTTP headers and User-Agent analysis
   - JavaScript-based behavioral signals (e.g. window size, mouse movement, webdriver presence)
4. Results are logged and analytics are written to disk (`data/`, `analytics/`).

This should help you build blocklists/allowlists or reroute payload delivery only to clean sessions.

## Features

- JS-based client fingerprinting (mouse movement, screen size, webdriver detection)
- Detects common bots, scanners, headless browsers via UA and behavior
- Simulates MS ATP Safe Links redirection UI
- Daily analytics (`analytics/daily-YYYY-MM-DD.json`)
- Customizable final redirect (`SAFE_REDIRECT_URL`)

## Customization

- Change the redirect destination by editing the `SAFE_REDIRECT_URL` constant.
- Adjust or expand the `suspicious_tokens` list in the decorator for more aggressive or relaxed detection.
- Modify the HTML in `render_scan_page()` if you want to impersonate a different brand or look.

## Example Log Entry

Each request results in a JSON log with fields like:

```json
{ "ip_address": "88.84.250.151",
  "user_agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
  "asn": "AS14061",
  "org": "DigitalOcean, LLC",
  "country": "DE",
  "region": "Hesse",
  "city": "Frankfurt am Main",
  "hostname": "Unknown",
  "loc": "50.1155,8.6842",
  "timestamp": "2025-04-14T14:15:43.689133",
  "headers": {
    "Host": "prestagedphish.com",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Dnt": "1",
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": "http://prestagedphish.com/api/v2/metrics/usr",
    "Accept-Encoding": "gzip, deflate",
    "Accept-Language": "en-US,en;q=0.9",
    "Cookie": "csession=f37e9808-37d6-4a6d-8ed5-136aa2d7bffc; session=eyJhZHZfbWV0cmljcyI6eyJtb3VzZU1vdmVzIjoxMywic2NyZWVuU2l6ZSI6WzI1NjAsMTA4MF0sIndlYmRyaXZlciI6ZmFsc2UsIndpbmRvd1NpemUiOls1NDEsOTMyXX19.Z_0Yjw.A9q9CWUTK7lJkFlGIjLgl8Szu-Q"
  },
  "cookies": {
    "csession": "f37e9808-37d6-4a6d-8ed5-136aa2d7bffc",
    "session": "eyJhZHZfbWV0cmljcyI6eyJtb3VzZU1vdmVzIjoxMywic2NyZWVuU2l6ZSI6WzI1NjAsMTA4MF0sIndlYmRyaXZlciI6ZmFsc2UsIndpbmRvd1NpemUiOls1NDEsOTMyXX19.Z_0Yjw.A9q9CWUTK7lJkFlGIjLgl8Szu-Q"
  },
  "path": "/evergreen-assets/safelinks/1/atp-safelinks.html",
  "method": "GET",
  "args": {},
  "referrer": "http://prestagedphish.com/api/v2/metrics/usr",
  "browser": "Chrome",
  "browser_version": "128.0",
  "os": "Linux",
  "device": "Desktop",
  "advanced_metrics": {
    "mouseMoves": 13,
    "screenSize": [
      2560,
      1080
    ],
    "webdriver": false,
    "windowSize": [
      541,
      932
    ]
  },
  "session_id": "f37e9808-37d6-4a6d-8ed5-136aa2d7bffc",
  "is_bot": false,
  "bot_kind": "UA"
}
```
