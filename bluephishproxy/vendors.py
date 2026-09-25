"""Fingerprint data for known security vendors, scanners and hosting networks.

This data drives BluePhishProxy's core value: recognising when a visitor is a
piece of *defensive* infrastructure (a secure email gateway, URL sandbox or
click-time scanner) rather than a real human target.

Everything here is matched case-insensitively as substrings, so entries stay
robust against minor naming differences between data sources (ipinfo org
strings, PTR records, User-Agent tokens, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Vendor:
    name: str
    category: str  # "email-security" | "url-sandbox" | "proxy-gateway" | "search"


# --- Organisation / ASN-org keywords ------------------------------------------
# Keyed by substring found in the "org" field returned by IP enrichment or in a
# reverse-DNS PTR record.
SECURITY_VENDOR_ORGS: dict[str, Vendor] = {
    "microsoft": Vendor("Microsoft (Defender / ATP Safe Links)", "email-security"),
    "proofpoint": Vendor("Proofpoint", "email-security"),
    "mimecast": Vendor("Mimecast", "email-security"),
    "barracuda": Vendor("Barracuda", "email-security"),
    "forcepoint": Vendor("Forcepoint", "proxy-gateway"),
    "websense": Vendor("Forcepoint (Websense)", "proxy-gateway"),
    "zscaler": Vendor("Zscaler", "proxy-gateway"),
    "netskope": Vendor("Netskope", "proxy-gateway"),
    "menlo security": Vendor("Menlo Security", "proxy-gateway"),
    "palo alto": Vendor("Palo Alto Networks", "email-security"),
    "fortinet": Vendor("Fortinet", "email-security"),
    "sophos": Vendor("Sophos", "email-security"),
    "trend micro": Vendor("Trend Micro", "email-security"),
    "symantec": Vendor("Symantec / Broadcom", "email-security"),
    "messagelabs": Vendor("Symantec MessageLabs", "email-security"),
    "broadcom": Vendor("Broadcom (Symantec)", "email-security"),
    "cisco": Vendor("Cisco (IronPort / Talos)", "email-security"),
    "talos": Vendor("Cisco Talos", "url-sandbox"),
    "ironport": Vendor("Cisco IronPort", "email-security"),
    "cloudflare": Vendor("Cloudflare (Area 1 / URL Scanner)", "email-security"),
    "agari": Vendor("Agari", "email-security"),
    "abnormal": Vendor("Abnormal Security", "email-security"),
    "avanan": Vendor("Check Point Avanan", "email-security"),
    "check point": Vendor("Check Point", "email-security"),
    "cyren": Vendor("Cyren", "email-security"),
    "vade": Vendor("Vade Secure", "email-security"),
    "google": Vendor("Google (Safe Browsing / Gmail scanning)", "search"),
    "urlscan": Vendor("urlscan.io", "url-sandbox"),
    "virustotal": Vendor("VirusTotal", "url-sandbox"),
    "hybrid analysis": Vendor("Hybrid Analysis", "url-sandbox"),
    "any.run": Vendor("ANY.RUN", "url-sandbox"),
    "spur": Vendor("Spur", "url-sandbox"),
    "greynoise": Vendor("GreyNoise", "url-sandbox"),
}

# --- User-Agent tokens for link scanners / unfurlers --------------------------
# Many secure email gateways and chat/link-preview services identify themselves.
# Catching them is exactly the point of the tool.
SCANNER_UA_TOKENS: dict[str, Vendor] = {
    "barracuda": Vendor("Barracuda", "email-security"),
    "proofpoint": Vendor("Proofpoint", "email-security"),
    "mimecast": Vendor("Mimecast", "email-security"),
    "forcepoint": Vendor("Forcepoint", "proxy-gateway"),
    "zscaler": Vendor("Zscaler", "proxy-gateway"),
    "safelinks": Vendor("Microsoft Safe Links", "email-security"),
    "bingpreview": Vendor("Microsoft BingPreview", "search"),
    "microsoftpreview": Vendor("Microsoft Preview", "email-security"),
    "skypeuripreview": Vendor("Microsoft Skype/Teams preview", "email-security"),
    "google-safety": Vendor("Google Safe Browsing", "search"),
    "googleimageproxy": Vendor("Gmail image proxy", "email-security"),
    "slackbot": Vendor("Slack link unfurl", "url-sandbox"),
    "slack-imgproxy": Vendor("Slack image proxy", "url-sandbox"),
    "telegrambot": Vendor("Telegram link preview", "url-sandbox"),
    "whatsapp": Vendor("WhatsApp link preview", "url-sandbox"),
    "discordbot": Vendor("Discord link preview", "url-sandbox"),
    "facebookexternalhit": Vendor("Facebook link preview", "url-sandbox"),
    "twitterbot": Vendor("Twitter/X link preview", "url-sandbox"),
    "linkedinbot": Vendor("LinkedIn link preview", "url-sandbox"),
    "cyren": Vendor("Cyren", "email-security"),
    "symantec": Vendor("Symantec", "email-security"),
    "urlscan": Vendor("urlscan.io", "url-sandbox"),
    "virustotal": Vendor("VirusTotal", "url-sandbox"),
    "phishtank": Vendor("PhishTank", "url-sandbox"),
}

# --- Generic automation User-Agent tokens (HTTP libraries / scanners) ---------
# Grouped by category so reporting can explain *why* something was flagged.
HTTP_LIBRARY_TOKENS: frozenset[str] = frozenset({
    "python-requests", "httpx", "aiohttp", "urllib", "urllib3", "httpclient",
    "go-http-client", "okhttp", "java", "libwww-perl", "lwp", "perl", "ruby",
    "http.rb", "mechanize", "axios", "node-fetch", "got ", "node.js", "guzzle",
    "cfnetwork", "pycurl", "urlgrabber", "curl", "wget", "powershell",
    "winhttp", "restsharp", "apache-httpclient", "reqwest", "hackney",
    "http_request", "http.request", "scrapy", "fetch",
})

HEADLESS_TOKENS: frozenset[str] = frozenset({
    "headless", "headlesschrome", "phantom", "phantomjs", "selenium",
    "webdriver", "puppeteer", "playwright", "electron", "splash", "chrome-lighthouse",
})

SCANNER_TOOL_TOKENS: frozenset[str] = frozenset({
    "masscan", "nmap", "nikto", "sqlmap", "nuclei", "zgrab", "zmap",
    "gobuster", "dirbuster", "wpscan", "acunetix", "nessus", "openvas",
    "qualys", "burp", "bench", "scan", "censys", "shodan",
})

GENERIC_BOT_TOKENS: frozenset[str] = frozenset({
    "bot", "crawler", "spider", "scraper", "monitor", "preview", "fetcher",
    "checker", "validator", "analyzer",
})

# --- Hosting / datacenter org keywords ----------------------------------------
# A real human target normally arrives from a residential/mobile/corporate ISP,
# not a cloud VM. Datacenter origins are a strong automation signal.
HOSTING_ORGS: frozenset[str] = frozenset({
    "amazon", "aws", "google cloud", "google llc", "microsoft azure", "azure",
    "digitalocean", "linode", "akamai", "ovh", "hetzner", "vultr", "scaleway",
    "contabo", "oracle cloud", "oracle", "leaseweb", "choopa", "hostwinds",
    "gcore", "upcloud", "kamatera", "ionos", "1&1", "godaddy", "namecheap",
    "cloudflare", "fastly", "colocrossing", "quadranet", "psychz", "m247",
    "datacamp", "worldstream", "servers.com", "packet", "equinix",
})


def match_org(org: str) -> Vendor | None:
    """Return a known security Vendor if *org* matches one, else None."""
    if not org:
        return None
    low = org.lower()
    for needle, vendor in SECURITY_VENDOR_ORGS.items():
        if needle in low:
            return vendor
    return None


def match_scanner_ua(user_agent: str) -> Vendor | None:
    """Return a known scanner Vendor if the UA advertises one, else None."""
    if not user_agent:
        return None
    low = user_agent.lower()
    for needle, vendor in SCANNER_UA_TOKENS.items():
        if needle in low:
            return vendor
    return None


def is_hosting_org(org: str) -> bool:
    if not org:
        return False
    low = org.lower()
    return any(needle in low for needle in HOSTING_ORGS)
