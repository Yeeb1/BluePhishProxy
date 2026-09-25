#!/usr/bin/env python3
"""BluePhishProxy — CLI entry point.

Usage:
    python BluePhishProxy.py serve [--port PORT] [--host HOST] [--debug] [--tls]
    python BluePhishProxy.py report [--out DIR]
    python BluePhishProxy.py campaign create --name NAME --template TEMPLATE [options]
    python BluePhishProxy.py campaign list
    python BluePhishProxy.py apikey create --name NAME [--role ROLE]
    python BluePhishProxy.py apikey list
    python BluePhishProxy.py apikey revoke KEY_ID
    python BluePhishProxy.py db init
    python BluePhishProxy.py templates

All runtime settings can also be supplied via environment variables
(BPP_PORT, BPP_HOST, BPP_DEBUG, …). See bluephishproxy/config.py for the
full list.
"""

from __future__ import annotations

import argparse
import json
import logging
import ssl
import sys
from pathlib import Path

from bluephishproxy.config import Config


def _setup_logging(cfg: Config) -> None:
    fmt = "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
    handlers: list[logging.Handler] = [logging.StreamHandler()]
    try:
        handlers.append(logging.FileHandler(str(cfg.log_file)))
    except OSError:
        pass
    logging.basicConfig(
        level=logging.DEBUG if cfg.debug else logging.INFO,
        format=fmt,
        handlers=handlers,
    )


def cmd_serve(args: argparse.Namespace) -> None:
    cfg = Config()
    if args.port:
        cfg.port = args.port
    if args.host:
        cfg.host = args.host
    if args.debug:
        cfg.debug = True

    _setup_logging(cfg)

    from bluephishproxy.app import create_app

    app = create_app(cfg)

    tls_info = "disabled"
    ssl_ctx = None
    if args.tls or cfg.tls_enabled:
        if not cfg.tls_cert or not cfg.tls_key:
            print("ERROR: TLS requested but BPP_TLS_CERT / BPP_TLS_KEY not set")
            sys.exit(1)
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.load_cert_chain(cfg.tls_cert, cfg.tls_key)
        tls_info = f"cert={cfg.tls_cert}"

    protocol = "https" if ssl_ctx else "http"
    cf_status = "enabled" if cfg.behind_cloudflare else "disabled"
    db_path = cfg.database_path

    print(f"""
╔══════════════════════════════════════════════════════╗
║           BluePhishProxy v3.0 — Running             ║
╠══════════════════════════════════════════════════════╣
║  Server:      {protocol}://{cfg.host}:{cfg.port}{' ' * max(0, 26 - len(f'{protocol}://{cfg.host}:{cfg.port}'))}║
║  Template:    {cfg.default_template:<38s}║
║  Dashboard:   /api/operator/dashboard               ║
║  SSE Feed:    /api/operator/feed                     ║
║  TLS:         {tls_info:<38s}║
║  Cloudflare:  {cf_status:<38s}║
║  Database:    {db_path:<38s}║
╚══════════════════════════════════════════════════════╝
""")

    app.run(host=cfg.host, port=cfg.port, debug=cfg.debug, ssl_context=ssl_ctx)


def cmd_report(args: argparse.Namespace) -> None:
    cfg = Config()
    _setup_logging(cfg)

    from bluephishproxy.reporting import write_report

    out_dir = Path(args.out) if args.out else None
    path = write_report(cfg, out_dir=out_dir)
    print(f"Report written to {path}")


def cmd_campaign(args: argparse.Namespace) -> None:
    cfg = Config()

    from bluephishproxy.database import init_db
    init_db(cfg)

    if args.campaign_action == "create":
        from bluephishproxy.campaigns import create_campaign

        c = create_campaign(
            name=args.name,
            template=args.template,
            cfg=cfg,
            safe_redirect_url=args.redirect or "",
            flagged_redirect_url=args.flagged_redirect or "",
            brand_name=args.brand or "",
            description=args.description or "",
            custom_params=json.loads(args.params) if args.params else None,
        )
        print(f"Campaign created: {c.id}")
        print(f"  Name:     {c.name}")
        print(f"  Template: {c.template}")
        print(f"  URL:      /c/{c.id}/")
        print(f"  Brand:    {c.brand_name}")

    elif args.campaign_action == "list":
        from bluephishproxy.campaigns import list_campaigns

        campaigns = list_campaigns(cfg)
        if not campaigns:
            print("No campaigns found.")
            return
        for c in campaigns:
            status = "ACTIVE" if c.active else "PAUSED"
            print(f"  [{status}] {c.id}  {c.name} ({c.template}) — /c/{c.id}/")

    elif args.campaign_action == "delete":
        from bluephishproxy.campaigns import delete_campaign

        if delete_campaign(args.campaign_id, cfg):
            print(f"Campaign {args.campaign_id} deleted.")
        else:
            print(f"Campaign {args.campaign_id} not found.")
            sys.exit(1)


def cmd_apikey(args: argparse.Namespace) -> None:
    cfg = Config()

    from bluephishproxy.database import init_db, create_api_key, list_api_keys, revoke_api_key
    init_db(cfg)

    if args.apikey_action == "create":
        name = args.name
        role = args.role or "admin"
        key = create_api_key(cfg, name, role)
        print(f"API key created:")
        print(f"  Key:  {key}")
        print(f"  Name: {name}")
        print(f"  Role: {role}")
        print(f"\n  Store this key securely — it cannot be retrieved again.")

    elif args.apikey_action == "list":
        keys = list_api_keys(cfg)
        if not keys:
            print("No API keys found.")
            return
        print(f"{'ID':<6} {'Prefix':<14} {'Name':<20} {'Role':<10} {'Active':<8} {'Last Used'}")
        print("-" * 80)
        for k in keys:
            active = "yes" if k.get("active") else "no"
            last_used = k.get("last_used") or "never"
            print(f"{k['id']:<6} {k['key_prefix']:<14} {k['name']:<20} {k['role']:<10} {active:<8} {last_used}")

    elif args.apikey_action == "revoke":
        key_id = int(args.key_id)
        if revoke_api_key(cfg, key_id):
            print(f"API key {key_id} revoked.")
        else:
            print(f"API key {key_id} not found.")
            sys.exit(1)


def cmd_db(args: argparse.Namespace) -> None:
    cfg = Config()

    if args.db_action == "init":
        from bluephishproxy.database import init_db
        init_db(cfg)
        print(f"Database initialized at {cfg.database_path}")


def cmd_templates(_args: argparse.Namespace) -> None:
    from bluephishproxy.lures import list_templates

    templates = list_templates()
    print("Available lure templates:\n")
    for t in templates:
        print(f"  {t['id']:<14s} {t['name']}")
        print(f"  {' ' * 14} {t['description']}")
        print()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="BluePhishProxy — red-team pre-staging reconnaissance proxy"
    )
    sub = parser.add_subparsers(dest="command")

    # --- serve ---
    serve = sub.add_parser("serve", help="Start the proxy server (default)")
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--host", type=str, default=None)
    serve.add_argument("--debug", action="store_true")
    serve.add_argument("--tls", action="store_true", help="Enable TLS (requires BPP_TLS_CERT/BPP_TLS_KEY)")

    # --- report ---
    report = sub.add_parser("report", help="Generate an engagement report")
    report.add_argument("--out", type=str, default=None, help="Output directory")

    # --- campaign ---
    campaign = sub.add_parser("campaign", help="Manage campaigns")
    csub = campaign.add_subparsers(dest="campaign_action")

    cc = csub.add_parser("create", help="Create a new campaign")
    cc.add_argument("--name", required=True, help="Campaign name")
    cc.add_argument("--template", required=True, help="Lure template ID")
    cc.add_argument("--redirect", type=str, default=None, help="Clean redirect URL")
    cc.add_argument("--flagged-redirect", type=str, default=None, help="Bot/suspicious redirect URL")
    cc.add_argument("--brand", type=str, default=None, help="Brand name for template")
    cc.add_argument("--description", type=str, default=None, help="Campaign description")
    cc.add_argument("--params", type=str, default=None, help="Custom template params as JSON")

    csub.add_parser("list", help="List all campaigns")

    cd = csub.add_parser("delete", help="Delete a campaign")
    cd.add_argument("campaign_id", help="Campaign ID to delete")

    # --- apikey ---
    apikey = sub.add_parser("apikey", help="Manage API keys")
    asub = apikey.add_subparsers(dest="apikey_action")

    ac = asub.add_parser("create", help="Create a new API key")
    ac.add_argument("--name", required=True, help="Key name/description")
    ac.add_argument("--role", type=str, default="admin", choices=["admin", "readonly"],
                     help="Key role (default: admin)")

    asub.add_parser("list", help="List all API keys")

    ar = asub.add_parser("revoke", help="Revoke an API key")
    ar.add_argument("key_id", help="Key ID to revoke")

    # --- db ---
    db = sub.add_parser("db", help="Database management")
    dsub = db.add_subparsers(dest="db_action")
    dsub.add_parser("init", help="Initialize the database schema")

    # --- templates ---
    sub.add_parser("templates", help="List available lure templates")

    args = parser.parse_args()

    if args.command == "report":
        cmd_report(args)
    elif args.command == "campaign":
        if not args.campaign_action:
            campaign.print_help()
        else:
            cmd_campaign(args)
    elif args.command == "apikey":
        if not args.apikey_action:
            apikey.print_help()
        else:
            cmd_apikey(args)
    elif args.command == "db":
        if not args.db_action:
            db.print_help()
        else:
            cmd_db(args)
    elif args.command == "templates":
        cmd_templates(args)
    else:
        cmd_serve(args)


if __name__ == "__main__":
    main()
