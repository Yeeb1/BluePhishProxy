#!/usr/bin/env python3
"""BluePhishProxy — CLI entry point.

Usage:
    python BluePhishProxy.py serve [--port PORT] [--host HOST] [--debug]
    python BluePhishProxy.py report [--out DIR]
    python BluePhishProxy.py campaign create --name NAME --template TEMPLATE [options]
    python BluePhishProxy.py campaign list
    python BluePhishProxy.py templates

All runtime settings can also be supplied via environment variables
(BPP_PORT, BPP_HOST, BPP_DEBUG, …). See bluephishproxy/config.py for the
full list.
"""

from __future__ import annotations

import argparse
import json
import logging
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

    print(f"""
╔══════════════════════════════════════════════════════╗
║           BluePhishProxy v2.0 — Running             ║
╠══════════════════════════════════════════════════════╣
║  Server:     http://{cfg.host}:{cfg.port}               {' ' * max(0, 10 - len(str(cfg.port)))}║
║  Template:   {cfg.default_template:<39s}║
║  Dashboard:  /api/operator/dashboard                ║
║  SSE Feed:   /api/operator/feed                     ║
║  Campaigns:  /api/operator/campaigns                ║
╚══════════════════════════════════════════════════════╝
""")

    app.run(host=cfg.host, port=cfg.port, debug=cfg.debug)


def cmd_report(args: argparse.Namespace) -> None:
    cfg = Config()
    _setup_logging(cfg)

    from bluephishproxy.reporting import write_report

    out_dir = Path(args.out) if args.out else None
    path = write_report(cfg, out_dir=out_dir)
    print(f"Report written to {path}")


def cmd_campaign(args: argparse.Namespace) -> None:
    cfg = Config()

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

    serve = sub.add_parser("serve", help="Start the proxy server (default)")
    serve.add_argument("--port", type=int, default=None)
    serve.add_argument("--host", type=str, default=None)
    serve.add_argument("--debug", action="store_true")

    report = sub.add_parser("report", help="Generate an engagement report")
    report.add_argument("--out", type=str, default=None, help="Output directory")

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

    cl = csub.add_parser("list", help="List all campaigns")

    cd = csub.add_parser("delete", help="Delete a campaign")
    cd.add_argument("campaign_id", help="Campaign ID to delete")

    sub.add_parser("templates", help="List available lure templates")

    args = parser.parse_args()

    if args.command == "report":
        cmd_report(args)
    elif args.command == "campaign":
        if not args.campaign_action:
            campaign.print_help()
        else:
            cmd_campaign(args)
    elif args.command == "templates":
        cmd_templates(args)
    else:
        cmd_serve(args)


if __name__ == "__main__":
    main()
