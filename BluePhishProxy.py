#!/usr/bin/env python3
"""BluePhishProxy — CLI entry point.

Usage:
    python BluePhishProxy.py [--port PORT] [--host HOST] [--debug]
    python BluePhishProxy.py report [--out DIR]

All runtime settings can also be supplied via environment variables
(BPP_PORT, BPP_HOST, BPP_DEBUG, …). See bluephishproxy/config.py for the
full list.
"""

from __future__ import annotations

import argparse
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
    app.run(host=cfg.host, port=cfg.port, debug=cfg.debug)


def cmd_report(args: argparse.Namespace) -> None:
    cfg = Config()
    _setup_logging(cfg)

    from bluephishproxy.reporting import write_report

    out_dir = Path(args.out) if args.out else None
    path = write_report(cfg, out_dir=out_dir)
    print(f"Report written to {path}")


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

    args = parser.parse_args()

    if args.command == "report":
        cmd_report(args)
    else:
        cmd_serve(args)


if __name__ == "__main__":
    main()
