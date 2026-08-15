from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import AuditConfig
from .engine import run_scan
from .errors import AuditError
from .output import render_console, write_json


def app() -> None:
    raise SystemExit(main())


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if not hasattr(args, "handler"):
        parser.print_help()
        return 0

    try:
        return args.handler(args)
    except (AuditError, OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2


def scan_command(args: argparse.Namespace) -> int:
    audit_config = AuditConfig.load(args.config)
    if args.allow_private:
        audit_config.scope.allow_private_networks = True

    result = run_scan(args.target, audit_config)
    if args.json_output:
        write_json(result, args.json_output)

    if args.json_console:
        print(result.to_json(indent=2))
    else:
        render_console(result)
        if args.json_output:
            print(f"\nJSON written to {args.json_output}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-web-auditor",
        description="Safe-first modular web audit CLI.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run a non-intrusive web audit against one target URL.")
    scan_parser.add_argument("target", help="Target URL, for example https://example.com")
    scan_parser.add_argument("--config", "-c", type=Path, help="JSON or TOML config file.")
    scan_parser.add_argument("--json-output", "-o", type=Path, help="Write full scan result to this JSON file.")
    scan_parser.add_argument("--json", dest="json_console", action="store_true", help="Print JSON to console.")
    scan_parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow private, loopback or local targets for labs.",
    )
    scan_parser.set_defaults(handler=scan_command)
    return parser
