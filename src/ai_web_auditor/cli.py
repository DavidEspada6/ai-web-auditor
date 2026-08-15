from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import AuditConfig
from .engine import run_scan
from .errors import AuditError
from .output import render_console, write_json
from .scope import normalize_target


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

    target = args.target or audit_config.target.url
    if not target:
        raise ValueError("Target URL is required unless it is set in the config file")

    result = run_scan(target, audit_config)
    if args.json_output:
        write_json(result, args.json_output)

    if args.json_console:
        print(result.to_json(indent=2))
    else:
        render_console(result)
        if args.json_output:
            print(f"\nJSON written to {args.json_output}")
    return 0


def init_scope_command(args: argparse.Namespace) -> int:
    output: Path = args.output
    if output.exists() and not args.force:
        raise ValueError(f"Config file already exists: {output}. Use --force to overwrite it")

    raw_target = args.target or _prompt("Target URL", "")
    target = normalize_target(raw_target)

    config = AuditConfig()
    config.target.url = target.normalized_url
    config.scope.allowed_hosts = _prompt_list("Allowed hosts", target.host)
    config.scope.allow_subdomains = _prompt_bool("Allow subdomains", True)
    config.scope.include_paths = _prompt_list("Included paths", "/")
    config.scope.exclude_paths = _prompt_list("Excluded paths", "")
    config.scope.allow_private_networks = _prompt_bool("Allow private/local targets", False)
    config.scope.resolve_dns = _prompt_bool("Resolve DNS before scan", True)
    config.http.timeout_seconds = _prompt_float("HTTP timeout seconds", config.http.timeout_seconds, minimum=1.0)
    config.http.max_redirects = _prompt_int("Maximum redirects", config.http.max_redirects, minimum=0)
    config.http.check_http_counterpart = _prompt_bool("Check HTTP counterpart for HTTPS targets", True)
    config.modules.fingerprinting = _prompt_bool("Enable web fingerprinting", True)
    config.modules.crawler = _prompt_bool("Enable safe crawler", True)
    config.crawler.max_depth = _prompt_int("Crawler max depth", config.crawler.max_depth, minimum=0)
    config.crawler.max_pages = _prompt_int("Crawler max pages", config.crawler.max_pages, minimum=1)
    config.crawler.delay_seconds = _prompt_float("Crawler delay between requests", config.crawler.delay_seconds, minimum=0.0)

    config.write_json(output)
    print(f"Config written to {output}")
    print(f"Run: ai-web-auditor scan --config {output}")
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-web-auditor",
        description="Safe-first modular web audit CLI.",
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Run a non-intrusive web audit against one target URL.")
    scan_parser.add_argument("target", nargs="?", help="Target URL, for example https://example.com")
    scan_parser.add_argument("--config", "-c", type=Path, help="JSON or TOML config file.")
    scan_parser.add_argument("--json-output", "-o", type=Path, help="Write full scan result to this JSON file.")
    scan_parser.add_argument("--json", dest="json_console", action="store_true", help="Print JSON to console.")
    scan_parser.add_argument(
        "--allow-private",
        action="store_true",
        help="Allow private, loopback or local targets for labs.",
    )
    scan_parser.set_defaults(handler=scan_command)

    scope_parser = subparsers.add_parser("init-scope", help="Create an audit config file interactively.")
    scope_parser.add_argument("target", nargs="?", help="Target URL, for example https://example.com")
    scope_parser.add_argument("--output", "-o", type=Path, default=Path("audit.json"), help="Config file to write.")
    scope_parser.add_argument("--force", action="store_true", help="Overwrite the config file if it already exists.")
    scope_parser.set_defaults(handler=init_scope_command)
    return parser


def _prompt(label: str, default: str) -> str:
    suffix = f" [{default}]" if default else ""
    value = input(f"{label}{suffix}: ").strip()
    value = value or default
    if not value:
        raise ValueError(f"{label} is required")
    return value


def _prompt_list(label: str, default: str) -> list[str]:
    value = _prompt(label, default) if default else input(f"{label} [none]: ").strip()
    if not value:
        return []
    return [item.strip() for item in value.split(",") if item.strip()]


def _prompt_bool(label: str, default: bool) -> bool:
    default_text = "Y/n" if default else "y/N"
    value = input(f"{label} [{default_text}]: ").strip().lower()
    if not value:
        return default
    if value in {"y", "yes", "s", "si", "true", "1"}:
        return True
    if value in {"n", "no", "false", "0"}:
        return False
    raise ValueError(f"Invalid yes/no value for {label}: {value}")


def _prompt_int(label: str, default: int, minimum: int) -> int:
    value = input(f"{label} [{default}]: ").strip()
    if not value:
        return default
    number = int(value)
    if number < minimum:
        raise ValueError(f"{label} must be at least {minimum}")
    return number


def _prompt_float(label: str, default: float, minimum: float) -> float:
    value = input(f"{label} [{default}]: ").strip()
    if not value:
        return default
    number = float(value)
    if number < minimum:
        raise ValueError(f"{label} must be at least {minimum}")
    return number
