from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .ai.analyzer import analyze_scan_file
from .ai.output import render_analysis_console, write_analysis_json, write_analysis_markdown
from .config import AuditConfig
from .engine import run_scan
from .errors import AuditError
from .output import render_console, write_json
from .reporting import (
    generate_html_report,
    generate_markdown_report,
    generate_pdf_report,
    load_json_file,
    write_html_report,
    write_markdown_report,
    write_pdf_report,
)
from .scope import normalize_target
from .web.server import serve_gui


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


def analyze_command(args: argparse.Namespace) -> int:
    audit_config = AuditConfig.load(args.config)
    result = analyze_scan_file(
        args.scan_json,
        audit_config,
        provider_name=args.provider,
        model=args.model,
        dry_run=args.dry_run,
    )

    if args.json_output:
        write_analysis_json(result, args.json_output)
    if args.markdown_output:
        write_analysis_markdown(result, args.markdown_output)

    if args.json_console:
        print(result.to_json(indent=2))
    else:
        render_analysis_console(result)

    if args.json_output:
        print(f"JSON analysis written to {args.json_output}")
    if args.markdown_output:
        print(f"Markdown analysis written to {args.markdown_output}")
    return 0


def report_command(args: argparse.Namespace) -> int:
    scan_data = load_json_file(args.scan_json)
    ai_analysis = load_json_file(args.ai_analysis) if args.ai_analysis else None
    metadata = _report_metadata_from_args(args)
    report_format = _resolve_report_format(args.format, args.output)

    if report_format == "markdown":
        markdown = generate_markdown_report(scan_data, ai_analysis=ai_analysis, title=args.title, metadata=metadata)
        if args.output:
            write_markdown_report(markdown, args.output)
            print(f"Markdown report written to {args.output}")
        else:
            print(markdown)
    elif report_format == "html":
        html = generate_html_report(scan_data, ai_analysis=ai_analysis, title=args.title, metadata=metadata)
        if args.output:
            write_html_report(html, args.output)
            print(f"HTML report written to {args.output}")
        else:
            print(html)
    elif report_format == "pdf":
        if not args.output:
            raise ValueError("PDF output requires --output")
        pdf = generate_pdf_report(scan_data, ai_analysis=ai_analysis, title=args.title, metadata=metadata)
        write_pdf_report(pdf, args.output)
        print(f"PDF report written to {args.output}")
    else:
        raise ValueError(f"Unsupported report format: {report_format}")
    return 0


def gui_command(args: argparse.Namespace) -> int:
    serve_gui(host=args.host, port=args.port, open_browser=not args.no_open)
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

    analyze_parser = subparsers.add_parser("analyze", help="Analyze a scan JSON with an AI provider.")
    analyze_parser.add_argument("scan_json", type=Path, help="Scan JSON generated by the scan command.")
    analyze_parser.add_argument("--config", "-c", type=Path, help="JSON or TOML config file.")
    analyze_parser.add_argument("--provider", default=None, help="AI provider name. Default comes from config.")
    analyze_parser.add_argument("--model", default=None, help="AI model. Default comes from config.")
    analyze_parser.add_argument("--json-output", type=Path, help="Write AI analysis as JSON.")
    analyze_parser.add_argument("--markdown-output", type=Path, help="Write AI analysis as Markdown.")
    analyze_parser.add_argument("--json", dest="json_console", action="store_true", help="Print JSON to console.")
    analyze_parser.add_argument("--dry-run", action="store_true", help="Build the redacted prompt without calling the API.")
    analyze_parser.set_defaults(handler=analyze_command)

    report_parser = subparsers.add_parser("report", help="Generate a report from scan JSON.")
    report_parser.add_argument("scan_json", type=Path, help="Scan JSON generated by the scan command.")
    report_parser.add_argument("--ai-analysis", type=Path, help="Optional AI analysis JSON generated by analyze.")
    report_parser.add_argument("--output", "-o", type=Path, help="Write report to this file.")
    report_parser.add_argument("--format", choices=["markdown", "html", "pdf"], help="Report format. Defaults to output extension or markdown.")
    report_parser.add_argument("--title", help="Custom report title.")
    report_parser.add_argument("--client", help="Client or organization name for the report.")
    report_parser.add_argument("--auditor", help="Auditor name for the report.")
    report_parser.add_argument("--engagement", help="Engagement or project name.")
    report_parser.add_argument("--scope-summary", help="Human-readable scope summary.")
    report_parser.add_argument("--notes", help="Additional report notes.")
    report_parser.set_defaults(handler=report_command)

    gui_parser = subparsers.add_parser("gui", help="Start the local web interface.")
    gui_parser.add_argument("--host", default="127.0.0.1", help="Host for the local GUI server.")
    gui_parser.add_argument("--port", type=int, default=8765, help="Port for the local GUI server.")
    gui_parser.add_argument("--no-open", action="store_true", help="Do not open the browser automatically.")
    gui_parser.set_defaults(handler=gui_command)
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


def _resolve_report_format(requested: str | None, output: Path | None) -> str:
    if requested:
        return requested
    if output:
        suffix = output.suffix.lower()
        if suffix in {".html", ".htm"}:
            return "html"
        if suffix == ".pdf":
            return "pdf"
    return "markdown"


def _report_metadata_from_args(args: argparse.Namespace) -> dict[str, str]:
    return {
        "client": args.client or "",
        "auditor": args.auditor or "",
        "engagement": args.engagement or "",
        "scope_summary": args.scope_summary or "",
        "notes": args.notes or "",
    }
