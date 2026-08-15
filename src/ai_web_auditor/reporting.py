from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from html import escape
from pathlib import Path
from textwrap import wrap
from typing import Any

from . import __version__
from .models import utc_now


SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "informational": 4,
}


@dataclass
class ReportMetadata:
    client: str = ""
    auditor: str = ""
    engagement: str = ""
    scope_summary: str = ""
    notes: str = ""
    generated_at: str = ""


def load_json_file(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"JSON root must be an object: {path}")
    return data


def generate_markdown_report(
    scan_data: dict[str, Any],
    *,
    ai_analysis: dict[str, Any] | None = None,
    title: str | None = None,
    metadata: ReportMetadata | dict[str, Any] | None = None,
) -> str:
    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    findings = _findings(scan_data)
    modules = _modules(scan_data)
    ai_analysis = ai_analysis or _embedded_ai_analysis(scan_data)
    ai_body = _analysis_body(ai_analysis)
    report_metadata = normalize_report_metadata(metadata)
    generated_at = report_metadata.generated_at or utc_now()
    report_title = title or f"Web Audit Report - {_value(target.get('host'), 'unknown target')}"

    lines: list[str] = [
        f"# {report_title}",
        "",
        f"- Generated: {generated_at}",
        f"- Report generator: ai-web-auditor {__version__}",
        f"- Scan version: {_value(scan_data.get('version'), 'unknown')}",
        f"- Scan status: {_value(scan_data.get('status'), 'unknown')}",
        "",
        "## Target",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Original URL | {_cell(target.get('original_url'))} |",
        f"| Normalized URL | {_cell(target.get('normalized_url'))} |",
        f"| Host | {_cell(target.get('host'))} |",
        f"| Scheme | {_cell(target.get('scheme'))} |",
        f"| Port | {_cell(target.get('port'))} |",
        "",
    ]

    lines.extend(_metadata_markdown_section(report_metadata))
    lines.extend(_executive_summary_section(findings, ai_body))
    lines.extend(_severity_summary_section(findings))
    lines.extend(_module_summary_section(modules))
    lines.extend(_findings_section(findings))
    lines.extend(_technology_section(modules))
    lines.extend(_crawler_section(modules))
    lines.extend(_ai_section(ai_body))
    lines.extend(_limitations_section(ai_body))

    return "\n".join(lines).rstrip() + "\n"


def write_markdown_report(markdown: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(markdown, encoding="utf-8")


def write_html_report(html: str, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(html, encoding="utf-8")


def write_pdf_report(pdf: bytes, output: Path) -> None:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_bytes(pdf)


def normalize_report_metadata(metadata: ReportMetadata | dict[str, Any] | None = None) -> ReportMetadata:
    if metadata is None:
        return ReportMetadata()
    if isinstance(metadata, ReportMetadata):
        return metadata
    return ReportMetadata(
        client=_clean_metadata_value(metadata.get("client")),
        auditor=_clean_metadata_value(metadata.get("auditor")),
        engagement=_clean_metadata_value(metadata.get("engagement")),
        scope_summary=_clean_metadata_value(metadata.get("scope_summary", metadata.get("scope"))),
        notes=_clean_metadata_value(metadata.get("notes")),
        generated_at=_clean_metadata_value(metadata.get("generated_at")),
    )


def generate_html_report(
    scan_data: dict[str, Any],
    *,
    ai_analysis: dict[str, Any] | None = None,
    title: str | None = None,
    metadata: ReportMetadata | dict[str, Any] | None = None,
) -> str:
    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    findings = _findings(scan_data)
    modules = _modules(scan_data)
    ai_analysis = ai_analysis or _embedded_ai_analysis(scan_data)
    ai_body = _analysis_body(ai_analysis)
    report_metadata = normalize_report_metadata(metadata)
    generated_at = report_metadata.generated_at or utc_now()
    report_title = title or f"Web Audit Report - {_value(target.get('host'), 'unknown target')}"
    severity_counts = _severity_counts(findings)
    summary, risk_level, rationale = _executive_summary_values(findings, ai_body)

    return "\n".join(
        [
            "<!doctype html>",
            '<html lang="es">',
            "<head>",
            '<meta charset="utf-8">',
            '<meta name="viewport" content="width=device-width, initial-scale=1">',
            f"<title>{_html(report_title)}</title>",
            "<style>",
            _REPORT_CSS,
            "</style>",
            "</head>",
            "<body>",
            '<main class="report">',
            '<section class="cover">',
            '<p class="label">AI Web Auditor</p>',
            f"<h1>{_html(report_title)}</h1>",
            f"<p>{_html(summary)}</p>",
            '<div class="cover-grid">',
            _meta_tile("Generated", generated_at),
            _meta_tile("Report generator", f"ai-web-auditor {__version__}"),
            _meta_tile("Scan version", _value(scan_data.get("version"), "unknown")),
            _meta_tile("Scan status", _value(scan_data.get("status"), "unknown")),
            _meta_tile("Overall risk", risk_level or "not assessed"),
            _meta_tile("Target", target.get("normalized_url") or target.get("host") or "unknown"),
            "</div>",
            "</section>",
            _metadata_html_section(report_metadata),
            '<section class="section">',
            "<h2>Target</h2>",
            _html_table(
                ["Field", "Value"],
                [
                    ["Original URL", target.get("original_url")],
                    ["Normalized URL", target.get("normalized_url")],
                    ["Host", target.get("host")],
                    ["Scheme", target.get("scheme")],
                    ["Port", target.get("port")],
                ],
            ),
            "</section>",
            '<section class="section">',
            "<h2>Executive Summary</h2>",
            f"<p>{_html(summary)}</p>",
            f'<p class="risk">Overall risk: <strong>{_html(risk_level or "unknown")}</strong></p>',
            f"<p>{_html(rationale)}</p>",
            "</section>",
            _severity_html_section(severity_counts),
            _module_html_section(modules),
            _findings_html_section(findings),
            _technology_html_section(modules),
            _crawler_html_section(modules),
            _ai_html_section(ai_body),
            _limitations_html_section(ai_body),
            "</main>",
            "</body>",
            "</html>",
            "",
        ]
    )


def generate_pdf_report(
    scan_data: dict[str, Any],
    *,
    ai_analysis: dict[str, Any] | None = None,
    title: str | None = None,
    metadata: ReportMetadata | dict[str, Any] | None = None,
) -> bytes:
    markdown = generate_markdown_report(
        scan_data,
        ai_analysis=ai_analysis,
        title=title,
        metadata=metadata,
    )
    lines = _markdown_to_plain_lines(markdown)
    return _build_simple_pdf(lines)


def _metadata_markdown_section(metadata: ReportMetadata) -> list[str]:
    rows = _metadata_rows(metadata)
    if not rows:
        return []
    lines = ["## Engagement", "", "| Field | Value |", "| --- | --- |"]
    lines.extend(f"| {_cell(label)} | {_cell(value)} |" for label, value in rows)
    lines.append("")
    return lines


def _executive_summary_section(findings: list[dict[str, Any]], ai_body: dict[str, Any] | None) -> list[str]:
    summary, risk_level, rationale = _executive_summary_values(findings, ai_body)
    if ai_body and ai_body.get("executive_summary"):
        return [
            "## Executive Summary",
            "",
            _text(summary),
            "",
            f"Overall risk: **{_text(risk_level or 'unknown')}**",
            "",
            _text(rationale),
            "",
        ]

    return ["## Executive Summary", "", _text(summary), ""]


def _executive_summary_values(
    findings: list[dict[str, Any]],
    ai_body: dict[str, Any] | None,
) -> tuple[str, str | None, str]:
    if ai_body and ai_body.get("executive_summary"):
        return (
            str(ai_body["executive_summary"]),
            _text(ai_body.get("risk_level", "unknown")),
            _text(ai_body.get("risk_rationale", "No rationale provided.")),
        )

    counts = Counter(_severity(finding) for finding in findings)
    if not findings:
        summary = "No findings were generated by the enabled modules."
    else:
        summary = (
            f"The scan generated {len(findings)} finding(s): "
            f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, "
            f"{counts.get('medium', 0)} medium, {counts.get('low', 0)} low and "
            f"{counts.get('info', 0) + counts.get('informational', 0)} informational."
        )
    return summary, None, "Review each finding against the authorized scope and business context."


def _severity_summary_section(findings: list[dict[str, Any]]) -> list[str]:
    counts = Counter(_severity(finding) for finding in findings)
    severities = ["critical", "high", "medium", "low", "info"]
    lines = [
        "## Severity Summary",
        "",
        "| Severity | Count |",
        "| --- | ---: |",
    ]
    for severity in severities:
        count = counts.get(severity, 0)
        if severity == "info":
            count += counts.get("informational", 0)
        lines.append(f"| {severity.upper()} | {count} |")
    lines.append("")
    return lines


def _module_summary_section(modules: list[dict[str, Any]]) -> list[str]:
    lines = [
        "## Module Summary",
        "",
        "| Module | Status | Summary |",
        "| --- | --- | --- |",
    ]
    for module in modules:
        lines.append(
            f"| {_cell(module.get('name'))} | {_cell(module.get('status'))} | {_cell(module.get('summary'))} |"
        )
    lines.append("")
    return lines


def _findings_section(findings: list[dict[str, Any]]) -> list[str]:
    lines = ["## Findings", ""]
    if not findings:
        lines.extend(["No findings were reported.", ""])
        return lines

    for finding in sorted(findings, key=lambda item: (SEVERITY_ORDER.get(_severity(item), 99), str(item.get("id", "")))):
        lines.extend(
            [
                f"### {_text(finding.get('severity', 'info')).upper()} - {_text(finding.get('title', 'Untitled finding'))}",
                "",
                f"- ID: `{_text(finding.get('id', 'unknown'))}`",
                f"- Category: {_text(finding.get('category', 'unknown'))}",
                f"- Module: `{_text(finding.get('module', 'unknown'))}`",
                f"- Target: `{_text(finding.get('target', 'unknown'))}`",
                "",
                "**Description**",
                "",
                _text(finding.get("description", "No description provided.")),
                "",
                "**Recommendation**",
                "",
                _text(finding.get("recommendation", "No recommendation provided.")),
                "",
            ]
        )
        evidence = finding.get("evidence")
        if isinstance(evidence, list) and evidence:
            lines.extend(["**Evidence**", ""])
            for item in evidence:
                if not isinstance(item, dict):
                    continue
                label = _text(item.get("label", "evidence"))
                value = _text(item.get("value", ""))
                location = item.get("location")
                suffix = f" ({_text(location)})" if location else ""
                lines.append(f"- {label}{suffix}: `{value}`")
            lines.append("")
    return lines


def _technology_section(modules: list[dict[str, Any]]) -> list[str]:
    fingerprinting = _module_by_name(modules, "fingerprinting")
    if not fingerprinting:
        return []

    artifacts = fingerprinting.get("artifacts") if isinstance(fingerprinting.get("artifacts"), dict) else {}
    technologies = artifacts.get("technologies") if isinstance(artifacts.get("technologies"), list) else []
    public_files = artifacts.get("public_files") if isinstance(artifacts.get("public_files"), list) else []
    lines = ["## Technology Fingerprinting", ""]

    if technologies:
        lines.extend(["| Technology | Category | Confidence | Signals |", "| --- | --- | --- | --- |"])
        for technology in technologies:
            if not isinstance(technology, dict):
                continue
            signals = technology.get("signals") if isinstance(technology.get("signals"), list) else []
            name = technology.get("name")
            version = technology.get("version")
            display_name = f"{name} {version}" if version else name
            lines.append(
                f"| {_cell(display_name)} | {_cell(technology.get('category'))} | {_cell(technology.get('confidence'))} | {_cell(', '.join(map(str, signals)))} |"
            )
        lines.append("")
    else:
        lines.extend(["No technology signals were identified.", ""])

    if public_files:
        lines.extend(["### Public Metadata Files", "", "| Path | Status | Present |", "| --- | ---: | --- |"])
        for item in public_files:
            if isinstance(item, dict):
                lines.append(
                    f"| {_cell(item.get('path'))} | {_cell(item.get('status_code', item.get('status')))} | {_cell(item.get('present'))} |"
                )
        lines.append("")
    return lines


def _crawler_section(modules: list[dict[str, Any]]) -> list[str]:
    crawler = _module_by_name(modules, "crawler")
    if not crawler:
        return []

    artifacts = crawler.get("artifacts") if isinstance(crawler.get("artifacts"), dict) else {}
    fetched = _string_list(artifacts.get("fetched_urls"))
    discovered = _string_list(artifacts.get("discovered_urls"))
    out_of_scope = _string_list(artifacts.get("out_of_scope_urls"))
    excluded = _string_list(artifacts.get("excluded_urls"))

    lines = [
        "## Crawler",
        "",
        f"- Seed URL: `{_text(artifacts.get('seed_url', 'unknown'))}`",
        f"- Max depth: {_text(artifacts.get('max_depth', 'unknown'))}",
        f"- Max pages: {_text(artifacts.get('max_pages', 'unknown'))}",
        f"- Fetched URLs: {len(fetched)}",
        f"- Discovered in-scope URLs: {len(discovered)}",
        f"- Out-of-scope URLs recorded but not visited: {len(out_of_scope)}",
        f"- Excluded URLs recorded but not visited: {len(excluded)}",
        "",
    ]

    if discovered:
        lines.extend(["### Discovered URLs", ""])
        lines.extend(f"- `{url}`" for url in discovered[:50])
        if len(discovered) > 50:
            lines.append(f"- ... {len(discovered) - 50} more")
        lines.append("")

    if out_of_scope:
        lines.extend(["### Out-of-Scope URLs", ""])
        lines.extend(f"- `{url}`" for url in out_of_scope[:25])
        lines.append("")

    if excluded:
        lines.extend(["### Excluded URLs", ""])
        lines.extend(f"- `{url}`" for url in excluded[:25])
        lines.append("")

    return lines


def _ai_section(ai_body: dict[str, Any] | None) -> list[str]:
    if not ai_body:
        return []

    lines: list[str] = []
    priority_findings = ai_body.get("priority_findings")
    if isinstance(priority_findings, list) and priority_findings:
        lines.extend(["## AI Prioritization", ""])
        for item in priority_findings:
            if not isinstance(item, dict):
                continue
            lines.extend(
                [
                    f"### {item.get('rank', '?')}. {_text(item.get('title', 'Untitled'))}",
                    "",
                    f"- Severity: {_text(item.get('severity', 'unknown'))}",
                    f"- Why it matters: {_text(item.get('why_it_matters', 'No explanation provided.'))}",
                    f"- Recommended action: {_text(item.get('recommended_action', 'No action provided.'))}",
                    "",
                ]
            )
            evidence = item.get("evidence")
            if isinstance(evidence, list) and evidence:
                lines.extend(["Evidence:", ""])
                lines.extend(f"- {_text(value)}" for value in evidence)
                lines.append("")

    safe_next_steps = ai_body.get("safe_next_steps")
    if isinstance(safe_next_steps, list) and safe_next_steps:
        lines.extend(["## Safe Next Steps", ""])
        lines.extend(f"- {_text(step)}" for step in safe_next_steps)
        lines.append("")

    report_notes = ai_body.get("report_notes")
    if isinstance(report_notes, list) and report_notes:
        lines.extend(["## Report Notes", ""])
        lines.extend(f"- {_text(note)}" for note in report_notes)
        lines.append("")

    return lines


def _limitations_section(ai_body: dict[str, Any] | None) -> list[str]:
    lines = [
        "## Limitations",
        "",
        "- This report is based on non-intrusive checks only.",
        "- No exploitation, brute force, aggressive fuzzing or destructive testing was performed.",
        "- Findings should be validated against the authorized scope and business context.",
    ]

    if ai_body:
        limitations = ai_body.get("limitations")
        if isinstance(limitations, list):
            lines.extend(f"- {_text(item)}" for item in limitations)
    lines.append("")
    return lines


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(_severity(finding) for finding in findings)
    return {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0) + counts.get("informational", 0),
    }


def _metadata_html_section(metadata: ReportMetadata) -> str:
    rows = _metadata_rows(metadata)
    if not rows:
        return ""
    return "\n".join(
        [
            '<section class="section">',
            "<h2>Engagement</h2>",
            _html_table(["Field", "Value"], rows),
            "</section>",
        ]
    )


def _severity_html_section(counts: dict[str, int]) -> str:
    cards = []
    for severity in ["critical", "high", "medium", "low", "info"]:
        cards.append(
            f'<div class="severity-card {severity}"><span>{_html(severity.upper())}</span>'
            f"<strong>{counts.get(severity, 0)}</strong></div>"
        )
    return "\n".join(
        [
            '<section class="section">',
            "<h2>Severity Summary</h2>",
            '<div class="severity-grid">',
            *cards,
            "</div>",
            "</section>",
        ]
    )


def _module_html_section(modules: list[dict[str, Any]]) -> str:
    rows = [[module.get("name"), module.get("status"), module.get("summary")] for module in modules]
    return "\n".join(
        [
            '<section class="section">',
            "<h2>Module Summary</h2>",
            _html_table(["Module", "Status", "Summary"], rows),
            "</section>",
        ]
    )


def _findings_html_section(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "\n".join(
            [
                '<section class="section">',
                "<h2>Findings</h2>",
                '<p class="empty">No findings were reported.</p>',
                "</section>",
            ]
        )

    cards = ['<section class="section">', "<h2>Findings</h2>", '<div class="finding-stack">']
    for finding in sorted(findings, key=lambda item: (SEVERITY_ORDER.get(_severity(item), 99), str(item.get("id", "")))):
        severity = _severity(finding)
        cards.extend(
            [
                '<article class="finding-card">',
                f'<span class="badge {severity}">{_html(severity.upper())}</span>',
                f"<h3>{_html(finding.get('title', 'Untitled finding'))}</h3>",
                '<dl class="finding-meta">',
                f"<div><dt>ID</dt><dd>{_html(finding.get('id', 'unknown'))}</dd></div>",
                f"<div><dt>Module</dt><dd>{_html(finding.get('module', 'unknown'))}</dd></div>",
                f"<div><dt>Category</dt><dd>{_html(finding.get('category', 'unknown'))}</dd></div>",
                f"<div><dt>Target</dt><dd>{_html(finding.get('target', 'unknown'))}</dd></div>",
                "</dl>",
                f"<p>{_html(finding.get('description', 'No description provided.'))}</p>",
                f'<p><strong>Recommendation:</strong> {_html(finding.get("recommendation", "No recommendation provided."))}</p>',
                _evidence_html(finding.get("evidence")),
                "</article>",
            ]
        )
    cards.extend(["</div>", "</section>"])
    return "\n".join(cards)


def _technology_html_section(modules: list[dict[str, Any]]) -> str:
    fingerprinting = _module_by_name(modules, "fingerprinting")
    if not fingerprinting:
        return ""

    artifacts = fingerprinting.get("artifacts") if isinstance(fingerprinting.get("artifacts"), dict) else {}
    technologies = artifacts.get("technologies") if isinstance(artifacts.get("technologies"), list) else []
    public_files = artifacts.get("public_files") if isinstance(artifacts.get("public_files"), list) else []
    lines = ['<section class="section">', "<h2>Technology Fingerprinting</h2>"]

    if technologies:
        rows = []
        for technology in technologies:
            if not isinstance(technology, dict):
                continue
            signals = technology.get("signals") if isinstance(technology.get("signals"), list) else []
            name = technology.get("name")
            version = technology.get("version")
            rows.append(
                [
                    f"{name} {version}" if version else name,
                    technology.get("category"),
                    technology.get("confidence"),
                    ", ".join(map(str, signals)),
                ]
            )
        lines.append(_html_table(["Technology", "Category", "Confidence", "Signals"], rows))
    else:
        lines.append('<p class="empty">No technology signals were identified.</p>')

    if public_files:
        rows = [
            [item.get("path"), item.get("status_code", item.get("status")), item.get("present")]
            for item in public_files
            if isinstance(item, dict)
        ]
        lines.extend(["<h3>Public Metadata Files</h3>", _html_table(["Path", "Status", "Present"], rows)])
    lines.append("</section>")
    return "\n".join(lines)


def _crawler_html_section(modules: list[dict[str, Any]]) -> str:
    crawler = _module_by_name(modules, "crawler")
    if not crawler:
        return ""

    artifacts = crawler.get("artifacts") if isinstance(crawler.get("artifacts"), dict) else {}
    fetched = _string_list(artifacts.get("fetched_urls"))
    discovered = _string_list(artifacts.get("discovered_urls"))
    out_of_scope = _string_list(artifacts.get("out_of_scope_urls"))
    excluded = _string_list(artifacts.get("excluded_urls"))
    rows = [
        ["Seed URL", artifacts.get("seed_url", "unknown")],
        ["Max depth", artifacts.get("max_depth", "unknown")],
        ["Max pages", artifacts.get("max_pages", "unknown")],
        ["Fetched URLs", len(fetched)],
        ["Discovered in-scope URLs", len(discovered)],
        ["Out-of-scope URLs recorded but not visited", len(out_of_scope)],
        ["Excluded URLs recorded but not visited", len(excluded)],
    ]
    lines = ['<section class="section">', "<h2>Crawler</h2>", _html_table(["Field", "Value"], rows)]
    if discovered:
        lines.extend(["<h3>Discovered URLs</h3>", _html_list(discovered[:50])])
    if out_of_scope:
        lines.extend(["<h3>Out-of-Scope URLs</h3>", _html_list(out_of_scope[:25])])
    if excluded:
        lines.extend(["<h3>Excluded URLs</h3>", _html_list(excluded[:25])])
    lines.append("</section>")
    return "\n".join(lines)


def _ai_html_section(ai_body: dict[str, Any] | None) -> str:
    if not ai_body:
        return ""

    lines: list[str] = []
    priority_findings = ai_body.get("priority_findings")
    if isinstance(priority_findings, list) and priority_findings:
        lines.extend(['<section class="section">', "<h2>AI Prioritization</h2>", '<div class="finding-stack">'])
        for item in priority_findings:
            if not isinstance(item, dict):
                continue
            lines.extend(
                [
                    '<article class="finding-card">',
                    f"<h3>{_html(item.get('rank', '?'))}. {_html(item.get('title', 'Untitled'))}</h3>",
                    f'<p><strong>Severity:</strong> {_html(item.get("severity", "unknown"))}</p>',
                    f'<p><strong>Why it matters:</strong> {_html(item.get("why_it_matters", "No explanation provided."))}</p>',
                    f'<p><strong>Recommended action:</strong> {_html(item.get("recommended_action", "No action provided."))}</p>',
                    _html_list(item.get("evidence") if isinstance(item.get("evidence"), list) else []),
                    "</article>",
                ]
            )
        lines.extend(["</div>", "</section>"])

    safe_next_steps = ai_body.get("safe_next_steps")
    if isinstance(safe_next_steps, list) and safe_next_steps:
        lines.extend(['<section class="section">', "<h2>Safe Next Steps</h2>", _html_list(safe_next_steps), "</section>"])

    report_notes = ai_body.get("report_notes")
    if isinstance(report_notes, list) and report_notes:
        lines.extend(['<section class="section">', "<h2>Report Notes</h2>", _html_list(report_notes), "</section>"])
    return "\n".join(lines)


def _limitations_html_section(ai_body: dict[str, Any] | None) -> str:
    limitations = [
        "This report is based on non-intrusive checks only.",
        "No exploitation, brute force, aggressive fuzzing or destructive testing was performed.",
        "Findings should be validated against the authorized scope and business context.",
    ]
    if ai_body and isinstance(ai_body.get("limitations"), list):
        limitations.extend(str(item) for item in ai_body["limitations"])
    return "\n".join(['<section class="section">', "<h2>Limitations</h2>", _html_list(limitations), "</section>"])


def _evidence_html(evidence: Any) -> str:
    if not isinstance(evidence, list) or not evidence:
        return ""
    rows = []
    for item in evidence:
        if isinstance(item, dict):
            rows.append([item.get("label", "evidence"), item.get("value", ""), item.get("location", "")])
    if not rows:
        return ""
    return "<h4>Evidence</h4>\n" + _html_table(["Label", "Value", "Location"], rows)


def _html_table(headers: list[str], rows: list[list[Any] | tuple[Any, ...]]) -> str:
    header_html = "".join(f"<th>{_html(header)}</th>" for header in headers)
    row_html = []
    for row in rows:
        row_html.append("<tr>" + "".join(f"<td>{_html(cell)}</td>" for cell in row) + "</tr>")
    return "<table><thead><tr>" + header_html + "</tr></thead><tbody>" + "".join(row_html) + "</tbody></table>"


def _html_list(items: list[Any]) -> str:
    if not items:
        return ""
    return "<ul>" + "".join(f"<li>{_html(item)}</li>" for item in items) + "</ul>"


def _meta_tile(label: str, value: Any) -> str:
    return f'<div><span>{_html(label)}</span><strong>{_html(value)}</strong></div>'


def _metadata_rows(metadata: ReportMetadata) -> list[tuple[str, str]]:
    rows = [
        ("Client", metadata.client),
        ("Auditor", metadata.auditor),
        ("Engagement", metadata.engagement),
        ("Scope summary", metadata.scope_summary),
        ("Notes", metadata.notes),
    ]
    return [(label, value) for label, value in rows if value]


def _clean_metadata_value(value: Any) -> str:
    if value is None:
        return ""
    return str(value).strip()


def _html(value: Any) -> str:
    return escape(_text(value), quote=True)


def _analysis_body(ai_analysis: dict[str, Any] | None) -> dict[str, Any] | None:
    if not ai_analysis:
        return None
    body = ai_analysis.get("analysis")
    return body if isinstance(body, dict) else ai_analysis


def _embedded_ai_analysis(scan_data: dict[str, Any]) -> dict[str, Any] | None:
    ai_analysis = scan_data.get("ai_analysis")
    return ai_analysis if isinstance(ai_analysis, dict) else None


def _findings(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    findings = scan_data.get("findings")
    return [item for item in findings if isinstance(item, dict)] if isinstance(findings, list) else []


def _modules(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    modules = scan_data.get("modules")
    return [item for item in modules if isinstance(item, dict)] if isinstance(modules, list) else []


def _module_by_name(modules: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for module in modules:
        if module.get("name") == name:
            return module
    return None


def _severity(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "info")).lower()
    return "info" if severity == "informational" else severity


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value]


def _cell(value: Any) -> str:
    return _text(value).replace("|", "\\|").replace("\n", "<br>")


def _text(value: Any) -> str:
    return str(_value(value, "unknown")).replace("\r\n", "\n").replace("\r", "\n").strip()


def _value(value: Any, default: str) -> Any:
    return default if value is None or value == "" else value


def _markdown_to_plain_lines(markdown: str) -> list[str]:
    lines: list[str] = []
    for raw_line in markdown.splitlines():
        line = raw_line.strip()
        if line.startswith("|"):
            if set(line.replace("|", "").replace(" ", "")) <= {"-", ":"}:
                continue
            line = "  ".join(part.strip() for part in line.strip("|").split("|"))
        if line.startswith("#"):
            line = line.lstrip("#").strip().upper()
        line = line.replace("**", "").replace("`", "")
        line = line.replace("<br>", " / ")
        if not line:
            lines.append("")
            continue
        wrapped = wrap(line, width=92, replace_whitespace=False, drop_whitespace=True)
        lines.extend(wrapped or [""])
    return lines


def _build_simple_pdf(lines: list[str]) -> bytes:
    page_line_limit = 52
    line_height = 14
    left = 48
    top = 800
    pages = [lines[index : index + page_line_limit] for index in range(0, len(lines), page_line_limit)] or [[]]

    objects: list[bytes] = [b"", b""]
    page_ids: list[int] = []

    def add_object(value: bytes) -> int:
        objects.append(value)
        return len(objects)

    for page_lines in pages:
        content_lines = ["BT", "/F1 10 Tf", f"{left} {top} Td", f"{line_height} TL"]
        for index, line in enumerate(page_lines):
            if index:
                content_lines.append("T*")
            if line:
                content_lines.append(f"({_pdf_escape(line)}) Tj")
        content_lines.append("ET")
        stream = "\n".join(content_lines).encode("latin-1", errors="replace")
        content_id = add_object(b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n" + stream + b"\nendstream")
        page_id = add_object(
            (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] "
                f"/Resources << /Font << /F1 << /Type /Font /Subtype /Type1 /BaseFont /Helvetica >> >> >> "
                f"/Contents {content_id} 0 R >>"
            ).encode("ascii")
        )
        page_ids.append(page_id)

    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects[0] = b"<< /Type /Catalog /Pages 2 0 R >>"
    objects[1] = f"<< /Type /Pages /Kids [{kids}] /Count {len(page_ids)} >>".encode("ascii")

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, value in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{index} 0 obj\n".encode("ascii"))
        pdf.extend(value)
        pdf.extend(b"\nendobj\n")

    xref_offset = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(pdf)


def _pdf_escape(value: str) -> str:
    return value.encode("latin-1", errors="replace").decode("latin-1").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


_REPORT_CSS = """
:root {
  color-scheme: light;
  --bg: #f4f7f8;
  --panel: #ffffff;
  --line: #d9e1e7;
  --text: #17202a;
  --muted: #667386;
  --brand: #0f766e;
  --ink: #1f2937;
  --critical: #b42318;
  --high: #c2410c;
  --medium: #b7791f;
  --low: #2563eb;
  --info: #4b5563;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  background: var(--bg);
  color: var(--text);
  font-family: Inter, Arial, sans-serif;
  line-height: 1.55;
}
.report {
  max-width: 1080px;
  margin: 0 auto;
  padding: 32px;
}
.cover,
.section {
  background: var(--panel);
  border: 1px solid var(--line);
  border-radius: 8px;
  margin-bottom: 18px;
  padding: 26px;
}
.cover {
  border-top: 6px solid var(--brand);
}
.label {
  margin: 0 0 8px;
  color: var(--muted);
  font-size: 12px;
  font-weight: 800;
  letter-spacing: 0;
  text-transform: uppercase;
}
h1,
h2,
h3,
h4 {
  color: var(--ink);
  letter-spacing: 0;
  line-height: 1.2;
}
h1 { margin: 0 0 14px; font-size: 34px; }
h2 { margin: 0 0 16px; font-size: 22px; }
h3 { margin: 18px 0 10px; font-size: 17px; }
h4 { margin: 14px 0 8px; font-size: 14px; }
.cover-grid,
.severity-grid,
.finding-meta {
  display: grid;
  gap: 10px;
}
.cover-grid {
  grid-template-columns: repeat(3, minmax(0, 1fr));
  margin-top: 22px;
}
.cover-grid div,
.severity-card {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 12px;
  background: #fafbfc;
}
.cover-grid span,
.severity-card span,
dt {
  display: block;
  color: var(--muted);
  font-size: 11px;
  font-weight: 800;
  text-transform: uppercase;
}
.cover-grid strong,
.severity-card strong {
  display: block;
  margin-top: 6px;
  overflow-wrap: anywhere;
}
.severity-grid {
  grid-template-columns: repeat(5, minmax(0, 1fr));
}
.severity-card strong {
  font-size: 28px;
}
.severity-card.critical strong { color: var(--critical); }
.severity-card.high strong { color: var(--high); }
.severity-card.medium strong { color: var(--medium); }
.severity-card.low strong { color: var(--low); }
.severity-card.info strong { color: var(--info); }
table {
  width: 100%;
  border-collapse: collapse;
  table-layout: fixed;
}
th,
td {
  border-bottom: 1px solid var(--line);
  padding: 10px;
  text-align: left;
  vertical-align: top;
  overflow-wrap: anywhere;
}
th {
  color: var(--muted);
  font-size: 11px;
  text-transform: uppercase;
}
.finding-stack {
  display: grid;
  gap: 14px;
}
.finding-card {
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 16px;
  background: #fafbfc;
  break-inside: avoid;
}
.finding-card h3 {
  margin-top: 10px;
}
.finding-meta {
  grid-template-columns: repeat(2, minmax(0, 1fr));
  margin: 12px 0;
}
.finding-meta div {
  min-width: 0;
}
dd {
  margin: 2px 0 0;
  overflow-wrap: anywhere;
}
.badge {
  display: inline-flex;
  min-height: 24px;
  align-items: center;
  border-radius: 999px;
  color: #ffffff;
  font-size: 11px;
  font-weight: 800;
  padding: 2px 9px;
}
.badge.critical { background: var(--critical); }
.badge.high { background: var(--high); }
.badge.medium { background: var(--medium); }
.badge.low { background: var(--low); }
.badge.info { background: var(--info); }
.risk strong {
  color: var(--brand);
}
.empty {
  color: var(--muted);
  font-weight: 700;
}
@media print {
  body { background: #ffffff; }
  .report { max-width: none; padding: 0; }
  .cover,
  .section {
    border: 0;
    border-radius: 0;
    page-break-inside: avoid;
  }
}
""".strip()
