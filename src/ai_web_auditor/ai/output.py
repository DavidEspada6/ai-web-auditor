from __future__ import annotations

from pathlib import Path
from typing import Any

from ai_web_auditor.models import AIAnalysisResult


def render_analysis_console(result: AIAnalysisResult) -> None:
    print(render_analysis_markdown(result))


def render_analysis_markdown(result: AIAnalysisResult) -> str:
    analysis = result.analysis
    lines = [
        "# AI Web Auditor Analysis",
        "",
        f"- Provider: {result.provider}",
        f"- Model: {result.model}",
        f"- Source: {result.source_file}",
        f"- Status: {result.status}",
        "",
        "## Executive Summary",
        "",
        str(analysis.get("executive_summary") or analysis.get("text") or "No summary returned."),
        "",
        "## Risk",
        "",
        f"- Level: {analysis.get('risk_level', 'unknown')}",
        f"- Rationale: {analysis.get('risk_rationale', 'No rationale returned.')}",
        "",
    ]

    findings = analysis.get("priority_findings")
    if isinstance(findings, list) and findings:
        lines.extend(["## Priority Findings", ""])
        for item in findings:
            if isinstance(item, dict):
                lines.extend(_finding_lines(item))

    safe_next_steps = analysis.get("safe_next_steps")
    if isinstance(safe_next_steps, list) and safe_next_steps:
        lines.extend(["## Safe Next Steps", ""])
        lines.extend(f"- {step}" for step in safe_next_steps)
        lines.append("")

    report_notes = analysis.get("report_notes")
    if isinstance(report_notes, list) and report_notes:
        lines.extend(["## Report Notes", ""])
        lines.extend(f"- {note}" for note in report_notes)
        lines.append("")

    limitations = analysis.get("limitations")
    if isinstance(limitations, list) and limitations:
        lines.extend(["## Limitations", ""])
        lines.extend(f"- {item}" for item in limitations)
        lines.append("")

    return "\n".join(lines).rstrip() + "\n"


def write_analysis_json(result: AIAnalysisResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(result.to_json(indent=2) + "\n", encoding="utf-8")


def write_analysis_markdown(result: AIAnalysisResult, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_analysis_markdown(result), encoding="utf-8")


def _finding_lines(item: dict[str, Any]) -> list[str]:
    rank = item.get("rank", "?")
    severity = item.get("severity", "unknown")
    title = item.get("title", "Untitled")
    lines = [
        f"### {rank}. {title}",
        "",
        f"- Severity: {severity}",
        f"- Why it matters: {item.get('why_it_matters', 'No explanation returned.')}",
        f"- Recommended action: {item.get('recommended_action', 'No action returned.')}",
    ]
    evidence = item.get("evidence")
    if isinstance(evidence, list) and evidence:
        lines.append("- Evidence:")
        lines.extend(f"  - {value}" for value in evidence)
    lines.append("")
    return lines
