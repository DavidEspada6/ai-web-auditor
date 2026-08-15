from __future__ import annotations

from typing import Any

from . import __version__
from .models import utc_now


def compare_scans(baseline: dict[str, Any], current: dict[str, Any]) -> dict[str, Any]:
    baseline_findings = _findings_by_key(baseline)
    current_findings = _findings_by_key(current)
    baseline_keys = set(baseline_findings)
    current_keys = set(current_findings)

    new_keys = sorted(current_keys - baseline_keys)
    resolved_keys = sorted(baseline_keys - current_keys)
    persistent_keys = sorted(current_keys & baseline_keys)
    changed = [
        {
            "key": key,
            "baseline": baseline_findings[key],
            "current": current_findings[key],
            "baseline_severity": _severity(baseline_findings[key]),
            "current_severity": _severity(current_findings[key]),
        }
        for key in persistent_keys
        if _severity(baseline_findings[key]) != _severity(current_findings[key])
    ]

    return {
        "tool": "ai-web-auditor",
        "version": __version__,
        "generated_at": utc_now(),
        "baseline": _scan_summary(baseline),
        "current": _scan_summary(current),
        "summary": {
            "new": len(new_keys),
            "resolved": len(resolved_keys),
            "persistent": len(persistent_keys),
            "severity_changed": len(changed),
        },
        "new_findings": [current_findings[key] for key in new_keys],
        "resolved_findings": [baseline_findings[key] for key in resolved_keys],
        "persistent_findings": [current_findings[key] for key in persistent_keys],
        "severity_changed": changed,
    }


def render_compare_console(comparison: dict[str, Any]) -> None:
    baseline = comparison.get("baseline", {})
    current = comparison.get("current", {})
    summary = comparison.get("summary", {})
    print("AI Web Auditor comparison")
    print(f"Baseline: {baseline.get('target', 'unknown')} | {baseline.get('generated_at', 'unknown')}")
    print(f"Current:  {current.get('target', 'unknown')} | {current.get('generated_at', 'unknown')}")
    print()
    print("Summary")
    print("-------")
    print(f"New findings: {summary.get('new', 0)}")
    print(f"Resolved findings: {summary.get('resolved', 0)}")
    print(f"Persistent findings: {summary.get('persistent', 0)}")
    print(f"Severity changed: {summary.get('severity_changed', 0)}")
    _print_finding_group("New", comparison.get("new_findings"))
    _print_finding_group("Resolved", comparison.get("resolved_findings"))


def _print_finding_group(label: str, findings: Any) -> None:
    if not isinstance(findings, list) or not findings:
        return
    print()
    print(label)
    print("-" * len(label))
    for finding in findings[:10]:
        if isinstance(finding, dict):
            print(f"- {_severity(finding).upper()} {finding.get('id', 'unknown')}: {finding.get('title', 'Untitled')}")


def _findings_by_key(scan_data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    findings = scan_data.get("findings") if isinstance(scan_data.get("findings"), list) else []
    output: dict[str, dict[str, Any]] = {}
    for finding in findings:
        if isinstance(finding, dict):
            output[_finding_key(finding)] = finding
    return output


def _finding_key(finding: dict[str, Any]) -> str:
    parts = [
        str(finding.get("id", "")).strip(),
        str(finding.get("module", "")).strip(),
        str(finding.get("target", "")).strip(),
    ]
    if not any(parts):
        parts = [
            str(finding.get("title", "")).strip(),
            str(finding.get("category", "")).strip(),
            str(finding.get("severity", "")).strip(),
        ]
    return "|".join(parts).lower()


def _scan_summary(scan_data: dict[str, Any]) -> dict[str, Any]:
    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    findings = scan_data.get("findings") if isinstance(scan_data.get("findings"), list) else []
    return {
        "generated_at": scan_data.get("generated_at", "unknown"),
        "status": scan_data.get("status", "unknown"),
        "version": scan_data.get("version", "unknown"),
        "target": target.get("normalized_url", target.get("original_url", "unknown")),
        "host": target.get("host", "unknown"),
        "finding_count": len([item for item in findings if isinstance(item, dict)]),
    }


def _severity(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "info")).lower()
    return "info" if severity == "informational" else severity
