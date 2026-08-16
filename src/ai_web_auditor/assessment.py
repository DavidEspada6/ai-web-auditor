from __future__ import annotations

from collections import Counter
from typing import Any

from .inventory import build_inventory_from_scan


SEVERITY_BASE = {
    "critical": 100,
    "high": 80,
    "medium": 55,
    "low": 30,
    "info": 10,
}

SEVERITY_WEIGHT = {
    "critical": 30,
    "high": 20,
    "medium": 10,
    "low": 4,
    "info": 1,
}

PRIORITY_HINTS = {
    "AUTH-BASIC-OVER-HTTP": (14, "credentials may be exposed before transport security is enforced"),
    "HTTP-NO-HTTPS-REDIRECT": (12, "unencrypted HTTP remains reachable for the same service"),
    "HTTP-COUNTERPART-OPEN": (10, "the HTTP counterpart is reachable and should be reviewed"),
    "METHOD-TRACE-ADVERTISED": (9, "an unnecessary HTTP method is advertised by the server"),
    "COOKIE-SECURE-MISSING": (7, "session cookies can be sent without the Secure attribute"),
    "COOKIE-HTTPONLY-MISSING": (6, "client-side scripts may access cookies without HttpOnly"),
    "TLS-CERT-VERIFY-FAILED": (12, "the TLS certificate could not be validated"),
    "TLS-CERT-EXPIRED": (12, "the TLS certificate is expired"),
    "TLS-OLD-VERSION-NEGOTIATED": (10, "the TLS endpoint negotiated an outdated protocol"),
    "PORTS-OPEN-TCP-PORTS": (6, "additional exposed services increase the review surface"),
}

QUICK_WIN_PREFIXES = (
    "HEADER-",
    "COOKIE-",
    "HTTP-NO-HTTPS",
    "HTTP-COUNTERPART",
    "METHOD-",
    "TLS-CERT-EXPIRING",
)


def build_assessment(scan_data: dict[str, Any]) -> dict[str, Any]:
    findings = _findings(scan_data)
    modules = _modules(scan_data)
    inventory = _inventory(scan_data)
    coverage = _coverage(modules, inventory)
    severity_counts = _severity_counts(findings)
    risk_score = _risk_score(findings, severity_counts, coverage, scan_data)
    risk_level = _risk_level(risk_score, severity_counts)
    priorities = _priorities(findings)
    quick_wins = _quick_wins(findings)

    return {
        "summary": {
            "risk_score": risk_score,
            "risk_level": risk_level,
            "finding_count": len(findings),
            "critical": severity_counts["critical"],
            "high": severity_counts["high"],
            "medium": severity_counts["medium"],
            "low": severity_counts["low"],
            "info": severity_counts["info"],
            "priority_count": len(priorities),
            "quick_win_count": len(quick_wins),
            "coverage": coverage,
        },
        "priorities": priorities,
        "quick_wins": quick_wins,
        "remediation_plan": _remediation_plan(priorities, quick_wins, coverage),
        "coverage_notes": _coverage_notes(modules, inventory, coverage),
        "safety_notes": [
            "This assessment is generated from existing non-intrusive scan evidence only.",
            "No exploitation, brute force, fuzzing or destructive validation was performed.",
            "Risk should be reviewed against the authorized scope and business context.",
        ],
    }


def render_assessment_console(assessment: dict[str, Any]) -> str:
    summary = assessment.get("summary") if isinstance(assessment.get("summary"), dict) else {}
    return (
        f"Risk: {_clean(summary.get('risk_level'), 'informational')} "
        f"({_int(summary.get('risk_score'), 0)}/100) | "
        f"Priorities: {_int(summary.get('priority_count'), 0)} | "
        f"Quick wins: {_int(summary.get('quick_win_count'), 0)}"
    )


def _risk_score(
    findings: list[dict[str, Any]],
    counts: dict[str, int],
    coverage: dict[str, Any],
    scan_data: dict[str, Any],
) -> int:
    if not findings:
        return 0

    highest = max(SEVERITY_BASE.get(_severity(finding), 10) for finding in findings)
    density = sum(SEVERITY_WEIGHT[severity] * counts[severity] for severity in SEVERITY_WEIGHT)
    exposure_bonus = 0
    exposure_bonus += min(8, _int(coverage.get("open_ports"), 0) * 2)
    exposure_bonus += min(5, _int(coverage.get("forms"), 0))
    exposure_bonus += min(5, _int(coverage.get("subdomains"), 0))

    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    if target.get("scheme") == "http":
        exposure_bonus += 5

    score = min(100, round(highest + min(20, density / 8) + exposure_bonus))
    if not counts["critical"]:
        score = min(score, 89)
    return score


def _risk_level(score: int, counts: dict[str, int]) -> str:
    if counts["critical"] or score >= 90:
        return "critical"
    if counts["high"] or score >= 70:
        return "high"
    if counts["medium"] or score >= 40:
        return "medium"
    if counts["low"] or score >= 15:
        return "low"
    return "informational"


def _priorities(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    scored = []
    for finding in findings:
        finding_id = _clean(finding.get("id"), "unknown")
        hint_bonus, hint_reason = PRIORITY_HINTS.get(finding_id, (0, ""))
        severity = _severity(finding)
        score = SEVERITY_BASE.get(severity, 10) + hint_bonus + min(4, len(_dict_list(finding.get("evidence"))))
        scored.append((score, finding_id, finding, hint_reason))

    priorities: list[dict[str, Any]] = []
    for rank, (score, finding_id, finding, hint_reason) in enumerate(
        sorted(scored, key=lambda item: (-item[0], item[1]))[:10],
        start=1,
    ):
        severity = _severity(finding)
        priorities.append(
            {
                "rank": rank,
                "finding_id": finding_id,
                "title": _clean(finding.get("title"), "Untitled finding"),
                "severity": severity,
                "module": _clean(finding.get("module"), "unknown"),
                "target": _clean(finding.get("target"), "unknown"),
                "score": int(score),
                "reason": hint_reason or f"{severity} finding reported by the {_clean(finding.get('module'), 'unknown')} module",
                "recommended_action": _clean(finding.get("recommendation"), "Review and remediate the finding."),
            }
        )
    return priorities


def _quick_wins(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = []
    for finding in findings:
        finding_id = _clean(finding.get("id"), "unknown")
        severity = _severity(finding)
        if severity not in {"low", "medium", "high"}:
            continue
        if not finding_id.startswith(QUICK_WIN_PREFIXES):
            continue
        output.append(
            {
                "finding_id": finding_id,
                "title": _clean(finding.get("title"), "Untitled finding"),
                "severity": severity,
                "effort": "low",
                "recommended_action": _clean(finding.get("recommendation"), "Review and remediate the finding."),
            }
        )
    return output[:8]


def _remediation_plan(
    priorities: list[dict[str, Any]],
    quick_wins: list[dict[str, Any]],
    coverage: dict[str, Any],
) -> list[dict[str, Any]]:
    immediate: list[str] = []
    short_term: list[str] = []
    planned: list[str] = []

    for item in priorities:
        line = f"{item['title']}: {item['recommended_action']}"
        if item["severity"] in {"critical", "high"} or item["finding_id"] in PRIORITY_HINTS:
            _append_unique(immediate, line)
        elif item["severity"] == "medium":
            _append_unique(short_term, line)
        else:
            _append_unique(planned, line)

    for item in quick_wins:
        _append_unique(short_term, f"{item['title']}: {item['recommended_action']}")

    if _int(coverage.get("open_ports"), 0) > 0:
        _append_unique(immediate, "Review every open TCP port and confirm it is required for the approved scope.")
    if _int(coverage.get("modules_error"), 0) > 0:
        _append_unique(planned, "Repeat modules that ended in error before closing the audit.")
    if _int(coverage.get("modules_skipped"), 0) > 0:
        _append_unique(planned, "Document skipped modules and decide whether they are required for this engagement.")

    if not immediate:
        immediate.append("No immediate high-risk remediation was derived from the current evidence.")
    if not short_term:
        short_term.append("Review medium and low hardening items if more evidence is added later.")
    if not planned:
        planned.append("Keep the scan JSON, report and scope notes as audit evidence.")

    return [
        {"phase": "Immediate", "objective": "Reduce the highest observable risk first.", "items": immediate[:8]},
        {"phase": "Short term", "objective": "Apply low-effort hardening and validation.", "items": short_term[:8]},
        {"phase": "Planned", "objective": "Improve evidence quality and follow-up coverage.", "items": planned[:8]},
    ]


def _coverage(modules: list[dict[str, Any]], inventory: dict[str, Any]) -> dict[str, Any]:
    statuses = Counter(_clean(module.get("status"), "unknown") for module in modules)
    inventory_summary = inventory.get("summary") if isinstance(inventory.get("summary"), dict) else {}
    subdomains = _module_by_name(modules, "subdomains")
    subdomain_artifacts = subdomains.get("artifacts") if subdomains and isinstance(subdomains.get("artifacts"), dict) else {}
    ports = _module_by_name(modules, "ports")
    port_artifacts = ports.get("artifacts") if ports and isinstance(ports.get("artifacts"), dict) else {}

    return {
        "modules_run": len(modules),
        "modules_passed": statuses.get("passed", 0),
        "modules_warning": statuses.get("warning", 0),
        "modules_skipped": statuses.get("skipped", 0),
        "modules_error": statuses.get("error", 0),
        "urls": _int(inventory_summary.get("total_urls"), 0),
        "fetched_urls": _int(inventory_summary.get("fetched_urls"), 0),
        "forms": _int(inventory_summary.get("forms"), 0),
        "interesting_urls": _int(inventory_summary.get("interesting_urls"), 0),
        "subdomains": _int(subdomain_artifacts.get("resolved_count"), 0),
        "open_ports": _int(port_artifacts.get("open_count"), 0),
    }


def _coverage_notes(
    modules: list[dict[str, Any]],
    inventory: dict[str, Any],
    coverage: dict[str, Any],
) -> list[str]:
    notes: list[str] = []
    for module in modules:
        status = _clean(module.get("status"), "unknown")
        if status in {"warning", "skipped", "error"}:
            notes.append(f"{_clean(module.get('name'), 'unknown')}: {status} - {_clean(module.get('summary'), 'no summary')}")

    if _int(coverage.get("forms"), 0) > 0:
        notes.append("HTML forms were identified passively; no form submission was performed.")
    if _int(coverage.get("subdomains"), 0) > 0:
        notes.append("Resolved subdomains were recorded as evidence but not scanned automatically.")
    if _int(coverage.get("open_ports"), 0) > 0:
        notes.append("Open TCP ports were detected using TCP connect checks only; no payloads or banners were requested.")
    if not _dict_list(inventory.get("urls")):
        notes.append("No URL inventory was available for this scan.")
    return notes


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = Counter(_severity(finding) for finding in findings)
    return {
        "critical": counts.get("critical", 0),
        "high": counts.get("high", 0),
        "medium": counts.get("medium", 0),
        "low": counts.get("low", 0),
        "info": counts.get("info", 0),
    }


def _inventory(scan_data: dict[str, Any]) -> dict[str, Any]:
    inventory = scan_data.get("inventory")
    return inventory if isinstance(inventory, dict) else build_inventory_from_scan(scan_data)


def _findings(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    return _dict_list(scan_data.get("findings"))


def _modules(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    return _dict_list(scan_data.get("modules"))


def _module_by_name(modules: list[dict[str, Any]], name: str) -> dict[str, Any] | None:
    for module in modules:
        if module.get("name") == name:
            return module
    return None


def _severity(finding: dict[str, Any]) -> str:
    severity = str(finding.get("severity", "info")).lower()
    if severity == "informational":
        return "info"
    return severity if severity in SEVERITY_BASE else "info"


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _append_unique(items: list[str], value: str) -> None:
    if value and value not in items:
        items.append(value)


def _clean(value: Any, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default


def _int(value: Any, default: int) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default
