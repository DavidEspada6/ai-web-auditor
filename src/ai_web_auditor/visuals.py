from __future__ import annotations

import json
from html import escape
from pathlib import Path
from typing import Any

from .models import utc_now


SVG_WIDTH = 960
SVG_HEIGHT = 540


def build_visual_evidence(scan_data: dict[str, Any]) -> dict[str, Any]:
    """Build deterministic visual evidence snapshots from passive scan data."""

    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    modules = _dict_list(scan_data.get("modules"))
    findings = _dict_list(scan_data.get("findings"))
    inventory = scan_data.get("inventory") if isinstance(scan_data.get("inventory"), dict) else {}
    entry_points = scan_data.get("entry_points") if isinstance(scan_data.get("entry_points"), dict) else {}
    assessment = scan_data.get("assessment") if isinstance(scan_data.get("assessment"), dict) else {}
    rule_evaluation = scan_data.get("rule_evaluation") if isinstance(scan_data.get("rule_evaluation"), dict) else {}
    auth_profile = scan_data.get("auth_profile") if isinstance(scan_data.get("auth_profile"), dict) else {}

    fingerprint = _build_fingerprint(
        target=target,
        modules=modules,
        findings=findings,
        inventory=inventory,
        entry_points=entry_points,
        assessment=assessment,
        rule_evaluation=rule_evaluation,
        auth_profile=auth_profile,
    )
    module_groups = _module_groups(modules)
    screenshots = [
        {
            "id": "audit-overview",
            "title": "Audit overview",
            "kind": "svg",
            "filename": "visuals/audit-overview.svg",
            "description": "Resumen visual del objetivo, severidades, riesgo y cobertura principal de la auditoria.",
            "svg": _overview_svg(fingerprint),
        },
        {
            "id": "fingerprint-map",
            "title": "Fingerprint map",
            "kind": "svg",
            "filename": "visuals/fingerprint-map.svg",
            "description": "Mapa visual de tecnologias, metadatos publicos y superficie descubierta de forma pasiva.",
            "svg": _fingerprint_svg(fingerprint),
        },
        {
            "id": "coverage-matrix",
            "title": "Coverage matrix",
            "kind": "svg",
            "filename": "visuals/coverage-matrix.svg",
            "description": "Matriz visual de modulos agrupados por fase para comprobar cobertura y estados.",
            "svg": _coverage_svg(module_groups, fingerprint),
        },
    ]

    return {
        "version": "1.0",
        "generated_at": utc_now(),
        "summary": {
            "screenshot_count": len(screenshots),
            "technology_count": len(fingerprint["technologies"]),
            "module_group_count": len(module_groups),
            "risk_level": fingerprint["risk"]["level"],
            "risk_score": fingerprint["risk"]["score"],
        },
        "fingerprint": fingerprint,
        "ui_groups": module_groups,
        "screenshots": screenshots,
        "safety_notes": [
            "Visual snapshots are generated locally from passive scan evidence.",
            "No browser rendering, exploitation, brute force, fuzzing or form submission is performed to create these visuals.",
            "Sensitive values already redacted in the scan JSON remain redacted in visual evidence.",
        ],
    }


def write_visual_evidence(visual_evidence: dict[str, Any], output: Path, svg_dir: Path | None = None) -> Path:
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(visual_evidence, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    if svg_dir is not None:
        svg_dir.mkdir(parents=True, exist_ok=True)
        for screenshot in _dict_list(visual_evidence.get("screenshots")):
            filename = str(screenshot.get("filename") or f"{screenshot.get('id', 'visual')}.svg")
            target = svg_dir / Path(filename).name
            target.write_text(str(screenshot.get("svg") or ""), encoding="utf-8")
    return output


def _build_fingerprint(
    *,
    target: dict[str, Any],
    modules: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    inventory: dict[str, Any],
    entry_points: dict[str, Any],
    assessment: dict[str, Any],
    rule_evaluation: dict[str, Any],
    auth_profile: dict[str, Any],
) -> dict[str, Any]:
    inventory_summary = inventory.get("summary") if isinstance(inventory.get("summary"), dict) else {}
    entry_summary = entry_points.get("summary") if isinstance(entry_points.get("summary"), dict) else {}
    assessment_summary = assessment.get("summary") if isinstance(assessment.get("summary"), dict) else {}
    coverage = assessment_summary.get("coverage") if isinstance(assessment_summary.get("coverage"), dict) else {}
    rule_summary = rule_evaluation.get("summary") if isinstance(rule_evaluation.get("summary"), dict) else {}
    fingerprinting = _module_artifacts(modules, "fingerprinting")
    javascript = _module_artifacts(modules, "javascript")
    subdomains = _module_artifacts(modules, "subdomains")
    ports = _module_artifacts(modules, "ports")
    crawler = _module_artifacts(modules, "crawler")

    return {
        "target": {
            "url": _string(target.get("normalized_url") or target.get("original_url") or ""),
            "host": _string(target.get("host") or "unknown"),
            "scheme": _string(target.get("scheme") or "unknown"),
            "port": _int(target.get("port"), 0),
        },
        "auth_profile": {
            "id": _string(auth_profile.get("id") or "public"),
            "name": _string(auth_profile.get("name") or auth_profile.get("id") or "Public"),
            "authenticated": bool(auth_profile.get("authenticated")),
        },
        "risk": {
            "level": _string(assessment_summary.get("risk_level") or "informational"),
            "score": _int(assessment_summary.get("risk_score"), 0),
            "findings": len(findings),
            "severity_counts": _severity_counts(findings),
        },
        "surface": {
            "urls": _int(inventory_summary.get("total_urls"), 0),
            "visited_urls": _int(inventory_summary.get("fetched_urls"), 0),
            "interesting_urls": _int(inventory_summary.get("interesting_urls"), 0),
            "forms": _int(inventory_summary.get("forms"), 0),
            "entry_points": _int(entry_summary.get("total_endpoints"), 0),
            "parameters": _int(entry_summary.get("parameters"), 0),
            "javascript_endpoints": len(_dict_list(javascript.get("discovered_endpoints"))),
            "metadata_urls": len(_string_list(crawler.get("metadata_discovered_urls"))),
            "resolved_subdomains": _int(subdomains.get("resolved_count"), len(_dict_list(subdomains.get("resolved")))),
            "open_ports": _int(ports.get("open_count"), 0),
            "rules_matched": _int(rule_summary.get("rules_matched"), 0),
            "framework_controls": _int(rule_summary.get("framework_controls_matched"), 0),
            "modules_run": _int(coverage.get("modules_run"), len(modules)),
        },
        "technologies": _technologies(fingerprinting),
        "public_files": _public_files(fingerprinting),
    }


def _overview_svg(fingerprint: dict[str, Any]) -> str:
    target = fingerprint["target"]
    risk = fingerprint["risk"]
    surface = fingerprint["surface"]
    severity_counts = risk["severity_counts"]
    cards = [
        ("Critical", severity_counts["critical"], "#ef4444"),
        ("High", severity_counts["high"], "#f97316"),
        ("Medium", severity_counts["medium"], "#f59e0b"),
        ("Low", severity_counts["low"], "#3b82f6"),
        ("Info", severity_counts["info"], "#94a3b8"),
    ]
    metrics = [
        ("URLs", surface["urls"]),
        ("Forms", surface["forms"]),
        ("Entradas", surface["entry_points"]),
        ("Parametros", surface["parameters"]),
        ("JS endpoints", surface["javascript_endpoints"]),
        ("Reglas", surface["rules_matched"]),
    ]
    parts = _svg_shell("Audit overview")
    parts.extend(
        [
            _text(44, 72, "AI Web Auditor", 16, "#22c55e", 800),
            _text(44, 108, _shorten(target["url"] or target["host"], 72), 28, "#f8fafc", 800),
            _text(44, 140, f"{target['scheme']} | {target['host']}:{target['port']}", 15, "#94a3b8", 600),
            _pill(720, 56, 178, 44, f"{risk['level'].upper()} {risk['score']}/100", _risk_color(risk["level"])),
        ]
    )
    for index, (label, value, color) in enumerate(cards):
        x = 44 + index * 176
        parts.extend(_metric_card(x, 182, 156, 108, label, value, color))
    for index, (label, value) in enumerate(metrics):
        x = 44 + (index % 3) * 292
        y = 330 + (index // 3) * 82
        parts.extend(_compact_card(x, y, 260, 56, label, value))
    parts.append("</svg>")
    return "\n".join(parts)


def _fingerprint_svg(fingerprint: dict[str, Any]) -> str:
    surface = fingerprint["surface"]
    technologies = fingerprint["technologies"][:12]
    public_files = fingerprint["public_files"][:8]
    parts = _svg_shell("Fingerprint map")
    parts.extend(
        [
            _text(44, 72, "Fingerprint visual", 26, "#f8fafc", 800),
            _text(44, 104, "Tecnologias, metadatos publicos y superficie observada", 15, "#94a3b8", 600),
            _text(44, 154, "Tecnologias", 18, "#bbf7d0", 800),
        ]
    )
    if technologies:
        for index, technology in enumerate(technologies):
            x = 44 + (index % 3) * 286
            y = 176 + (index // 3) * 42
            label = _shorten(technology["label"], 28)
            parts.append(_pill(x, y, 250, 30, f"{label} | {technology['confidence']}", "#134e4a"))
    else:
        parts.append(_text(44, 184, "Sin tecnologias identificadas", 14, "#94a3b8", 600))

    parts.extend(
        [
            _text(44, 360, "Superficie", 18, "#bbf7d0", 800),
            *_compact_card(44, 384, 200, 56, "URLs", surface["urls"]),
            *_compact_card(260, 384, 200, 56, "Entradas", surface["entry_points"]),
            *_compact_card(476, 384, 200, 56, "Subdominios", surface["resolved_subdomains"]),
            *_compact_card(692, 384, 200, 56, "Puertos abiertos", surface["open_ports"]),
            _text(44, 474, "Metadatos publicos", 15, "#94a3b8", 700),
            _text(44, 500, _shorten(", ".join(item["path"] for item in public_files) or "Sin ficheros publicos presentes", 112), 14, "#e2e8f0", 600),
        ]
    )
    parts.append("</svg>")
    return "\n".join(parts)


def _coverage_svg(module_groups: list[dict[str, Any]], fingerprint: dict[str, Any]) -> str:
    parts = _svg_shell("Coverage matrix")
    parts.extend(
        [
            _text(44, 72, "Cobertura de enumeracion", 26, "#f8fafc", 800),
            _text(44, 104, "Modulos agrupados por flujo de trabajo y estado observado", 15, "#94a3b8", 600),
        ]
    )
    for group_index, group in enumerate(module_groups[:4]):
        x = 44 + (group_index % 2) * 438
        y = 146 + (group_index // 2) * 176
        parts.append(_rect(x, y, 394, 138, "#111827", "#274236"))
        parts.append(_text(x + 18, y + 32, group["label"], 18, "#bbf7d0", 800))
        for item_index, item in enumerate(_dict_list(group.get("modules"))[:4]):
            row_y = y + 58 + item_index * 20
            color = _status_color(item.get("status"))
            parts.append(_circle(x + 22, row_y - 4, 5, color))
            parts.append(_text(x + 36, row_y, _shorten(str(item.get("name") or "module"), 30), 13, "#e5edf5", 700))
            parts.append(_text(x + 250, row_y, _shorten(str(item.get("status") or "unknown"), 16), 13, "#94a3b8", 600))
        if len(_dict_list(group.get("modules"))) > 4:
            parts.append(_text(x + 36, y + 140, f"+{len(_dict_list(group.get('modules'))) - 4} mas", 12, "#94a3b8", 600))

    surface = fingerprint["surface"]
    parts.append(_text(44, 500, f"Modulos ejecutados: {surface['modules_run']} | Reglas OWASP: {surface['rules_matched']} | Controles: {surface['framework_controls']}", 14, "#94a3b8", 700))
    parts.append("</svg>")
    return "\n".join(parts)


def _module_groups(modules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    groups = [
        ("scope", "Alcance", ["scope"]),
        ("transport", "Transporte y plataforma", ["http", "security_headers", "cookies", "basic_auth", "http_methods", "tls"]),
        ("surface", "Superficie web", ["fingerprinting", "crawler", "javascript", "subdomains", "ports"]),
        ("evidence", "Evidencias y trazabilidad", ["passive-rules", "rules", "import", "external", "assessment"]),
    ]
    by_name = {str(module.get("name")): module for module in modules}
    output = []
    for group_id, label, names in groups:
        selected = []
        for name in names:
            module = by_name.get(name)
            if module:
                selected.append(
                    {
                        "name": str(module.get("name") or name),
                        "status": str(module.get("status") or "unknown"),
                        "summary": str(module.get("summary") or ""),
                    }
                )
        output.append({"id": group_id, "label": label, "modules": selected})
    ungrouped = [
        {
            "name": str(module.get("name") or "unknown"),
            "status": str(module.get("status") or "unknown"),
            "summary": str(module.get("summary") or ""),
        }
        for module in modules
        if str(module.get("name")) not in {name for _group_id, _label, names in groups for name in names}
    ]
    if ungrouped:
        output.append({"id": "other", "label": "Otros", "modules": ungrouped})
    return output


def _technologies(artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    technologies = []
    for item in _dict_list(artifacts.get("technologies")):
        name = _string(item.get("name") or "unknown")
        version = _string(item.get("version") or "")
        technologies.append(
            {
                "name": name,
                "version": version,
                "label": f"{name} {version}".strip(),
                "category": _string(item.get("category") or "unknown"),
                "confidence": _string(item.get("confidence") or "unknown"),
                "signals": _string_list(item.get("signals")),
            }
        )
    return technologies


def _public_files(artifacts: dict[str, Any]) -> list[dict[str, Any]]:
    output = []
    for item in _dict_list(artifacts.get("public_files")):
        if item.get("present") is False:
            continue
        output.append(
            {
                "path": _string(item.get("path") or ""),
                "status_code": _int(item.get("status_code", item.get("status")), 0),
                "present": bool(item.get("present", True)),
            }
        )
    return output


def _severity_counts(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for finding in findings:
        severity = str(finding.get("severity") or "info").lower()
        if severity == "informational":
            severity = "info"
        if severity not in counts:
            severity = "info"
        counts[severity] += 1
    return counts


def _svg_shell(title: str) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{SVG_WIDTH}" height="{SVG_HEIGHT}" viewBox="0 0 {SVG_WIDTH} {SVG_HEIGHT}" role="img" aria-label="{_attr(title)}">',
        '<rect width="960" height="540" fill="#020617"/>',
        '<rect x="20" y="20" width="920" height="500" rx="18" fill="#0b1220" stroke="#1f3d34"/>',
    ]


def _metric_card(x: int, y: int, width: int, height: int, label: str, value: Any, color: str) -> list[str]:
    return [
        _rect(x, y, width, height, "#111827", "#263244"),
        _text(x + 18, y + 34, label, 14, "#94a3b8", 700),
        _text(x + 18, y + 82, str(value), 34, color, 900),
    ]


def _compact_card(x: int, y: int, width: int, height: int, label: str, value: Any) -> list[str]:
    return [
        _rect(x, y, width, height, "#111827", "#263244"),
        _text(x + 14, y + 23, label, 12, "#94a3b8", 700),
        _text(x + 14, y + 46, str(value), 18, "#f8fafc", 800),
    ]


def _pill(x: int, y: int, width: int, height: int, text: str, color: str) -> str:
    return f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="14" fill="{color}"/>{_text(x + 14, y + 28, text, 14, "#f8fafc", 800)}'


def _rect(x: int, y: int, width: int, height: int, fill: str, stroke: str) -> str:
    return f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="12" fill="{fill}" stroke="{stroke}"/>'


def _circle(x: int, y: int, radius: int, fill: str) -> str:
    return f'<circle cx="{x}" cy="{y}" r="{radius}" fill="{fill}"/>'


def _text(x: int, y: int, text: str, size: int, fill: str, weight: int) -> str:
    return (
        f'<text x="{x}" y="{y}" fill="{fill}" font-family="Inter, Segoe UI, Arial, sans-serif" '
        f'font-size="{size}" font-weight="{weight}">{escape(str(text), quote=False)}</text>'
    )


def _risk_color(level: str) -> str:
    return {
        "critical": "#991b1b",
        "high": "#9a3412",
        "medium": "#92400e",
        "low": "#1d4ed8",
        "informational": "#334155",
        "info": "#334155",
    }.get(str(level).lower(), "#334155")


def _status_color(status: Any) -> str:
    return {
        "passed": "#22c55e",
        "warning": "#f59e0b",
        "error": "#ef4444",
        "skipped": "#94a3b8",
    }.get(str(status or "").lower(), "#64748b")


def _module_artifacts(modules: list[dict[str, Any]], name: str) -> dict[str, Any]:
    for module in modules:
        if module.get("name") == name and isinstance(module.get("artifacts"), dict):
            return module["artifacts"]
    return {}


def _dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _string_list(value: Any) -> list[str]:
    return [str(item) for item in value if item is not None] if isinstance(value, list) else []


def _string(value: Any) -> str:
    return str(value) if value is not None else ""


def _int(value: Any, default: int) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default


def _shorten(value: str, max_chars: int) -> str:
    text = str(value)
    if len(text) <= max_chars:
        return text
    return f"{text[: max_chars - 1]}..."


def _attr(value: str) -> str:
    return escape(str(value), quote=True)
