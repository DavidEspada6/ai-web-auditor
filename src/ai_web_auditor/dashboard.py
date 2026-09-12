from __future__ import annotations

import json
from typing import Any

from .models import utc_now


def build_audit_dashboard(scan_data: dict[str, Any], comparison: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build an operational dashboard from passive audit evidence."""

    enriched = _ensure_derived_sections(scan_data)
    modules = _dict_list(enriched.get("modules"))
    findings = _dict_list(enriched.get("findings"))
    inventory = _dict(enriched.get("inventory"))
    entry_points = _dict(enriched.get("entry_points"))
    assessment = _dict(enriched.get("assessment"))
    rule_evaluation = _dict(enriched.get("rule_evaluation"))
    visual_evidence = _dict(enriched.get("visual_evidence"))
    external_sources = _dict(enriched.get("external_sources"))

    coverage = _build_coverage(modules, inventory, entry_points, assessment, rule_evaluation, visual_evidence)
    risks = _build_risk_summary(findings, assessment)
    pending = _build_pending_items(modules, inventory, entry_points, assessment, rule_evaluation, external_sources, comparison)
    checklist = _build_checklist(modules, inventory, entry_points, assessment, rule_evaluation, visual_evidence)
    changes = _build_changes(comparison)
    checklist_summary = _checklist_summary(checklist)
    readiness = _readiness(risks, pending, checklist_summary)

    return {
        "version": "1.0",
        "generated_at": utc_now(),
        "summary": {
            "readiness": readiness,
            "risk_level": risks["risk_level"],
            "risk_score": risks["risk_score"],
            "coverage_score": coverage["score"],
            "pending_count": len(pending),
            "checklist_done": checklist_summary["done"],
            "checklist_total": checklist_summary["total"],
            "change_status": changes["status"],
        },
        "coverage": coverage,
        "risks": risks,
        "pending": pending,
        "checklist": checklist,
        "changes": changes,
        "safety_notes": [
            "Dashboard values are derived from passive evidence already present in the audit JSON.",
            "Pending items are triage guidance; they are not proof of exploitability.",
            "No additional requests, exploitation, fuzzing, brute force or form submission are performed to build this dashboard.",
        ],
    }


def render_dashboard_console(dashboard: dict[str, Any]) -> str:
    summary = _dict(dashboard.get("summary"))
    coverage = _dict(dashboard.get("coverage"))
    risks = _dict(dashboard.get("risks"))
    changes = _dict(dashboard.get("changes"))
    pending = _dict_list(dashboard.get("pending"))
    checklist = _dict_list(dashboard.get("checklist"))
    lines = [
        "Audit Dashboard",
        "---------------",
        f"Readiness: {summary.get('readiness', 'unknown')}",
        f"Risk: {summary.get('risk_level', 'unknown')} ({summary.get('risk_score', 0)}/100)",
        f"Coverage: {summary.get('coverage_score', coverage.get('score', 0))}%",
        f"Pending items: {summary.get('pending_count', len(pending))}",
        f"Checklist: {summary.get('checklist_done', 0)}/{summary.get('checklist_total', len(checklist))}",
        f"Changes: {changes.get('status', 'baseline_required')}",
    ]
    top_priorities = _dict_list(risks.get("top_priorities"))
    if top_priorities:
        lines.extend(["", "Top priorities"])
        for item in top_priorities[:5]:
            severity = str(item.get("severity") or "info").upper()
            lines.append(f"- {severity} {item.get('title', 'Untitled')}")
    if pending:
        lines.extend(["", "Pending"])
        for item in pending[:8]:
            severity = str(item.get("severity") or "info").upper()
            lines.append(f"- {severity} {item.get('title', 'Pending item')}: {item.get('next_step', '')}")
    return "\n".join(lines)


def dashboard_to_json(dashboard: dict[str, Any], indent: int = 2) -> str:
    return json.dumps(dashboard, indent=indent, ensure_ascii=True) + "\n"


def _ensure_derived_sections(scan_data: dict[str, Any]) -> dict[str, Any]:
    enriched = dict(scan_data)
    if not isinstance(enriched.get("inventory"), dict):
        from .inventory import build_inventory_from_scan

        enriched["inventory"] = build_inventory_from_scan(enriched)
    if not isinstance(enriched.get("entry_points"), dict):
        from .entrypoints import build_entry_points_from_scan

        enriched["entry_points"] = build_entry_points_from_scan(enriched)
    if not isinstance(enriched.get("rule_evaluation"), dict):
        from .rules import build_rule_evaluation

        enriched["rule_evaluation"] = build_rule_evaluation(enriched)
    if not isinstance(enriched.get("assessment"), dict):
        from .assessment import build_assessment

        enriched["assessment"] = build_assessment(enriched)
    if not isinstance(enriched.get("visual_evidence"), dict):
        from .visuals import build_visual_evidence

        enriched["visual_evidence"] = build_visual_evidence(enriched)
    return enriched


def _build_coverage(
    modules: list[dict[str, Any]],
    inventory: dict[str, Any],
    entry_points: dict[str, Any],
    assessment: dict[str, Any],
    rule_evaluation: dict[str, Any],
    visual_evidence: dict[str, Any],
) -> dict[str, Any]:
    module_names = {str(module.get("name")) for module in modules}
    assessment_summary = _dict(assessment.get("summary"))
    assessment_coverage = _dict(assessment_summary.get("coverage"))
    inventory_summary = _dict(inventory.get("summary"))
    entry_summary = _dict(entry_points.get("summary"))
    rule_summary = _dict(rule_evaluation.get("summary"))
    visual_summary = _dict(visual_evidence.get("summary"))
    metrics = [
        _metric("modules", "Modulos ejecutados", len(modules), 10, len(modules) >= 10),
        _metric("inventory", "URLs inventariadas", _int(inventory_summary.get("total_urls"), 0), 1, _int(inventory_summary.get("total_urls"), 0) > 0),
        _metric("entry_points", "Puntos de entrada", _int(entry_summary.get("total_endpoints"), 0), 1, _int(entry_summary.get("total_endpoints"), 0) > 0),
        _metric("javascript", "Endpoints JavaScript", _int(assessment_coverage.get("javascript_endpoints"), 0), 1, "javascript" in module_names),
        _metric("rules", "Reglas pasivas", _int(rule_summary.get("rules_matched"), 0), _int(rule_summary.get("rules_total"), 0), _int(rule_summary.get("rules_matched"), 0) > 0),
        _metric("controls", "Controles OWASP", _int(rule_summary.get("framework_controls_matched"), 0), 1, _int(rule_summary.get("framework_controls_matched"), 0) > 0),
        _metric("visuals", "Capturas visuales", _int(visual_summary.get("screenshot_count"), 0), 3, _int(visual_summary.get("screenshot_count"), 0) >= 3),
        _metric("subdomains", "Subdominios revisados", _int(assessment_coverage.get("subdomains"), 0), 1, "subdomains" in module_names),
        _metric("ports", "Puertos revisados", _int(assessment_coverage.get("open_ports"), 0), 1, "ports" in module_names),
    ]
    weighted = sum(metric["weight"] for metric in metrics if metric["status"] in {"done", "review"})
    total = sum(metric["weight"] for metric in metrics) or 1
    score = round((weighted / total) * 100)
    return {
        "score": score,
        "metrics": metrics,
        "notes": [
            "Subdominios y puertos se consideran cubiertos si el modulo se ejecuto, aunque no encuentre resultados.",
            "La cobertura mide enumeracion inicial, no profundidad de pruebas ofensivas.",
        ],
    }


def _build_risk_summary(findings: list[dict[str, Any]], assessment: dict[str, Any]) -> dict[str, Any]:
    summary = _dict(assessment.get("summary"))
    return {
        "risk_level": str(summary.get("risk_level") or "informational"),
        "risk_score": _int(summary.get("risk_score"), 0),
        "severity_counts": _severity_counts(findings),
        "top_priorities": _dict_list(assessment.get("priorities"))[:5],
        "quick_wins": _dict_list(assessment.get("quick_wins"))[:5],
    }


def _build_pending_items(
    modules: list[dict[str, Any]],
    inventory: dict[str, Any],
    entry_points: dict[str, Any],
    assessment: dict[str, Any],
    rule_evaluation: dict[str, Any],
    external_sources: dict[str, Any],
    comparison: dict[str, Any] | None,
) -> list[dict[str, Any]]:
    pending: list[dict[str, Any]] = []
    module_names = {str(module.get("name")) for module in modules}
    for module in modules:
        status = str(module.get("status") or "").lower()
        if status in {"warning", "error"}:
            pending.append(
                _pending(
                    f"module-{module.get('name', 'unknown')}",
                    f"Revisar modulo {module.get('name', 'unknown')}",
                    "high" if status == "error" else "medium",
                    str(module.get("summary") or "Modulo con advertencias."),
                    "Revisa la evidencia del modulo y decide si requiere validacion manual.",
                    "modules",
                )
            )

    entry_summary = _dict(entry_points.get("summary"))
    review_candidates = _int(entry_summary.get("review_candidates"), 0)
    if review_candidates:
        pending.append(
            _pending(
                "entry-points-review",
                "Priorizar puntos de entrada",
                "medium",
                f"{review_candidates} endpoint(s) necesitan revision manual.",
                "Abre la pestana Entradas y filtra login, admin, token, upload, POST o delete.",
                "entry_points",
            )
        )

    parameters = _dict_list(entry_points.get("parameters"))
    sensitive_parameters = [item for item in parameters if item.get("sensitive_hint")]
    if sensitive_parameters:
        pending.append(
            _pending(
                "sensitive-parameters",
                "Revisar parametros sensibles",
                "medium",
                f"{len(sensitive_parameters)} parametro(s) parecen sensibles por nombre.",
                "Confirma contexto y documenta si transportan tokens, sesiones, claves o datos personales.",
                "entry_points",
            )
        )

    rule_summary = _dict(rule_evaluation.get("summary"))
    unmapped = _int(rule_summary.get("findings_unmapped"), 0)
    if unmapped:
        pending.append(
            _pending(
                "unmapped-findings",
                "Mapear hallazgos sin control OWASP",
                "low",
                f"{unmapped} hallazgo(s) no tienen mapeo de regla pasiva.",
                "Revisa si necesitan regla nueva, mapeo manual o nota de limitacion.",
                "rules",
            )
        )

    external_summary = _dict(external_sources.get("summary"))
    if _int(external_summary.get("source_count"), 0):
        pending.append(
            _pending(
                "external-validation",
                "Validar importaciones externas",
                "medium",
                f"{external_summary.get('source_count')} fuente(s) externa(s) importadas.",
                "Marca que hallazgos vienen de otra herramienta y conserva su evidencia original.",
                "external_sources",
            )
        )

    if "subdomains" not in module_names:
        pending.append(
            _pending(
                "subdomains-not-run",
                "Decidir si entra reconocimiento de subdominios",
                "low",
                "El modulo de subdominios no se ejecuto.",
                "Activalo solo si el scope autoriza subdominios del dominio raiz.",
                "subdomains",
            )
        )

    if "ports" not in module_names:
        pending.append(
            _pending(
                "ports-not-run",
                "Decidir si entra chequeo de puertos",
                "low",
                "El modulo de puertos no se ejecuto.",
                "Activalo solo si el alcance permite conectividad TCP basica sobre el host objetivo.",
                "ports",
            )
        )

    if not comparison:
        pending.append(
            _pending(
                "baseline-comparison",
                "Comparar contra baseline",
                "info",
                "No hay comparacion asociada al dashboard.",
                "Cuando tengas dos auditorias guardadas, usa Comparar para ver nuevos, resueltos y persistentes.",
                "compare",
            )
        )

    priorities = _dict_list(assessment.get("priorities"))
    for priority in priorities[:3]:
        pending.append(
            _pending(
                f"priority-{priority.get('finding_id', priority.get('rank', 'item'))}",
                str(priority.get("title") or "Prioridad de remediacion"),
                str(priority.get("severity") or "medium"),
                str(priority.get("reason") or "Prioridad derivada de la valoracion determinista."),
                str(priority.get("recommended_action") or "Revisar evidencia y documentar decision."),
                "assessment",
            )
        )

    return _deduplicate_pending(pending)


def _build_checklist(
    modules: list[dict[str, Any]],
    inventory: dict[str, Any],
    entry_points: dict[str, Any],
    assessment: dict[str, Any],
    rule_evaluation: dict[str, Any],
    visual_evidence: dict[str, Any],
) -> list[dict[str, Any]]:
    module_names = {str(module.get("name")) for module in modules}
    inventory_summary = _dict(inventory.get("summary"))
    entry_summary = _dict(entry_points.get("summary"))
    assessment_summary = _dict(assessment.get("summary"))
    coverage = _dict(assessment_summary.get("coverage"))
    rule_summary = _dict(rule_evaluation.get("summary"))
    visual_summary = _dict(visual_evidence.get("summary"))
    return [
        _check("scope", "Alcance", "Scope validado", "scope" in module_names, "El objetivo entra en hosts/rutas autorizadas."),
        _check("profile", "Alcance", "Perfil documentado", True, "Perfil anonimo/autenticado incluido en JSON."),
        _check("http", "Transporte", "HTTP y redirecciones revisadas", "http" in module_names, "Estado, URL final y cadena de redireccion revisados."),
        _check("tls", "Transporte", "TLS basico revisado", "tls" in module_names, "Certificado y datos basicos TLS si aplica."),
        _check("headers", "Transporte", "Cabeceras defensivas revisadas", "security_headers" in module_names, "HSTS, CSP, X-Frame-Options y politicas de navegador."),
        _check("cookies", "Transporte", "Cookies revisadas", "cookies" in module_names, "Secure, HttpOnly y SameSite."),
        _check("fingerprint", "Superficie", "Fingerprinting ejecutado", "fingerprinting" in module_names, "Tecnologias y ficheros publicos."),
        _check("crawler", "Superficie", "Crawler seguro ejecutado", "crawler" in module_names, "Enlaces, robots, sitemap y rutas relevantes."),
        _check("inventory", "Superficie", "Inventario generado", _int(inventory_summary.get("total_urls"), 0) > 0, "URLs normalizadas y clasificadas."),
        _check("entrypoints", "Superficie", "Puntos de entrada generados", _int(entry_summary.get("total_endpoints"), 0) > 0, "Endpoints, parametros, formularios y metodos."),
        _check("javascript", "Superficie", "JavaScript revisado", "javascript" in module_names, "Scripts y referencias a endpoints."),
        _check("subdomains", "Recon", "Subdominios considerados", "subdomains" in module_names, "DNS seguro si el scope lo permite.", optional=True),
        _check("ports", "Recon", "Puertos considerados", "ports" in module_names, "TCP connect limitado si el scope lo permite.", optional=True),
        _check("rules", "Trazabilidad", "Reglas OWASP calculadas", _int(rule_summary.get("rules_total"), 0) > 0, "Mapeo WSTG/ASVS."),
        _check("assessment", "Trazabilidad", "Valoracion de riesgo generada", bool(assessment_summary), "Riesgo, prioridades, quick wins y plan."),
        _check("visuals", "Entregables", "Evidencia visual generada", _int(visual_summary.get("screenshot_count"), 0) >= 3, "Capturas SVG de resumen, fingerprint y cobertura."),
        _check("report", "Entregables", "Informe preparado", False, "Genera Markdown/HTML/PDF desde la pestana Informe.", status_if_false="pending"),
        _check("compare", "Seguimiento", "Comparacion realizada", False, "Compara contra baseline cuando exista una segunda ejecucion.", status_if_false="pending"),
        _check(
            "open-ports-review",
            "Seguimiento",
            "Puertos abiertos revisados",
            _int(coverage.get("open_ports"), 0) == 0,
            "Si hay puertos abiertos, documenta si pertenecen al alcance.",
            status_if_false="review",
        ),
    ]


def _build_changes(comparison: dict[str, Any] | None) -> dict[str, Any]:
    if not comparison:
        return {
            "status": "baseline_required",
            "summary": {"new": 0, "resolved": 0, "persistent": 0, "severity_changed": 0},
            "notes": ["No hay comparacion asociada. Usa una auditoria anterior como baseline cuando exista."],
        }
    summary = _dict(comparison.get("summary"))
    notes = [
        f"Nuevos: {_int(summary.get('new'), 0)}",
        f"Resueltos: {_int(summary.get('resolved'), 0)}",
        f"Persistentes: {_int(summary.get('persistent'), 0)}",
        f"Cambio de severidad: {_int(summary.get('severity_changed'), 0)}",
    ]
    return {
        "status": "compared",
        "summary": {
            "new": _int(summary.get("new"), 0),
            "resolved": _int(summary.get("resolved"), 0),
            "persistent": _int(summary.get("persistent"), 0),
            "severity_changed": _int(summary.get("severity_changed"), 0),
        },
        "notes": notes,
    }


def _checklist_summary(checklist: list[dict[str, Any]]) -> dict[str, int]:
    total = len(checklist)
    done = sum(1 for item in checklist if item.get("status") == "done")
    review = sum(1 for item in checklist if item.get("status") == "review")
    pending = sum(1 for item in checklist if item.get("status") == "pending")
    return {"total": total, "done": done, "review": review, "pending": pending}


def _readiness(risks: dict[str, Any], pending: list[dict[str, Any]], checklist_summary: dict[str, int]) -> str:
    severity_counts = _dict(risks.get("severity_counts"))
    if _int(severity_counts.get("critical"), 0):
        return "critical_review"
    if any(item.get("severity") in {"high", "critical"} for item in pending):
        return "needs_attention"
    if checklist_summary["pending"] > 2:
        return "in_progress"
    if pending:
        return "ready_with_notes"
    return "ready_for_report"


def _metric(metric_id: str, label: str, value: int, target: int, done: bool, *, weight: int = 1) -> dict[str, Any]:
    if done:
        status = "done"
    elif value:
        status = "review"
    else:
        status = "pending"
    return {"id": metric_id, "label": label, "value": value, "target": target, "status": status, "weight": weight}


def _pending(item_id: str, title: str, severity: str, reason: str, next_step: str, source: str) -> dict[str, str]:
    normalized = str(severity or "info").lower()
    if normalized == "informational":
        normalized = "info"
    if normalized not in {"critical", "high", "medium", "low", "info"}:
        normalized = "info"
    return {
        "id": item_id,
        "title": title,
        "severity": normalized,
        "reason": reason,
        "next_step": next_step,
        "source": source,
    }


def _deduplicate_pending(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in items:
        key = item.get("id")
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    return sorted(output, key=lambda item: (severity_rank.get(str(item.get("severity")), 99), str(item.get("id"))))


def _check(
    item_id: str,
    group: str,
    label: str,
    done: bool,
    evidence: str,
    *,
    optional: bool = False,
    status_if_false: str = "review",
) -> dict[str, str]:
    status = "done" if done else ("optional" if optional else status_if_false)
    return {"id": item_id, "group": group, "label": label, "status": status, "evidence": evidence}


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


def _dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _dict_list(value: Any) -> list[dict[str, Any]]:
    return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []


def _int(value: Any, default: int) -> int:
    try:
        if value is None or value == "":
            return default
        return int(value)
    except (TypeError, ValueError):
        return default
