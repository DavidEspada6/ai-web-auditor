from __future__ import annotations

import csv
import hashlib
import json
import re
from copy import deepcopy
from html import unescape
from io import StringIO
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit
from xml.etree import ElementTree as ET

from . import __version__
from .assessment import build_assessment
from .entrypoints import build_entry_points_from_scan
from .evidence import sanitize_scan_data, sanitize_url
from .inventory import build_inventory_from_scan
from .models import utc_now
from .rules import build_rule_evaluation
from .scope import normalize_target


SUPPORTED_IMPORT_FORMATS = ("auto", "zap-json", "burp-xml", "nmap-xml", "url-list", "csv", "generic-json")
HTML_TAG_RE = re.compile(r"<[^>]+>")


def import_external_file(
    path: Path,
    *,
    source_format: str = "auto",
    target: str = "",
    merge_scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    content = path.read_text(encoding="utf-8", errors="replace")
    return import_external_text(
        content,
        filename=str(path),
        source_format=source_format,
        target=target,
        merge_scan=merge_scan,
    )


def import_external_text(
    content: str,
    *,
    filename: str = "",
    source_format: str = "auto",
    target: str = "",
    merge_scan: dict[str, Any] | None = None,
) -> dict[str, Any]:
    detected_format = detect_import_format(content, filename=filename, requested_format=source_format)
    imported = _parse_content(content, filename=filename, source_format=detected_format, target=target)
    if merge_scan:
        imported = merge_external_scan(merge_scan, imported)
    return _enrich_scan(imported)


def detect_import_format(content: str, *, filename: str = "", requested_format: str = "auto") -> str:
    requested = _clean(requested_format).lower() or "auto"
    if requested not in SUPPORTED_IMPORT_FORMATS:
        raise ValueError(f"Unsupported import format: {requested_format}")
    if requested != "auto":
        return requested

    suffix = Path(filename).suffix.lower()
    stripped = content.lstrip("\ufeff\r\n\t ")
    if suffix == ".csv":
        return "csv"
    if stripped.startswith("{") or stripped.startswith("["):
        data = _json_loads(content)
        if _looks_like_zap_json(data):
            return "zap-json"
        return "generic-json"
    if stripped.startswith("<"):
        root = _xml_root(content)
        root_name = _local_name(root.tag).lower()
        if root_name == "nmaprun":
            return "nmap-xml"
        if root_name in {"issues", "issue"}:
            return "burp-xml"
        raise ValueError(f"Unsupported XML import root: {root_name}")
    if _looks_like_csv(content):
        return "csv"
    return "url-list"


def merge_external_scan(base_scan: dict[str, Any], imported_scan: dict[str, Any]) -> dict[str, Any]:
    merged = deepcopy(base_scan)
    merged["status"] = "completed"
    merged["generated_at"] = utc_now()
    merged["version"] = __version__
    merged["findings"] = _dedupe_findings(_dict_list(merged.get("findings")) + _dict_list(imported_scan.get("findings")))
    merged["modules"] = _merge_modules(_dict_list(merged.get("modules")), _dict_list(imported_scan.get("modules")))
    merged["external_sources"] = _merge_external_sources(merged.get("external_sources"), imported_scan.get("external_sources"))
    for key in ("inventory", "entry_points", "rule_evaluation", "assessment"):
        merged.pop(key, None)
    return merged


def render_import_console(scan_data: dict[str, Any]) -> str:
    external_sources = scan_data.get("external_sources") if isinstance(scan_data.get("external_sources"), dict) else {}
    summary = external_sources.get("summary") if isinstance(external_sources.get("summary"), dict) else {}
    return (
        f"Imported sources: {_int(summary.get('source_count'), 0)} | "
        f"Findings: {_int(summary.get('finding_count'), 0)} | "
        f"URLs: {_int(summary.get('url_count'), 0)} | "
        f"Open ports: {_int(summary.get('open_port_count'), 0)}"
    )


def _parse_content(content: str, *, filename: str, source_format: str, target: str) -> dict[str, Any]:
    if source_format == "zap-json":
        parsed = _parse_zap_json(content)
    elif source_format == "burp-xml":
        parsed = _parse_burp_xml(content)
    elif source_format == "nmap-xml":
        parsed = _parse_nmap_xml(content)
    elif source_format == "url-list":
        parsed = _parse_url_list(content)
    elif source_format == "csv":
        parsed = _parse_csv(content)
    elif source_format == "generic-json":
        parsed = _parse_generic_json(content)
    else:
        raise ValueError(f"Unsupported import format: {source_format}")

    return _scan_from_import(parsed, filename=filename, source_format=source_format, target=target)


def _parse_zap_json(content: str) -> dict[str, Any]:
    data = _json_loads(content)
    sites = _list(data.get("site")) if isinstance(data, dict) else []
    alerts = _list(data.get("alerts")) if isinstance(data, dict) else []
    findings: list[dict[str, Any]] = []
    urls: list[dict[str, Any]] = []

    for site in sites:
        if not isinstance(site, dict):
            continue
        site_url = _clean(site.get("@name") or site.get("name") or site.get("site"))
        if site_url:
            urls.append(_url_record(site_url, source="zap_site"))
        alerts.extend(_dict_list(site.get("alerts")))

    for alert in _dict_list(alerts):
        instances = _dict_list(alert.get("instances"))
        targets = [_clean(item.get("uri") or item.get("url")) for item in instances]
        target = next((item for item in targets if item), _clean(alert.get("url") or alert.get("uri")))
        if not target and sites:
            target = _clean(sites[0].get("@name") if isinstance(sites[0], dict) else "")
        if target:
            urls.append(_url_record(target, source="zap_alert"))
        for item in instances:
            uri = _clean(item.get("uri") or item.get("url"))
            if uri:
                urls.append(_url_record(uri, source="zap_instance", method=_clean(item.get("method")).upper()))

        name = _clean(alert.get("alert") or alert.get("name"), "ZAP alert")
        plugin_id = _clean(alert.get("pluginid") or alert.get("alertRef") or alert.get("id"))
        severity = _severity(alert.get("riskdesc") or alert.get("risk") or alert.get("riskcode"))
        finding_id = _known_finding_id(name, tool="zap", target=target) or _external_id("ZAP", plugin_id or name)
        evidence = [
            _evidence("source_tool", "OWASP ZAP"),
            _evidence("external_id", plugin_id or "unknown"),
            _evidence("confidence", alert.get("confidence")),
            _evidence("cwe", alert.get("cweid")),
            _evidence("wasc", alert.get("wascid")),
        ]
        for item in instances[:3]:
            if item.get("param"):
                evidence.append(_evidence("parameter", item.get("param"), item.get("uri")))
            if item.get("evidence"):
                evidence.append(_evidence("evidence", item.get("evidence"), item.get("uri")))

        findings.append(
            _finding(
                finding_id=finding_id,
                title=name,
                severity=severity,
                category=_category(name, default="external-zap"),
                description=_clean_html(alert.get("desc") or alert.get("description") or alert.get("otherinfo")),
                recommendation=_clean_html(alert.get("solution")),
                target=target,
                evidence=evidence,
                source_tool="zap",
            )
        )

    return {"tool": "zap", "findings": findings, "urls": urls, "ports": []}


def _parse_burp_xml(content: str) -> dict[str, Any]:
    root = _xml_root(content)
    issues = [root] if _local_name(root.tag).lower() == "issue" else [
        item for item in root.iter() if _local_name(item.tag).lower() == "issue"
    ]
    findings: list[dict[str, Any]] = []
    urls: list[dict[str, Any]] = []

    for issue in issues:
        name = _child_text(issue, "name") or "Burp issue"
        issue_type = _child_text(issue, "type")
        severity = _severity(_child_text(issue, "severity"))
        confidence = _child_text(issue, "confidence")
        host = _child_text(issue, "host")
        path = _child_text(issue, "path")
        location = _child_text(issue, "location")
        target = _burp_issue_url(host, path, location)
        if target:
            urls.append(_url_record(target, source="burp_issue"))

        finding_id = _known_finding_id(name, tool="burp", target=target) or _external_id("BURP", issue_type or name)
        description = "\n\n".join(
            item
            for item in [
                _clean_html(_child_text(issue, "issueBackground")),
                _clean_html(_child_text(issue, "issueDetail")),
            ]
            if item
        )
        recommendation = "\n\n".join(
            item
            for item in [
                _clean_html(_child_text(issue, "remediationBackground")),
                _clean_html(_child_text(issue, "remediationDetail")),
            ]
            if item
        )
        evidence = [
            _evidence("source_tool", "Burp Suite"),
            _evidence("external_id", issue_type or "unknown"),
            _evidence("serial", _child_text(issue, "serialNumber")),
            _evidence("confidence", confidence),
            _evidence("location", location or target),
        ]
        findings.append(
            _finding(
                finding_id=finding_id,
                title=name,
                severity=severity,
                category=_category(name, default="external-burp"),
                description=description,
                recommendation=recommendation,
                target=target,
                evidence=evidence,
                source_tool="burp",
            )
        )

    return {"tool": "burp", "findings": findings, "urls": urls, "ports": []}


def _parse_nmap_xml(content: str) -> dict[str, Any]:
    root = _xml_root(content)
    if _local_name(root.tag).lower() != "nmaprun":
        raise ValueError("Nmap XML import must use a nmaprun root element")

    ports: list[dict[str, Any]] = []
    urls: list[dict[str, Any]] = []
    for host in [item for item in root.iter() if _local_name(item.tag).lower() == "host"]:
        addresses = [
            _clean(item.attrib.get("addr"))
            for item in _children(host, "address")
            if item.attrib.get("addrtype") in {"ipv4", "ipv6", "mac", None}
        ]
        hostnames = [_clean(item.attrib.get("name")) for item in host.iter() if _local_name(item.tag).lower() == "hostname"]
        host_label = next((item for item in hostnames if item), next((item for item in addresses if item), "unknown"))
        for port in [item for item in host.iter() if _local_name(item.tag).lower() == "port"]:
            state_node = _first_child(port, "state")
            service_node = _first_child(port, "service")
            status = _clean(state_node.attrib.get("state") if state_node is not None else "unknown", "unknown")
            service = _clean(service_node.attrib.get("name") if service_node is not None else "", "unknown")
            row = {
                "host": host_label,
                "addresses": [item for item in addresses if item],
                "port": _int(port.attrib.get("portid"), 0),
                "protocol": _clean(port.attrib.get("protocol"), "tcp"),
                "status": status,
                "service": service,
                "product": _clean(service_node.attrib.get("product") if service_node is not None else ""),
                "version": _clean(service_node.attrib.get("version") if service_node is not None else ""),
                "extra": _clean(service_node.attrib.get("extrainfo") if service_node is not None else ""),
                "source": "nmap_xml_import",
            }
            ports.append(row)
            if status == "open" and row["port"] in {80, 443, 8080, 8443, 8000, 3000, 5000, 9000}:
                scheme = "https" if row["port"] in {443, 8443} else "http"
                port_suffix = "" if row["port"] in {80, 443} else f":{row['port']}"
                urls.append(_url_record(f"{scheme}://{host_label}{port_suffix}/", source="nmap_open_port"))

    findings = []
    open_ports = [item for item in ports if item.get("status") == "open"]
    if open_ports:
        findings.append(
            _finding(
                finding_id="PORTS-OPEN-TCP-PORTS",
                title="Open TCP ports imported from Nmap XML",
                severity="info",
                category="infrastructure",
                description="An external Nmap XML file reported open TCP ports. This importer only reads existing results; it does not run a port scan.",
                recommendation="Confirm whether each open port is expected and in scope before using it to expand testing.",
                target=_clean(open_ports[0].get("host"), "unknown"),
                evidence=[
                    _evidence("source_tool", "Nmap"),
                    _evidence("open_ports", ", ".join(f"{item.get('host')}:{item.get('port')}" for item in open_ports[:15])),
                ],
                source_tool="nmap",
            )
        )
    return {"tool": "nmap", "findings": findings, "urls": urls, "ports": ports}


def _parse_url_list(content: str) -> dict[str, Any]:
    urls = []
    for line in content.splitlines():
        value = line.strip()
        if not value or value.startswith("#"):
            continue
        candidate = value.split()[0]
        if _is_url(candidate):
            urls.append(_url_record(candidate, source="url_list"))
    return {"tool": "url-list", "findings": [], "urls": urls, "ports": []}


def _parse_csv(content: str) -> dict[str, Any]:
    sample = content.lstrip("\ufeff")
    rows = list(csv.DictReader(StringIO(sample)))
    if not rows:
        return _parse_url_list(content)
    urls = []
    findings = []
    for row in rows:
        normalized = {_clean(key).strip().lower(): value for key, value in row.items() if key is not None}
        url = _first_value(normalized, "url", "uri", "request_url", "target", "endpoint", "path")
        if url:
            urls.append(
                _url_record(
                    url,
                    source="csv_import",
                    method=_first_value(normalized, "method", "http_method"),
                    status_code=_optional_int(_first_value(normalized, "status", "status_code", "code")),
                    content_type=_first_value(normalized, "content_type", "mime", "mime_type"),
                )
            )
        name = _first_value(normalized, "finding", "issue", "alert", "name", "title")
        severity = _first_value(normalized, "severity", "risk", "level")
        if name and severity:
            target = url or _first_value(normalized, "host", "asset")
            findings.append(
                _finding(
                    finding_id=_known_finding_id(name, tool="csv", target=target) or _external_id("CSV", name),
                    title=name,
                    severity=_severity(severity),
                    category=_first_value(normalized, "category", "type") or _category(name, default="external-csv"),
                    description=_first_value(normalized, "description", "desc", "details"),
                    recommendation=_first_value(normalized, "recommendation", "solution", "remediation"),
                    target=target,
                    evidence=[_evidence("source_tool", "CSV import"), _evidence("confidence", _first_value(normalized, "confidence"))],
                    source_tool="csv",
                )
            )
    return {"tool": "csv", "findings": findings, "urls": urls, "ports": []}


def _parse_generic_json(content: str) -> dict[str, Any]:
    data = _json_loads(content)
    containers = [data] if isinstance(data, dict) else []
    if isinstance(data, list):
        containers = [{"items": data}]

    findings = []
    urls = []
    for container in containers:
        for item in _dict_list(container.get("findings")) + _dict_list(container.get("issues")) + _dict_list(container.get("alerts")) + _dict_list(container.get("items")):
            url = _clean(item.get("url") or item.get("uri") or item.get("target") or item.get("endpoint"))
            if url and _is_url(url):
                urls.append(_url_record(url, source="generic_json"))
            name = _clean(item.get("title") or item.get("name") or item.get("alert") or item.get("issue"))
            severity = _clean(item.get("severity") or item.get("risk") or item.get("level"))
            if name and severity:
                findings.append(
                    _finding(
                        finding_id=_known_finding_id(name, tool="generic", target=url) or _external_id("GENERIC", item.get("id") or name),
                        title=name,
                        severity=_severity(severity),
                        category=_clean(item.get("category") or item.get("type"), _category(name, default="external-generic")),
                        description=_clean(item.get("description") or item.get("desc") or item.get("detail")),
                        recommendation=_clean(item.get("recommendation") or item.get("solution") or item.get("remediation")),
                        target=url,
                        evidence=[_evidence("source_tool", "Generic JSON"), _evidence("external_id", item.get("id"))],
                        source_tool="generic-json",
                    )
                )
    return {"tool": "generic-json", "findings": findings, "urls": urls, "ports": []}


def _scan_from_import(parsed: dict[str, Any], *, filename: str, source_format: str, target: str) -> dict[str, Any]:
    urls = _dedupe_urls(_dict_list(parsed.get("urls")))
    ports = _dict_list(parsed.get("ports"))
    findings = _dedupe_findings(_dict_list(parsed.get("findings")))
    target_model = _target_from_import(target, urls, ports)
    import_source = {
        "filename": Path(filename).name if filename else "uploaded-content",
        "source_format": source_format,
        "source_tool": _clean(parsed.get("tool"), source_format),
        "imported_at": utc_now(),
        "finding_count": len(findings),
        "url_count": len(urls),
        "port_count": len(ports),
        "open_port_count": sum(1 for item in ports if item.get("status") == "open"),
        "notes": [
            "Import reads an existing external file and does not contact the target.",
            "Full raw HTTP requests and responses from external reports are intentionally not preserved.",
        ],
    }
    modules = [
        {
            "name": "external_import",
            "status": "passed",
            "summary": f"Imported {len(findings)} finding(s), {len(urls)} URL(s) and {len(ports)} port result(s) from {source_format}.",
            "findings": [],
            "artifacts": {
                "sources": [import_source],
                "imported_urls": urls,
                "imported_findings": findings,
            },
        }
    ]
    if ports:
        modules.append(_ports_module_from_import(ports))

    return {
        "tool": "ai-web-auditor",
        "version": __version__,
        "generated_at": utc_now(),
        "status": "imported",
        "target": target_model.__dict__,
        "modules": modules,
        "findings": findings,
        "requests": [],
        "external_sources": _external_sources([import_source]),
    }


def _enrich_scan(scan_data: dict[str, Any]) -> dict[str, Any]:
    data = deepcopy(scan_data)
    data["inventory"] = build_inventory_from_scan(data)
    data["entry_points"] = build_entry_points_from_scan(data)
    data["rule_evaluation"] = build_rule_evaluation(data)
    data["assessment"] = build_assessment(data)
    return sanitize_scan_data(data)


def _ports_module_from_import(ports: list[dict[str, Any]]) -> dict[str, Any]:
    status_counts: dict[str, int] = {}
    for item in ports:
        status = _clean(item.get("status"), "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    open_count = status_counts.get("open", 0)
    return {
        "name": "ports",
        "status": "warning" if open_count else "passed",
        "summary": f"Imported {len(ports)} TCP port result(s), {open_count} open.",
        "findings": [],
        "artifacts": {
            "host": _clean(ports[0].get("host"), "unknown") if ports else "unknown",
            "source": "external_import",
            "ports_checked": [item.get("port") for item in ports if item.get("port")],
            "open_count": open_count,
            "closed_count": status_counts.get("closed", 0),
            "filtered_count": status_counts.get("filtered", 0),
            "error_count": status_counts.get("error", 0),
            "results": ports,
        },
    }


def _merge_modules(base_modules: list[dict[str, Any]], imported_modules: list[dict[str, Any]]) -> list[dict[str, Any]]:
    output = deepcopy(base_modules)
    for module in imported_modules:
        if module.get("name") == "ports":
            existing = next((item for item in output if item.get("name") == "ports" and isinstance(item.get("artifacts"), dict)), None)
            if existing:
                existing["artifacts"] = _merge_ports_artifacts(existing["artifacts"], module.get("artifacts") if isinstance(module.get("artifacts"), dict) else {})
                existing["status"] = "warning" if existing["artifacts"].get("open_count") else existing.get("status", "passed")
                existing["summary"] = f"Checked/imported {len(existing['artifacts'].get('results', []))} TCP port result(s), {existing['artifacts'].get('open_count', 0)} open."
            else:
                output.append(deepcopy(module))
            continue
        if module.get("name") == "external_import":
            existing = next((item for item in output if item.get("name") == "external_import" and isinstance(item.get("artifacts"), dict)), None)
            if existing:
                _merge_external_import_artifacts(existing["artifacts"], module.get("artifacts") if isinstance(module.get("artifacts"), dict) else {})
                sources = _dict_list(existing["artifacts"].get("sources"))
                urls = _dict_list(existing["artifacts"].get("imported_urls"))
                findings = _dict_list(existing["artifacts"].get("imported_findings"))
                existing["summary"] = f"Imported {len(findings)} finding(s) and {len(urls)} URL(s) from {len(sources)} source file(s)."
            else:
                output.append(deepcopy(module))
            continue
        output.append(deepcopy(module))
    return output


def _merge_external_import_artifacts(base: dict[str, Any], imported: dict[str, Any]) -> None:
    base["sources"] = _dict_list(base.get("sources")) + _dict_list(imported.get("sources"))
    base["imported_urls"] = _dedupe_urls(_dict_list(base.get("imported_urls")) + _dict_list(imported.get("imported_urls")))
    base["imported_findings"] = _dedupe_findings(_dict_list(base.get("imported_findings")) + _dict_list(imported.get("imported_findings")))


def _merge_ports_artifacts(base: dict[str, Any], imported: dict[str, Any]) -> dict[str, Any]:
    results = _dedupe_ports(_dict_list(base.get("results")) + _dict_list(imported.get("results")))
    status_counts: dict[str, int] = {}
    for item in results:
        status = _clean(item.get("status"), "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    output = dict(base)
    output["results"] = results
    output["ports_checked"] = sorted({item.get("port") for item in results if item.get("port")})
    output["open_count"] = status_counts.get("open", 0)
    output["closed_count"] = status_counts.get("closed", 0)
    output["filtered_count"] = status_counts.get("filtered", 0)
    output["error_count"] = status_counts.get("error", 0)
    return output


def _merge_external_sources(base: Any, imported: Any) -> dict[str, Any]:
    sources = []
    if isinstance(base, dict):
        sources.extend(_dict_list(base.get("sources")))
    if isinstance(imported, dict):
        sources.extend(_dict_list(imported.get("sources")))
    return _external_sources(sources)


def _external_sources(sources: list[dict[str, Any]]) -> dict[str, Any]:
    source_count = len(sources)
    return {
        "summary": {
            "source_count": source_count,
            "finding_count": sum(_int(item.get("finding_count"), 0) for item in sources),
            "url_count": sum(_int(item.get("url_count"), 0) for item in sources),
            "port_count": sum(_int(item.get("port_count"), 0) for item in sources),
            "open_port_count": sum(_int(item.get("open_port_count"), 0) for item in sources),
            "formats": sorted({_clean(item.get("source_format")) for item in sources if _clean(item.get("source_format"))}),
            "tools": sorted({_clean(item.get("source_tool")) for item in sources if _clean(item.get("source_tool"))}),
        },
        "sources": sources,
        "safety_notes": [
            "Imported files are parsed locally; importing does not contact targets.",
            "Raw external HTTP request/response bodies are not retained by the importer.",
            "Imported scanner findings should be reviewed for scope, confidence and false positives.",
        ],
    }


def _target_from_import(target: str, urls: list[dict[str, Any]], ports: list[dict[str, Any]]):
    candidates = []
    if target:
        candidates.append(target)
    candidates.extend(_clean(item.get("url")) for item in urls)
    for item in ports:
        host = _clean(item.get("host"))
        port = _int(item.get("port"), 0)
        if host:
            scheme = "https" if port in {443, 8443} else "http"
            port_suffix = "" if port in {80, 443, 0} else f":{port}"
            candidates.append(f"{scheme}://{host}{port_suffix}/")
    for candidate in candidates:
        if not candidate:
            continue
        try:
            return normalize_target(candidate)
        except Exception:
            continue
    return normalize_target("https://imported.local/")


def _url_record(
    url: str,
    *,
    source: str,
    method: str = "",
    status_code: int | None = None,
    content_type: str = "",
) -> dict[str, Any]:
    return {
        "url": sanitize_url(_clean(url)),
        "source": source,
        "method": _clean(method).upper(),
        "status_code": status_code,
        "content_type": _clean(content_type),
    }


def _finding(
    *,
    finding_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    recommendation: str,
    target: str,
    evidence: list[dict[str, Any]],
    source_tool: str,
) -> dict[str, Any]:
    safe_target = sanitize_url(target) if target else "unknown"
    return {
        "id": finding_id,
        "title": _clean(title, "Imported finding"),
        "severity": _severity(severity),
        "category": _clean(category, f"external-{source_tool}"),
        "description": _clean(description, "Imported external finding. Review the original tool output before reporting."),
        "recommendation": _clean(recommendation, "Validate scope, confidence and remediation guidance before final reporting."),
        "module": "external_import",
        "target": safe_target,
        "evidence": [item for item in evidence if item.get("value")],
        "source": {
            "type": "external_import",
            "tool": source_tool,
            "validation_required": True,
        },
    }


def _known_finding_id(name: str, *, tool: str, target: str = "") -> str:
    lowered = name.lower()
    target_scheme = urlsplit(target).scheme.lower()
    if "basic" in lowered and "auth" in lowered:
        return "AUTH-BASIC-OVER-HTTP" if target_scheme == "http" else "AUTH-BASIC-DETECTED"
    if ("content security policy" in lowered or "csp" in lowered) and any(term in lowered for term in ["missing", "not set", "absent"]):
        return "HEADER-CONTENT_SECURITY_POLICY-MISSING"
    if ("x-frame-options" in lowered or "clickjack" in lowered) and any(term in lowered for term in ["missing", "not set", "absent"]):
        return "HEADER-CLICKJACKING-MISSING"
    if ("x-content-type-options" in lowered or "nosniff" in lowered) and any(term in lowered for term in ["missing", "not set", "absent"]):
        return "HEADER-NOSNIFF-MISSING"
    if ("strict-transport-security" in lowered or "hsts" in lowered) and any(term in lowered for term in ["missing", "not set", "absent"]):
        return "HEADER-STRICT_TRANSPORT_SECURITY-MISSING"
    if "cookie" in lowered and "httponly" in lowered:
        return "COOKIE-HTTPONLY-MISSING"
    if "cookie" in lowered and "secure" in lowered:
        return "COOKIE-SECURE-MISSING"
    if "cookie" in lowered and "samesite" in lowered:
        return "COOKIE-SAMESITE-MISSING"
    if "trace" in lowered and "method" in lowered:
        return "METHOD-TRACE-ADVERTISED"
    if "x-powered-by" in lowered:
        return "FINGERPRINT-POWERED-BY-DISCLOSED"
    if "server" in lowered and "version" in lowered:
        return "FINGERPRINT-SERVER-VERSION-DISCLOSED"
    return ""


def _category(name: str, *, default: str) -> str:
    lowered = name.lower()
    if any(marker in lowered for marker in ["cookie", "session"]):
        return "session-management"
    if any(marker in lowered for marker in ["header", "csp", "clickjack", "hsts"]):
        return "security-headers"
    if any(marker in lowered for marker in ["tls", "ssl", "certificate", "https"]):
        return "transport-security"
    if any(marker in lowered for marker in ["auth", "login", "password"]):
        return "authentication"
    if any(marker in lowered for marker in ["server", "version", "fingerprint", "powered-by"]):
        return "information-disclosure"
    return default


def _severity(value: Any) -> str:
    lowered = _clean(value, "info").lower()
    if lowered in {"4", "4.0"}:
        return "critical"
    if lowered in {"3", "3.0"}:
        return "high"
    if lowered in {"2", "2.0"}:
        return "medium"
    if lowered in {"1", "1.0"}:
        return "low"
    if lowered in {"0", "0.0", "-1"}:
        return "info"
    if "critical" in lowered:
        return "critical"
    if "high" in lowered:
        return "high"
    if "medium" in lowered or "moderate" in lowered:
        return "medium"
    if "low" in lowered:
        return "low"
    return "info"


def _evidence(label: str, value: Any, location: Any = "") -> dict[str, str]:
    return {
        "label": label,
        "value": _clean_html(value),
        "location": sanitize_url(_clean(location)) if _clean(location).startswith(("http://", "https://")) else _clean(location),
    }


def _burp_issue_url(host: str, path: str, location: str) -> str:
    if _is_url(path):
        return sanitize_url(path)
    if _is_url(location):
        return sanitize_url(location)
    if not host:
        return sanitize_url(path) if path else ""
    base = host if "://" in host else f"https://{host}"
    return sanitize_url(urljoin(base.rstrip("/") + "/", path.lstrip("/"))) if path else sanitize_url(base)


def _child_text(node: ET.Element, name: str) -> str:
    for child in list(node):
        if _local_name(child.tag).lower() == name.lower():
            return _clean(child.text)
    return ""


def _children(node: ET.Element, name: str) -> list[ET.Element]:
    return [child for child in list(node) if _local_name(child.tag).lower() == name.lower()]


def _first_child(node: ET.Element, name: str) -> ET.Element | None:
    for child in _children(node, name):
        return child
    return None


def _xml_root(content: str) -> ET.Element:
    try:
        return ET.fromstring(content)
    except ET.ParseError as exc:
        raise ValueError(f"Could not parse XML import: {exc}") from exc


def _json_loads(content: str) -> Any:
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise ValueError(f"Could not parse JSON import: {exc}") from exc


def _looks_like_zap_json(data: Any) -> bool:
    if not isinstance(data, dict):
        return False
    program = _clean(data.get("@programName") or data.get("programName")).lower()
    if "zap" in program:
        return True
    sites = data.get("site")
    return isinstance(sites, list) and any(isinstance(item, dict) and "alerts" in item for item in sites)


def _looks_like_csv(content: str) -> bool:
    first_line = next((line for line in content.splitlines() if line.strip()), "")
    headers = {item.strip().lower() for item in first_line.split(",")}
    return "url" in headers or "uri" in headers or "target" in headers


def _dedupe_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for finding in findings:
        key = "|".join([_clean(finding.get("id")), _clean(finding.get("target")), _clean(finding.get("title"))])
        if key in seen:
            continue
        seen.add(key)
        output.append(finding)
    return output


def _dedupe_urls(urls: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_url: dict[str, dict[str, Any]] = {}
    methods: dict[str, set[str]] = {}
    sources: dict[str, set[str]] = {}
    for item in urls:
        url = sanitize_url(_clean(item.get("url")))
        if not url:
            continue
        entry = by_url.setdefault(url, {"url": url, "source": "", "method": "", "status_code": None, "content_type": ""})
        method = _clean(item.get("method")).upper()
        source = _clean(item.get("source"), "external_import")
        if method:
            methods.setdefault(url, set()).add(method)
        sources.setdefault(url, set()).add(source)
        if entry.get("status_code") is None and item.get("status_code") is not None:
            entry["status_code"] = item.get("status_code")
        if not entry.get("content_type") and item.get("content_type"):
            entry["content_type"] = _clean(item.get("content_type"))
    output = []
    for url, item in by_url.items():
        row = dict(item)
        row["method"] = ", ".join(sorted(methods.get(url, set())))
        row["source"] = ", ".join(sorted(sources.get(url, set())))
        output.append(row)
    output.sort(key=lambda item: item["url"])
    return output


def _dedupe_ports(ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    seen = set()
    output = []
    for item in ports:
        key = (_clean(item.get("host")), _int(item.get("port"), 0), _clean(item.get("protocol")), _clean(item.get("status")))
        if key in seen:
            continue
        seen.add(key)
        output.append(item)
    output.sort(key=lambda item: (_clean(item.get("host")), _int(item.get("port"), 0), _clean(item.get("protocol"))))
    return output


def _external_id(prefix: str, value: Any) -> str:
    raw = _clean(value, prefix)
    slug = re.sub(r"[^A-Za-z0-9]+", "-", raw).strip("-").upper()
    if not slug or len(slug) > 50:
        slug = hashlib.sha1(raw.encode("utf-8", errors="ignore")).hexdigest()[:12].upper()
    return f"{prefix}-{slug}"


def _first_value(row: dict[str, Any], *keys: str) -> str:
    for key in keys:
        value = _clean(row.get(key))
        if value:
            return value
    return ""


def _optional_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _int(value: Any, default: int) -> int:
    parsed = _optional_int(value)
    return default if parsed is None else parsed


def _is_url(value: str) -> bool:
    parsed = urlsplit(_clean(value))
    return parsed.scheme in {"http", "https"} and bool(parsed.netloc)


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _list(value: Any) -> list[Any]:
    if isinstance(value, list):
        return value
    if value is None:
        return []
    return [value]


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _clean_html(value: Any) -> str:
    text = unescape(_clean(value))
    text = HTML_TAG_RE.sub(" ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def _clean(value: Any, default: str = "") -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text or default
