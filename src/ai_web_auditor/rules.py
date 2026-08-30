from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Any

from .entrypoints import build_entry_points_from_scan
from .inventory import build_inventory_from_scan


SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0, "informational": 0}


@dataclass(frozen=True)
class FrameworkReference:
    framework: str
    control_id: str
    title: str
    url: str = ""


@dataclass(frozen=True)
class PassiveRule:
    id: str
    title: str
    category: str
    severity: str
    why_it_matters: str
    next_review: str
    references: tuple[FrameworkReference, ...]
    finding_ids: tuple[str, ...] = ()
    finding_prefixes: tuple[str, ...] = ()
    signals: tuple[str, ...] = ()
    not_observed_note: str = ""


def _wstg(control_id: str, title: str, slug: str) -> FrameworkReference:
    return FrameworkReference(
        framework="OWASP WSTG",
        control_id=control_id,
        title=title,
        url=f"https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/{slug}",
    )


def _asvs(control_id: str, title: str, slug: str) -> FrameworkReference:
    return FrameworkReference(
        framework="OWASP ASVS 5.0",
        control_id=control_id,
        title=title,
        url=f"https://cornucopia.owasp.org/taxonomy/asvs-5.0/{slug}",
    )


RULES: tuple[PassiveRule, ...] = (
    PassiveRule(
        id="RULE-TRANSPORT-ENFORCE-TLS",
        title="Transport encryption and HTTPS enforcement",
        category="transport-security",
        severity="high",
        finding_ids=("AUTH-BASIC-OVER-HTTP", "HTTP-NO-HTTPS-REDIRECT", "HTTP-COUNTERPART-OPEN"),
        why_it_matters="Credentials, cookies and session tokens must not be exposed through clear-text HTTP or downgrade paths.",
        next_review="Confirm HTTPS is enforced for every entry point and that HTTP redirects safely before authentication or session exchange.",
        references=(
            _wstg(
                "WSTG-CRYP-03",
                "Sensitive information sent via unencrypted channels",
                "09-Testing_for_Weak_Cryptography/03-Testing_for_Sensitive_Information_Sent_via_Unencrypted_Channels",
            ),
            _wstg(
                "WSTG-ATHN-01",
                "Credentials transported over an encrypted channel",
                "04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel",
            ),
            _asvs(
                "V12.2.1",
                "TLS is used for client connectivity",
                "12-secure-communication/02-https-communication-with-external-facing-services",
            ),
            _asvs(
                "V14.2.1",
                "Sensitive data is sent through protected channels",
                "14-data-protection/02-general-data-protection",
            ),
        ),
        not_observed_note="No clear-text credential transport or missing HTTPS upgrade finding was observed.",
    ),
    PassiveRule(
        id="RULE-TRANSPORT-HSTS",
        title="HSTS response policy",
        category="transport-security",
        severity="medium",
        finding_ids=("HEADER-STRICT_TRANSPORT_SECURITY-MISSING", "HEADER-HSTS-MAX-AGE-LOW"),
        why_it_matters="HSTS reduces downgrade and first-click HTTP exposure once HTTPS is working correctly.",
        next_review="Set Strict-Transport-Security with an adequate max-age and decide whether includeSubDomains/preload are appropriate.",
        references=(
            _wstg(
                "WSTG-CONF-07",
                "HTTP Strict Transport Security",
                "02-Configuration_and_Deployment_Management_Testing/07-Test_HTTP_Strict_Transport_Security",
            ),
            _asvs(
                "V3.4.1",
                "Strict-Transport-Security header is included",
                "03-web-frontend-security/04-browser-security-mechanism-headers",
            ),
        ),
        not_observed_note="No HSTS absence or low max-age finding was observed.",
    ),
    PassiveRule(
        id="RULE-TRANSPORT-TLS-BASIC",
        title="TLS version and certificate baseline",
        category="transport-security",
        severity="high",
        finding_ids=(
            "TLS-CERT-VERIFY-FAILED",
            "TLS-CERT-EXPIRED",
            "TLS-CERT-EXPIRING-SOON",
            "TLS-OLD-VERSION-NEGOTIATED",
        ),
        why_it_matters="Weak TLS configuration or invalid certificates can break confidentiality and trust for the whole application.",
        next_review="Review certificate validity, trust chain and negotiated protocol before relying on the service for authenticated traffic.",
        references=(
            _wstg(
                "WSTG-CRYP-01",
                "Weak transport layer security",
                "09-Testing_for_Weak_Cryptography/01-Testing_for_Weak_Transport_Layer_Security",
            ),
            _asvs(
                "V12.1.1",
                "Recommended TLS versions are enabled",
                "12-secure-communication/01-general-tls-security-guidance",
            ),
            _asvs(
                "V12.2.2",
                "External services use publicly trusted TLS certificates",
                "12-secure-communication/02-https-communication-with-external-facing-services",
            ),
        ),
        not_observed_note="No TLS protocol or certificate finding was observed.",
    ),
    PassiveRule(
        id="RULE-SESSION-COOKIE-ATTRIBUTES",
        title="Cookie security attributes",
        category="session-management",
        severity="medium",
        finding_ids=(
            "COOKIE-SECURE-MISSING",
            "COOKIE-HTTPONLY-MISSING",
            "COOKIE-SAMESITE-MISSING",
            "COOKIE-SAMESITE-NONE-WITHOUT-SECURE",
            "COOKIE-PARSE-FAILED",
        ),
        why_it_matters="Cookie flags constrain session token exposure across insecure transport, browser scripts and cross-site requests.",
        next_review="Confirm session cookies use Secure, HttpOnly and a deliberate SameSite value based on the application flow.",
        references=(
            _wstg(
                "WSTG-SESS-02",
                "Cookie attributes",
                "06-Session_Management_Testing/02-Testing_for_Cookies_Attributes",
            ),
            _asvs("V3.3.1", "Cookies have Secure attributes", "03-web-frontend-security/03-cookie-setup"),
            _asvs("V3.3.2", "Cookies define a SameSite policy", "03-web-frontend-security/03-cookie-setup"),
            _asvs("V3.3.4", "Sensitive cookies use HttpOnly", "03-web-frontend-security/03-cookie-setup"),
        ),
        not_observed_note="No cookie attribute finding was observed.",
    ),
    PassiveRule(
        id="RULE-FRONTEND-BROWSER-SECURITY-HEADERS",
        title="Browser security mechanism headers",
        category="browser-hardening",
        severity="medium",
        finding_ids=(
            "HEADER-CONTENT_SECURITY_POLICY-MISSING",
            "HEADER-CSP-MISSING",
            "HEADER-CLICKJACKING-MISSING",
            "HEADER-NOSNIFF-MISSING",
            "HEADER-REFERRER_POLICY-MISSING",
            "HEADER-PERMISSIONS_POLICY-MISSING",
        ),
        why_it_matters="Security headers provide browser-enforced defense in depth against content injection, clickjacking and data leakage.",
        next_review="Review CSP, frame-ancestors/X-Frame-Options, X-Content-Type-Options, Referrer-Policy and Permissions-Policy per route.",
        references=(
            _wstg(
                "WSTG-CONF-12",
                "Content Security Policy",
                "02-Configuration_and_Deployment_Management_Testing/12-Test_for_Content_Security_Policy",
            ),
            _wstg(
                "WSTG-CLNT-09",
                "Clickjacking",
                "11-Client-side_Testing/09-Testing_for_Clickjacking",
            ),
            _wstg(
                "WSTG-CONF-14",
                "Other HTTP security header misconfigurations",
                "02-Configuration_and_Deployment_Management_Testing/14-Test_Other_HTTP_Security_Header_Misconfigurations",
            ),
            _asvs(
                "V3.4",
                "Browser security mechanism headers",
                "03-web-frontend-security/04-browser-security-mechanism-headers",
            ),
        ),
        not_observed_note="No browser security header finding was observed.",
    ),
    PassiveRule(
        id="RULE-CONFIG-HTTP-METHODS",
        title="Advertised HTTP methods",
        category="configuration",
        severity="medium",
        finding_prefixes=("METHOD-",),
        why_it_matters="Unnecessary HTTP methods can expand the attack surface or expose method tampering paths.",
        next_review="Verify that each advertised method is intentionally supported and protected by route-level authorization.",
        references=(
            _wstg(
                "WSTG-CONF-06",
                "HTTP methods",
                "02-Configuration_and_Deployment_Management_Testing/06-Test_HTTP_Methods",
            ),
            _asvs(
                "V4.1.4",
                "Only explicitly supported HTTP methods are accepted",
                "04-api-and-web-service/01-generic-web-service-security",
            ),
            _asvs(
                "V13.4.4",
                "HTTP TRACE method is not supported in production",
                "13-configuration/04-unintended-information-leakage",
            ),
        ),
        not_observed_note="No risky HTTP method finding was observed.",
    ),
    PassiveRule(
        id="RULE-INFO-TECH-FINGERPRINTING",
        title="Technology and version disclosure",
        category="information-gathering",
        severity="info",
        finding_prefixes=("FINGERPRINT-",),
        signals=("technologies_identified",),
        why_it_matters="Technology signals help focus later manual review and can expose unnecessary version details.",
        next_review="Keep useful technology evidence, then remove precise version disclosure where it is not operationally required.",
        references=(
            _wstg(
                "WSTG-INFO-02",
                "Fingerprint web server",
                "01-Information_Gathering/02-Fingerprint_Web_Server",
            ),
            _wstg(
                "WSTG-INFO-08",
                "Fingerprint web application framework",
                "01-Information_Gathering/08-Fingerprint_Web_Application_Framework",
            ),
            _wstg(
                "WSTG-INFO-10",
                "Map application architecture",
                "01-Information_Gathering/10-Map_Application_Architecture",
            ),
            _asvs(
                "V13.4",
                "Unintended information leakage",
                "13-configuration/04-unintended-information-leakage",
            ),
        ),
        not_observed_note="No technology fingerprinting signal was observed.",
    ),
    PassiveRule(
        id="RULE-INFO-WEBSERVER-METAFILES",
        title="Public metadata files and declared paths",
        category="information-gathering",
        severity="info",
        signals=("public_metadata",),
        why_it_matters="robots.txt, sitemap.xml and well-known files can reveal intended routes, policies, identity metadata and hidden paths.",
        next_review="Review discovered metadata paths manually and decide what belongs in scope before following sensitive paths.",
        references=(
            _wstg(
                "WSTG-INFO-03",
                "Review webserver metafiles for information leakage",
                "01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage",
            ),
            _wstg(
                "WSTG-INFO-07",
                "Map execution paths through application",
                "01-Information_Gathering/07-Map_Execution_Paths_Through_Application",
            ),
            _asvs(
                "V13.4",
                "Unintended information leakage",
                "13-configuration/04-unintended-information-leakage",
            ),
        ),
        not_observed_note="No public metadata file signal was observed.",
    ),
    PassiveRule(
        id="RULE-INFO-ENTRY-POINTS",
        title="Application entry point inventory",
        category="information-gathering",
        severity="info",
        signals=("entry_points_present", "state_changing_entry_points", "sensitive_parameters"),
        why_it_matters="A useful audit starts with a reliable inventory of URLs, forms, methods and parameters before any validation testing.",
        next_review="Prioritize state-changing endpoints, sensitive parameters and authenticated flows for later authorized testing.",
        references=(
            _wstg(
                "WSTG-INFO-06",
                "Identify application entry points",
                "01-Information_Gathering/06-Identify_Application_Entry_Points",
            ),
            _wstg(
                "WSTG-INFO-07",
                "Map execution paths through application",
                "01-Information_Gathering/07-Map_Execution_Paths_Through_Application",
            ),
            _asvs(
                "V4.1.2",
                "Only intended user-facing endpoints are exposed",
                "04-api-and-web-service/01-generic-web-service-security",
            ),
        ),
        not_observed_note="No entry point inventory signal was observed.",
    ),
    PassiveRule(
        id="RULE-INFO-JAVASCRIPT-SURFACE",
        title="Client-side JavaScript exposed routes",
        category="information-gathering",
        severity="info",
        finding_prefixes=("JS-",),
        signals=("javascript_endpoints",),
        why_it_matters="Client-side JavaScript often exposes API routes, identity flows and external integrations that are not visible as links.",
        next_review="Review JavaScript-discovered endpoints before selecting any later validation or attack simulation.",
        references=(
            _wstg(
                "WSTG-INFO-05",
                "Review web page content for information leakage",
                "01-Information_Gathering/05-Review_Web_Page_Content_for_Information_Leakage",
            ),
            _wstg(
                "WSTG-INFO-06",
                "Identify application entry points",
                "01-Information_Gathering/06-Identify_Application_Entry_Points",
            ),
            _asvs(
                "V13.4",
                "Unintended information leakage",
                "13-configuration/04-unintended-information-leakage",
            ),
        ),
        not_observed_note="No JavaScript endpoint signal was observed.",
    ),
    PassiveRule(
        id="RULE-AUTH-AUTHENTICATION-SURFACE",
        title="Authentication and account-management surface",
        category="authentication",
        severity="info",
        finding_ids=("AUTH-BASIC-DETECTED",),
        signals=("auth_routes",),
        why_it_matters="Authentication, account and recovery flows usually define the highest-value manual review paths.",
        next_review="Document every authentication path, recovery path and callback before testing controls in a later authorized phase.",
        references=(
            _wstg(
                "WSTG-ATHN-01",
                "Credentials transported over an encrypted channel",
                "04-Authentication_Testing/01-Testing_for_Credentials_Transported_over_an_Encrypted_Channel",
            ),
            _wstg(
                "WSTG-ATHN-09",
                "Weak password change or reset functionality",
                "04-Authentication_Testing/09-Testing_for_Weak_Password_Change_or_Reset_Functionalities",
            ),
            _asvs(
                "V6.1.3",
                "Multiple authentication pathways are documented",
                "06-authentication/01-authentication-documentation",
            ),
            _asvs(
                "V6.4.3",
                "Secure forgotten password reset process",
                "06-authentication/04-authentication-factor-lifecycle-and-recovery",
            ),
        ),
        not_observed_note="No authentication route signal was observed.",
    ),
    PassiveRule(
        id="RULE-AUTHZ-ADMIN-SURFACE",
        title="Administrative and privileged route inventory",
        category="authorization",
        severity="info",
        signals=("admin_routes",),
        why_it_matters="Administrative routes are high-value review targets even when they are only passively discovered.",
        next_review="Confirm ownership, required roles and whether the route should remain in scope before any access-control testing.",
        references=(
            _wstg(
                "WSTG-CONF-05",
                "Enumerate infrastructure and application admin interfaces",
                "02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces",
            ),
            _asvs(
                "V8.4.2",
                "Administrative interfaces include stronger access controls",
                "08-authorization/04-other-authorization-considerations",
            ),
        ),
        not_observed_note="No administrative route signal was observed.",
    ),
    PassiveRule(
        id="RULE-FILE-UPLOAD-SURFACE",
        title="File upload route inventory",
        category="file-handling",
        severity="info",
        signals=("upload_routes",),
        why_it_matters="Upload endpoints commonly require extra validation, storage and authorization review.",
        next_review="Confirm accepted file types, size limits, storage location and authorization before any upload testing.",
        references=(
            _asvs(
                "V5.2.1",
                "Accepted files have safe size limits",
                "05-file-handling/02-file-upload-and-content",
            ),
            _asvs(
                "V5.2.2",
                "Uploaded file extension and content are validated",
                "05-file-handling/02-file-upload-and-content",
            ),
        ),
        not_observed_note="No upload route signal was observed.",
    ),
    PassiveRule(
        id="RULE-INFRA-DISCOVERY-SURFACE",
        title="Infrastructure surface from DNS and TCP checks",
        category="infrastructure",
        severity="info",
        finding_ids=("SUBDOMAIN-DISCOVERY-RESOLVED", "PORTS-OPEN-TCP-PORTS"),
        signals=("subdomains_resolved", "ports_open"),
        why_it_matters="Resolved hosts and open TCP ports help identify what infrastructure should be confirmed in or out of scope.",
        next_review="Confirm every resolved host and open port with the application owner before expanding testing beyond the main URL.",
        references=(
            _wstg(
                "WSTG-INFO-04",
                "Enumerate applications on webserver",
                "01-Information_Gathering/04-Enumerate_Applications_on_Webserver",
            ),
            _wstg(
                "WSTG-INFO-10",
                "Map application architecture",
                "01-Information_Gathering/10-Map_Application_Architecture",
            ),
            _asvs(
                "V13.1.1",
                "Application communication needs are documented",
                "13-configuration/01-configuration-documentation",
            ),
        ),
        not_observed_note="No DNS or TCP infrastructure expansion signal was observed.",
    ),
    PassiveRule(
        id="RULE-SCOPE-EXTERNAL-REFERENCES",
        title="External and out-of-scope references",
        category="scope-management",
        severity="info",
        finding_ids=(
            "CRAWLER-OUT-OF-SCOPE-LINKS",
            "HTTP-REDIRECT-OUT-OF-SCOPE",
            "HTTP-COUNTERPART-REDIRECT-OUT-OF-SCOPE",
            "JS-OUT-OF-SCOPE-ENDPOINTS",
        ),
        signals=("external_references",),
        why_it_matters="External references may be legitimate dependencies, third parties or missing scope items; they should not be scanned automatically.",
        next_review="Classify each external host as third-party, dependency, redirect target or candidate scope extension.",
        references=(
            _wstg(
                "WSTG-INFO-10",
                "Map application architecture",
                "01-Information_Gathering/10-Map_Application_Architecture",
            ),
            _asvs(
                "V13.2.4",
                "External resource allowlists are defined",
                "13-configuration/02-backend-communication-configuration",
            ),
        ),
        not_observed_note="No out-of-scope reference signal was observed.",
    ),
)


def build_rule_evaluation(scan_data: dict[str, Any]) -> dict[str, Any]:
    findings = _findings(scan_data)
    matches: list[dict[str, Any]] = []
    not_observed: list[dict[str, Any]] = []
    mapped_finding_ids: set[str] = set()

    for rule in RULES:
        matched_findings = [finding for finding in findings if _finding_matches_rule(rule, finding)]
        matched_signals = {
            signal: evidence
            for signal in rule.signals
            if (evidence := _signal_evidence(signal, scan_data))
        }

        if matched_findings or matched_signals:
            for finding in matched_findings:
                finding_id = _clean(finding.get("id"))
                if finding_id:
                    mapped_finding_ids.add(finding_id)
            matches.append(_rule_match(rule, matched_findings, matched_signals))
            continue

        not_observed.append(
            {
                "rule_id": rule.id,
                "title": rule.title,
                "category": rule.category,
                "severity": rule.severity,
                "status": "not_observed",
                "note": rule.not_observed_note,
                "frameworks": [asdict(item) for item in rule.references],
            }
        )

    unmapped_findings = [
        {
            "finding_id": _clean(finding.get("id"), "unknown"),
            "title": _clean(finding.get("title"), "Untitled finding"),
            "severity": _severity(finding),
            "module": _clean(finding.get("module"), "unknown"),
            "category": _clean(finding.get("category"), "unknown"),
        }
        for finding in findings
        if _clean(finding.get("id")) not in mapped_finding_ids
    ]

    framework_index = _framework_index(matches)
    severity_counts = Counter(match["severity"] for match in matches)
    category_counts = Counter(match["category"] for match in matches)

    return {
        "engine": "passive-rules",
        "version": "1.0",
        "source_frameworks": [
            {
                "name": "OWASP WSTG",
                "version": "latest/stable references",
                "url": "https://wstg.owasp.org/",
            },
            {
                "name": "OWASP ASVS",
                "version": "5.0",
                "url": "https://cornucopia.owasp.org/taxonomy/asvs-5.0",
            },
        ],
        "summary": {
            "rules_total": len(RULES),
            "rules_matched": len(matches),
            "rules_not_observed": len(not_observed),
            "findings_mapped": len(mapped_finding_ids),
            "findings_unmapped": len(unmapped_findings),
            "framework_controls_matched": len(framework_index),
            "critical": severity_counts.get("critical", 0),
            "high": severity_counts.get("high", 0),
            "medium": severity_counts.get("medium", 0),
            "low": severity_counts.get("low", 0),
            "info": severity_counts.get("info", 0),
            "categories": dict(sorted(category_counts.items())),
        },
        "matches": matches,
        "not_observed": not_observed,
        "unmapped_findings": unmapped_findings,
        "framework_index": framework_index,
        "safety_notes": [
            "Rules are evaluated from existing passive scan evidence only.",
            "A matched rule is review guidance, not proof of exploitability.",
            "Out-of-scope references are recorded but must not be scanned without explicit authorization.",
        ],
    }


def render_rules_console(rule_evaluation: dict[str, Any]) -> str:
    summary = rule_evaluation.get("summary") if isinstance(rule_evaluation.get("summary"), dict) else {}
    return (
        f"Rules: {_int(summary.get('rules_matched'), 0)}/{_int(summary.get('rules_total'), 0)} matched | "
        f"Mapped findings: {_int(summary.get('findings_mapped'), 0)} | "
        f"Framework controls: {_int(summary.get('framework_controls_matched'), 0)}"
    )


def _rule_match(
    rule: PassiveRule,
    findings: list[dict[str, Any]],
    signals: dict[str, list[dict[str, str]]],
) -> dict[str, Any]:
    severity = _highest_severity(findings, fallback=rule.severity)
    matched_finding_ids = sorted({_clean(finding.get("id"), "unknown") for finding in findings})
    targets = sorted({_clean(finding.get("target")) for finding in findings if _clean(finding.get("target"))})
    evidence = _finding_evidence(findings)
    for signal, signal_evidence in signals.items():
        evidence.extend(signal_evidence[:8])
        for item in signal_evidence:
            value = _clean(item.get("value"))
            if value.startswith(("http://", "https://")):
                targets.append(value)

    return {
        "rule_id": rule.id,
        "title": rule.title,
        "status": "matched",
        "severity": severity,
        "category": rule.category,
        "matched_findings": matched_finding_ids,
        "matched_signals": sorted(signals),
        "targets": sorted(set(targets))[:25],
        "evidence": evidence[:20],
        "why_it_matters": rule.why_it_matters,
        "next_review": rule.next_review,
        "frameworks": [asdict(item) for item in rule.references],
    }


def _finding_matches_rule(rule: PassiveRule, finding: dict[str, Any]) -> bool:
    finding_id = _clean(finding.get("id"))
    if not finding_id:
        return False
    return finding_id in rule.finding_ids or any(finding_id.startswith(prefix) for prefix in rule.finding_prefixes)


def _finding_evidence(findings: list[dict[str, Any]]) -> list[dict[str, str]]:
    output: list[dict[str, str]] = []
    for finding in findings:
        finding_id = _clean(finding.get("id"), "unknown")
        output.append(
            {
                "type": "finding",
                "label": finding_id,
                "value": _clean(finding.get("title"), "Untitled finding"),
                "location": _clean(finding.get("target"), _clean(finding.get("module"), "unknown")),
            }
        )
        for item in _dict_list(finding.get("evidence"))[:3]:
            output.append(
                {
                    "type": "finding_evidence",
                    "label": _clean(item.get("label"), finding_id),
                    "value": _clean(item.get("value")),
                    "location": _clean(item.get("location"), _clean(finding.get("target"))),
                }
            )
    return output


def _signal_evidence(signal: str, scan_data: dict[str, Any]) -> list[dict[str, str]]:
    if signal == "entry_points_present":
        endpoints = _entrypoint_items(scan_data)
        return [_evidence("entry_point", "endpoint", item.get("url"), item.get("state")) for item in endpoints[:8]]

    if signal == "state_changing_entry_points":
        endpoints = [item for item in _entrypoint_items(scan_data) if item.get("state_changing")]
        return [_evidence("entry_point", "state_changing", item.get("url"), ", ".join(_string_list(item.get("methods")))) for item in endpoints[:8]]

    if signal == "sensitive_parameters":
        parameters = [item for item in _entrypoint_parameters(scan_data) if item.get("sensitive_hint")]
        return [
            _evidence("parameter", _clean(item.get("name"), "parameter"), str(item.get("occurrences", "")), ", ".join(_string_list(item.get("locations"))))
            for item in parameters[:8]
        ]

    if signal == "admin_routes":
        return _route_evidence(scan_data, {"admin"})

    if signal == "upload_routes":
        return _route_evidence(scan_data, {"upload"})

    if signal == "auth_routes":
        evidence = _route_evidence(scan_data, {"account", "callback", "login", "password_reset"})
        forms = [item for item in _entrypoint_forms(scan_data) if int(item.get("password_fields") or 0) > 0]
        evidence.extend(_evidence("form", "password_form", item.get("action") or item.get("page_url"), item.get("method")) for item in forms[:5])
        return evidence[:10]

    if signal == "public_metadata":
        return _metadata_evidence(scan_data)

    if signal == "technologies_identified":
        technologies = _module_artifacts(scan_data, "fingerprinting").get("technologies")
        return [
            _evidence(
                "technology",
                _clean(item.get("category"), "technology"),
                _technology_name(item),
                _clean(item.get("confidence"), "unknown"),
            )
            for item in _dict_list(technologies)[:8]
        ]

    if signal == "javascript_endpoints":
        endpoints = _module_artifacts(scan_data, "javascript").get("discovered_endpoints")
        return [_evidence("javascript_endpoint", "endpoint", item.get("url"), item.get("method")) for item in _dict_list(endpoints)[:8]]

    if signal == "subdomains_resolved":
        resolved = _module_artifacts(scan_data, "subdomains").get("resolved")
        return [
            _evidence("subdomain", "resolved", item.get("host"), ", ".join(_string_list(item.get("ip_addresses"))))
            for item in _dict_list(resolved)[:8]
        ]

    if signal == "ports_open":
        results = [
            item
            for item in _dict_list(_module_artifacts(scan_data, "ports").get("results"))
            if _clean(item.get("status")).lower() == "open"
        ]
        return [
            _evidence("tcp_port", "open", f"{_clean(item.get('host'), 'unknown')}:{_clean(item.get('port'), 'unknown')}", item.get("service"))
            for item in results[:8]
        ]

    if signal == "external_references":
        values: list[str] = []
        crawler = _module_artifacts(scan_data, "crawler")
        values.extend(_string_list(crawler.get("out_of_scope_urls")))
        javascript = _module_artifacts(scan_data, "javascript")
        values.extend(_clean(item.get("url")) for item in _dict_list(javascript.get("out_of_scope_endpoints")))
        return [_evidence("scope", "out_of_scope", value, "recorded_not_requested") for value in values[:10] if value]

    return []


def _metadata_evidence(scan_data: dict[str, Any]) -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []
    crawler = _module_artifacts(scan_data, "crawler").get("metadata")
    if isinstance(crawler, dict):
        robots = crawler.get("robots")
        if isinstance(robots, dict) and robots.get("present"):
            evidence.append(_evidence("metadata", "robots.txt", robots.get("url"), robots.get("status_code")))
        for item in _dict_list(crawler.get("sitemaps")):
            if item.get("present"):
                evidence.append(_evidence("metadata", "sitemap", item.get("url"), item.get("url_count")))
        for item in _dict_list(crawler.get("well_known")):
            if item.get("present"):
                evidence.append(_evidence("metadata", _clean(item.get("path"), "well-known"), item.get("url"), item.get("status_code")))

    public_files = _module_artifacts(scan_data, "fingerprinting").get("public_files")
    for item in _dict_list(public_files):
        if item.get("present"):
            evidence.append(_evidence("metadata", _clean(item.get("path"), "public_file"), item.get("url") or item.get("path"), item.get("status_code")))
    return evidence[:10]


def _route_evidence(scan_data: dict[str, Any], route_markers: set[str]) -> list[dict[str, str]]:
    evidence: list[dict[str, str]] = []
    for item in _entrypoint_items(scan_data):
        route_types = set(_string_list(item.get("route_types")))
        notes = set(_string_list(item.get("notes")))
        if route_markers.intersection(route_types) or any(note.removesuffix("_route") in route_markers for note in notes):
            evidence.append(_evidence("entry_point", ",".join(sorted(route_markers)), item.get("url"), ", ".join(sorted(route_types))))
    if len(evidence) >= 10:
        return evidence[:10]

    inventory = build_inventory_from_scan(scan_data)
    for item in _dict_list(inventory.get("urls")):
        route_types = set(_string_list(item.get("route_types")))
        reasons = set(_string_list(item.get("reasons")))
        if route_markers.intersection(route_types) or route_markers.intersection(reasons):
            evidence.append(_evidence("inventory_url", ",".join(sorted(route_markers)), item.get("url"), ", ".join(sorted(route_types))))
    return evidence[:10]


def _framework_index(matches: list[dict[str, Any]]) -> list[dict[str, Any]]:
    controls: dict[tuple[str, str], dict[str, Any]] = {}
    for match in matches:
        for reference in _dict_list(match.get("frameworks")):
            key = (_clean(reference.get("framework"), "unknown"), _clean(reference.get("control_id"), "unknown"))
            entry = controls.setdefault(
                key,
                {
                    "framework": key[0],
                    "control_id": key[1],
                    "title": _clean(reference.get("title"), "unknown"),
                    "url": _clean(reference.get("url")),
                    "matched_rules": set(),
                    "matched_findings": set(),
                    "matched_signals": set(),
                    "categories": set(),
                    "highest_severity": "info",
                },
            )
            entry["matched_rules"].add(_clean(match.get("rule_id"), "unknown"))
            entry["matched_findings"].update(_string_list(match.get("matched_findings")))
            entry["matched_signals"].update(_string_list(match.get("matched_signals")))
            entry["categories"].add(_clean(match.get("category"), "unknown"))
            if SEVERITY_ORDER.get(_severity(match), 0) > SEVERITY_ORDER.get(entry["highest_severity"], 0):
                entry["highest_severity"] = _severity(match)

    output = []
    for item in controls.values():
        row = dict(item)
        row["matched_rules"] = sorted(row["matched_rules"])
        row["matched_findings"] = sorted(row["matched_findings"])
        row["matched_signals"] = sorted(row["matched_signals"])
        row["categories"] = sorted(row["categories"])
        output.append(row)
    output.sort(key=lambda item: (item["framework"], item["control_id"]))
    return output


def _entrypoint_items(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    entry_points = build_entry_points_from_scan(scan_data)
    return _dict_list(entry_points.get("endpoints"))


def _entrypoint_parameters(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    entry_points = build_entry_points_from_scan(scan_data)
    return _dict_list(entry_points.get("parameters"))


def _entrypoint_forms(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    entry_points = build_entry_points_from_scan(scan_data)
    return _dict_list(entry_points.get("forms"))


def _module_artifacts(scan_data: dict[str, Any], name: str) -> dict[str, Any]:
    for module in _dict_list(scan_data.get("modules")):
        if module.get("name") == name and isinstance(module.get("artifacts"), dict):
            return module["artifacts"]
    return {}


def _findings(scan_data: dict[str, Any]) -> list[dict[str, Any]]:
    return _dict_list(scan_data.get("findings"))


def _highest_severity(findings: list[dict[str, Any]], *, fallback: str) -> str:
    highest = _severity_name(fallback)
    for finding in findings:
        severity = _severity(finding)
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(highest, 0):
            highest = severity
    return highest


def _severity(item: dict[str, Any]) -> str:
    return _severity_name(_clean(item.get("severity"), "info"))


def _severity_name(value: str) -> str:
    severity = value.lower()
    if severity == "informational":
        return "info"
    return severity if severity in SEVERITY_ORDER else "info"


def _technology_name(item: dict[str, Any]) -> str:
    name = _clean(item.get("name"), "unknown")
    version = _clean(item.get("version"))
    return f"{name} {version}" if version else name


def _evidence(kind: str, label: Any, value: Any, location: Any = "") -> dict[str, str]:
    return {
        "type": kind,
        "label": _clean(label, kind),
        "value": _clean(value),
        "location": _clean(location),
    }


def _dict_list(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [_clean(item) for item in value if _clean(item)]


def _clean(value: Any, default: str = "") -> str:
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
