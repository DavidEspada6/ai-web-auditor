from __future__ import annotations

import ipaddress
import socket
from typing import Any

from ai_web_auditor.context import ScanContext
from ai_web_auditor.models import Evidence, Finding, ModuleResult
from ai_web_auditor.scope import is_host_allowed


COMMON_HOST_PREFIXES = {"www", "app", "api", "portal", "admin", "login"}


class SubdomainModule:
    name = "subdomains"

    def run(self, context: ScanContext) -> ModuleResult:
        if not context.config.scope.resolve_dns:
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="Subdomain discovery skipped because DNS resolution is disabled.",
                artifacts={"reason": "resolve_dns_disabled"},
            )

        roots = _root_domains(context.target.host, context.config.scope.allowed_hosts)
        if not roots:
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="Subdomain discovery skipped because no DNS root domain is available.",
                artifacts={"reason": "no_dns_root"},
            )

        candidates = _candidate_hosts(roots, context.config.subdomains.candidates, context.config.subdomains.max_candidates)
        resolved: list[dict[str, Any]] = []
        unresolved: list[str] = []
        out_of_scope: list[str] = []

        for host in candidates:
            if not is_host_allowed(host, context.config.scope, default_host=context.target.host):
                out_of_scope.append(host)
                continue
            addresses = _resolve_host(host, timeout_seconds=context.config.subdomains.timeout_seconds)
            if addresses:
                resolved.append({"host": host, "ip_addresses": addresses, "source": "dns_candidate", "in_scope": True})
            else:
                unresolved.append(host)

        findings: list[Finding] = []
        if resolved:
            findings.append(
                Finding(
                    id="SUBDOMAIN-DISCOVERY-RESOLVED",
                    title="In-scope subdomains resolved by DNS",
                    severity="info",
                    category="reconnaissance",
                    description="The scan resolved one or more candidate subdomains inside the configured scope. They were recorded but not audited automatically.",
                    recommendation="Review these hosts and add them explicitly to the authorized scope before running deeper checks against them.",
                    module=self.name,
                    target=context.target.host,
                    evidence=[Evidence("host", item["host"], ", ".join(item["ip_addresses"])) for item in resolved[:10]],
                )
            )

        status = "warning" if findings else "passed"
        return ModuleResult(
            name=self.name,
            status=status,
            summary=f"Checked {len(candidates)} candidate subdomain(s), resolved {len(resolved)} in-scope host(s).",
            findings=findings,
            artifacts={
                "root_domains": roots,
                "candidate_count": len(candidates),
                "resolved": resolved,
                "resolved_count": len(resolved),
                "unresolved_count": len(unresolved),
                "out_of_scope": out_of_scope,
                "out_of_scope_count": len(out_of_scope),
                "note": "Resolved hosts were not scanned automatically.",
            },
        )


def _root_domains(target_host: str, allowed_hosts: list[str]) -> list[str]:
    roots: list[str] = []
    for value in allowed_hosts or [target_host]:
        host = _clean_host(value)
        if not host or _is_ip_or_local(host):
            continue
        roots.append(_base_domain(host))
    return sorted(set(item for item in roots if item and "." in item))


def _candidate_hosts(roots: list[str], prefixes: list[str], max_candidates: int) -> list[str]:
    output: list[str] = []
    seen: set[str] = set()
    limit = max(1, max_candidates)
    clean_prefixes = [_clean_prefix(prefix) for prefix in prefixes]
    for root in roots:
        for prefix in clean_prefixes:
            if not prefix:
                continue
            host = f"{prefix}.{root}"
            if host not in seen:
                output.append(host)
                seen.add(host)
            if len(output) >= limit:
                return output
    return output


def _resolve_host(host: str, *, timeout_seconds: float) -> list[str]:
    previous_timeout = socket.getdefaulttimeout()
    socket.setdefaulttimeout(max(0.5, timeout_seconds))
    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except (socket.gaierror, TimeoutError, OSError):
        return []
    finally:
        socket.setdefaulttimeout(previous_timeout)
    return sorted({record[4][0] for record in records})


def _base_domain(host: str) -> str:
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if labels[0] in COMMON_HOST_PREFIXES:
        return ".".join(labels[1:])
    return host


def _clean_host(value: str) -> str:
    host = str(value or "").strip().lower().rstrip(".")
    if host.startswith("*."):
        host = host[2:]
    if host.startswith("."):
        host = host[1:]
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _clean_prefix(value: str) -> str:
    return str(value or "").strip().lower().strip(".").replace(" ", "")


def _is_ip_or_local(host: str) -> bool:
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
