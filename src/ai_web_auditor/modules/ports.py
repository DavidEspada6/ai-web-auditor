from __future__ import annotations

import socket
import time
from typing import Any

from ai_web_auditor.context import ScanContext
from ai_web_auditor.models import Evidence, Finding, ModuleResult


COMMON_SERVICES = {
    21: "ftp",
    22: "ssh",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    445: "smb",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3000: "dev-http",
    3306: "mysql",
    5000: "dev-http",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8000: "http-alt",
    8080: "http-alt",
    8443: "https-alt",
    9000: "app",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


class PortsModule:
    name = "ports"

    def run(self, context: ScanContext) -> ModuleResult:
        ports = _clean_ports(context.config.ports.ports, context.config.ports.max_ports)
        if not ports:
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="Port scan skipped because no valid ports are configured.",
                artifacts={"reason": "no_ports"},
            )

        host = context.target.host
        results = [_probe_port(host, port, context.config.ports.timeout_seconds) for port in ports]
        open_ports = [item for item in results if item["status"] == "open"]
        filtered_ports = [item for item in results if item["status"] == "filtered"]
        error_ports = [item for item in results if item["status"] == "error"]
        findings: list[Finding] = []

        if open_ports:
            findings.append(
                Finding(
                    id="PORTS-OPEN-TCP-PORTS",
                    title="Open TCP ports detected",
                    severity="info",
                    category="network-exposure",
                    description="The limited TCP connectivity check found open ports on the target host. This is inventory evidence, not exploitation.",
                    recommendation="Review whether each exposed service is expected, patched and covered by the authorized audit scope.",
                    module=self.name,
                    target=host,
                    evidence=[Evidence("open_port", str(item["port"]), item.get("service", "")) for item in open_ports[:10]],
                )
            )

        status = "warning" if findings else "passed"
        return ModuleResult(
            name=self.name,
            status=status,
            summary=f"Checked {len(results)} TCP port(s), found {len(open_ports)} open port(s).",
            findings=findings,
            artifacts={
                "host": host,
                "ports_checked": ports,
                "max_ports": context.config.ports.max_ports,
                "timeout_seconds": context.config.ports.timeout_seconds,
                "open_count": len(open_ports),
                "closed_count": sum(1 for item in results if item["status"] == "closed"),
                "filtered_count": len(filtered_ports),
                "error_count": len(error_ports),
                "results": results,
                "note": "Only TCP connect checks were performed; no payloads or banners were requested.",
            },
        )


def _probe_port(host: str, port: int, timeout_seconds: float) -> dict[str, Any]:
    started = time.monotonic()
    try:
        with socket.create_connection((host, port), timeout=max(0.2, timeout_seconds)):
            status = "open"
            error = ""
    except TimeoutError:
        status = "filtered"
        error = "timeout"
    except ConnectionRefusedError:
        status = "closed"
        error = ""
    except OSError as exc:
        status = _status_from_os_error(exc)
        error = f"{exc.__class__.__name__}: {exc}" if status == "error" else ""

    elapsed_ms = int((time.monotonic() - started) * 1000)
    result = {
        "host": host,
        "port": port,
        "status": status,
        "service": COMMON_SERVICES.get(port, ""),
        "elapsed_ms": elapsed_ms,
    }
    if error:
        result["error"] = error
    return result


def _status_from_os_error(exc: OSError) -> str:
    errno = getattr(exc, "errno", None)
    winerror = getattr(exc, "winerror", None)
    if errno in {111, 61, 10061} or winerror == 10061:
        return "closed"
    if errno in {110, 10060} or winerror == 10060:
        return "filtered"
    return "error"


def _clean_ports(values: list[int], max_ports: int) -> list[int]:
    output: list[int] = []
    seen: set[int] = set()
    limit = max(1, max_ports)
    for value in values:
        try:
            port = int(value)
        except (TypeError, ValueError):
            continue
        if port < 1 or port > 65535 or port in seen:
            continue
        output.append(port)
        seen.add(port)
        if len(output) >= limit:
            break
    return output
