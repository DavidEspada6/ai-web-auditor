from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlsplit

from ai_web_auditor.context import ScanContext
from ai_web_auditor.models import Evidence, Finding, ModuleResult


class TLSBasicModule:
    name = "tls"

    def run(self, context: ScanContext) -> ModuleResult:
        url = context.final_response.url if context.final_response is not None else context.target.normalized_url
        parsed = urlsplit(url)
        if parsed.scheme != "https":
            return ModuleResult(
                name=self.name,
                status="skipped",
                summary="TLS check skipped because the final URL is not HTTPS.",
                artifacts={"url": url},
            )

        host = parsed.hostname or context.target.host
        port = parsed.port or 443
        findings: list[Finding] = []
        artifacts: dict[str, object] = {"host": host, "port": port}

        try:
            tls_info = _connect_tls(host, port, verify=True, timeout=context.config.http.timeout_seconds)
            artifacts.update(tls_info)
            _inspect_tls_info(self.name, url, tls_info, findings)
        except ssl.SSLCertVerificationError as exc:
            findings.append(
                Finding(
                    id="TLS-CERT-VERIFY-FAILED",
                    title="TLS certificate verification failed",
                    severity="high",
                    category="tls",
                    description="The certificate could not be validated by the default trust store.",
                    recommendation="Install a valid certificate for the hostname and full certificate chain.",
                    module=self.name,
                    target=url,
                    evidence=[Evidence("verify_message", str(exc))],
                )
            )
            artifacts["verification_error"] = str(exc)
            try:
                artifacts.update(_connect_tls(host, port, verify=False, timeout=context.config.http.timeout_seconds))
            except OSError as retry_exc:
                artifacts["unverified_retry_error"] = f"{retry_exc.__class__.__name__}: {retry_exc}"
        except OSError as exc:
            return ModuleResult(
                name=self.name,
                status="error",
                summary="TLS connection failed.",
                artifacts={"error": f"{exc.__class__.__name__}: {exc}", **artifacts},
            )

        return ModuleResult(
            name=self.name,
            status="warning" if findings else "passed",
            summary="Basic TLS handshake and certificate details checked.",
            findings=findings,
            artifacts=artifacts,
        )


def _connect_tls(host: str, port: int, *, verify: bool, timeout: float) -> dict[str, object]:
    context = ssl.create_default_context() if verify else ssl._create_unverified_context()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with context.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
            return {
                "tls_version": tls.version(),
                "cipher": tls.cipher()[0] if tls.cipher() else None,
                "certificate": _certificate_summary(cert),
            }


def _certificate_summary(cert: dict[str, object]) -> dict[str, object]:
    if not cert:
        return {}
    return {
        "subject": _name_tuple_to_string(cert.get("subject")),
        "issuer": _name_tuple_to_string(cert.get("issuer")),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": [value for key, value in cert.get("subjectAltName", []) if key == "DNS"],
    }


def _inspect_tls_info(module: str, target: str, tls_info: dict[str, object], findings: list[Finding]) -> None:
    version = str(tls_info.get("tls_version") or "")
    if version in {"TLSv1", "TLSv1.1"}:
        findings.append(
            Finding(
                id="TLS-OLD-VERSION-NEGOTIATED",
                title="Old TLS version negotiated",
                severity="high",
                category="tls",
                description=f"The handshake negotiated {version}, which is obsolete.",
                recommendation="Disable TLS 1.0 and TLS 1.1; support TLS 1.2 and TLS 1.3.",
                module=module,
                target=target,
                evidence=[Evidence("tls_version", version)],
            )
        )

    cert = tls_info.get("certificate") or {}
    if isinstance(cert, dict) and cert.get("not_after"):
        seconds = ssl.cert_time_to_seconds(str(cert["not_after"]))
        expires_at = datetime.fromtimestamp(seconds, tz=timezone.utc)
        days_left = (expires_at - datetime.now(timezone.utc)).days
        if days_left < 0:
            findings.append(
                Finding(
                    id="TLS-CERT-EXPIRED",
                    title="TLS certificate is expired",
                    severity="high",
                    category="tls",
                    description="The certificate expiry date is in the past.",
                    recommendation="Renew and deploy a valid certificate.",
                    module=module,
                    target=target,
                    evidence=[Evidence("not_after", str(cert["not_after"]))],
                )
            )
        elif days_left <= 30:
            findings.append(
                Finding(
                    id="TLS-CERT-EXPIRING-SOON",
                    title="TLS certificate expires soon",
                    severity="medium",
                    category="tls",
                    description="The certificate expires within 30 days.",
                    recommendation="Renew the certificate before it expires.",
                    module=module,
                    target=target,
                    evidence=[Evidence("days_left", str(days_left)), Evidence("not_after", str(cert["not_after"]))],
                )
            )


def _name_tuple_to_string(value: object) -> str:
    if not value:
        return ""
    parts: list[str] = []
    for rdn in value:
        for key, item in rdn:
            parts.append(f"{key}={item}")
    return ", ".join(parts)
