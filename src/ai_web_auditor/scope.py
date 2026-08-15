from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

from .config import ScopeConfig
from .errors import ScopeError
from .models import Target


SUPPORTED_SCHEMES = {"http", "https"}


def validate_target(raw_url: str, config: ScopeConfig) -> Target:
    target = normalize_target(raw_url)
    _validate_allowed_host(target.host, config)

    ip_addresses = _resolve_ips(target.host, config.resolve_dns)
    if not config.allow_private_networks:
        _reject_private_networks(target.host, ip_addresses)

    target.ip_addresses = ip_addresses
    return target


def normalize_target(raw_url: str) -> Target:
    candidate = raw_url.strip()
    if not candidate:
        raise ScopeError("Target URL is empty")

    if "://" not in candidate:
        candidate = f"https://{candidate}"

    parsed = urlsplit(candidate)
    scheme = parsed.scheme.lower()
    if scheme not in SUPPORTED_SCHEMES:
        raise ScopeError("Only http and https URLs are supported")

    if parsed.username or parsed.password:
        raise ScopeError("Credentials embedded in URLs are not allowed")

    if not parsed.hostname:
        raise ScopeError("URL must include a hostname")

    host = _normalize_host(parsed.hostname)
    port = parsed.port or (443 if scheme == "https" else 80)
    path = parsed.path or "/"
    netloc = _format_netloc(host, parsed.port, scheme)
    normalized_url = urlunsplit((scheme, netloc, path, parsed.query, ""))
    base_url = urlunsplit((scheme, netloc, "/", "", ""))

    return Target(
        original_url=raw_url,
        normalized_url=normalized_url,
        scheme=scheme,
        host=host,
        port=port,
        base_url=base_url,
    )


def _normalize_host(hostname: str) -> str:
    host = hostname.strip().rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(host)
        return ip.compressed
    except ValueError:
        return host.encode("idna").decode("ascii")


def _format_netloc(host: str, explicit_port: int | None, scheme: str) -> str:
    display_host = f"[{host}]" if ":" in host else host
    default_port = 443 if scheme == "https" else 80
    if explicit_port and explicit_port != default_port:
        return f"{display_host}:{explicit_port}"
    return display_host


def is_host_allowed(host: str, config: ScopeConfig, default_host: str | None = None) -> bool:
    normalized_host = _normalize_host(host)
    fallback_host = _normalize_host(default_host) if default_host else normalized_host
    allowed_hosts = [_normalize_host(item) for item in config.allowed_hosts] or [fallback_host]
    for allowed in allowed_hosts:
        if normalized_host == allowed:
            return True
        if config.allow_subdomains and normalized_host.endswith(f".{allowed}"):
            return True
    return False


def _validate_allowed_host(host: str, config: ScopeConfig) -> None:
    if not is_host_allowed(host, config, default_host=host):
        raise ScopeError(f"Host {host} is outside the configured scope")


def _resolve_ips(host: str, enabled: bool) -> list[str]:
    if _is_ip_literal(host):
        return [host]
    if not enabled:
        return []

    try:
        records = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ScopeError(f"Could not resolve target hostname: {host}") from exc

    ips = sorted({record[4][0] for record in records})
    return ips


def _reject_private_networks(host: str, ips: list[str]) -> None:
    if host in {"localhost"} or host.endswith(".localhost"):
        raise ScopeError("Localhost targets require --allow-private")

    for value in ips:
        ip = ipaddress.ip_address(value)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ScopeError(f"Private or local address {value} requires --allow-private")


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False
