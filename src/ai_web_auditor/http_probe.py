from __future__ import annotations

import http.client
import ssl
import time
from dataclasses import dataclass, field
from typing import Mapping
from urllib.parse import urljoin, urlsplit, urlunsplit

from .config import HTTPConfig
from .errors import ProbeError
from .models import HTTPRequestRecord


@dataclass
class SimpleResponse:
    method: str
    url: str
    status_code: int
    reason: str
    headers: list[tuple[str, str]]
    history: list["SimpleResponse"] = field(default_factory=list)

    @property
    def scheme(self) -> str:
        return urlsplit(self.url).scheme

    @property
    def host(self) -> str | None:
        return urlsplit(self.url).hostname

    def get_header(self, name: str, default: str | None = None) -> str | None:
        lower_name = name.lower()
        for key, value in self.headers:
            if key.lower() == lower_name:
                return value
        return default

    def get_headers(self, name: str) -> list[str]:
        lower_name = name.lower()
        return [value for key, value in self.headers if key.lower() == lower_name]

    def headers_dict(self) -> dict[str, str]:
        output: dict[str, str] = {}
        for key, value in self.headers:
            output[key.lower()] = value
        return output


class HttpProbe:
    def __init__(self, config: HTTPConfig, records: list[HTTPRequestRecord]) -> None:
        self._config = config
        self._records = records

    def request(
        self,
        method: str,
        url: str,
        *,
        follow_redirects: bool = False,
        headers: Mapping[str, str] | None = None,
    ) -> SimpleResponse:
        current_url = url
        current_method = method.upper()
        history: list[SimpleResponse] = []
        extra_headers = dict(headers or {})

        for redirect_count in range(self._config.max_redirects + 1):
            response = self._single_request(current_method, current_url, extra_headers)
            if not follow_redirects or response.status_code not in {301, 302, 303, 307, 308}:
                response.history = history
                return response

            location = response.get_header("location")
            if not location:
                response.history = history
                return response

            history.append(response)
            current_url = urljoin(current_url, location)
            if response.status_code == 303:
                current_method = "GET"

        raise ProbeError(f"Too many redirects after {self._config.max_redirects} hops")

    def _single_request(self, method: str, url: str, headers: Mapping[str, str]) -> SimpleResponse:
        parsed = urlsplit(url)
        if parsed.scheme not in {"http", "https"}:
            raise ProbeError(f"Unsupported URL scheme: {parsed.scheme}")
        if not parsed.hostname:
            raise ProbeError("URL has no hostname")

        started = time.monotonic()
        record = HTTPRequestRecord(method=method, url=url, status_code=None, elapsed_ms=None)
        connection: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
        try:
            connection = self._connection(parsed.scheme, parsed.hostname, parsed.port)
            request_path = urlunsplit(("", "", parsed.path or "/", parsed.query, ""))
            request_headers = {
                "User-Agent": self._config.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                **headers,
            }
            connection.request(method, request_path, headers=request_headers)
            raw_response = connection.getresponse()
            header_items = raw_response.getheaders()
            response = SimpleResponse(
                method=method,
                url=url,
                status_code=raw_response.status,
                reason=raw_response.reason,
                headers=header_items,
            )
            record.status_code = raw_response.status
            record.final_url = url
            return response
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            record.error = f"{exc.__class__.__name__}: {exc}"
            raise ProbeError(record.error) from exc
        finally:
            record.elapsed_ms = int((time.monotonic() - started) * 1000)
            self._records.append(record)
            if connection is not None:
                connection.close()

    def _connection(
        self,
        scheme: str,
        host: str,
        port: int | None,
    ) -> http.client.HTTPConnection | http.client.HTTPSConnection:
        timeout = self._config.timeout_seconds
        if scheme == "https":
            ssl_context = ssl.create_default_context() if self._config.verify_tls else ssl._create_unverified_context()
            return http.client.HTTPSConnection(host, port or 443, timeout=timeout, context=ssl_context)
        return http.client.HTTPConnection(host, port or 80, timeout=timeout)
