from __future__ import annotations

from dataclasses import dataclass, field

from .auth import auth_request_headers
from .config import AuditConfig
from .http_probe import HttpProbe, SimpleResponse
from .models import HTTPRequestRecord, ModuleResult, Target


@dataclass
class ScanContext:
    target: Target
    config: AuditConfig
    requests: list[HTTPRequestRecord] = field(default_factory=list)
    module_results: list[ModuleResult] = field(default_factory=list)
    final_response: SimpleResponse | None = None
    response_error: str | None = None

    @property
    def probe(self) -> HttpProbe:
        return HttpProbe(
            self.config.http,
            self.requests,
            self.config.evidence,
            default_headers=auth_request_headers(self.config),
        )
