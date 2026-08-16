from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


Severity = str
Status = str


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass
class Evidence:
    label: str
    value: str
    location: str | None = None


@dataclass
class Finding:
    id: str
    title: str
    severity: Severity
    category: str
    description: str
    recommendation: str
    module: str
    target: str
    evidence: list[Evidence] = field(default_factory=list)


@dataclass
class Target:
    original_url: str
    normalized_url: str
    scheme: str
    host: str
    port: int
    base_url: str
    ip_addresses: list[str] = field(default_factory=list)


@dataclass
class HTTPRequestRecord:
    method: str
    url: str
    status_code: int | None
    elapsed_ms: int | None
    final_url: str | None = None
    error: str | None = None


@dataclass
class ModuleResult:
    name: str
    status: Status
    summary: str
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    tool: str
    version: str
    generated_at: str
    status: Status
    target: Target
    modules: list[ModuleResult]
    requests: list[HTTPRequestRecord] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        output: list[Finding] = []
        for module in self.modules:
            output.extend(module.findings)
        return output

    def to_dict(self) -> dict[str, Any]:
        from .assessment import build_assessment
        from .inventory import build_inventory_from_scan

        data = asdict(self)
        data["findings"] = [asdict(finding) for finding in self.findings]
        data["inventory"] = build_inventory_from_scan(data)
        data["assessment"] = build_assessment(data)
        return data

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=True)


@dataclass
class AIAnalysisResult:
    tool: str
    version: str
    generated_at: str
    provider: str
    model: str
    source_file: str
    status: Status
    analysis: dict[str, Any]
    raw_text: str = ""
    redacted: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=True)
