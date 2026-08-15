from __future__ import annotations

from typing import Protocol

from ai_web_auditor.context import ScanContext
from ai_web_auditor.models import ModuleResult


class AuditModule(Protocol):
    name: str

    def run(self, context: ScanContext) -> ModuleResult:
        ...
