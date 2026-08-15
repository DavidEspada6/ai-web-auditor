from __future__ import annotations

from ai_web_auditor.context import ScanContext
from ai_web_auditor.models import ModuleResult


class ScopeModule:
    name = "scope"

    def run(self, context: ScanContext) -> ModuleResult:
        target = context.target
        return ModuleResult(
            name=self.name,
            status="passed",
            summary="Target URL validated and inside configured scope.",
            artifacts={
                "normalized_url": target.normalized_url,
                "host": target.host,
                "scheme": target.scheme,
                "port": target.port,
                "ip_addresses": target.ip_addresses,
                "allowed_hosts": context.config.scope.allowed_hosts or [target.host],
                "allow_subdomains": context.config.scope.allow_subdomains,
                "allow_private_networks": context.config.scope.allow_private_networks,
            },
        )
