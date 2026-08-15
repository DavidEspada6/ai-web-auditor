class AuditError(Exception):
    """Base exception for controlled audit failures."""


class ScopeError(AuditError):
    """Raised when the target is invalid or outside the allowed scope."""


class ProbeError(AuditError):
    """Raised when an HTTP or TLS probe cannot complete."""


class AIError(AuditError):
    """Raised when AI analysis cannot complete."""
