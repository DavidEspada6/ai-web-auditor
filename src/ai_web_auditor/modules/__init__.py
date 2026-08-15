from .basic_auth import BasicAuthModule
from .cookies import CookiesModule
from .crawler import CrawlerModule
from .http_methods import HTTPMethodsModule
from .http_redirects import HTTPRedirectsModule
from .scope import ScopeModule
from .security_headers import SecurityHeadersModule
from .tls_basic import TLSBasicModule

__all__ = [
    "BasicAuthModule",
    "CookiesModule",
    "CrawlerModule",
    "HTTPMethodsModule",
    "HTTPRedirectsModule",
    "ScopeModule",
    "SecurityHeadersModule",
    "TLSBasicModule",
]
