# AI Web Auditor Lab Report

- Generated: 2026-08-27T15:30:31Z
- Report generator: ai-web-auditor 0.19.0
- Scan version: 0.19.0
- Scan status: completed

## Target

| Field | Value |
| --- | --- |
| Original URL | http://127.0.0.1:56147/members/ |
| Normalized URL | http://127.0.0.1:56147/members/ |
| Host | 127.0.0.1 |
| Scheme | http |
| Port | 56147 |

## Engagement

| Field | Value |
| --- | --- |
| Client | Practica Evolve |
| Auditor | David |
| Engagement | Demo v0.19.0 |
| Scope summary | http://127.0.0.1:56147/members/ |
| Notes | Laboratorio local controlado en localhost. |

## Executive Summary

The scan generated 19 finding(s): 0 critical, 3 high, 4 medium, 6 low and 6 informational.

## Severity Summary

| Severity | Count |
| --- | ---: |
| CRITICAL | 0 |
| HIGH | 3 |
| MEDIUM | 4 |
| LOW | 6 |
| INFO | 6 |

## Risk Assessment

- Risk level: **HIGH**
- Risk score: **89/100**
- Priorities: 10
- Quick wins: 8

### Coverage

| Metric | Value |
| --- | ---: |
| Modules run | 9 |
| Module warnings | 8 |
| Module errors | 0 |
| URLs | 23 |
| Forms | 2 |
| Entry points | 23 |
| Entry point parameters | 4 |
| State-changing entry points | 3 |
| Resolved subdomains | 0 |
| Open TCP ports | 1 |

### Priorities

| Rank | Severity | Finding | Reason | Recommended action |
| ---: | --- | --- | --- | --- |
| 1 | HIGH | AUTH-BASIC-OVER-HTTP: HTTP Basic Authentication over HTTP | credentials may be exposed before transport security is enforced | Force HTTPS before authentication and enable HSTS after validation. |
| 2 | HIGH | HTTP-NO-HTTPS-REDIRECT: HTTP is not redirected to HTTPS | unencrypted HTTP remains reachable for the same service | Redirect all HTTP traffic to HTTPS and consider enabling HSTS after verification. |
| 3 | HIGH | METHOD-TRACE-ADVERTISED: HTTP method TRACE is advertised | an unnecessary HTTP method is advertised by the server | Disable unnecessary HTTP methods or enforce strict authorization before use. |
| 4 | MEDIUM | METHOD-DELETE-ADVERTISED: HTTP method DELETE is advertised | medium finding reported by the http_methods module | Disable unnecessary HTTP methods or enforce strict authorization before use. |
| 5 | MEDIUM | METHOD-PUT-ADVERTISED: HTTP method PUT is advertised | medium finding reported by the http_methods module | Disable unnecessary HTTP methods or enforce strict authorization before use. |
| 6 | MEDIUM | COOKIE-SAMESITE-NONE-WITHOUT-SECURE: Cookie uses SameSite=None without Secure | medium finding reported by the cookies module | Set Secure or avoid SameSite=None if cross-site usage is not required. |
| 7 | MEDIUM | HEADER-CONTENT_SECURITY_POLICY-MISSING: Content-Security-Policy header is missing | medium finding reported by the security_headers module | Define an appropriate Content-Security-Policy header for this application. |
| 8 | LOW | COOKIE-HTTPONLY-MISSING: Cookie missing HttpOnly flag | client-side scripts may access cookies without HttpOnly | Set HttpOnly for session or sensitive cookies. |
| 9 | LOW | COOKIE-HTTPONLY-MISSING: Cookie missing HttpOnly flag | client-side scripts may access cookies without HttpOnly | Set HttpOnly for session or sensitive cookies. |
| 10 | LOW | COOKIE-SAMESITE-MISSING: Cookie missing SameSite attribute | low finding reported by the cookies module | Set SameSite=Lax or SameSite=Strict unless cross-site usage is required. |

### Quick Wins

- **HTTP is not redirected to HTTPS**: Redirect all HTTP traffic to HTTPS and consider enabling HSTS after verification.
- **Content-Security-Policy header is missing**: Define an appropriate Content-Security-Policy header for this application.
- **Clickjacking protection header is missing**: Set frame-ancestors in Content-Security-Policy or use X-Frame-Options where appropriate.
- **X-Content-Type-Options nosniff is missing**: Set X-Content-Type-Options: nosniff.
- **Referrer-Policy header is missing**: Define an appropriate Referrer-Policy header for this application.
- **Cookie missing HttpOnly flag**: Set HttpOnly for session or sensitive cookies.
- **Cookie missing SameSite attribute**: Set SameSite=Lax or SameSite=Strict unless cross-site usage is required.
- **Cookie missing HttpOnly flag**: Set HttpOnly for session or sensitive cookies.

### Remediation Plan

#### Immediate

Reduce the highest observable risk first.

- HTTP Basic Authentication over HTTP: Force HTTPS before authentication and enable HSTS after validation.
- HTTP is not redirected to HTTPS: Redirect all HTTP traffic to HTTPS and consider enabling HSTS after verification.
- HTTP method TRACE is advertised: Disable unnecessary HTTP methods or enforce strict authorization before use.
- Cookie missing HttpOnly flag: Set HttpOnly for session or sensitive cookies.
- Review every open TCP port and confirm it is required for the approved scope.

#### Short term

Apply low-effort hardening and validation.

- HTTP method DELETE is advertised: Disable unnecessary HTTP methods or enforce strict authorization before use.
- HTTP method PUT is advertised: Disable unnecessary HTTP methods or enforce strict authorization before use.
- Cookie uses SameSite=None without Secure: Set Secure or avoid SameSite=None if cross-site usage is not required.
- Content-Security-Policy header is missing: Define an appropriate Content-Security-Policy header for this application.
- HTTP is not redirected to HTTPS: Redirect all HTTP traffic to HTTPS and consider enabling HSTS after verification.
- Clickjacking protection header is missing: Set frame-ancestors in Content-Security-Policy or use X-Frame-Options where appropriate.
- X-Content-Type-Options nosniff is missing: Set X-Content-Type-Options: nosniff.
- Referrer-Policy header is missing: Define an appropriate Referrer-Policy header for this application.

#### Planned

Improve evidence quality and follow-up coverage.

- Cookie missing SameSite attribute: Set SameSite=Lax or SameSite=Strict unless cross-site usage is required.

### Coverage Notes

- http: warning - HTTP/HTTPS reachability and redirects checked.
- security_headers: warning - Security headers checked.
- cookies: warning - Checked 2 cookie(s).
- basic_auth: warning - HTTP authentication challenge checked.
- http_methods: warning - HTTP methods advertised by OPTIONS checked.
- ports: warning - Checked 3 TCP port(s), found 1 open port(s).
- fingerprinting: warning - Identified 4 technology signal(s) and checked 4 public metadata path(s).
- crawler: warning - Crawled 5 page(s), discovered 9 in-scope URL(s), 9 from metadata.
- HTML forms were identified passively; no form submission was performed.
- Entry points were derived from passive evidence: URLs, query strings, forms and advertised HTTP methods.
- State-changing entry points were inferred from methods or form actions; no request bodies were sent.
- Some entry point parameters have sensitive-looking names and should be reviewed without exposing their values.
- Open TCP ports were detected using TCP connect checks only; no payloads or banners were requested.

### Safety Notes

- This assessment is generated from existing non-intrusive scan evidence only.
- No exploitation, brute force, fuzzing or destructive validation was performed.
- Risk should be reviewed against the authorized scope and business context.

## Module Summary

| Module | Status | Summary |
| --- | --- | --- |
| scope | passed | Target URL validated and inside configured scope. |
| http | warning | HTTP/HTTPS reachability and redirects checked. |
| security_headers | warning | Security headers checked. |
| cookies | warning | Checked 2 cookie(s). |
| basic_auth | warning | HTTP authentication challenge checked. |
| http_methods | warning | HTTP methods advertised by OPTIONS checked. |
| ports | warning | Checked 3 TCP port(s), found 1 open port(s). |
| fingerprinting | warning | Identified 4 technology signal(s) and checked 4 public metadata path(s). |
| crawler | warning | Crawled 5 page(s), discovered 9 in-scope URL(s), 9 from metadata. |

## Findings

### HIGH - HTTP Basic Authentication over HTTP

- ID: `AUTH-BASIC-OVER-HTTP`
- Category: authentication
- Module: `basic_auth`
- Target: `http://127.0.0.1:56147/members/`

**Description**

The server requests Basic Authentication over unencrypted HTTP.

**Recommendation**

Force HTTPS before authentication and enable HSTS after validation.

**Evidence**

- status_code: `401`
- www-authenticate: `Basic realm="AI Web Auditor Lab"`

### HIGH - HTTP is not redirected to HTTPS

- ID: `HTTP-NO-HTTPS-REDIRECT`
- Category: transport-security
- Module: `http`
- Target: `http://127.0.0.1:56147/members/`

**Description**

The requested HTTP URL remains available without being upgraded to HTTPS.

**Recommendation**

Redirect all HTTP traffic to HTTPS and consider enabling HSTS after verification.

**Evidence**

- initial_url: `http://127.0.0.1:56147/members/`
- final_url: `http://127.0.0.1:56147/members/`
- status_code: `401`

### HIGH - HTTP method TRACE is advertised

- ID: `METHOD-TRACE-ADVERTISED`
- Category: http-methods
- Module: `http_methods`
- Target: `http://127.0.0.1:56147/members/`

**Description**

TRACE can expose request data and is rarely needed.

**Recommendation**

Disable unnecessary HTTP methods or enforce strict authorization before use.

**Evidence**

- allow: `GET, POST, OPTIONS, PUT, DELETE, TRACE`
- access-control-allow-methods: `GET, POST, OPTIONS, PUT, DELETE, TRACE`

### MEDIUM - Cookie uses SameSite=None without Secure

- ID: `COOKIE-SAMESITE-NONE-WITHOUT-SECURE`
- Category: cookies
- Module: `cookies`
- Target: `http://127.0.0.1:56147/members/`

**Description**

SameSite=None cookies should also use Secure.

**Recommendation**

Set Secure or avoid SameSite=None if cross-site usage is not required.

**Evidence**

- cookie: `tracking_id`

### MEDIUM - Content-Security-Policy header is missing

- ID: `HEADER-CONTENT_SECURITY_POLICY-MISSING`
- Category: security-headers
- Module: `security_headers`
- Target: `http://127.0.0.1:56147/members/`

**Description**

The response does not include the Content-Security-Policy header.

**Recommendation**

Define an appropriate Content-Security-Policy header for this application.

### MEDIUM - HTTP method DELETE is advertised

- ID: `METHOD-DELETE-ADVERTISED`
- Category: http-methods
- Module: `http_methods`
- Target: `http://127.0.0.1:56147/members/`

**Description**

DELETE may allow destructive actions if authorization is weak.

**Recommendation**

Disable unnecessary HTTP methods or enforce strict authorization before use.

**Evidence**

- allow: `GET, POST, OPTIONS, PUT, DELETE, TRACE`
- access-control-allow-methods: `GET, POST, OPTIONS, PUT, DELETE, TRACE`

### MEDIUM - HTTP method PUT is advertised

- ID: `METHOD-PUT-ADVERTISED`
- Category: http-methods
- Module: `http_methods`
- Target: `http://127.0.0.1:56147/members/`

**Description**

PUT may allow content upload if authorization is weak.

**Recommendation**

Disable unnecessary HTTP methods or enforce strict authorization before use.

**Evidence**

- allow: `GET, POST, OPTIONS, PUT, DELETE, TRACE`
- access-control-allow-methods: `GET, POST, OPTIONS, PUT, DELETE, TRACE`

### LOW - Cookie missing HttpOnly flag

- ID: `COOKIE-HTTPONLY-MISSING`
- Category: cookies
- Module: `cookies`
- Target: `http://127.0.0.1:56147/members/`

**Description**

A cookie is accessible to client-side scripts when HttpOnly is absent.

**Recommendation**

Set HttpOnly for session or sensitive cookies.

**Evidence**

- cookie: `sessionid`

### LOW - Cookie missing HttpOnly flag

- ID: `COOKIE-HTTPONLY-MISSING`
- Category: cookies
- Module: `cookies`
- Target: `http://127.0.0.1:56147/members/`

**Description**

A cookie is accessible to client-side scripts when HttpOnly is absent.

**Recommendation**

Set HttpOnly for session or sensitive cookies.

**Evidence**

- cookie: `tracking_id`

### LOW - Cookie missing SameSite attribute

- ID: `COOKIE-SAMESITE-MISSING`
- Category: cookies
- Module: `cookies`
- Target: `http://127.0.0.1:56147/members/`

**Description**

A cookie does not declare a SameSite policy.

**Recommendation**

Set SameSite=Lax or SameSite=Strict unless cross-site usage is required.

**Evidence**

- cookie: `sessionid`

### LOW - Clickjacking protection header is missing

- ID: `HEADER-CLICKJACKING-MISSING`
- Category: security-headers
- Module: `security_headers`
- Target: `http://127.0.0.1:56147/members/`

**Description**

The response does not include X-Frame-Options or a CSP frame-ancestors directive.

**Recommendation**

Set frame-ancestors in Content-Security-Policy or use X-Frame-Options where appropriate.

### LOW - X-Content-Type-Options nosniff is missing

- ID: `HEADER-NOSNIFF-MISSING`
- Category: security-headers
- Module: `security_headers`
- Target: `http://127.0.0.1:56147/members/`

**Description**

The browser may try to infer content types when nosniff is absent.

**Recommendation**

Set X-Content-Type-Options: nosniff.

**Evidence**

- x-content-type-options: `missing`

### LOW - Referrer-Policy header is missing

- ID: `HEADER-REFERRER_POLICY-MISSING`
- Category: security-headers
- Module: `security_headers`
- Target: `http://127.0.0.1:56147/members/`

**Description**

The response does not include the Referrer-Policy header.

**Recommendation**

Define an appropriate Referrer-Policy header for this application.

### INFO - Crawler found links outside scope

- ID: `CRAWLER-OUT-OF-SCOPE-LINKS`
- Category: crawler
- Module: `crawler`
- Target: `http://127.0.0.1:56147/members/`

**Description**

The crawler discovered links outside the configured scope. They were recorded but not requested.

**Recommendation**

Review whether any external host should be added to the authorized scope before scanning it.

**Evidence**

- sample_url: `https://example.org/external`

### INFO - HTML generator metadata is exposed

- ID: `FINGERPRINT-GENERATOR-DISCLOSED`
- Category: fingerprinting
- Module: `fingerprinting`
- Target: `http://127.0.0.1:56147/members/`

**Description**

The HTML generator metadata can disclose CMS or framework details.

**Recommendation**

Remove generator metadata if it is not required.

**Evidence**

- generator: `WordPress 4.7.0`

### INFO - X-Powered-By header discloses technology information

- ID: `FINGERPRINT-POWERED-BY-DISCLOSED`
- Category: fingerprinting
- Module: `fingerprinting`
- Target: `http://127.0.0.1:56147/members/`

**Description**

The X-Powered-By header can reveal backend technology details to attackers.

**Recommendation**

Remove or reduce technology-identifying response headers where practical.

**Evidence**

- x-powered-by: `PHP/5.6.40`

### INFO - Server header discloses version information

- ID: `FINGERPRINT-SERVER-VERSION-DISCLOSED`
- Category: fingerprinting
- Module: `fingerprinting`
- Target: `http://127.0.0.1:56147/members/`

**Description**

The Server header appears to include product version information.

**Recommendation**

Avoid exposing precise server versions unless there is an operational reason.

**Evidence**

- server: `AIWebAuditorLab/0.19`

### INFO - Permissions-Policy header is missing

- ID: `HEADER-PERMISSIONS_POLICY-MISSING`
- Category: security-headers
- Module: `security_headers`
- Target: `http://127.0.0.1:56147/members/`

**Description**

The response does not include the Permissions-Policy header.

**Recommendation**

Define an appropriate Permissions-Policy header for this application.

### INFO - Open TCP ports detected

- ID: `PORTS-OPEN-TCP-PORTS`
- Category: network-exposure
- Module: `ports`
- Target: `127.0.0.1`

**Description**

The limited TCP connectivity check found open ports on the target host. This is inventory evidence, not exploitation.

**Recommendation**

Review whether each exposed service is expected, patched and covered by the authorized audit scope.

**Evidence**

- open_port: `56147`

## Technology Fingerprinting

| Technology | Category | Confidence | Signals |
| --- | --- | --- | --- |
| AIWebAuditorLab/0.19 | server | low | header:server |
| Django | framework | medium | cookie:sessionid |
| PHP 5.6.40 | language | high | header:x-powered-by |
| WordPress 4.7.0 | cms | high | html:meta-generator |

### Public Metadata Files

| Path | Status | Present |
| --- | ---: | --- |
| /robots.txt | 200 | True |
| /.well-known/security.txt | 200 | True |
| /security.txt | 404 | False |
| /sitemap.xml | 200 | True |

## Crawler

- Seed URL: `http://127.0.0.1:56147/members/`
- Max depth: 1
- Max pages: 20
- Fetched URLs: 5
- Discovered in-scope URLs: 9
- Metadata-discovered URLs: 9
- Classified interesting routes: 6
- robots.txt: present (200)
- Sitemaps checked: 1 (1 present)
- .well-known endpoints checked: 8 (2 present)
- Out-of-scope URLs recorded but not visited: 1
- Excluded URLs recorded but not visited: 3

### Interesting Routes

| URL | Types | Sources |
| --- | --- | --- |
| http://127.0.0.1:56147/api/users | api | crawler_fetched, sitemap |
| http://127.0.0.1:56147/login | form, login | crawler_fetched, sitemap |
| http://127.0.0.1:56147/members/ | account, form, login | crawler_fetched, html_link, robots_allow, seed, sitemap |
| http://127.0.0.1:56147/oauth/authorize | callback, login | well_known_endpoint |
| http://127.0.0.1:56147/oauth/token | callback | well_known_endpoint |
| http://127.0.0.1:56147/reset-password | password_reset | crawler_fetched, sitemap |

### Present .well-known Endpoints

| Path | Status | Highlights |
| --- | ---: | --- |
| /.well-known/security.txt | 200 | contact: mailto:security@example.test; policy: http://127.0.0.1/security-policy |
| /.well-known/openid-configuration | 200 | endpoints: 2 |

### Discovered URLs

- `http://127.0.0.1:56147/`
- `http://127.0.0.1:56147/.well-known/openid-configuration`
- `http://127.0.0.1:56147/.well-known/security.txt`
- `http://127.0.0.1:56147/api/users`
- `http://127.0.0.1:56147/login`
- `http://127.0.0.1:56147/members/`
- `http://127.0.0.1:56147/oauth/authorize`
- `http://127.0.0.1:56147/oauth/token`
- `http://127.0.0.1:56147/reset-password`

### Out-of-Scope URLs

- `https://example.org/external`

### Excluded URLs

- `http://127.0.0.1:56147/admin/`
- `http://127.0.0.1:56147/private/`
- `http://127.0.0.1:56147/private/report`

## Web Inventory

- Total URLs: 23
- Fetched URLs: 15
- Interesting URLs: 13
- Forms detected: 2
- Out-of-scope URLs recorded but not visited: 1
- Excluded URLs recorded but not visited: 3

### URL Inventory

| URL | Status | Type | Forms | Interest |
| --- | ---: | --- | ---: | --- |
| http://127.0.0.1:56147/.well-known/change-password | 404 | unknown | 0 | password_reset, password_reset_path |
| http://127.0.0.1:56147/.well-known/oauth-authorization-server | 404 | unknown | 0 | callback, callback_path |
| http://127.0.0.1:56147/admin/ | unknown | unknown | 0 | admin, admin_path |
| http://127.0.0.1:56147/api/users | 200 | application/json; charset=utf-8 | 0 | api, api_path |
| http://127.0.0.1:56147/login | 200 | text/html; charset=utf-8 | 1 | form, login, login_path, form_detected |
| http://127.0.0.1:56147/login/ | unknown | unknown | 0 | login, state_changing_candidate, login_path, post_method |
| http://127.0.0.1:56147/members/ | 401 | text/html; charset=utf-8 | 1 | account, form, login, login_path, account_area, form_detected |
| http://127.0.0.1:56147/oauth/authorize | unknown | unknown | 0 | callback, login, login_path, callback_path |
| http://127.0.0.1:56147/oauth/token | unknown | unknown | 0 | callback, callback_path |
| http://127.0.0.1:56147/private/ | unknown | unknown | 0 | account, account_area |
| http://127.0.0.1:56147/private/report | unknown | unknown | 0 | account, account_area |
| http://127.0.0.1:56147/reset-password | 200 | text/html; charset=utf-8 | 0 | password_reset, password_reset_path |
| http://127.0.0.1:56147/session | unknown | unknown | 0 | login, state_changing_candidate, login_path, post_method |
| http://127.0.0.1:56147/ | 200 | text/html; charset=utf-8 | 0 | unknown |
| http://127.0.0.1:56147/.well-known/openid-configuration | 200 | unknown | 0 | unknown |
| http://127.0.0.1:56147/.well-known/security.txt | 200 | unknown | 0 | unknown |
| https://example.org/external | unknown | unknown | 0 | unknown |
| http://127.0.0.1:56147/.well-known/apple-app-site-association | 404 | unknown | 0 | unknown |
| http://127.0.0.1:56147/.well-known/assetlinks.json | 404 | unknown | 0 | unknown |
| http://127.0.0.1:56147/.well-known/webfinger | 404 | unknown | 0 | unknown |
| http://127.0.0.1:56147/robots.txt | 200 | unknown | 0 | unknown |
| http://127.0.0.1:56147/security.txt | 404 | unknown | 0 | unknown |
| http://127.0.0.1:56147/sitemap.xml | 200 | unknown | 0 | unknown |

### Forms

| Page | Action | Method | Inputs | Password Fields |
| --- | --- | --- | ---: | ---: |
| http://127.0.0.1:56147/login | http://127.0.0.1:56147/session | POST | 2 | 1 |
| http://127.0.0.1:56147/members/ | http://127.0.0.1:56147/login/ | POST | 3 | 1 |

## Entry Points

- Endpoints: 23
- Review candidates: 19
- Forms: 2
- Parameters: 4
- State-changing endpoints: 3

Only passive evidence was used: URLs, query strings, forms and advertised HTTP methods. No form submission was performed.

### HTTP Methods Observed

| Method | Endpoints | State-changing |
| --- | ---: | --- |
| DELETE | 1 | True |
| GET | 15 | False |
| OPTIONS | 1 | False |
| POST | 3 | True |
| PUT | 1 | True |
| TRACE | 1 | False |

### Endpoint Review List

| URL | State | Methods | Parameters | Forms | Route types | Notes |
| --- | --- | --- | --- | ---: | --- | --- |
| http://127.0.0.1:56147/login/ | form_action | POST | csrf_token, password, username | 1 | login, state_changing_candidate | form_action, login_route, parameters_observed, sensitive_parameter_name, state_changing_method |
| http://127.0.0.1:56147/session | form_action | POST | password, user | 1 | login, state_changing_candidate | form_action, login_route, parameters_observed, sensitive_parameter_name, state_changing_method |
| http://127.0.0.1:56147/members/ | fetched | DELETE, GET, OPTIONS, POST, PUT, TRACE | unknown | 0 | account, form, login | login_route, state_changing_method |
| http://127.0.0.1:56147/ | fetched | GET | unknown | 0 | unknown | unknown |
| http://127.0.0.1:56147/.well-known/apple-app-site-association | fetched | GET | unknown | 0 | unknown | unknown |
| http://127.0.0.1:56147/.well-known/assetlinks.json | fetched | GET | unknown | 0 | unknown | unknown |
| http://127.0.0.1:56147/.well-known/change-password | fetched | GET | unknown | 0 | password_reset | password_reset_route |
| http://127.0.0.1:56147/.well-known/oauth-authorization-server | fetched | GET | unknown | 0 | callback | callback_route |
| http://127.0.0.1:56147/.well-known/openid-configuration | fetched | GET | unknown | 0 | unknown | unknown |
| http://127.0.0.1:56147/.well-known/security.txt | fetched | GET | unknown | 0 | unknown | unknown |
| http://127.0.0.1:56147/.well-known/webfinger | fetched | GET | unknown | 0 | unknown | unknown |
| http://127.0.0.1:56147/api/users | fetched | GET | unknown | 0 | api | api_route |
| http://127.0.0.1:56147/login | fetched | GET | unknown | 0 | form, login | login_route |
| http://127.0.0.1:56147/oauth/authorize | metadata | unknown | unknown | 0 | callback, login | callback_route, login_route |
| http://127.0.0.1:56147/oauth/token | metadata | unknown | unknown | 0 | callback | callback_route |
| http://127.0.0.1:56147/reset-password | fetched | GET | unknown | 0 | password_reset | password_reset_route |
| http://127.0.0.1:56147/robots.txt | fetched | GET | unknown | 0 | unknown | unknown |
| http://127.0.0.1:56147/security.txt | fetched | GET | unknown | 0 | unknown | unknown |
| http://127.0.0.1:56147/sitemap.xml | fetched | GET | unknown | 0 | unknown | unknown |
| http://127.0.0.1:56147/admin/ | excluded | unknown | unknown | 0 | admin | admin_route |
| http://127.0.0.1:56147/private/ | excluded | unknown | unknown | 0 | account | unknown |
| http://127.0.0.1:56147/private/report | excluded | unknown | unknown | 0 | account | unknown |
| https://example.org/external | out_of_scope | unknown | unknown | 0 | unknown | unknown |

### Form Entry Points

| Page | Action | Method | Inputs | Password fields | CSRF candidates |
| --- | --- | --- | ---: | ---: | --- |
| http://127.0.0.1:56147/login | http://127.0.0.1:56147/session | POST | 2 | 1 | unknown |
| http://127.0.0.1:56147/members/ | http://127.0.0.1:56147/login/ | POST | 3 | 1 | csrf_token |

### Sensitive-Looking Parameters

| Parameter | Locations | Occurrences | Methods |
| --- | --- | ---: | --- |
| csrf_token | form | 1 | POST |
| password | form | 2 | POST |

## TCP Port Check

- Host: `127.0.0.1`
- Ports checked: 3
- Open ports: 1
- Closed ports: 0
- Filtered ports: 2
- Only TCP connect checks were performed; no payloads or banners were requested.

| Port | Service | Status | Elapsed |
| ---: | --- | --- | ---: |
| 56147 | unknown | open | 0 ms |
| 80 | http | filtered | 515 ms |
| 443 | https | filtered | 500 ms |

## Limitations

- This report is based on non-intrusive checks only.
- No exploitation, brute force, aggressive fuzzing or destructive testing was performed.
- Findings should be validated against the authorized scope and business context.
