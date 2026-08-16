# Web Audit Report - example.com

- Generated: 2026-08-16T00:51:47Z
- Report generator: ai-web-auditor 0.15.0
- Scan version: 0.15.0
- Scan status: completed

## Target

| Field | Value |
| --- | --- |
| Original URL | https://example.com |
| Normalized URL | https://example.com/ |
| Host | example.com |
| Scheme | https |
| Port | 443 |

## Executive Summary

The scan generated 2 finding(s): 0 critical, 0 high, 0 medium, 0 low and 2 informational.

## Severity Summary

| Severity | Count |
| --- | ---: |
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 2 |

## Risk Assessment

- Risk level: **INFORMATIONAL**
- Risk score: **13/100**
- Priorities: 2
- Quick wins: 0

### Coverage

| Metric | Value |
| --- | ---: |
| Modules run | 4 |
| Module warnings | 2 |
| Module errors | 0 |
| URLs | 2 |
| Forms | 0 |
| Resolved subdomains | 1 |
| Open TCP ports | 1 |

### Priorities

| Rank | Severity | Finding | Reason | Recommended action |
| ---: | --- | --- | --- | --- |
| 1 | INFO | PORTS-OPEN-TCP-PORTS: Open TCP ports detected | additional exposed services increase the review surface | Review whether each exposed service is expected, patched and covered by the authorized audit scope. |
| 2 | INFO | SUBDOMAIN-DISCOVERY-RESOLVED: In-scope subdomains resolved by DNS | info finding reported by the subdomains module | Review these hosts and add them explicitly to the authorized scope before running deeper checks against them. |

### Remediation Plan

#### Immediate

Reduce the highest observable risk first.

- Open TCP ports detected: Review whether each exposed service is expected, patched and covered by the authorized audit scope.
- Review every open TCP port and confirm it is required for the approved scope.

#### Short term

Apply low-effort hardening and validation.

- Review medium and low hardening items if more evidence is added later.

#### Planned

Improve evidence quality and follow-up coverage.

- In-scope subdomains resolved by DNS: Review these hosts and add them explicitly to the authorized scope before running deeper checks against them.

### Coverage Notes

- subdomains: warning - Checked 3 candidate subdomain(s), resolved 1 in-scope host(s).
- ports: warning - Checked 3 TCP port(s), found 1 open port(s).
- Resolved subdomains were recorded as evidence but not scanned automatically.
- Open TCP ports were detected using TCP connect checks only; no payloads or banners were requested.

### Safety Notes

- This assessment is generated from existing non-intrusive scan evidence only.
- No exploitation, brute force, fuzzing or destructive validation was performed.
- Risk should be reviewed against the authorized scope and business context.

## Module Summary

| Module | Status | Summary |
| --- | --- | --- |
| fingerprinting | passed | Identified 0 technology signal(s) and checked 4 public metadata path(s). |
| crawler | passed | Crawled 1 page(s), discovered 2 in-scope URL(s). |
| subdomains | warning | Checked 3 candidate subdomain(s), resolved 1 in-scope host(s). |
| ports | warning | Checked 3 TCP port(s), found 1 open port(s). |

## Findings

### INFO - Open TCP ports detected

- ID: `PORTS-OPEN-TCP-PORTS`
- Category: network-exposure
- Module: `ports`
- Target: `example.com`

**Description**

The limited TCP connectivity check found open ports on the target host. This is inventory evidence, not exploitation.

**Recommendation**

Review whether each exposed service is expected, patched and covered by the authorized audit scope.

**Evidence**

- open_port (https): `443`

### INFO - In-scope subdomains resolved by DNS

- ID: `SUBDOMAIN-DISCOVERY-RESOLVED`
- Category: reconnaissance
- Module: `subdomains`
- Target: `example.com`

**Description**

The scan resolved one or more candidate subdomains inside the configured scope. They were recorded but not audited automatically.

**Recommendation**

Review these hosts and add them explicitly to the authorized scope before running deeper checks against them.

**Evidence**

- host (93.184.216.35): `api.example.com`

## Technology Fingerprinting

No technology signals were identified.

### Public Metadata Files

| Path | Status | Present |
| --- | ---: | --- |
| /robots.txt | 404 | False |
| /.well-known/security.txt | 404 | False |
| /security.txt | 404 | False |
| /sitemap.xml | 404 | False |

## Crawler

- Seed URL: `https://example.com/`
- Max depth: 1
- Max pages: 25
- Fetched URLs: 1
- Discovered in-scope URLs: 2
- Out-of-scope URLs recorded but not visited: 0
- Excluded URLs recorded but not visited: 0

### Discovered URLs

- `https://example.com/`
- `https://example.com/login`

## Web Inventory

- Total URLs: 2
- Fetched URLs: 1
- Interesting URLs: 1
- Forms detected: 0
- Out-of-scope URLs recorded but not visited: 0
- Excluded URLs recorded but not visited: 0

### URL Inventory

| URL | Status | Type | Forms | Interest |
| --- | ---: | --- | ---: | --- |
| https://example.com/login | unknown | unknown | 0 | login_path |
| https://example.com/ | 200 | text/html | 0 | unknown |

## Subdomain Discovery

- Candidate hosts checked: 3
- Resolved in-scope hosts: 1
- Unresolved candidates: 2
- Out-of-scope candidates skipped: 0
- Resolved hosts were not scanned automatically.

### Resolved Subdomains

| Host | IP Addresses | Source |
| --- | --- | --- |
| api.example.com | 93.184.216.35 | dns_candidate |

## TCP Port Check

- Host: `example.com`
- Ports checked: 3
- Open ports: 1
- Closed ports: 1
- Filtered ports: 1
- Only TCP connect checks were performed; no payloads or banners were requested.

| Port | Service | Status | Elapsed |
| ---: | --- | --- | ---: |
| 80 | http | closed | 8 ms |
| 443 | https | open | 5 ms |
| 8080 | http-alt | filtered | 1000 ms |

## Limitations

- This report is based on non-intrusive checks only.
- No exploitation, brute force, aggressive fuzzing or destructive testing was performed.
- Findings should be validated against the authorized scope and business context.
