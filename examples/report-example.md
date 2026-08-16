# Web Audit Report - example.com

- Generated: 2026-08-16T00:25:10Z
- Report generator: ai-web-auditor 0.13.0
- Scan version: 0.13.0
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

La auditoria no intrusiva no muestra hallazgos criticos en la muestra, pero conviene revisar las cabeceras y metadatos expuestos.

Overall risk: **low**

Los hallazgos son principalmente informativos o de endurecimiento defensivo.

## Severity Summary

| Severity | Count |
| --- | ---: |
| CRITICAL | 0 |
| HIGH | 0 |
| MEDIUM | 0 |
| LOW | 0 |
| INFO | 1 |

## Module Summary

| Module | Status | Summary |
| --- | --- | --- |
| fingerprinting | passed | Identified 0 technology signal(s) and checked 4 public metadata path(s). |
| crawler | passed | Crawled 1 page(s), discovered 2 in-scope URL(s). |
| subdomains | warning | Checked 3 candidate subdomain(s), resolved 1 in-scope host(s). |

## Findings

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

## AI Prioritization

### 1. Cabeceras de seguridad incompletas

- Severity: low
- Why it matters: Las cabeceras defensivas reducen la exposicion ante ataques comunes del navegador.
- Recommended action: Definir una politica CSP adaptada a la aplicacion.

Evidence:

- HEADER-CONTENT_SECURITY_POLICY-MISSING

## Safe Next Steps

- Revisar manualmente las cabeceras recomendadas antes de aplicarlas en produccion.
- Ejecutar de nuevo el escaneo tras corregir la configuracion.

## Report Notes

- El analisis esta basado solo en evidencias del JSON generado por la herramienta.

## Limitations

- This report is based on non-intrusive checks only.
- No exploitation, brute force, aggressive fuzzing or destructive testing was performed.
- Findings should be validated against the authorized scope and business context.
- No se han realizado pruebas autenticadas ni intrusivas.
