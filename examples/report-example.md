# Web Audit Report - example.com

- Generated: 2026-08-16T00:00:00Z
- Report generator: ai-web-auditor 0.5.0
- Scan version: 0.5.0
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
| INFO | 0 |

## Module Summary

| Module | Status | Summary |
| --- | --- | --- |
| fingerprinting | passed | Identified 0 technology signal(s) and checked 4 public metadata path(s). |
| crawler | passed | Crawled 1 page(s), discovered 1 in-scope URL(s). |

## Findings

No findings were reported.

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
- Discovered in-scope URLs: 1
- Out-of-scope URLs recorded but not visited: 0
- Excluded URLs recorded but not visited: 0

### Discovered URLs

- `https://example.com/`

## Safe Next Steps

- Revisa manualmente los controles relevantes antes de aplicar cambios en produccion.

## Limitations

- This report is based on non-intrusive checks only.
- No exploitation, brute force, aggressive fuzzing or destructive testing was performed.
- Findings should be validated against the authorized scope and business context.
