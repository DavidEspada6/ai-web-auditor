from __future__ import annotations

import json
from typing import Any


def build_analysis_prompt(scan_data: dict[str, Any], *, max_chars: int, language: str) -> str:
    compact_scan = json.dumps(scan_data, ensure_ascii=True, separators=(",", ":"))
    if len(compact_scan) > max_chars:
        compact_scan = compact_scan[:max_chars] + "\n...[TRUNCATED]"

    return f"""Eres un asistente de auditoria web defensiva.

Analiza un resultado JSON generado por una herramienta propia de auditoria web no intrusiva.

Reglas:
- No inventes vulnerabilidades que no esten respaldadas por evidencias del JSON.
- No propongas explotacion, fuerza bruta, bypasses ni pruebas intrusivas.
- Puedes recomendar validaciones manuales seguras y mejoras de configuracion.
- Prioriza por impacto, facilidad de correccion y evidencia disponible.
- Responde en idioma: {language}.
- Devuelve exclusivamente JSON valido, sin Markdown.

Formato exacto:
{{
  "executive_summary": "resumen breve",
  "risk_level": "informational|low|medium|high|critical",
  "risk_rationale": "motivo del nivel global",
  "priority_findings": [
    {{
      "rank": 1,
      "severity": "informational|low|medium|high|critical",
      "title": "titulo",
      "why_it_matters": "explicacion",
      "evidence": ["evidencia breve"],
      "recommended_action": "accion recomendada"
    }}
  ],
  "safe_next_steps": ["siguiente paso seguro"],
  "report_notes": ["nota util para informe"],
  "limitations": ["limitacion del analisis"]
}}

JSON de auditoria:
{compact_scan}
"""
