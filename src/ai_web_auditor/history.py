from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .models import utc_now


DEFAULT_HISTORY_DIR = Path("audits")
SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class HistoryEntry:
    id: str
    path: str
    generated_at: str
    saved_at: str
    target: str
    host: str
    status: str
    version: str
    finding_count: int
    severity_counts: dict[str, int]
    label: str = ""
    has_ai_analysis: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def save_scan_history(
    scan_data: dict[str, Any],
    *,
    history_dir: Path = DEFAULT_HISTORY_DIR,
    label: str = "",
) -> HistoryEntry:
    history_dir.mkdir(parents=True, exist_ok=True)
    generated_at = _text(scan_data.get("generated_at"), utc_now())
    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    host = _text(target.get("host"), "unknown-host")
    base_name = "-".join(
        item
        for item in [
            _slug(generated_at.replace(":", "").replace("T", "-").replace("Z", "")),
            _slug(host),
            _slug(label),
        ]
        if item
    )
    if not base_name:
        base_name = "audit"

    output = _unique_path(history_dir / f"{base_name}.json")
    saved_data = dict(scan_data)
    saved_data["_history"] = {
        "id": output.stem,
        "saved_at": utc_now(),
        "label": label,
    }
    output.write_text(json.dumps(saved_data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return history_entry_from_data(output, saved_data)


def list_history(history_dir: Path = DEFAULT_HISTORY_DIR) -> list[HistoryEntry]:
    if not history_dir.exists():
        return []

    entries: list[HistoryEntry] = []
    for path in sorted(history_dir.glob("*.json"), reverse=True):
        try:
            entries.append(history_entry_from_data(path, load_scan_reference(path, history_dir=history_dir)))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return entries


def load_scan_reference(reference: str | Path, *, history_dir: Path = DEFAULT_HISTORY_DIR) -> dict[str, Any]:
    path = resolve_history_reference(reference, history_dir=history_dir)
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Scan JSON root must be an object: {path}")
    return data


def save_analysis_for_history(
    reference: str | Path,
    analysis_data: dict[str, Any],
    *,
    history_dir: Path = DEFAULT_HISTORY_DIR,
) -> dict[str, Any]:
    path = resolve_history_reference(reference, history_dir=history_dir)
    data = load_scan_reference(path, history_dir=history_dir)
    data["ai_analysis"] = analysis_data
    history = data.get("_history") if isinstance(data.get("_history"), dict) else {}
    history["ai_analysis_saved_at"] = utc_now()
    data["_history"] = history
    path.write_text(json.dumps(data, indent=2, ensure_ascii=True) + "\n", encoding="utf-8")
    return data


def resolve_history_reference(reference: str | Path, *, history_dir: Path = DEFAULT_HISTORY_DIR) -> Path:
    raw = Path(reference)
    if raw.exists():
        return raw

    identifier = str(reference).strip()
    if not identifier:
        raise ValueError("History reference is required")
    candidate = history_dir / f"{identifier}.json"
    if candidate.exists():
        return candidate
    raise FileNotFoundError(f"Audit history item not found: {reference}")


def history_entry_from_data(path: Path, scan_data: dict[str, Any]) -> HistoryEntry:
    target = scan_data.get("target") if isinstance(scan_data.get("target"), dict) else {}
    findings = scan_data.get("findings") if isinstance(scan_data.get("findings"), list) else []
    history = scan_data.get("_history") if isinstance(scan_data.get("_history"), dict) else {}
    severity_counts = _severity_counts(findings)
    return HistoryEntry(
        id=_text(history.get("id"), path.stem),
        path=str(path),
        generated_at=_text(scan_data.get("generated_at"), "unknown"),
        saved_at=_text(history.get("saved_at"), "unknown"),
        target=_text(target.get("normalized_url", target.get("original_url")), "unknown"),
        host=_text(target.get("host"), "unknown"),
        status=_text(scan_data.get("status"), "unknown"),
        version=_text(scan_data.get("version"), "unknown"),
        finding_count=len([item for item in findings if isinstance(item, dict)]),
        severity_counts=severity_counts,
        label=_text(history.get("label"), ""),
        has_ai_analysis=isinstance(scan_data.get("ai_analysis"), dict),
    )


def _severity_counts(findings: list[Any]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        if not isinstance(finding, dict):
            continue
        severity = str(finding.get("severity", "info")).lower()
        if severity == "informational":
            severity = "info"
        if severity not in counts:
            severity = "info"
        counts[severity] += 1
    return counts


def _unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    for index in range(2, 10_000):
        candidate = path.with_name(f"{path.stem}-{index}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise OSError(f"Could not create unique history file for {path}")


def _slug(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9._-]+", "-", value)
    value = re.sub(r"-+", "-", value).strip("-._")
    return value[:80]


def _text(value: Any, default: str) -> str:
    if value is None or value == "":
        return default
    return str(value)
