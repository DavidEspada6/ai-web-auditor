from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from .config import AuditConfig
from .models import utc_now
from .scope import normalize_target


DEFAULT_PROJECTS_DIR = Path("projects")
PROJECT_FILE = "project.json"
PROJECT_CONFIG_FILE = "scope.json"


@dataclass
class ProjectProfile:
    id: str
    name: str
    path: str
    created_at: str
    updated_at: str
    target_url: str = ""
    client: str = ""
    auditor: str = ""
    engagement: str = ""
    scope_summary: str = ""
    config_file: str = PROJECT_CONFIG_FILE
    history_dir: str = "audits"
    reports_dir: str = "reports"
    ai_dir: str = "ai"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def base_path(self) -> Path:
        return Path(self.path)

    @property
    def config_path(self) -> Path:
        return self.base_path / self.config_file

    @property
    def audit_history_dir(self) -> Path:
        return self.base_path / self.history_dir

    @property
    def report_output_dir(self) -> Path:
        return self.base_path / self.reports_dir

    @property
    def ai_output_dir(self) -> Path:
        return self.base_path / self.ai_dir


def create_project(
    name: str,
    *,
    target: str = "",
    client: str = "",
    auditor: str = "",
    engagement: str = "",
    scope_summary: str = "",
    projects_dir: Path = DEFAULT_PROJECTS_DIR,
    force: bool = False,
) -> ProjectProfile:
    project_id = slug_project_name(name)
    if not project_id:
        raise ValueError("Project name is required")

    base_path = projects_dir / project_id
    if base_path.exists() and not force:
        raise ValueError(f"Project already exists: {project_id}. Use --force to overwrite metadata")

    base_path.mkdir(parents=True, exist_ok=True)
    (base_path / "audits").mkdir(exist_ok=True)
    (base_path / "reports").mkdir(exist_ok=True)
    (base_path / "ai").mkdir(exist_ok=True)

    now = utc_now()
    existing_created_at = now
    if (base_path / PROJECT_FILE).exists():
        try:
            existing = json.loads((base_path / PROJECT_FILE).read_text(encoding="utf-8"))
            existing_created_at = str(existing.get("created_at") or now)
        except (OSError, json.JSONDecodeError):
            existing_created_at = now

    normalized_target = ""
    config = AuditConfig()
    if target:
        target_data = normalize_target(target)
        normalized_target = target_data.normalized_url
        config.target.url = normalized_target
        config.scope.allowed_hosts = [target_data.host]
        scope_summary = scope_summary or normalized_target

    profile = ProjectProfile(
        id=project_id,
        name=name.strip(),
        path=str(base_path),
        created_at=existing_created_at,
        updated_at=now,
        target_url=normalized_target,
        client=client.strip(),
        auditor=auditor.strip(),
        engagement=engagement.strip(),
        scope_summary=scope_summary.strip(),
    )
    write_project_profile(profile)
    config.write_json(profile.config_path)
    return profile


def list_projects(projects_dir: Path = DEFAULT_PROJECTS_DIR) -> list[ProjectProfile]:
    if not projects_dir.exists():
        return []

    projects: list[ProjectProfile] = []
    for project_file in sorted(projects_dir.glob(f"*/{PROJECT_FILE}")):
        try:
            projects.append(load_project(project_file.parent, projects_dir=projects_dir))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
    return sorted(projects, key=lambda item: item.updated_at, reverse=True)


def load_project(reference: str | Path, *, projects_dir: Path = DEFAULT_PROJECTS_DIR) -> ProjectProfile:
    project_path = resolve_project_path(reference, projects_dir=projects_dir)
    data = json.loads((project_path / PROJECT_FILE).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError(f"Project file root must be an object: {project_path / PROJECT_FILE}")
    return project_from_data(project_path, data)


def resolve_project_path(reference: str | Path, *, projects_dir: Path = DEFAULT_PROJECTS_DIR) -> Path:
    raw = Path(reference)
    if raw.exists() and raw.is_dir():
        return raw

    identifier = slug_project_name(str(reference))
    if not identifier:
        raise ValueError("Project reference is required")
    candidate = projects_dir / identifier
    if candidate.exists() and candidate.is_dir():
        return candidate
    raise FileNotFoundError(f"Project not found: {reference}")


def write_project_profile(profile: ProjectProfile) -> None:
    profile.base_path.mkdir(parents=True, exist_ok=True)
    data = profile.to_dict()
    data.pop("path", None)
    (profile.base_path / PROJECT_FILE).write_text(
        json.dumps(data, indent=2, ensure_ascii=True) + "\n",
        encoding="utf-8",
    )


def load_project_config(profile: ProjectProfile) -> AuditConfig:
    return AuditConfig.load(profile.config_path)


def project_report_metadata(profile: ProjectProfile) -> dict[str, str]:
    return {
        "client": profile.client,
        "auditor": profile.auditor,
        "engagement": profile.engagement,
        "scope_summary": profile.scope_summary or profile.target_url,
        "notes": "",
    }


def project_from_data(path: Path, data: dict[str, Any]) -> ProjectProfile:
    return ProjectProfile(
        id=str(data.get("id") or path.name),
        name=str(data.get("name") or path.name),
        path=str(path),
        created_at=str(data.get("created_at") or "unknown"),
        updated_at=str(data.get("updated_at") or data.get("created_at") or "unknown"),
        target_url=str(data.get("target_url") or ""),
        client=str(data.get("client") or ""),
        auditor=str(data.get("auditor") or ""),
        engagement=str(data.get("engagement") or ""),
        scope_summary=str(data.get("scope_summary") or ""),
        config_file=str(data.get("config_file") or PROJECT_CONFIG_FILE),
        history_dir=str(data.get("history_dir") or "audits"),
        reports_dir=str(data.get("reports_dir") or "reports"),
        ai_dir=str(data.get("ai_dir") or "ai"),
    )


def slug_project_name(value: str) -> str:
    slug = value.strip().lower()
    slug = re.sub(r"[^a-z0-9._-]+", "-", slug)
    slug = re.sub(r"-+", "-", slug).strip("-._")
    return slug[:80]
