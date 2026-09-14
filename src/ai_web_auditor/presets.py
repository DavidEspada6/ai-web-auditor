from __future__ import annotations

from copy import deepcopy
from typing import Any

from .config import AuditConfig


PRESET_NAMES = ("quick", "standard", "extended")


def list_presets() -> list[dict[str, Any]]:
    items = []
    for name, label, pages, depth, scripts, js_pages, delay in [
        ("quick", "Rapida", 5, 0, 5, 2, 0.2),
        ("standard", "Estandar", 25, 1, 25, 10, 0.2),
        ("extended", "Ampliada", 100, 3, 100, 30, 0.5),
    ]:
        modules = AuditConfig().to_dict()["modules"]
        if name == "quick":
            modules.update(fingerprinting=False, crawler=False, javascript=False)
        items.append({
            "id": name,
            "name": label,
            "description": (
                "Revision inicial de HTTP, cabeceras, cookies, Basic Auth, OPTIONS y TLS."
                if name == "quick" else
                f"Incluye fingerprinting, crawler hasta {pages} paginas y analisis de hasta {scripts} scripts."
            ) + " Conserva alcance y credenciales. Desactiva los modulos DNS de subdominios y puertos TCP.",
            "settings": {
                "modules": modules,
                "http": {"timeout_seconds": 10.0, "max_redirects": 10},
                "crawler": {
                    "max_depth": depth, "max_pages": pages, "delay_seconds": delay,
                    "use_robots_txt": True, "use_sitemap_xml": True, "use_well_known": True,
                    "follow_sitemap_urls": name != "quick", "follow_robots_paths": False,
                    "metadata_max_urls": 250 if name == "extended" else 100,
                },
                "javascript": {
                    "max_pages": js_pages, "max_scripts": scripts, "max_body_bytes": 262144,
                    "include_inline": True, "fetch_external_scripts": True,
                },
            },
        })
    return items


def apply_preset(config: AuditConfig, name: str) -> AuditConfig:
    preset = next((item for item in list_presets() if item["id"] == name), None)
    if preset is None:
        raise ValueError(f"Unknown audit preset: {name}")
    result = deepcopy(config)
    for section, settings in preset["settings"].items():
        for key, value in settings.items():
            setattr(getattr(result, section), key, deepcopy(value))
    return result
