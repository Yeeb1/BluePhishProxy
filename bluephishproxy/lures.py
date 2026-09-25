"""Filesystem-based lure template registry.

Templates are HTML files using Jinja2 syntax, stored in:
  1. Built-in: bluephishproxy/templates/*.html
  2. Custom:   BPP_TEMPLATES_DIR (overrides built-ins with same name)

Each template file can include metadata in an HTML comment header:
    <!-- BPP-Template
    name: Human-Readable Name
    description: Short description of the template
    -->

Templates automatically get the fingerprint JS injected via:
    {% include '_fingerprint.html' %}

Available variables in templates:
    {{ brand }}         - Brand name (default: Microsoft)
    {{ title }}         - Custom title
    {{ message }}       - Custom message text
    {{ button_text }}   - Custom button label
    {{ sender }}        - Sender name/number
    {{ doc_name }}      - Document filename
    {{ app_name }}      - Application name
    {{ org_name }}      - Organisation name
    {{ caller }}        - Phone number
    {{ duration }}      - Duration string
    {{ permissions }}   - List of permission strings
    Plus any custom_params from the campaign config.

To add a custom template, drop an HTML file into the templates directory.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, ChoiceLoader

_BUILTIN_DIR = Path(__file__).parent / "templates"

_META_PATTERN = re.compile(
    r"<!--\s*BPP-Template\s*\n(.*?)-->",
    re.DOTALL,
)


def _parse_metadata(content: str) -> dict[str, str]:
    match = _META_PATTERN.search(content)
    if not match:
        return {}
    meta: dict[str, str] = {}
    for line in match.group(1).strip().splitlines():
        line = line.strip()
        if ":" in line:
            key, _, val = line.partition(":")
            meta[key.strip().lower()] = val.strip()
    return meta


def _build_registry() -> dict[str, dict[str, str]]:
    registry: dict[str, dict[str, str]] = {}

    for html_file in sorted(_BUILTIN_DIR.glob("*.html")):
        if html_file.name.startswith("_"):
            continue
        template_id = html_file.stem
        content = html_file.read_text(encoding="utf-8")
        meta = _parse_metadata(content)
        registry[template_id] = {
            "name": meta.get("name", template_id),
            "description": meta.get("description", ""),
            "file": str(html_file),
        }

    custom_dir = os.environ.get("BPP_TEMPLATES_DIR")
    if custom_dir:
        custom_path = Path(custom_dir)
        if custom_path.is_dir():
            for html_file in sorted(custom_path.glob("*.html")):
                if html_file.name.startswith("_"):
                    continue
                template_id = html_file.stem
                content = html_file.read_text(encoding="utf-8")
                meta = _parse_metadata(content)
                registry[template_id] = {
                    "name": meta.get("name", template_id),
                    "description": meta.get("description", "Custom template"),
                    "file": str(html_file),
                }

    return registry


def _get_jinja_env() -> Environment:
    loaders = [FileSystemLoader(str(_BUILTIN_DIR))]
    custom_dir = os.environ.get("BPP_TEMPLATES_DIR")
    if custom_dir and Path(custom_dir).is_dir():
        loaders.insert(0, FileSystemLoader(custom_dir))
    return Environment(
        loader=ChoiceLoader(loaders),
        autoescape=False,
    )


_jinja_env: Environment | None = None


def _env() -> Environment:
    global _jinja_env
    if _jinja_env is None:
        _jinja_env = _get_jinja_env()
    return _jinja_env


def reload_templates() -> None:
    global _jinja_env, LURE_REGISTRY
    _jinja_env = _get_jinja_env()
    LURE_REGISTRY = _build_registry()


LURE_REGISTRY: dict[str, dict[str, str]] = _build_registry()


def render_lure(template_name: str, params: dict[str, Any] | None = None) -> str:
    if template_name not in LURE_REGISTRY:
        template_name = "safelinks"

    p = params or {}
    if "brand" not in p:
        p["brand"] = "Microsoft"

    # Handle permissions as a list for oauth template
    if "permissions" in p and isinstance(p["permissions"], str):
        p["permissions"] = [s.strip() for s in p["permissions"].split(",")]

    template = _env().get_template(f"{template_name}.html")
    return template.render(**p)


def list_templates() -> list[dict[str, str]]:
    return [
        {"id": k, "name": v["name"], "description": v["description"]}
        for k, v in LURE_REGISTRY.items()
    ]
