from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


def render_report_html(data: dict[str, Any], template_name: str = "report_daily.html") -> str:
    env = Environment(loader=FileSystemLoader(str(_TEMPLATES_DIR)), autoescape=True)
    env.filters["fmtbytes"] = _fmt_bytes
    template = env.get_template(template_name)
    return template.render(**data, generated_at=datetime.now(UTC).isoformat())


def _fmt_bytes(b: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if b < 1024:
            return f"{b:.1f} {unit}"
        b //= 1024
    return f"{b:.1f} TB"
