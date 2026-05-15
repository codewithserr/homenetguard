from __future__ import annotations

from pathlib import Path

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)


def export_pdf(html_content: str, output_path: str) -> str:
    try:
        from weasyprint import HTML  # type: ignore[import]
    except ImportError:
        raise RuntimeError("weasyprint not installed — install with: pip install weasyprint")

    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    HTML(string=html_content).write_pdf(str(out))
    logger.info("PDF exported to %s", out)
    return str(out)
