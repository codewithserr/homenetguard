from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_BREW_LIB = "/opt/homebrew/lib"
_LOCAL_LIB = "/usr/local/lib"


def export_pdf(html_content: str, output_path: str) -> str:
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)

    if sys.platform == "darwin":
        return _export_via_subprocess(html_content, str(out))
    else:
        return _export_direct(html_content, str(out))


def _export_direct(html_content: str, output_path: str) -> str:
    try:
        from weasyprint import HTML  # type: ignore[import]
    except ImportError:
        raise RuntimeError("weasyprint not installed — run: pip install weasyprint")
    except OSError as exc:
        raise RuntimeError(
            f"WeasyPrint system libs missing: {exc}\n"
            "Fix: sudo apt install libpango-1.0-0 libcairo2 libgdk-pixbuf-2.0-0 libffi-dev"
        ) from exc

    HTML(string=html_content).write_pdf(output_path)
    logger.info("PDF exported to %s", output_path)
    return output_path


def _export_via_subprocess(html_content: str, output_path: str) -> str:
    """
    On macOS, WeasyPrint's cffi bindings look for Linux sonames (libgobject-2.0-0)
    that dyld won't find unless DYLD_LIBRARY_PATH points to Homebrew's lib dir.
    Setting that env var from inside Python has no effect (dyld reads it at exec time),
    so we re-exec a child process with the correct env.
    """
    with tempfile.NamedTemporaryFile(
        suffix=".html", delete=False, mode="w", encoding="utf-8"
    ) as tmp:
        tmp.write(html_content)
        tmp_html = tmp.name

    env = os.environ.copy()
    existing_dyld = env.get("DYLD_LIBRARY_PATH", "")
    brew_paths = ":".join(p for p in [_BREW_LIB, _LOCAL_LIB] if Path(p).exists())
    env["DYLD_LIBRARY_PATH"] = f"{brew_paths}:{existing_dyld}".strip(":")

    script = (
        "from weasyprint import HTML; "
        f"HTML(filename={tmp_html!r}).write_pdf({output_path!r})"
    )

    try:
        result = subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"PDF generation failed (exit {result.returncode}):\n"
                f"{result.stderr.strip()}\n\n"
                "Ensure system libs are installed:\n"
                "  brew install pango cairo gdk-pixbuf libffi"
            )
    finally:
        Path(tmp_html).unlink(missing_ok=True)

    logger.info("PDF exported to %s", output_path)
    return output_path
