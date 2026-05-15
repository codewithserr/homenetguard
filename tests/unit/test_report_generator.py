import pytest
from pathlib import Path
from homenetguard.storage import database, repository
from homenetguard.reports.report_generator import ReportGenerator, _build_recommendations
from homenetguard.reports.html_renderer import render_report_html


@pytest.fixture(autouse=True)
def in_memory_db(tmp_path):
    database.init_db(str(tmp_path / "test.db"))


@pytest.fixture
def cfg(tmp_path):
    return {
        "storage": {
            "db_path": str(tmp_path / "test.db"),
            "reports_path": str(tmp_path / "reports"),
        }
    }


def test_report_generator_html(cfg, tmp_path):
    gen = ReportGenerator(cfg)
    paths = gen.generate(report_type="daily", fmt="html")
    assert len(paths) == 1
    assert paths[0].endswith(".html")
    assert Path(paths[0]).exists()


def test_report_generator_both(cfg, tmp_path):
    try:
        gen = ReportGenerator(cfg)
        paths = gen.generate(report_type="daily", fmt="both")
        html_paths = [p for p in paths if p.endswith(".html")]
        assert len(html_paths) == 1
    except (RuntimeError, OSError, Exception) as e:
        msg = str(e).lower()
        if any(k in msg for k in ("weasyprint", "libgobject", "dlopen", "cannot load")):
            pytest.skip("WeasyPrint system dependencies not installed")
        raise


def test_report_saved_to_db(cfg):
    gen = ReportGenerator(cfg)
    gen.generate(report_type="daily", fmt="html")
    reports = repository.get_reports()
    assert len(reports) >= 1
    assert reports[0]["report_type"] == "daily"
    assert reports[0]["format"] == "html"


def test_build_recommendations_no_alerts():
    recs = _build_recommendations([])
    assert len(recs) == 1
    assert "No significant" in recs[0]


def test_build_recommendations_with_port_scan():
    alerts = [{"alert_type": "port_scan", "severity": "high"}]
    recs = _build_recommendations(alerts)
    assert any("port scan" in r.lower() for r in recs)


def test_render_report_html():
    data = {
        "report_type": "daily",
        "period_start": "2026-05-14T00:00:00",
        "period_end": "2026-05-14T23:59:59",
        "stats": {"total_flows": 100, "total_bytes": 50000, "unique_src_ips": 5},
        "top_ips": [],
        "protocols": [],
        "alerts": [],
        "alert_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
        "dns_queries": [],
        "recommendations": ["No significant threats detected."],
    }
    html = render_report_html(data)
    assert "HomeNetGuard" in html
    assert "Daily" in html
    assert "No significant" in html
