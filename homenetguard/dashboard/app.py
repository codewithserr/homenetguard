from __future__ import annotations

import threading
from typing import Any

from flask import Flask
from flask_socketio import SocketIO

from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

socketio = SocketIO()


def create_app(config: dict[str, Any], sniffer: Any = None) -> Flask:
    app = Flask(__name__, template_folder="templates", static_folder="static")
    app.config["SECRET_KEY"] = "homenetguard-local-only-do-not-expose"
    app.config["HNG_CONFIG"] = config
    app.config["HNG_SNIFFER"] = sniffer

    socketio.init_app(app, cors_allowed_origins="*", async_mode="threading")

    from homenetguard.dashboard.routes import bp
    app.register_blueprint(bp)

    from homenetguard.dashboard import events  # noqa: F401

    return app


def run_dashboard(config: dict[str, Any], sniffer: Any = None) -> None:
    dash_cfg = config.get("dashboard", {})
    host = dash_cfg.get("host", "127.0.0.1")
    port = dash_cfg.get("port", 5000)

    app = create_app(config, sniffer)

    if dash_cfg.get("auto_open_browser", False):
        import webbrowser
        threading.Timer(1.5, lambda: webbrowser.open(f"http://{host}:{port}")).start()

    logger.info("Dashboard at http://%s:%d", host, port)
    socketio.run(app, host=host, port=port, debug=False, use_reloader=False, log_output=False)
