from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

from homenetguard.dashboard.app import socketio
from homenetguard.storage import repository
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_push_thread: threading.Thread | None = None
_push_running = False
_connected_clients = 0


@socketio.on("connect")
def on_connect():
    global _push_thread, _push_running, _connected_clients
    _connected_clients += 1
    logger.debug("Dashboard client connected (%d total)", _connected_clients)
    if _push_thread is None or not _push_thread.is_alive():
        _push_running = True
        _push_thread = threading.Thread(target=_push_loop, daemon=True, name="ws-push")
        _push_thread.start()


@socketio.on("disconnect")
def on_disconnect():
    global _connected_clients
    _connected_clients = max(0, _connected_clients - 1)
    logger.debug("Dashboard client disconnected (%d remaining)", _connected_clients)


def _push_loop() -> None:
    while _push_running:
        try:
            if _connected_clients > 0:
                since = datetime.now(UTC) - timedelta(minutes=1)
                stats = repository.get_flow_stats(since=since)
                alerts = repository.get_unacknowledged_alerts(limit=10)
                flows = repository.get_recent_flows(limit=20)
                socketio.emit("stats_update", {
                    "stats": stats,
                    "alerts": alerts,
                    "flows": flows,
                    "timestamp": datetime.now(UTC).isoformat(),
                })
        except Exception as exc:
            logger.debug("Push loop error: %s", exc)
        time.sleep(2)
