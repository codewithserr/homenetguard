from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator

from homenetguard.storage.models import SCHEMA_SQL
from homenetguard.utils.logger import get_logger

logger = get_logger(__name__)

_db_path: str = "data/homenetguard.db"


def init_db(db_path: str = "data/homenetguard.db") -> None:
    global _db_path
    _db_path = db_path
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    with get_connection() as conn:
        conn.executescript(SCHEMA_SQL)
        _migrate(conn)
        from homenetguard.storage.migrations import run_migrations
        run_migrations(conn)
    logger.info("Database initialized at %s", db_path)


def _migrate(conn: sqlite3.Connection) -> None:
    """Apply additive migrations safe to run on existing DBs."""
    migrations = [
        "ALTER TABLE ip_reputation ADD COLUMN org TEXT",
        "ALTER TABLE ip_reputation ADD COLUMN asn TEXT",
    ]
    for sql in migrations:
        try:
            conn.execute(sql)
        except sqlite3.OperationalError:
            pass  # column already exists


@contextmanager
def get_connection() -> Generator[sqlite3.Connection, None, None]:
    conn = sqlite3.connect(_db_path, detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def get_db_path() -> str:
    return _db_path
