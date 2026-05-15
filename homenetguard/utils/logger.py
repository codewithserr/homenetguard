from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logger(
    name: str = "homenetguard",
    level: str = "INFO",
    log_file: str = "logs/homenetguard.log",
    max_size_mb: int = 50,
    backup_count: int = 5,
) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger

    logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    fmt = logging.Formatter(
        "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(fmt)
    logger.addHandler(console)

    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(
        log_path,
        maxBytes=max_size_mb * 1024 * 1024,
        backupCount=backup_count,
    )
    file_handler.setFormatter(fmt)
    logger.addHandler(file_handler)

    return logger


def get_logger(name: str = "homenetguard") -> logging.Logger:
    return logging.getLogger(name)
