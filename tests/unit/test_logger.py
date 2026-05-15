import logging
import pytest
from homenetguard.utils.logger import setup_logger, get_logger


def test_setup_logger_creates_handlers(tmp_path):
    log_file = str(tmp_path / "test.log")
    logger = setup_logger(name="test_hng_unique", level="DEBUG", log_file=log_file)
    assert logger.level == logging.DEBUG
    assert len(logger.handlers) >= 2  # console + file


def test_setup_logger_idempotent(tmp_path):
    log_file = str(tmp_path / "test2.log")
    logger1 = setup_logger(name="test_hng_idem", log_file=log_file)
    handler_count = len(logger1.handlers)
    logger2 = setup_logger(name="test_hng_idem", log_file=log_file)
    assert logger1 is logger2
    assert len(logger2.handlers) == handler_count


def test_get_logger_returns_named():
    logger = get_logger("homenetguard.storage")
    assert logger.name == "homenetguard.storage"


def test_logger_writes_to_file(tmp_path):
    log_file = str(tmp_path / "output.log")
    logger = setup_logger(name="test_hng_write", level="INFO", log_file=log_file)
    logger.info("Test message 12345")
    import pathlib
    content = pathlib.Path(log_file).read_text()
    assert "Test message 12345" in content
