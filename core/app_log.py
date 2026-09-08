from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from config import LOG_DIR, ensure_app_dirs

_MAX_BYTES = 2 * 1024 * 1024  # 2 MB
_BACKUP_COUNT = 5
_loggers: dict[str, logging.Logger] = {}


def _handler(path: Path) -> RotatingFileHandler:
    path.parent.mkdir(parents=True, exist_ok=True)
    h = RotatingFileHandler(
        str(path),
        maxBytes=_MAX_BYTES,
        backupCount=_BACKUP_COUNT,
        encoding="utf-8",
    )
    h.setFormatter(logging.Formatter(
        "%(asctime)s | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    ))
    return h


def get_logger(name: str, *, file_name: Optional[str] = None) -> logging.Logger:
    """Named logger with rotating file under Logs/."""
    key = name
    if key in _loggers:
        return _loggers[key]

    ensure_app_dirs()
    logger = logging.getLogger(f"disk_diagnostic.{name}")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    if not logger.handlers:
        fname = file_name or f"{name}.log"
        logger.addHandler(_handler(LOG_DIR / fname))
        # errors also go to errors.log
        if name != "errors":
            err = _handler(LOG_DIR / "errors.log")
            err.setLevel(logging.ERROR)
            logger.addHandler(err)
    _loggers[key] = logger
    return logger


def log_exception(name: str, msg: str, exc: BaseException) -> None:
    get_logger(name).error("%s: %s", msg, exc, exc_info=True)
    get_logger("errors", file_name="errors.log").error("%s | %s: %s", name, msg, exc, exc_info=True)
