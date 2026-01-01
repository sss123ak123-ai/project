"""
Centralized logging utilities for the AI-assisted web vulnerability analysis framework.
"""

from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path


def setup_logger(log_dir: str) -> logging.Logger:
    """
    Configure a structured logger that writes both to stdout and a rotating log file.

    Args:
        log_dir: Directory where log files should be created.

    Returns:
        Configured logger instance.
    """
    Path(log_dir).mkdir(parents=True, exist_ok=True)
    log_path = os.path.join(log_dir, "ai_web_assistant.log")

    logger = logging.getLogger("ai_web_assistant")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] %(name)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    file_handler = RotatingFileHandler(log_path, maxBytes=1_000_000, backupCount=3)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)

    logger.info("Logger initialized. Writing logs to %s", log_path)
    return logger
