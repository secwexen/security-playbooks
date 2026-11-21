"""Centralized logging configuration with sensitive-data redaction."""

import logging
import re
from logging.handlers import RotatingFileHandler
from pathlib import Path

LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "security_playbooks.log"

SECRET_PATTERNS = [
    re.compile(
        r"""(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token)"""
        r"""(\s*[:=]\s*)['"]?([^\s,'";]+)['"]?"""
    ),
    re.compile(r"(?i)\b(authorization)\s*:\s*bearer\s+[^\s]+"),
    re.compile(r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+"),
]


class SecretRedactionFilter(logging.Filter):
    """Redact common credentials and secrets from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Remove sensitive values before a log record is emitted."""
        message = record.getMessage()

        for pattern in SECRET_PATTERNS:

            def redact(match: re.Match[str]) -> str:
                """Replace a matched secret with a redaction marker."""
                label = match.group(1)

                if label.lower() not in {"authorization", "bearer"}:
                    return f"{label}=[REDACTED]"

                return "[REDACTED]"

            message = pattern.sub(redact, message)

        record.msg = message
        record.args = ()

        return True


def get_logger(
    name: str,
    level: int = logging.INFO,
) -> logging.Logger:
    """Create or retrieve a configured application logger.

    Args:
        name: Logger name, typically __name__.
        level: Logging threshold. Defaults to logging.INFO.

    Returns:
        A configured logger with console and rotating file handlers.
    """
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger.setLevel(level)
    logger.propagate = False

    formatter = logging.Formatter("%(asctime)s | %(levelname)s | %(name)s | %(message)s")

    redaction_filter = SecretRedactionFilter()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(redaction_filter)

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8",
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redaction_filter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
