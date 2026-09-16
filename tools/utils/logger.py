from pathlib import Path
import logging
import re
from logging.handlers import RotatingFileHandler


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "security_playbooks.log"


SECRET_PATTERNS = [
    re.compile(r"(?i)(password|passwd|pwd)\s*=\s*[^\s]+"),
    re.compile(r"(?i)(token|api[_-]?key|secret)\s*=\s*[^\s]+"),
    re.compile(r"(?i)authorization\s*:\s*bearer\s+[^\s]+"),
]


class SecretRedactionFilter(logging.Filter):
    """Redact common secrets and credentials from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()

        for pattern in SECRET_PATTERNS:
            message = pattern.sub(
                "[REDACTED]",
                message,
            )

        record.msg = message
        record.args = ()

        return True


def get_logger(name: str) -> logging.Logger:
    """
    Return a configured project-wide logger.
    """

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.INFO)
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    redaction_filter = SecretRedactionFilter()

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    console_handler.addFilter(redaction_filter)

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8"
    )
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redaction_filter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
