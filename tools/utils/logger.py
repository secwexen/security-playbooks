from pathlib import Path
import logging
import re
from logging.handlers import RotatingFileHandler


LOG_DIR = Path("logs")
LOG_FILE = LOG_DIR / "security_playbooks.log"


SECRET_PATTERNS = [
    re.compile(
        r"(?i)\b(password|passwd|pwd|token|secret|api[_-]?key|access[_-]?token)"
        r"(\s*[:=]\s*)['\"]?([^\s,'\";]+)['\"]?"
    ),
    re.compile(
        r"(?i)\b(authorization)\s*:\s*bearer\s+[^\s]+"
    ),
    re.compile(
        r"(?i)\b(bearer)\s+[A-Za-z0-9._~+/=-]+"
    ),
]


class SecretRedactionFilter(logging.Filter):
    """Redact common credentials and secrets from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        message = record.getMessage()

        for pattern in SECRET_PATTERNS:
            message = pattern.sub(
                lambda match: (
                    f"{match.group(1)}=[REDACTED]"
                    if match.lastindex and match.group(1).lower()
                    != "authorization"
                    and match.group(1).lower() != "bearer"
                    else "[REDACTED]"
                ),
                message,
            )

        record.msg = message
        record.args = ()

        return True


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(level)
    logger.propagate = False

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | %(message)s"
    )

    redaction_filter = SecretRedactionFilter()

    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(redaction_filter)

    file_handler = RotatingFileHandler(
        LOG_FILE,
        maxBytes=5 * 1024 * 1024,
        backupCount=3,
        encoding="utf-8"
    )
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    file_handler.addFilter(redaction_filter)

    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger
