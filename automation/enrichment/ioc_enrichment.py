from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from tools.utils.logger import get_logger


PROJECT_ROOT = Path(__file__).resolve().parents[2]

IOC_STORE_FILE = PROJECT_ROOT / "iocs" / "iocs.json"
THREAT_FEED_FILE = PROJECT_ROOT / "iocs" / "threat_feed.json"
FEEDS_DIR = PROJECT_ROOT / "iocs" / "feeds"

DOMAINS_FILE = PROJECT_ROOT / "iocs" / "domains.txt"
IPS_FILE = PROJECT_ROOT / "iocs" / "ips.txt"
URLS_FILE = PROJECT_ROOT / "iocs" / "urls.txt"
HASHES_FILE = PROJECT_ROOT / "iocs" / "file-hashes.txt"

logger = get_logger(__name__)


HASH_PATTERNS = {
    "md5": re.compile(r"^[a-fA-F0-9]{32}$"),
    "sha1": re.compile(r"^[a-fA-F0-9]{40}$"),
    "sha256": re.compile(r"^[a-fA-F0-9]{64}$"),
}

DOMAIN_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9]"
    r"(?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"[a-zA-Z]{2,63}$"
)

IOC_TYPE_KEYS = {
    "ip": "ip",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "hostname": "hostname",
    "url": "url",
    "uri": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "hash": "file_hash",
    "file_hash": "file_hash",
    "email": "email",
    "cve": "cve",
}


def utc_now() -> str:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def normalize_value(value: str) -> str:
    """Normalize an IOC value for comparison."""
    value = value.strip()

    if not value:
        return ""

    if value.startswith(("http://", "https://")):
        parsed = urlparse(value)

        hostname = (parsed.hostname or "").lower()
        path = parsed.path or ""

        if parsed.query:
            path += f"?{parsed.query}"

        return f"{parsed.scheme.lower()}://{hostname}{path}"

    return value.lower()


def detect_ioc_type(value: str) -> str:
    """Detect the IOC type."""
    normalized = value.strip()

    if not normalized:
        return "other"

    try:
        ip = ipaddress.ip_address(normalized)

        if isinstance(ip, ipaddress.IPv4Address):
            return "ipv4"

        return "ipv6"

    except ValueError:
        pass

    for hash_type, pattern in HASH_PATTERNS.items():
        if pattern.fullmatch(normalized):
            return hash_type

    if normalized.startswith(("http://", "https://")):
        return "url"

    if DOMAIN_PATTERN.fullmatch(normalized):
        return "domain"

    return "other"


def normalize_declared_type(value: Any) -> str | None:
    """Normalize a feed-provided IOC type."""
    if value is None:
        return None

    normalized = str(value).strip().lower()

    return IOC_TYPE_KEYS.get(normalized)


def calculate_ioc_id(
    ioc_type: str,
    normalized_value: str,
) -> str:
    """Generate a deterministic IOC ID."""
    raw = f"{ioc_type}:{normalized_value}".encode("utf-8")
    digest = hashlib.sha256(raw).hexdigest()

    return f"IOC-{digest[:16]}"


def load_json_file(path: Path) -> Any:
    """Load a JSON file."""
    with path.open("r", encoding="utf-8") as file:
        return json.load(file)


def load_lines(path: Path) -> list[str]:
    """Load non-empty, non-comment lines from a text file."""
    if not path.exists():
        return []

    values: list[str] = []

    with path.open("r", encoding="utf-8") as file:
        for line in file:
            value = line.strip()

            if not value or value.startswith("#"):
                continue

            values.append(value)

    return values


def create_normalized_ioc(
    value: str,
    *,
    source: str = "internal",
    source_type: str = "internal",
    confidence: int = 50,
    status: str = "active",
    malicious: bool = False,
    feed: str | None = None,
    tags: list[str] | None = None,
    declared_type: str | None = None,
) -> dict[str, Any]:
    """Create a normalized IOC record."""

    original_value = str(value).strip()
    normalized_value = normalize_value(original_value)

    if not normalized_value:
        raise ValueError("IOC value cannot be empty.")

    ioc_type = (
        normalize_declared_type(declared_type)
        or detect_ioc_type(normalized_value)
    )

    now = utc_now()

    result: dict[str, Any] = {
        "id": calculate_ioc_id(
            ioc_type,
            normalized_value,
        ),
        "type": ioc_type,
        "value": original_value,
        "normalized_value": normalized_value,
        "confidence": max(
            0,
            min(100, int(confidence)),
        ),
        "status": status,
        "malicious": bool(malicious),
        "first_seen": now,
        "last_seen": now,
        "source": source,
        "source_type": source_type,
        "tags": sorted(set(tags or [])),
        "created_at": now,
        "updated_at": now,
    }

    if feed:
        result["feed"] = feed

    return result


def _extract_from_record(
    record: dict[str, Any],
    *,
    source: str,
    feed_name: str | None,
) -> dict[str, Any] | None:
    """
    Convert a generic feed record into a normalized IOC.

    Supported common keys include:
    value, indicator, ioc, observable, indicator_value,
    type, ioc_type, confidence, score, malicious, status,
    tags, feed, source.
    """
    value = (
        record.get("value")
        or record.get("indicator")
        or record.get("ioc")
        or record.get("observable")
        or record.get("indicator_value")
    )

    if value is None:
        return None

    declared_type = (
        record.get("type")
        or record.get("ioc_type")
    )

    confidence = record.get(
        "confidence",
        record.get("score", 50),
    )

    try:
        confidence = int(confidence)
    except (TypeError, ValueError):
        confidence = 50

    malicious = bool(
        record.get("malicious", False)
    )

    status = str(
        record.get("status", "active")
    )

    tags = record.get("tags", [])

    if not isinstance(tags, list):
        tags = [str(tags)]

    record_feed = (
        record.get("feed")
        or feed_name
    )

    record_source = str(
        record.get("source")
        or source
    )

    source_type = "feed" if feed_name else "internal"

    return create_normalized_ioc(
        str(value),
        source=record_source,
        source_type=source_type,
        confidence=confidence,
        status=status,
        malicious=malicious,
        feed=(
            str(record_feed)
            if record_feed
            else None
        ),
        tags=[
            str(tag)
            for tag in tags
        ],
        declared_type=(
            str(declared_type)
            if declared_type is not None
            else None
        ),
    )


def extract_iocs_from_json(
    data: Any,
    *,
    source: str,
    feed_name: str | None = None,
) -> list[dict[str, Any]]:
    """
    Recursively extract IOC-like records from JSON data.
    """
    results: list[dict[str, Any]] = []

    if isinstance(data, dict):
        direct = _extract_from_record(
            data,
            source=source,
            feed_name=feed_name,
        )

        if direct is not None:
            results.append(direct)

        for value in data.values():
            results.extend(
                extract_iocs_from_json(
                    value,
                    source=source,
                    feed_name=feed_name,
                )
            )

    elif isinstance(data, list):
        for item in data:
            results.extend(
                extract_iocs_from_json(
                    item,
                    source=source,
                    feed_name=feed_name,
                )
            )

    return results


def load_text_iocs() -> list[dict[str, Any]]:
    """Load IOC values from the text sources."""
    results: list[dict[str, Any]] = []

    files = (
        DOMAINS_FILE,
        IPS_FILE,
        URLS_FILE,
        HASHES_FILE,
    )

    for path in files:
        for value in load_lines(path):
            try:
                results.append(
                    create_normalized_ioc(
                        value,
                        source=path.name,
                        source_type="internal",
                    )
                )
            except ValueError as exc:
                logger.warning(
                    "Skipping invalid IOC from %s: %s",
                    path,
                    exc,
                )

    return results


def load_json_ioc_sources() -> list[dict[str, Any]]:
    """Load IOC records from the primary JSON sources."""
    results: list[dict[str, Any]] = []

    sources = (
        (IOC_STORE_FILE, "iocs.json", None),
        (
            THREAT_FEED_FILE,
            "threat_feed.json",
            "threat_feed",
        ),
    )

    for path, source, feed_name in sources:
        if not path.exists():
            continue

        try:
            data = load_json_file(path)

            results.extend(
                extract_iocs_from_json(
                    data,
                    source=source,
                    feed_name=feed_name,
                )
            )

        except (
            OSError,
            json.JSONDecodeError,
        ) as exc:
            logger.error(
                "Failed to read %s: %s",
                path,
                exc,
            )

    return results


def load_feed_sources() -> list[dict[str, Any]]:
    """Load IOC records from all JSON files in iocs/feeds."""
    if not FEEDS_DIR.exists():
        return []

    results: list[dict[str, Any]] = []

    for path in sorted(
        FEEDS_DIR.glob("*.json")
    ):
        try:
            data = load_json_file(path)

            results.extend(
                extract_iocs_from_json(
                    data,
                    source=path.name,
                    feed_name=path.stem,
                )
            )

        except (
            OSError,
            json.JSONDecodeError,
        ) as exc:
            logger.error(
                "Failed to read feed %s: %s",
                path,
                exc,
            )

    return results


def merge_iocs(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Deduplicate IOC records by type and normalized value."""

    merged: dict[
        tuple[str, str],
        dict[str, Any],
    ] = {}

    for record in records:
        ioc_type = str(
            record.get("type", "other")
        )

        normalized_value = normalize_value(
            str(
                record.get(
                    "normalized_value",
                    record.get("value", ""),
                )
            )
        )

        if not normalized_value:
            continue

        key = (
            ioc_type,
            normalized_value,
        )

        existing = merged.get(key)

        if existing is None:
            merged[key] = record
            continue

        existing["confidence"] = max(
            int(existing.get("confidence", 0)),
            int(record.get("confidence", 0)),
        )

        if record.get("malicious") is True:
            existing["malicious"] = True

        existing_tags = set(
            existing.get("tags", [])
        )

        existing_tags.update(
            record.get("tags", [])
        )

        existing["tags"] = sorted(
            existing_tags
        )

        if (
            record.get("status")
            and record["status"] != "unknown"
        ):
            existing["status"] = record["status"]

        if record.get("feed"):
            existing["feed"] = record["feed"]

        existing["updated_at"] = utc_now()

    return list(merged.values())


def save_iocs(
    iocs: list[dict[str, Any]],
    path: Path = IOC_STORE_FILE,
) -> None:
    """Write normalized IOC records to the IOC store."""
    path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with path.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            iocs,
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")


def main() -> None:
    """Build the normalized IOC store."""

    logger.info(
        "Starting IOC enrichment."
    )

    records: list[dict[str, Any]] = []

    text_records = load_text_iocs()
    json_records = load_json_ioc_sources()
    feed_records = load_feed_sources()

    records.extend(text_records)
    records.extend(json_records)
    records.extend(feed_records)

    if not records:
        logger.warning(
            "No IOC source values found."
        )
        return

    normalized = merge_iocs(records)

    save_iocs(normalized)

    logger.info(
        "IOC enrichment completed. "
        "Text=%d JSON=%d Feeds=%d Stored=%d",
        len(text_records),
        len(json_records),
        len(feed_records),
        len(normalized),
    )


if __name__ == "__main__":
    main()
