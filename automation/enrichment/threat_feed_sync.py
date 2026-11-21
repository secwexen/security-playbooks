"""Synchronize local threat intelligence feeds and normalize IOC records."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from tools.utils.logger import get_logger

PROJECT_ROOT = Path(__file__).resolve().parents[2]

FEEDS_DIR = PROJECT_ROOT / "iocs" / "feeds"
THREAT_FEED_FILE = PROJECT_ROOT / "iocs" / "threat_feed.json"

logger = get_logger(__name__)

IOC_TYPES = {
    "ip",
    "ipv4",
    "ipv6",
    "domain",
    "hostname",
    "url",
    "md5",
    "sha1",
    "sha256",
    "sha512",
}

IOC_FIELD_ALIASES = {
    "ip_address": "ip",
    "ip": "ip",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "hostname": "hostname",
    "host": "hostname",
    "url": "url",
    "uri": "url",
    "md5": "md5",
    "sha1": "sha1",
    "sha256": "sha256",
    "sha512": "sha512",
}

NORMALIZE_LOWERCASE_TYPES = {
    "domain",
    "hostname",
    "md5",
    "sha1",
    "sha256",
    "sha512",
}


def utc_now() -> str:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def normalize_ioc(
    ioc_type: str,
    value: Any,
    source: str,
    feed_name: str,
) -> dict[str, Any] | None:
    """Normalize an individual IOC into a standard record."""

    normalized_type = IOC_FIELD_ALIASES.get(ioc_type.strip().lower())

    if normalized_type not in IOC_TYPES:
        return None

    if not isinstance(value, (str, int)):
        return None

    normalized_value = str(value).strip()

    if not normalized_value:
        return None

    if normalized_type in NORMALIZE_LOWERCASE_TYPES:
        normalized_value = normalized_value.lower()

    return {
        "type": normalized_type,
        "value": normalized_value,
        "source": source,
        "feed_name": feed_name,
    }


def extract_typed_ioc(
    item: dict[str, Any],
    source: str,
    feed_name: str,
) -> list[dict[str, Any]]:
    """Extract IOC records using the type/value JSON structure."""

    ioc_type = item.get("type")
    value = item.get("value")

    if not isinstance(ioc_type, str) or value is None:
        return []

    record = normalize_ioc(
        ioc_type,
        value,
        source,
        feed_name,
    )

    return [record] if record else []


def extract_direct_iocs(
    item: dict[str, Any],
    source: str,
    feed_name: str,
) -> list[dict[str, Any]]:
    """Extract IOC values from direct JSON fields."""

    extracted = []

    for key, value in item.items():
        if not isinstance(key, str):
            continue

        if key.lower() not in IOC_FIELD_ALIASES:
            continue

        values = value if isinstance(value, list) else [value]

        for entry in values:
            record = normalize_ioc(
                key,
                entry,
                source,
                feed_name,
            )

            if record:
                extracted.append(record)

    return extracted


def extract_nested_iocs(
    item: dict[str, Any],
    source: str,
    feed_name: str,
) -> list[dict[str, Any]]:
    """Extract IOC records from nested JSON structures."""

    extracted = []

    for value in item.values():
        if isinstance(value, (dict, list)):
            extracted.extend(
                extract_iocs_from_json(
                    value,
                    source=source,
                    feed_name=feed_name,
                )
            )

    return extracted


def extract_iocs_from_json(
    data: Any,
    source: str = "unknown",
    feed_name: str = "unknown",
) -> list[dict[str, Any]]:
    """
    Extract IOC records from common JSON threat intelligence formats.

    Supports:
    - Direct IOC fields.
    - Type/value IOC objects.
    - Nested dictionaries.
    - Lists of IOC objects.
    """

    if isinstance(data, list):
        extracted = []

        for item in data:
            extracted.extend(
                extract_iocs_from_json(
                    item,
                    source=source,
                    feed_name=feed_name,
                )
            )

        return merge_iocs(extracted)

    if not isinstance(data, dict):
        return []

    extracted = []

    extracted.extend(
        extract_typed_ioc(
            data,
            source,
            feed_name,
        )
    )

    extracted.extend(
        extract_direct_iocs(
            data,
            source,
            feed_name,
        )
    )

    extracted.extend(
        extract_nested_iocs(
            data,
            source,
            feed_name,
        )
    )

    return merge_iocs(extracted)


def merge_metadata(
    existing: dict[str, Any],
    incoming: dict[str, Any],
) -> None:
    """Merge metadata while preserving existing IOC information."""

    for field, incoming_value in incoming.items():
        if incoming_value is None:
            continue

        if field in {"source", "feed_name"}:
            existing_values = set(str(existing.get(field, "")).split(","))

            incoming_values = set(str(incoming_value).split(","))

            combined = existing_values | incoming_values

            existing[field] = ",".join(sorted(value for value in combined if value))

        elif field == "tags":
            old_tags = existing.get("tags", [])
            new_tags = incoming_value

            if not isinstance(old_tags, list):
                old_tags = [old_tags]

            if not isinstance(new_tags, list):
                new_tags = [new_tags]

            existing[field] = sorted(
                set(old_tags + new_tags),
                key=str,
            )

        elif field not in existing or not existing[field]:
            existing[field] = incoming_value


def merge_iocs(
    records: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Merge IOC records and remove duplicates.

    IOC identity is determined by type and value.
    Metadata from duplicate records is preserved.
    """

    merged: dict[tuple[str, str], dict[str, Any]] = {}

    for record in records:
        if not isinstance(record, dict):
            continue

        ioc_type = record.get("type")
        value = record.get("value")

        if not isinstance(ioc_type, str):
            continue

        if not isinstance(value, str):
            continue

        ioc_type = ioc_type.strip().lower()
        value = value.strip()

        if ioc_type not in IOC_TYPES or not value:
            continue

        identity_value = value if ioc_type == "url" else value.lower()

        key = (ioc_type, identity_value)

        if key not in merged:
            merged[key] = dict(record)
            continue

        merge_metadata(
            merged[key],
            record,
        )

    return list(merged.values())


def load_feed_files() -> list[dict[str, Any]]:
    """Load and normalize JSON feed files."""

    records: list[dict[str, Any]] = []

    if not FEEDS_DIR.exists():
        logger.warning(
            "Feed directory not found: %s",
            FEEDS_DIR,
        )
        return records

    feed_files = sorted(FEEDS_DIR.glob("*.json"))

    if not feed_files:
        logger.warning(
            "No JSON feed files found in: %s",
            FEEDS_DIR,
        )
        return records

    for feed_file in feed_files:
        try:
            raw = feed_file.read_text(encoding="utf-8").strip()

            if not raw:
                logger.warning(
                    "Skipping empty feed: %s",
                    feed_file,
                )
                continue

            data = json.loads(raw)

            normalized = extract_iocs_from_json(
                data,
                source=feed_file.name,
                feed_name=feed_file.stem,
            )

            records.extend(normalized)

            logger.info(
                "Loaded feed %s: %d IOC(s)",
                feed_file.name,
                len(normalized),
            )

        except json.JSONDecodeError as exc:
            logger.error(
                "Invalid JSON in feed %s: %s",
                feed_file,
                exc,
            )

        except OSError as exc:
            logger.error(
                "Unable to read feed %s: %s",
                feed_file,
                exc,
            )

    return merge_iocs(records)


def load_existing_threat_feed() -> list[dict[str, Any]]:
    """Load the existing normalized threat feed."""

    if not THREAT_FEED_FILE.exists():
        return []

    try:
        raw = THREAT_FEED_FILE.read_text(encoding="utf-8").strip()

        if not raw:
            return []

        data = json.loads(raw)

    except (OSError, json.JSONDecodeError) as exc:
        logger.error(
            "Unable to load threat feed %s: %s",
            THREAT_FEED_FILE,
            exc,
        )
        return []

    if not isinstance(data, list):
        logger.error(
            "Threat feed must contain a JSON array: %s",
            THREAT_FEED_FILE,
        )
        return []

    return [item for item in data if isinstance(item, dict)]


def save_threat_feed(
    records: list[dict[str, Any]],
) -> None:
    """Save the normalized threat feed."""

    THREAT_FEED_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    with THREAT_FEED_FILE.open(
        "w",
        encoding="utf-8",
    ) as file:
        json.dump(
            records,
            file,
            indent=2,
            ensure_ascii=False,
        )
        file.write("\n")


def sync_threat_feeds() -> list[dict[str, Any]]:
    """Synchronize local feed files into threat_feed.json."""

    logger.info("Starting threat feed synchronization.")

    incoming = load_feed_files()
    existing = load_existing_threat_feed()

    if not incoming:
        logger.warning("No IOC records found in local feeds.")
        return existing

    merged = merge_iocs(existing + incoming)
    timestamp = utc_now()

    for record in merged:
        record.setdefault("created_at", timestamp)
        record["updated_at"] = timestamp

    save_threat_feed(merged)

    logger.info(
        "Threat feed synchronization completed. Incoming=%d Stored=%d",
        len(incoming),
        len(merged),
    )

    return merged


def main() -> None:
    """Run the threat feed synchronization job."""
    sync_threat_feeds()


if __name__ == "__main__":
    main()
