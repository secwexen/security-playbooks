from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from automation.enrichment.ioc_enrichment import (
    extract_iocs_from_json,
    load_json_file,
    merge_iocs,
)
from tools.utils.logger import get_logger


PROJECT_ROOT = Path(__file__).resolve().parents[2]

FEEDS_DIR = PROJECT_ROOT / "iocs" / "feeds"
THREAT_FEED_FILE = PROJECT_ROOT / "iocs" / "threat_feed.json"

logger = get_logger(__name__)


def utc_now() -> str:
    """Return the current UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def load_feed_files() -> list[dict[str, Any]]:
    """Load and normalize JSON feed files."""
    records: list[dict[str, Any]] = []

    if not FEEDS_DIR.exists():
        logger.warning(
            "Feed directory not found: %s",
            FEEDS_DIR,
        )
        return records

    feed_files = sorted(
        FEEDS_DIR.glob("*.json")
    )

    if not feed_files:
        logger.warning(
            "No JSON feed files found in: %s",
            FEEDS_DIR,
        )
        return records

    for feed_file in feed_files:
        try:
            raw = feed_file.read_text(
                encoding="utf-8"
            ).strip()

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

    return records


def load_existing_threat_feed() -> list[dict[str, Any]]:
    """Load the existing normalized threat feed."""
    if not THREAT_FEED_FILE.exists():
        return []

    try:
        raw = THREAT_FEED_FILE.read_text(
            encoding="utf-8"
        ).strip()

        if not raw:
            return []

        data = json.loads(raw)

    except (
        OSError,
        json.JSONDecodeError,
    ) as exc:
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

    return [
        item
        for item in data
        if isinstance(item, dict)
    ]


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
    logger.info(
        "Starting threat feed synchronization."
    )

    incoming = load_feed_files()

    if not incoming:
        logger.warning(
            "No IOC records found in local feeds."
        )
        return load_existing_threat_feed()

    existing = load_existing_threat_feed()

    merged = merge_iocs(
        existing + incoming
    )

    timestamp = utc_now()

    for record in merged:
        if "created_at" not in record:
            record["created_at"] = timestamp

        record["updated_at"] = timestamp

    save_threat_feed(merged)

    logger.info(
        "Threat feed synchronization completed. "
        "Incoming=%d Stored=%d",
        len(incoming),
        len(merged),
    )

    return merged


def main() -> None:
    """Run the threat feed synchronization job."""
    sync_threat_feeds()


if __name__ == "__main__":
    main()
