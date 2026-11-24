"""Ingestion adapter: the only module that understands Suricata's EVE JSON format.

To use another detection engine, write a new adapter that yields AlertRecord
objects; nothing after this module needs to change (NFR7).
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Iterator, Optional

from .models import AlertRecord


def _parse_time(value: str) -> datetime:
    # Suricata writes e.g. 2026-10-26T09:59:13.123456+0000
    for fmt in ("%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    return datetime.now(timezone.utc)


def parse_line(line: str) -> Optional[AlertRecord]:
    """Turn one EVE JSON line into an AlertRecord, or None if it is not an alert."""
    line = line.strip()
    if not line:
        return None
    try:
        event = json.loads(line)
    except json.JSONDecodeError:
        return None
    if event.get("event_type") != "alert":
        return None
    alert = event.get("alert", {})
    metadata = alert.get("metadata") or {}
    confidence = metadata.get("confidence")
    if isinstance(confidence, list):
        confidence = confidence[0] if confidence else None
    return AlertRecord(
        timestamp=_parse_time(event.get("timestamp", "")),
        src_ip=event.get("src_ip", ""),
        dest_ip=event.get("dest_ip", ""),
        src_port=event.get("src_port"),
        dest_port=event.get("dest_port"),
        proto=event.get("proto"),
        signature_id=int(alert.get("signature_id", 0)),
        signature=alert.get("signature", ""),
        category=alert.get("category"),
        suricata_severity=int(alert.get("severity", 3)),
        rule_confidence=confidence,
        raw=event,
    )


def read_all(path: str) -> Iterator[AlertRecord]:
    """Read a finished EVE file once (used for scenario replay and testing)."""
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            record = parse_line(line)
            if record:
                yield record


def follow(path: str, from_start: bool = False, poll_seconds: float = 0.5) -> Iterator[Optional[AlertRecord]]:
    """Follow a live EVE file like `tail -F`, surviving log rotation.

    Yields an AlertRecord for each new alert, and None on idle ticks so that the
    caller can run time-based checks such as escalation.
    """
    while not os.path.exists(path):
        time.sleep(poll_seconds)
    handle = open(path, "r", encoding="utf-8")
    inode = os.fstat(handle.fileno()).st_ino
    if not from_start:
        handle.seek(0, os.SEEK_END)
    buffer = ""
    while True:
        chunk = handle.readline()
        if chunk:
            buffer += chunk
            if buffer.endswith("\n"):
                record = parse_line(buffer)
                buffer = ""
                if record:
                    yield record
            continue
        time.sleep(poll_seconds)
        yield None  # idle tick
        try:
            stat = os.stat(path)
        except FileNotFoundError:
            continue
        if stat.st_ino != inode or stat.st_size < handle.tell():
            handle.close()  # file was rotated or truncated: reopen from the start
            handle = open(path, "r", encoding="utf-8")
            inode = os.fstat(handle.fileno()).st_ino
            buffer = ""
