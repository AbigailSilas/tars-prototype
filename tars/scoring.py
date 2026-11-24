"""Scoring engine: confidence score C and severity level (thesis Section 3.5.1).

    C = min(1, w_r * r + w_k * min(k / 3, 1) + w_b * b)

r = reliability of the detection rule, k = related alerts on the same device
within the corroboration window, b = 1 if the external address is on the local
blocklist. Weights come from policy.yaml so they can be changed and approved.
"""
from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta
from typing import Dict

RELIABILITY = {"high": 0.9, "medium": 0.6, "low": 0.3}
DEFAULT_RELIABILITY = 0.5
LEVELS = ["Low", "Medium", "High", "Critical"]


def rule_reliability(rule_confidence) -> float:
    if not rule_confidence:
        return DEFAULT_RELIABILITY
    return RELIABILITY.get(str(rule_confidence).strip().lower(), DEFAULT_RELIABILITY)


def confidence(r: float, k: int, b: int, weights: Dict[str, float]) -> float:
    value = weights["rule"] * r + weights["corroboration"] * min(k / 3, 1) + weights["blocklist"] * b
    return round(min(1.0, value), 2)


def severity(suricata_severity: int, asset_criticality: str) -> str:
    """Suricata uses 1 for the highest priority. Raise one level for a high-criticality device."""
    if suricata_severity <= 1:
        index = 2      # High
    elif suricata_severity == 2:
        index = 1      # Medium
    else:
        index = 0      # Low
    if asset_criticality == "high":
        index = min(index + 1, 3)
    return LEVELS[index]


class Corroborator:
    """Counts other alerts on the same device within a time window."""

    def __init__(self, window_minutes: int = 10):
        self.window = timedelta(minutes=window_minutes)
        self._seen = defaultdict(deque)

    def count_and_add(self, device_ip: str, when: datetime) -> int:
        times = self._seen[device_ip]
        while times and when - times[0] > self.window:
            times.popleft()
        k = len(times)
        times.append(when)
        return k


def load_blocklist(path: str) -> set:
    items = set()
    try:
        with open(path, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.split("#", 1)[0].strip()
                if line:
                    items.add(line)
    except FileNotFoundError:
        pass
    return items
