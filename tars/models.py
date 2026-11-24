"""Data records passed between TARS components."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


@dataclass
class AlertRecord:
    """Engine-neutral alert. Only the adapter knows the detection engine's format."""
    timestamp: datetime
    src_ip: str
    dest_ip: str
    signature_id: int
    signature: str
    suricata_severity: int
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    proto: Optional[str] = None
    category: Optional[str] = None
    rule_confidence: Optional[str] = None  # e.g. "High", "Medium", "Low" from rule metadata
    raw: dict = field(default_factory=dict)


@dataclass
class Asset:
    ip_address: str
    hostname: str = "unknown device"
    device_type: str = "unknown"
    criticality: str = "medium"  # low | medium | high
    is_protected: bool = False


@dataclass
class Decision:
    confidence: float
    severity: str          # Low | Medium | High | Critical
    tier: int              # 1, 2 or 3
    action_type: Optional[str]
    target: Optional[str]
    rationale: str
