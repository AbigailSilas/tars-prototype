"""Enrichment: find which facility device an alert concerns and how critical it is."""
from __future__ import annotations

import ipaddress
from typing import Optional, Tuple

import yaml

from .models import AlertRecord, Asset


DEFAULT_HOME_NET = ["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"]  # same default as Suricata


def is_internal(ip: str, home_net=None) -> bool:
    """True if the address belongs to the facility network (HOME_NET)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(n) for n in (home_net or DEFAULT_HOME_NET))


class AssetInventory:
    def __init__(self, path: str):
        with open(path, "r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle) or {}
        self._assets = {}
        for item in data.get("assets", []):
            asset = Asset(
                ip_address=item["ip"],
                hostname=item.get("hostname", "unknown device"),
                device_type=item.get("device_type", "unknown"),
                criticality=str(item.get("criticality", "medium")).lower(),
                is_protected=bool(item.get("protected", False)),
            )
            self._assets[asset.ip_address] = asset

    def lookup(self, ip: str) -> Asset:
        return self._assets.get(ip) or Asset(ip_address=ip)

    def all(self):
        return list(self._assets.values())


def locate(alert: AlertRecord, home_net=None) -> Tuple[str, Optional[str]]:
    """Return (internal device IP, external party IP or None).

    If the alert is between two internal devices there is no external party,
    and the destination is treated as the affected device.
    """
    src_in, dst_in = is_internal(alert.src_ip, home_net), is_internal(alert.dest_ip, home_net)
    if dst_in and not src_in:
        return alert.dest_ip, alert.src_ip
    if src_in and not dst_in:
        return alert.src_ip, alert.dest_ip
    return alert.dest_ip, None
