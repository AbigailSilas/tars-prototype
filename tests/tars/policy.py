"""Tier decision engine: applies the approved tier policy (thesis Table 3.4)."""
from __future__ import annotations

from typing import Optional

import yaml

from .models import Asset, Decision


class TierPolicy:
    def __init__(self, path: str):
        with open(path, "r", encoding="utf-8") as handle:
            self.data = yaml.safe_load(handle)
        self.version = str(self.data["version"])
        self.weights = self.data["weights"]
        t = self.data["thresholds"]
        self.tier1_confidence = float(t["tier1_confidence"])
        self.tier2_confidence = float(t["tier2_confidence"])
        self.high_severities = set(t.get("high_severities", ["High", "Critical"]))
        self.approved_actions = set(self.data.get("approved_actions", []))
        self.window_minutes = int(self.data.get("corroboration_window_minutes", 10))

    @staticmethod
    def choose_action(device_ip: str, external_ip: Optional[str]):
        """Block the outside party if there is one; otherwise isolate the internal device."""
        if external_ip:
            return "block_external_ip", external_ip
        return "isolate_internal_host", device_ip

    def decide(self, asset: Asset, external_ip: Optional[str], c: float, sev: str,
               evidence: str) -> Decision:
        action_type, target = self.choose_action(asset.ip_address, external_ip)
        high_sev = sev in self.high_severities
        reasons = []

        if c >= self.tier1_confidence and high_sev:
            if asset.is_protected:
                reasons.append(f"{asset.hostname} is a protected device, so no automatic action")
            elif action_type not in self.approved_actions:
                reasons.append(f"action '{action_type}' is not on the approved list")
            else:
                rationale = (f"Tier 1: C = {c:.2f} ({evidence}); severity {sev}; "
                             f"action '{action_type}' on {target} approved in policy version {self.version}.")
                return Decision(c, sev, 1, action_type, target, rationale)
            rationale = f"Tier 2: C = {c:.2f} ({evidence}); severity {sev}; " + "; ".join(reasons) + "."
            return Decision(c, sev, 2, None, None, rationale)

        if c >= self.tier2_confidence or high_sev:
            rationale = (f"Tier 2: C = {c:.2f} ({evidence}); severity {sev}; "
                         f"below the Tier 1 threshold of {self.tier1_confidence} or severity not High/Critical.")
            return Decision(c, sev, 2, None, None, rationale)

        rationale = (f"Tier 3: C = {c:.2f} ({evidence}); severity {sev}; "
                     f"below the Tier 2 threshold of {self.tier2_confidence}.")
        return Decision(c, sev, 3, None, None, rationale)
