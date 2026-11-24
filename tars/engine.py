"""Engine: wires the components together in the order shown in thesis Figure 3.1."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import yaml

from .actions import Containment, Notifier, message_for
from .enrich import AssetInventory, locate
from .models import AlertRecord
from .policy import TierPolicy
from .scoring import Corroborator, confidence, load_blocklist, rule_reliability, severity
from .store import Store


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


class Engine:
    def __init__(self, cfg: dict, quiet: bool = False):
        self.cfg = cfg
        self.quiet = quiet
        self.home_net = cfg.get("home_net")
        self.inventory = AssetInventory(cfg["assets"])
        self.policy = TierPolicy(cfg["policy"])
        self.blocklist = load_blocklist(cfg.get("blocklist", ""))
        self.corroborator = Corroborator(self.policy.window_minutes)
        self.store = Store(cfg["database"])
        cont = cfg.get("containment", {})
        self.containment = Containment(dry_run=not cont.get("enabled", False),
                                       family=cont.get("family", "inet"), table=cont.get("table", "tars"),
                                       nft_set=cont.get("set", "blocklist"))
        notes = cfg.get("notifications", {})
        self.notifier = Notifier(dry_run=not notes.get("enabled", False))
        self.suppress_minutes = int(notes.get("suppress_repeat_minutes", 30))
        self.escalate_minutes = int(notes.get("escalate_after_minutes", 60))
        with open(cfg["contacts"], "r", encoding="utf-8") as handle:
            self.contacts = (yaml.safe_load(handle) or {}).get("contacts", [])
        for c in self.contacts:
            c["contact_id"] = self.store.upsert_contact(c)
        self.store.ensure_policy(self.policy)

    def log(self, text: str) -> None:
        if not self.quiet:
            print(text, flush=True)

    # ------------------------------------------------------------------
    def process(self, alert: AlertRecord):
        device_ip, external_ip = locate(alert, self.home_net)
        asset = self.inventory.lookup(device_ip)
        asset_id = self.store.upsert_asset(asset)
        alert_id = self.store.add_alert(asset_id, alert)

        r = rule_reliability(alert.rule_confidence)
        k = self.corroborator.count_and_add(device_ip, alert.timestamp)
        b = 1 if external_ip and external_ip in self.blocklist else 0
        c = confidence(r, k, b, self.policy.weights)
        sev = severity(alert.suricata_severity, asset.criticality)
        evidence = (f"rule reliability {r}, {k} related alert(s) in {self.policy.window_minutes} min, "
                    f"{'on' if b else 'not on'} blocklist")
        d = self.policy.decide(asset, external_ip, c, sev, evidence)
        decision_id = self.store.add_decision(alert_id, self.policy.version, d)
        self.log(f"[decision {decision_id}] {alert.signature} | {asset.hostname} | {d.rationale}")

        if d.tier == 1:
            if self.store.active_block(d.target):
                self.store.add_action(decision_id, d.action_type, d.target, "already_active",
                                      "address already blocked by an earlier decision")
                self.log(f"  {d.target} already blocked; no new action")
            else:
                ok, detail = self.containment.block(d.target)
                self.store.add_action(decision_id, d.action_type, d.target, "executed" if ok else "failed", detail)
                self.log(f"  containment {'executed' if ok else 'FAILED'}: {detail}")
                if not ok:  # fall back to a Tier 2 style message so a person is told
                    self._notify(decision_id, 2, asset, alert, d.target)
                    return d
            self._notify(decision_id, 1, asset, alert, d.target)
        elif d.tier == 2:
            self._notify(decision_id, 2, asset, alert, None)
        return d

    def _notify(self, decision_id, tier, asset, alert, target):
        since = (datetime.now(timezone.utc) - timedelta(minutes=self.suppress_minutes)).isoformat(timespec="seconds")
        repeat = tier == 2 and self.store.recent_notification(
            self.store.upsert_asset(asset), alert.signature_id, since)
        text = message_for(tier, decision_id, asset.hostname, asset.device_type, target or "")
        for c in self.contacts:
            if tier not in c.get("notify_tiers", [1, 2]):
                continue
            if repeat:
                self.store.add_notification(decision_id, c["contact_id"], c.get("channel", "sms"), text, "suppressed")
                continue
            status, detail = self.notifier.send(c["phone"], c.get("channel", "sms"), text)
            self.store.add_notification(decision_id, c["contact_id"], c.get("channel", "sms"), text, status)
            self.log(f"  notify {c['name']}: {status}")

    # ------------------------------------------------------------------
    def check_escalations(self):
        """FR11: if nobody acknowledged a notification in time, tell the escalation contacts once."""
        cutoff = (datetime.now(timezone.utc) - timedelta(minutes=self.escalate_minutes)).isoformat(timespec="seconds")
        rows = self.store.db.execute(
            "SELECT DISTINCT decision_id FROM notification WHERE status IN ('sent','dry-run') "
            "AND acknowledged_at IS NULL AND escalated = 0 AND sent_at <= ? "
            "AND decision_id NOT IN (SELECT decision_id FROM notification WHERE acknowledged_at IS NOT NULL)",
            (cutoff,)).fetchall()
        for row in rows:
            ref = row["decision_id"]
            text = (f"TARS alert {ref} has not been acknowledged after {self.escalate_minutes} minutes. "
                    f"Please contact the IT contractor and quote {ref}.")
            for c in self.contacts:
                if c.get("escalation"):
                    status, _ = self.notifier.send(c["phone"], c.get("channel", "sms"), text)
                    self.store.add_notification(ref, c["contact_id"], c.get("channel", "sms"), text, status)
            for n in self.store.db.execute("SELECT notification_id FROM notification WHERE decision_id = ? "
                                           "AND escalated = 0", (ref,)).fetchall():
                self.store.mark_escalated(n["notification_id"])
            self.log(f"[escalation] decision {ref} escalated")
