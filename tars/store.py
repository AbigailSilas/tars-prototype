"""Audit store: SQLite tables from thesis Figure 3.3 plus a hash-chained audit log.

Every insert or update writes an AUDIT_LOG entry holding:
  record_hash = SHA-256 of the row as it stood at that moment
  entry_hash  = SHA-256 of (prev_hash, table, record id, event, timestamp, record_hash)
Changing a past row or a past log entry breaks the chain, and `tars verify` reports it.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from typing import Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS asset (
    asset_id INTEGER PRIMARY KEY,
    ip_address TEXT UNIQUE NOT NULL,
    hostname TEXT, device_type TEXT, criticality TEXT, is_protected INTEGER
);
CREATE TABLE IF NOT EXISTS alert (
    alert_id INTEGER PRIMARY KEY,
    asset_id INTEGER REFERENCES asset(asset_id),
    timestamp TEXT, src_ip TEXT, dest_ip TEXT,
    signature_id INTEGER, signature TEXT, suricata_severity INTEGER, raw_json TEXT
);
CREATE TABLE IF NOT EXISTS policy_version (
    policy_id TEXT PRIMARY KEY,
    thresholds TEXT, approved_actions TEXT, approved_by TEXT, approved_at TEXT
);
CREATE TABLE IF NOT EXISTS decision (
    decision_id INTEGER PRIMARY KEY,
    alert_id INTEGER UNIQUE REFERENCES alert(alert_id),
    policy_id TEXT REFERENCES policy_version(policy_id),
    confidence REAL, severity TEXT, tier INTEGER, rationale TEXT, decided_at TEXT
);
CREATE TABLE IF NOT EXISTS action (
    action_id INTEGER PRIMARY KEY,
    decision_id INTEGER REFERENCES decision(decision_id),
    action_type TEXT, target TEXT, status TEXT, detail TEXT,
    executed_at TEXT, released_at TEXT, released_by TEXT
);
CREATE TABLE IF NOT EXISTS contact (
    contact_id INTEGER PRIMARY KEY,
    name TEXT, role TEXT, phone TEXT UNIQUE, channel TEXT
);
CREATE TABLE IF NOT EXISTS notification (
    notification_id INTEGER PRIMARY KEY,
    decision_id INTEGER REFERENCES decision(decision_id),
    contact_id INTEGER REFERENCES contact(contact_id),
    channel TEXT, message TEXT, status TEXT, sent_at TEXT,
    acknowledged_at TEXT, acknowledged_by TEXT, escalated INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit_log (
    entry_id INTEGER PRIMARY KEY,
    table_name TEXT, record_id TEXT, event TEXT, timestamp TEXT,
    record_hash TEXT, prev_hash TEXT, entry_hash TEXT
);
"""

GENESIS = "0" * 64
KEYS = {"asset": "asset_id", "alert": "alert_id", "policy_version": "policy_id",
        "decision": "decision_id", "action": "action_id", "contact": "contact_id",
        "notification": "notification_id"}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _entry_hash(prev_hash, table, record_id, event, timestamp, record_hash) -> str:
    return _sha("|".join([prev_hash, table, str(record_id), event, timestamp, record_hash]))


class Store:
    def __init__(self, path: str):
        self.db = sqlite3.connect(path)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ---------- audit chain ----------
    def _row(self, table: str, record_id) -> Optional[dict]:
        row = self.db.execute(f"SELECT * FROM {table} WHERE {KEYS[table]} = ?", (record_id,)).fetchone()
        return dict(row) if row else None

    def _row_hash(self, table: str, record_id) -> str:
        return _sha(json.dumps(self._row(table, record_id), sort_keys=True, default=str))

    def audit(self, table: str, record_id, event: str) -> None:
        last = self.db.execute("SELECT entry_hash FROM audit_log ORDER BY entry_id DESC LIMIT 1").fetchone()
        prev_hash = last["entry_hash"] if last else GENESIS
        ts = now_iso()
        record_hash = self._row_hash(table, record_id)
        entry_hash = _entry_hash(prev_hash, table, record_id, event, ts, record_hash)
        self.db.execute(
            "INSERT INTO audit_log (table_name, record_id, event, timestamp, record_hash, prev_hash, entry_hash)"
            " VALUES (?,?,?,?,?,?,?)", (table, str(record_id), event, ts, record_hash, prev_hash, entry_hash))
        self.db.commit()

    def verify(self):
        """Return a list of problems; an empty list means the log and records are intact."""
        problems = []
        prev = GENESIS
        latest = {}
        for e in self.db.execute("SELECT * FROM audit_log ORDER BY entry_id"):
            if e["prev_hash"] != prev:
                problems.append(f"entry {e['entry_id']}: chain broken (prev_hash does not match)")
            expected = _entry_hash(e["prev_hash"], e["table_name"], e["record_id"], e["event"],
                                   e["timestamp"], e["record_hash"])
            if expected != e["entry_hash"]:
                problems.append(f"entry {e['entry_id']}: entry has been altered")
            prev = e["entry_hash"]
            latest[(e["table_name"], e["record_id"])] = e["record_hash"]
        for (table, record_id), recorded in latest.items():
            if self._row_hash(table, record_id) != recorded:
                problems.append(f"{table} {record_id}: record changed outside TARS since its last audit entry")
        return problems

    # ---------- inserts and updates ----------
    def _insert(self, table: str, values: dict, event: str) -> int:
        cols = ", ".join(values)
        marks = ", ".join("?" for _ in values)
        cur = self.db.execute(f"INSERT INTO {table} ({cols}) VALUES ({marks})", tuple(values.values()))
        self.db.commit()
        record_id = values.get(KEYS[table], cur.lastrowid)
        self.audit(table, record_id, event)
        return record_id

    def _update(self, table: str, record_id, values: dict, event: str) -> None:
        sets = ", ".join(f"{k} = ?" for k in values)
        self.db.execute(f"UPDATE {table} SET {sets} WHERE {KEYS[table]} = ?", (*values.values(), record_id))
        self.db.commit()
        self.audit(table, record_id, event)

    def upsert_asset(self, asset) -> int:
        row = self.db.execute("SELECT asset_id FROM asset WHERE ip_address = ?", (asset.ip_address,)).fetchone()
        if row:
            return row["asset_id"]
        return self._insert("asset", {"ip_address": asset.ip_address, "hostname": asset.hostname,
                                      "device_type": asset.device_type, "criticality": asset.criticality,
                                      "is_protected": int(asset.is_protected)}, "asset registered")

    def ensure_policy(self, policy) -> None:
        if self._row("policy_version", policy.version):
            return
        self._insert("policy_version", {
            "policy_id": policy.version,
            "thresholds": json.dumps({"weights": policy.weights,
                                      "tier1_confidence": policy.tier1_confidence,
                                      "tier2_confidence": policy.tier2_confidence}),
            "approved_actions": json.dumps(sorted(policy.approved_actions)),
            "approved_by": policy.data.get("approved_by", "not recorded"),
            "approved_at": str(policy.data.get("approved_at", "not recorded"))}, "policy version loaded")

    def upsert_contact(self, c: dict) -> int:
        row = self.db.execute("SELECT contact_id FROM contact WHERE phone = ?", (c["phone"],)).fetchone()
        if row:
            return row["contact_id"]
        return self._insert("contact", {"name": c["name"], "role": c["role"], "phone": c["phone"],
                                        "channel": c.get("channel", "sms")}, "contact registered")

    def add_alert(self, asset_id: int, alert) -> int:
        return self._insert("alert", {"asset_id": asset_id, "timestamp": alert.timestamp.isoformat(),
                                      "src_ip": alert.src_ip, "dest_ip": alert.dest_ip,
                                      "signature_id": alert.signature_id, "signature": alert.signature,
                                      "suricata_severity": alert.suricata_severity,
                                      "raw_json": json.dumps(alert.raw, sort_keys=True)}, "alert received")

    def add_decision(self, alert_id: int, policy_id: str, d) -> int:
        return self._insert("decision", {"alert_id": alert_id, "policy_id": policy_id,
                                         "confidence": d.confidence, "severity": d.severity, "tier": d.tier,
                                         "rationale": d.rationale, "decided_at": now_iso()},
                            f"tier {d.tier} assigned")

    def add_action(self, decision_id: int, action_type: str, target: str, status: str, detail: str) -> int:
        return self._insert("action", {"decision_id": decision_id, "action_type": action_type,
                                       "target": target, "status": status, "detail": detail,
                                       "executed_at": now_iso()}, f"action {status}")

    def add_notification(self, decision_id, contact_id, channel, message, status) -> int:
        return self._insert("notification", {"decision_id": decision_id, "contact_id": contact_id,
                                             "channel": channel, "message": message, "status": status,
                                             "sent_at": now_iso()}, f"notification {status}")

    def release_action(self, action_id: int, by: str) -> None:
        self._update("action", action_id, {"status": "released", "released_at": now_iso(),
                                           "released_by": by}, f"containment released by {by}")

    def acknowledge(self, notification_id: int, by: str) -> None:
        self._update("notification", notification_id, {"acknowledged_at": now_iso(),
                                                       "acknowledged_by": by}, f"acknowledged by {by}")

    def mark_escalated(self, notification_id: int) -> None:
        self._update("notification", notification_id, {"escalated": 1}, "escalated")

    # ---------- queries ----------
    def active_block(self, target: str):
        return self.db.execute("SELECT * FROM action WHERE target = ? AND status = 'executed'",
                               (target,)).fetchone()

    def recent_notification(self, asset_id: int, signature_id: int, since_iso: str):
        return self.db.execute(
            "SELECT n.notification_id FROM notification n JOIN decision d ON n.decision_id = d.decision_id "
            "JOIN alert a ON d.alert_id = a.alert_id WHERE a.asset_id = ? AND a.signature_id = ? "
            "AND n.sent_at >= ? AND n.status != 'suppressed'", (asset_id, signature_id, since_iso)).fetchone()
