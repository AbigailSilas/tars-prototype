"""Unit and integration tests. Run with:  python -m pytest -q"""
import copy
import json
import os
from datetime import datetime, timedelta, timezone

import pytest

from tars.adapter import parse_line
from tars.engine import Engine, load_config
from tars.models import Asset
from tars.policy import TierPolicy
from tars.scoring import Corroborator, confidence, rule_reliability, severity

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
WEIGHTS = {"rule": 0.5, "corroboration": 0.3, "blocklist": 0.2}


def eve(src, dst, sev=1, conf="High", sid=9000001, ts="2026-10-26T10:00:00.000000+0000"):
    return json.dumps({"timestamp": ts, "event_type": "alert", "src_ip": src, "dest_ip": dst,
                       "alert": {"signature_id": sid, "signature": "test", "severity": sev,
                                 "metadata": {"confidence": [conf]}}})


# ---------- adapter ----------
def test_parse_alert_line():
    a = parse_line(eve("203.0.113.50", "192.168.10.21"))
    assert a.signature_id == 9000001 and a.suricata_severity == 1 and a.rule_confidence == "High"


def test_non_alert_lines_are_ignored():
    assert parse_line('{"event_type":"flow"}') is None
    assert parse_line("not json") is None


# ---------- scoring ----------
def test_confidence_formula_matches_thesis():
    assert confidence(0.9, 0, 0, WEIGHTS) == 0.45
    assert confidence(0.9, 2, 1, WEIGHTS) == 0.85
    assert confidence(0.9, 10, 1, WEIGHTS) == 0.95   # corroboration capped at k = 3
    assert confidence(1.0, 3, 1, WEIGHTS) == 1.0


def test_unknown_rule_confidence_defaults_to_half():
    assert rule_reliability(None) == 0.5 and rule_reliability("weird") == 0.5


def test_severity_raised_for_critical_devices():
    assert severity(1, "medium") == "High"
    assert severity(1, "high") == "Critical"
    assert severity(3, "low") == "Low"


def test_corroboration_window():
    c = Corroborator(10)
    t = datetime(2026, 10, 26, tzinfo=timezone.utc)
    assert c.count_and_add("x", t) == 0
    assert c.count_and_add("x", t + timedelta(minutes=5)) == 1
    assert c.count_and_add("x", t + timedelta(minutes=30)) == 0


# ---------- policy ----------
@pytest.fixture
def policy():
    return TierPolicy(os.path.join(ROOT, "config", "policy.yaml"))


def test_tier1_when_all_conditions_hold(policy):
    d = policy.decide(Asset("192.168.10.21"), "203.0.113.50", 0.9, "High", "e")
    assert d.tier == 1 and d.action_type == "block_external_ip" and d.target == "203.0.113.50"


def test_protected_device_never_contained(policy):
    d = policy.decide(Asset("192.168.10.5", is_protected=True), "203.0.113.50", 1.0, "Critical", "e")
    assert d.tier == 2 and d.action_type is None


def test_unapproved_action_falls_to_tier2(policy):
    d = policy.decide(Asset("192.168.10.21"), None, 0.95, "High", "e")   # would need host isolation
    assert d.tier == 2


def test_tier3_for_low_confidence_low_severity(policy):
    assert policy.decide(Asset("192.168.10.21"), None, 0.2, "Low", "e").tier == 3


# ---------- engine + audit store ----------
@pytest.fixture
def engine(tmp_path):
    os.chdir(ROOT)
    cfg = copy.deepcopy(load_config("config/tars.yaml"))
    cfg["database"] = str(tmp_path / "t.db")
    return Engine(cfg, quiet=True)


def test_escalation_to_tier1_and_single_block(engine):
    tiers = [engine.process(parse_line(eve("203.0.113.50", "192.168.10.21",
                                           ts=f"2026-10-26T10:0{i}:00.000000+0000"))).tier for i in range(4)]
    assert tiers == [2, 2, 1, 1]
    statuses = [r[0] for r in engine.store.db.execute("SELECT status FROM action ORDER BY action_id")]
    assert statuses == ["executed", "already_active"]


def test_audit_chain_detects_tampering(engine):
    engine.process(parse_line(eve("203.0.113.50", "192.168.10.21")))
    assert engine.store.verify() == []
    engine.store.db.execute("UPDATE decision SET tier = 3")
    engine.store.db.commit()
    assert any("record changed" in p for p in engine.store.verify())


def test_notifications_contain_no_patient_fields(engine):
    engine.process(parse_line(eve("203.0.113.50", "192.168.10.5")))
    for (msg,) in engine.store.db.execute("SELECT message FROM notification"):
        assert "patient" not in msg.lower() and "ehr-server" in msg


def test_unacknowledged_notification_is_escalated_once(engine):
    engine.escalate_minutes = 0
    engine.process(parse_line(eve("198.51.100.77", "192.168.10.21")))      # Tier 2, notifies staff
    engine.check_escalations()
    engine.check_escalations()                                              # second call must not repeat
    escalations = engine.store.db.execute(
        "SELECT COUNT(*) FROM notification WHERE message LIKE '%has not been acknowledged%'").fetchone()[0]
    assert escalations == 1   # one escalation contact in contacts.yaml
