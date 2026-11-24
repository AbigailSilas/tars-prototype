"""Sensitivity analysis and comparison with a simple baseline (thesis Section 5.4.5).

Run:  python scenarios/sensitivity.py
Part A replays the eight scenarios under different Tier 1 thresholds and weight sets
and reports which scenarios reach automatic containment.
Part B compares TARS with a simple "block on every high-priority alert" rule, the
behaviour of an intrusion prevention system that drops traffic on every severity-1 alert.
Containment and notifications stay in dry-run mode throughout.
"""
import copy
import csv
import os
import subprocess
import sys
import tempfile

import yaml

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from tars.adapter import read_all          # noqa: E402
from tars.engine import Engine, load_config  # noqa: E402
from tars.enrich import AssetInventory, locate  # noqa: E402

cfg = load_config("config/tars.yaml")
base_policy = yaml.safe_load(open(cfg["policy"]))
names = [r["scenario"] for r in csv.DictReader(open(os.path.join(HERE, "expected.csv")))]
short = {n: n.split("_")[0].upper() for n in names}

# Run Suricata once per scenario and keep the alerts.
alerts = {}
for name in names:
    work = tempfile.mkdtemp(prefix="tars-sens-")
    subprocess.run(["suricata", "-r", os.path.join(HERE, "pcaps", name + ".pcap"),
                    "-S", "rules/tars-test.rules", "-l", work, "-k", "none"], check=True, capture_output=True)
    alerts[name] = list(read_all(os.path.join(work, "eve.json")))


def run(policy):
    """Return {scenario: (highest tier, automatic blocks executed)} under a policy."""
    tmp = tempfile.mkdtemp(prefix="tars-pol-")
    path = os.path.join(tmp, "policy.yaml")
    yaml.safe_dump(policy, open(path, "w"))
    out = {}
    for name in names:
        c = copy.deepcopy(cfg)
        c["policy"] = path
        c["database"] = os.path.join(tmp, name + ".db")
        c["containment"]["enabled"] = False
        c["notifications"]["enabled"] = False
        engine = Engine(c, quiet=True)
        tiers = [engine.process(a).tier for a in alerts[name]]
        blocks = engine.store.db.execute("SELECT COUNT(*) FROM action WHERE status = 'executed'").fetchone()[0]
        out[name] = (min(tiers), blocks)
    return out


def describe(label, res):
    t1 = [short[n] for n in names if res[n][0] == 1]
    print(f"{label:<44} Tier 1 in: {', '.join(t1) or 'none':<14} blocks: {sum(b for _, b in res.values())}")


print("Part A: sensitivity of automatic containment to thresholds and weights\n")
print("A1. Tier 1 confidence threshold (weights 0.5 / 0.3 / 0.2)")
for th in [0.75, 0.80, 0.85, 0.90, 0.95]:
    p = copy.deepcopy(base_policy)
    p["thresholds"]["tier1_confidence"] = th
    describe(f"  threshold {th:.2f}" + ("  (approved value)" if th == 0.85 else ""), run(p))

print("\nA2. Weight sets (rule / corroboration / blocklist), threshold 0.85")
for label, w in [("0.50 / 0.30 / 0.20  (approved value)", (0.5, 0.3, 0.2)),
                 ("0.60 / 0.30 / 0.10  rule-heavy", (0.6, 0.3, 0.1)),
                 ("0.40 / 0.40 / 0.20  corroboration-heavy", (0.4, 0.4, 0.2)),
                 ("0.40 / 0.30 / 0.30  blocklist-heavy", (0.4, 0.3, 0.3)),
                 ("0.34 / 0.33 / 0.33  equal", (0.34, 0.33, 0.33))]:
    p = copy.deepcopy(base_policy)
    p["weights"] = {"rule": w[0], "corroboration": w[1], "blocklist": w[2]}
    describe("  " + label, run(p))

print("\nA3. Highest confidence reachable without a blocklist match (r = 0.9, k >= 3)")
for label, w in [("approved", (0.5, 0.3, 0.2)), ("rule-heavy", (0.6, 0.3, 0.1)),
                 ("corroboration-heavy", (0.4, 0.4, 0.2)), ("blocklist-heavy", (0.4, 0.3, 0.3)),
                 ("equal", (0.34, 0.33, 0.33))]:
    print(f"  {label:<22} C max = {min(1, w[0] * 0.9 + w[1]):.2f}")

print("\nPart B: TARS compared with blocking on every high-priority alert\n")
inv = AssetInventory(cfg["assets"])
home = cfg.get("home_net")
tars = run(base_policy)
print(f"{'scenario':<6}{'alerts':>7}  {'baseline blocks':>15}  {'1st block at alert':>18}  "
      f"{'device protected/internal':>25}  {'TARS blocks':>11}  {'TARS 1st block':>14}  TARS tier")
tot = {"b": 0, "single": 0, "internal": 0, "tars": 0}
for name in names:
    blocked, first, internal_hits = set(), None, 0
    for i, a in enumerate(alerts[name], 1):
        if a.suricata_severity <= 1:
            device, external = locate(a, home)
            target = external or a.src_ip   # an IPS drops the offending source
            if target not in blocked:
                blocked.add(target)
                first = first or i
                if external is None or inv.lookup(device).is_protected:
                    internal_hits += 1
    # When did TARS first block in this scenario?
    tars_first = None
    if tars[name][1]:
        p = copy.deepcopy(cfg)
        tmp = tempfile.mkdtemp(prefix="tars-first-")
        p["database"] = os.path.join(tmp, "x.db")
        p["containment"]["enabled"] = False
        p["notifications"]["enabled"] = False
        e = Engine(p, quiet=True)
        for i, a in enumerate(alerts[name], 1):
            if e.process(a).tier == 1:
                tars_first = i
                break
    tot["b"] += len(blocked)
    tot["single"] += 1 if (blocked and len(alerts[name]) == 1) else 0
    tot["internal"] += internal_hits
    tot["tars"] += tars[name][1]
    print(f"{short[name]:<6}{len(alerts[name]):>7}  {len(blocked):>15}  {str(first or '-'):>18}  "
          f"{internal_hits:>25}  {tars[name][1]:>11}  {str(tars_first or '-'):>14}  {tars[name][0]}")
print(f"\nBaseline: {tot['b']} automatic blocks, {tot['single']} on a single uncorroborated alert, "
      f"{tot['internal']} where the facility device was protected or the target was internal; no one is notified.")
print(f"TARS:     {tot['tars']} automatic block(s); all other high-priority alerts sent to staff (Tier 2).")
