"""Replay every scenario through Suricata and TARS, and compare tiers with expectations.

Run:  python scenarios/evaluate.py
Each scenario gets a fresh database. Containment and notifications stay in dry-run.
Measures (thesis Section 3.1.3): tier agreement, TARS processing time per alert,
safety violations (automatic action on a protected device or an unapproved action),
and audit-log integrity. Output: a table and scenarios/results.csv.
"""
import copy
import csv
import os
import statistics
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from tars.adapter import read_all          # noqa: E402
from tars.engine import Engine, load_config  # noqa: E402

cfg = load_config("config/tars.yaml")
rows = list(csv.DictReader(open(os.path.join(HERE, "expected.csv"))))
results = []
for row in rows:
    name = row["scenario"]
    pcap = os.path.join(HERE, "pcaps", name + ".pcap")
    work = tempfile.mkdtemp(prefix="tars-" + name + "-")
    subprocess.run(["suricata", "-r", pcap, "-S", "rules/tars-test.rules", "-l", work, "-k", "none"],
                   check=True, capture_output=True)
    run_cfg = copy.deepcopy(cfg)
    run_cfg["database"] = os.path.join(work, "tars.db")
    run_cfg["containment"]["enabled"] = False
    run_cfg["notifications"]["enabled"] = False
    engine = Engine(run_cfg, quiet=True)
    tiers, times = [], []
    for alert in read_all(os.path.join(work, "eve.json")):
        t0 = time.perf_counter()
        tiers.append(engine.process(alert).tier)
        times.append((time.perf_counter() - t0) * 1000)
    protected = {a.ip_address for a in engine.inventory.all() if a.is_protected}
    violations = 0
    for act in engine.store.db.execute("SELECT * FROM action"):
        alert_row = engine.store.db.execute(
            "SELECT a.src_ip, a.dest_ip FROM decision d JOIN alert a ON d.alert_id = a.alert_id "
            "WHERE d.decision_id = ?", (act["decision_id"],)).fetchone()
        if (act["action_type"] not in engine.policy.approved_actions
                or alert_row["src_ip"] in protected or alert_row["dest_ip"] in protected):
            violations += 1
    actual = min(tiers) if tiers else None   # Tier 1 is the strongest response reached
    expected = int(row["expected_tier"])
    results.append({"scenario": name, "alerts": len(tiers), "tiers_assigned": " ".join(map(str, tiers)),
                    "highest_response_tier": actual, "expected_tier": expected,
                    "match": "yes" if actual == expected else "no",
                    "mean_ms": round(statistics.mean(times), 2) if times else "",
                    "max_ms": round(max(times), 2) if times else "",
                    "safety_violations": violations,
                    "audit_log": "intact" if not engine.store.verify() else "FAILED"})

print(f"{'scenario':<36}{'alerts':>6}  {'tiers':<9}{'got':>4}{'exp':>4}  match {'mean ms':>8} {'max ms':>7}  viol  audit")
for r in results:
    print(f"{r['scenario']:<36}{r['alerts']:>6}  {r['tiers_assigned']:<9}{str(r['highest_response_tier']):>4}"
          f"{r['expected_tier']:>4}  {r['match']:<5} {r['mean_ms']:>8} {r['max_ms']:>7}  {r['safety_violations']:>4}  {r['audit_log']}")
agree = sum(r["match"] == "yes" for r in results)
alerts = sum(r["alerts"] for r in results)
print(f"\nAgreement with expected tiers: {agree}/{len(results)} ({100 * agree / len(results):.0f}%)")
print(f"Alerts processed: {alerts}; safety violations: {sum(r['safety_violations'] for r in results)}")
with open(os.path.join(HERE, "results.csv"), "w", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=list(results[0]))
    writer.writeheader()
    writer.writerows(results)
print("Saved scenarios/results.csv")
