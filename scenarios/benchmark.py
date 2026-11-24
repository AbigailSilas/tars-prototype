"""Performance measurements for Research Question 2 (thesis Section 3.1.3).

Part A (any user): processing time per alert for 1,000 synthetic alerts, dry-run.
Part B (root, test machine only): live end-to-end time from an alert being written
        to the EVE file until the attacker's address is present in the nftables set,
        repeated for 20 separate attackers. Requires setup/nftables-setup.sh first.

Run:  python scenarios/benchmark.py          (Part A)
      sudo .venv/bin/python scenarios/benchmark.py --live   (Parts A and B)
"""
import copy
import json
import os
import statistics
import subprocess
import sys
import random
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
os.chdir(ROOT)

from tars.adapter import parse_line          # noqa: E402
from tars.engine import Engine, load_config  # noqa: E402


def line(src, dst, sev=1, conf="High", sid=9000001):
    ts = time.strftime("%Y-%m-%dT%H:%M:%S.000000+0000", time.gmtime())
    return json.dumps({"timestamp": ts, "event_type": "alert", "src_ip": src, "dest_ip": dst,
                       "alert": {"signature_id": sid, "signature": "TARS TEST benchmark", "severity": sev,
                                 "metadata": {"confidence": [conf]}}})


def summary(name, values):
    values = sorted(values)
    p95 = values[max(0, int(round(0.95 * len(values))) - 1)]
    print(f"{name}: n={len(values)} mean={statistics.mean(values):.2f} median={statistics.median(values):.2f} "
          f"p95={p95:.2f} max={max(values):.2f}")
    return {"n": len(values), "mean": statistics.mean(values), "median": statistics.median(values),
            "p95": p95, "max": max(values)}


def part_a():
    cfg = copy.deepcopy(load_config("config/tars.yaml"))
    cfg["database"] = os.path.join(tempfile.mkdtemp(), "bench.db")
    engine = Engine(cfg, quiet=True)
    mix = [("203.0.113.50", "192.168.10.21", 1, "High"), ("198.51.100.77", "192.168.10.22", 1, "High"),
           ("192.168.10.22", "192.168.10.1", 2, "Medium"), ("198.51.100.9", "192.168.10.21", 3, "Low"),
           ("203.0.113.50", "192.168.10.5", 1, "High")]
    times, tiers = [], {1: 0, 2: 0, 3: 0}
    start = time.perf_counter()
    for i in range(1000):
        src, dst, sev, conf = mix[i % len(mix)]
        alert = parse_line(line(src, dst, sev, conf))
        t0 = time.perf_counter()
        tiers[engine.process(alert).tier] += 1
        times.append((time.perf_counter() - t0) * 1000)
    total = time.perf_counter() - start
    print(f"Part A: 1,000 alerts in {total:.2f} s ({1000 / total:.0f} alerts per second); tiers {tiers}")
    stats = summary("Part A processing time per alert (ms)", times)
    print("Audit log after Part A:", "intact" if not engine.store.verify() else "FAILED")
    return stats


def nft_has(ip):
    out = subprocess.run(["nft", "list", "set", "inet", "tars", "blocklist"], capture_output=True, text=True)
    return ip in out.stdout


def part_b(trials=20):
    work = tempfile.mkdtemp()
    eve = os.path.join(work, "eve.json")
    open(eve, "w").close()
    attackers = [f"203.0.113.{100 + i}" for i in range(trials)]
    with open(os.path.join(work, "blocklist.txt"), "w") as f:
        f.write("\n".join(attackers) + "\n")
    cfg = copy.deepcopy(load_config("config/tars.yaml"))
    cfg.update({"database": os.path.join(work, "live.db"), "blocklist": os.path.join(work, "blocklist.txt"),
                "eve_path": eve})
    cfg["containment"]["enabled"] = True
    import yaml
    cfg_path = os.path.join(work, "live.yaml")
    with open(cfg_path, "w") as f:
        yaml.safe_dump(cfg, f)
    proc = subprocess.Popen([sys.executable, "-m", "tars", "--config", cfg_path, "run", "--quiet"],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(2)
    latencies = []
    try:
        for i, attacker in enumerate(attackers):
            device = f"192.168.20.{10 + i}"          # a separate, unprotected device per trial
            with open(eve, "a") as f:
                f.write(line(attacker, device) + "\n" + line(attacker, device) + "\n")
                f.flush()
            time.sleep(1.5 + random.uniform(0, 0.5))   # random offset so writes do not line up with TARS's 0.5 s polling
            t0 = time.perf_counter()
            with open(eve, "a") as f:                # third alert pushes confidence to the Tier 1 threshold
                f.write(line(attacker, device) + "\n")
                f.flush()
            while not nft_has(attacker):
                if time.perf_counter() - t0 > 10:
                    break
                time.sleep(0.005)
            latencies.append((time.perf_counter() - t0) * 1000)
    finally:
        proc.terminate()
        proc.wait()
    blocked = sum(nft_has(a) for a in attackers)
    print(f"Part B: {blocked}/{trials} attacker addresses present in the nftables set")
    stats = summary("Part B alert-to-containment time (ms)", latencies)
    for a in attackers:                              # clean up the test addresses
        subprocess.run(["nft", "delete", "element", "inet", "tars", "blocklist", "{", a, "}"],
                       capture_output=True)
    return stats


if __name__ == "__main__":
    part_a()
    if "--live" in sys.argv:
        part_b()
