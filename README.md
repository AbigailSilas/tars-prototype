# TARS prototype (Tiered Autonomous Response System)

Decision-and-action layer that reads Suricata EVE JSON alerts, scores them,
assigns Tier 1 (contain, then notify), Tier 2 (notify) or Tier 3 (log), and
keeps a hash-chained audit log. See the TARS Prototype Build Guide for setup.

Quick start (safe dry-run mode, nothing is blocked or sent):

    python3 -m venv .venv && source .venv/bin/activate
    pip install -r requirements.txt
    python -m pytest -q                 # 14 tests should pass
    python scenarios/make_pcaps.py      # build the 8 test scenarios
    python scenarios/evaluate.py        # needs Suricata installed
    python scenarios/benchmark.py       # processing-time measurement
    python scenarios/sensitivity.py     # threshold/weight sensitivity and baseline comparison

Commands: `python -m tars run|list|show|verify|release|ack|report --help`

FOR TEST NETWORKS ONLY. Do not enable containment on a live hospital network.
