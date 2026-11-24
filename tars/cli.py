"""Command-line interface: `python -m tars <command>`.

  run       process alerts (live, or --once for a finished file)
  list      show recent decisions
  show      show one decision with its actions and notifications
  verify    check the hash-chained audit log
  release   reverse a containment action (authorised staff only)
  ack       record that a notification was seen
  report    write a summary report for the IT contractor or auditor
"""
from __future__ import annotations

import argparse
import sys
import time
from datetime import datetime, timezone

from .adapter import follow, read_all
from .engine import Engine, load_config
from .store import Store


def cmd_run(args, cfg):
    engine = Engine(cfg, quiet=args.quiet)
    eve = args.eve or cfg["eve_path"]
    if args.once:
        count = 0
        for alert in read_all(eve):
            engine.process(alert)
            count += 1
        print(f"Processed {count} alert(s) from {eve}")
        return 0
    print(f"TARS watching {eve} (Ctrl+C to stop)", flush=True)
    last_check = time.monotonic()
    try:
        for alert in follow(eve, from_start=args.from_start):
            if alert is not None:
                engine.process(alert)
            if time.monotonic() - last_check >= 60:
                engine.check_escalations()
                last_check = time.monotonic()
    except KeyboardInterrupt:
        print("Stopped.")
    return 0


def cmd_list(args, cfg):
    store = Store(cfg["database"])
    sql = ("SELECT d.decision_id, d.tier, d.confidence, d.severity, a.signature, s.hostname, d.decided_at "
           "FROM decision d JOIN alert a ON d.alert_id = a.alert_id JOIN asset s ON a.asset_id = s.asset_id")
    params = []
    if args.tier:
        sql += " WHERE d.tier = ?"
        params.append(args.tier)
    sql += " ORDER BY d.decision_id DESC LIMIT ?"
    params.append(args.limit)
    for r in store.db.execute(sql, params):
        print(f"{r['decision_id']:>5}  Tier {r['tier']}  C={r['confidence']:.2f}  {r['severity']:<8}  "
              f"{r['hostname']:<16}  {r['signature']}")
    return 0


def cmd_show(args, cfg):
    store = Store(cfg["database"])
    d = store.db.execute("SELECT * FROM decision WHERE decision_id = ?", (args.ref,)).fetchone()
    if not d:
        print("No such decision.")
        return 1
    print(f"Decision {d['decision_id']} (policy {d['policy_id']}, {d['decided_at']})\n  {d['rationale']}")
    for a in store.db.execute("SELECT * FROM action WHERE decision_id = ?", (args.ref,)):
        print(f"  Action {a['action_id']}: {a['action_type']} {a['target']} -> {a['status']} ({a['detail']})")
    for n in store.db.execute("SELECT n.*, c.name FROM notification n JOIN contact c "
                              "ON n.contact_id = c.contact_id WHERE decision_id = ?", (args.ref,)):
        ack = f"acknowledged by {n['acknowledged_by']}" if n["acknowledged_at"] else "not acknowledged"
        print(f"  Notification {n['notification_id']} to {n['name']} via {n['channel']}: {n['status']}, {ack}")
    return 0


def cmd_verify(args, cfg):
    problems = Store(cfg["database"]).verify()
    if problems:
        print("AUDIT LOG FAILED VERIFICATION:")
        for p in problems:
            print("  - " + p)
        return 2
    print("Audit log verified: chain intact and all records match their last audit entry.")
    return 0


def cmd_release(args, cfg):
    engine = Engine(cfg, quiet=True)
    a = engine.store.db.execute("SELECT * FROM action WHERE action_id = ?", (args.action_id,)).fetchone()
    if not a or a["status"] != "executed":
        print("No active containment with that ID.")
        return 1
    ok, detail = engine.containment.release(a["target"])
    if not ok:
        print(f"Release failed: {detail}")
        return 1
    engine.store.release_action(args.action_id, args.by)
    print(f"Released {a['target']}. {detail}")
    return 0


def cmd_ack(args, cfg):
    store = Store(cfg["database"])
    store.acknowledge(args.notification_id, args.by)
    print(f"Notification {args.notification_id} acknowledged by {args.by}.")
    return 0


def cmd_report(args, cfg):
    store = Store(cfg["database"])
    q = store.db.execute
    lines = ["# TARS summary report", f"Generated {datetime.now(timezone.utc):%Y-%m-%d %H:%M} UTC", ""]
    lines.append("## Decisions by tier")
    for r in q("SELECT tier, COUNT(*) n FROM decision GROUP BY tier ORDER BY tier"):
        lines.append(f"- Tier {r['tier']}: {r['n']}")
    lines += ["", "## Automatic containment actions"]
    for r in q("SELECT * FROM action ORDER BY action_id"):
        extra = f", released {r['released_at']} by {r['released_by']}" if r["released_at"] else ""
        lines.append(f"- Action {r['action_id']} (decision {r['decision_id']}): {r['action_type']} "
                     f"{r['target']}, {r['status']}, executed {r['executed_at']}{extra}")
    lines += ["", "## Notifications not yet acknowledged"]
    for r in q("SELECT DISTINCT decision_id FROM notification WHERE status != 'suppressed' AND decision_id "
               "NOT IN (SELECT decision_id FROM notification WHERE acknowledged_at IS NOT NULL)"):
        lines.append(f"- Decision {r['decision_id']}")
    problems = store.verify()
    lines += ["", "## Audit log check", "Intact." if not problems else "FAILED: " + "; ".join(problems)]
    text = "\n".join(lines) + "\n"
    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(text)
        print(f"Report written to {args.out}")
    else:
        print(text)
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="tars", description="Tiered Autonomous Response System prototype")
    p.add_argument("--config", default="config/tars.yaml")
    sub = p.add_subparsers(dest="command", required=True)
    r = sub.add_parser("run"); r.add_argument("--eve"); r.add_argument("--once", action="store_true")
    r.add_argument("--from-start", action="store_true"); r.add_argument("--quiet", action="store_true")
    li = sub.add_parser("list"); li.add_argument("--tier", type=int); li.add_argument("--limit", type=int, default=20)
    s = sub.add_parser("show"); s.add_argument("ref", type=int)
    sub.add_parser("verify")
    rl = sub.add_parser("release"); rl.add_argument("action_id", type=int); rl.add_argument("--by", required=True)
    a = sub.add_parser("ack"); a.add_argument("notification_id", type=int); a.add_argument("--by", required=True)
    rp = sub.add_parser("report"); rp.add_argument("--out")
    args = p.parse_args(argv)
    cfg = load_config(args.config)
    handlers = {"run": cmd_run, "list": cmd_list, "show": cmd_show, "verify": cmd_verify,
                "release": cmd_release, "ack": cmd_ack, "report": cmd_report}
    return handlers[args.command](args, cfg)


if __name__ == "__main__":
    sys.exit(main())
