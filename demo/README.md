# Demo alerts (no Suricata needed)

These files hold the alerts Suricata 7.0.3 raised for the eight test scenarios
(23 alerts in total), so the TARS decision layer can be demonstrated on any
computer, including Windows. Run from the project folder:

    python -m tars run --eve demo/s1_eve.json --once --from-start
    python -m tars list
    python -m tars show 3
    python -m tars verify

To start again with an empty audit store, delete data/tars.db.
