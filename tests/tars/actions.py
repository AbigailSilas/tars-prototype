"""Action handlers: containment (nftables) and notification (Twilio SMS/WhatsApp).

Both run in dry-run mode by default, so nothing is blocked and no message is sent
until they are deliberately switched on in config/tars.yaml.
"""
from __future__ import annotations

import ipaddress
import os
import subprocess
from typing import Tuple


def _valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


class Containment:
    """Adds or removes an address in an nftables set that the gateway drops.

    Expects the table/set/chain created by setup/nftables-setup.sh.
    """

    def __init__(self, dry_run: bool = True, family: str = "inet", table: str = "tars", nft_set: str = "blocklist"):
        self.dry_run, self.family, self.table, self.set = dry_run, family, table, nft_set

    def _nft(self, verb: str, ip: str) -> Tuple[bool, str]:
        if not _valid_ip(ip):
            return False, f"refused: '{ip}' is not a valid IP address"
        cmd = ["nft", verb, "element", self.family, self.table, self.set, "{", ip, "}"]
        if self.dry_run:
            return True, "DRY-RUN: would run " + " ".join(cmd)
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return False, f"nft failed: {exc}"
        if out.returncode != 0:
            return False, f"nft error: {out.stderr.strip()}"
        return True, "ran " + " ".join(cmd)

    def block(self, ip: str):
        return self._nft("add", ip)

    def release(self, ip: str):
        return self._nft("delete", ip)


class Notifier:
    """Sends plain-language messages. Credentials are read from environment variables (NFR3)."""

    def __init__(self, dry_run: bool = True):
        self.dry_run = dry_run
        self._client = None

    def _twilio(self):
        if self._client is None:
            from twilio.rest import Client  # imported only when real sending is switched on
            self._client = Client(os.environ["TWILIO_ACCOUNT_SID"], os.environ["TWILIO_AUTH_TOKEN"])
        return self._client

    def send(self, phone: str, channel: str, message: str) -> Tuple[str, str]:
        if self.dry_run:
            return "dry-run", f"DRY-RUN {channel} to {phone}: {message}"
        try:
            if channel == "whatsapp":
                sender, to = os.environ["TWILIO_FROM_WHATSAPP"], f"whatsapp:{phone}"
                if not sender.startswith("whatsapp:"):
                    sender = f"whatsapp:{sender}"
            else:
                sender, to = os.environ["TWILIO_FROM_SMS"], phone
            msg = self._twilio().messages.create(body=message, from_=sender, to=to)
            return "sent", f"Twilio SID {msg.sid}"
        except Exception as exc:  # network down, bad credentials, etc. Logged, never fatal.
            return "failed", f"send failed: {exc}"


def message_for(tier: int, ref: int, hostname: str, device_type: str, target: str = "") -> str:
    """Plain-language text with no patient data (NFR5, NFR6)."""
    if tier == 1:
        return (f"TARS alert {ref}: suspicious network activity on {hostname} ({device_type}). "
                f"The system has automatically blocked {target}. No action is needed now. "
                f"If something stops working, call your IT contact and quote {ref}.")
    return (f"TARS alert {ref}: possible security problem on {hostname} ({device_type}). "
            f"Nothing has been blocked. Please call your IT contact today and quote {ref}.")
