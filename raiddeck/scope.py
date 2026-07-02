"""Scope enforcement - the white-hat guardrail.

A scan is only allowed against a target that is either:
  (a) local / private (loopback or a private LAN range = your own machine/network), or
  (b) a host you've explicitly added to your Authorized Targets allowlist,
      acknowledging you own it or have written permission.
Anything else is refused. This is what makes RaidDeck a self-testing tool, not
an attack tool.
"""
from __future__ import annotations

import ipaddress
import json
import os
from pathlib import Path
from urllib.parse import urlparse

CONFIG_DIR = Path(os.environ.get("APPDATA") or Path.home()) / "RaidDeck"
ALLOWLIST_FILE = CONFIG_DIR / "authorized_targets.json"


def _load() -> list[str]:
    try:
        return list(json.loads(ALLOWLIST_FILE.read_text(encoding="utf-8")))
    except Exception:
        return []


def _save(items: list[str]) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    ALLOWLIST_FILE.write_text(json.dumps(sorted(set(items)), indent=2), encoding="utf-8")


def authorized_hosts() -> list[str]:
    return sorted(set(_load()))


def add_authorized(host: str) -> None:
    items = _load()
    items.append(host.strip().lower())
    _save(items)


def remove_authorized(host: str) -> None:
    _save([h for h in _load() if h != host.strip().lower()])


def is_local_or_private(host: str) -> bool:
    host = host.lower()
    if host == "localhost" or host.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def check(target: str) -> tuple[bool, str]:
    """Return (allowed, reason)."""
    p = urlparse(target.strip())
    if p.scheme not in ("http", "https"):
        return False, "Target must start with http:// or https://"
    host = (p.hostname or "").lower()
    if not host:
        return False, "Invalid URL - no host."
    if is_local_or_private(host):
        return True, "local / private (your own machine or LAN)"
    if host in authorized_hosts():
        return True, "on your Authorized Targets list"
    return False, (
        f"'{host}' is not authorized. RaidDeck only scans local/private hosts "
        f"or targets on your Authorized Targets list. Add it only if you own it "
        f"or have written permission to test it."
    )
