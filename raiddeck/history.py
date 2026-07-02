"""Scan history — persist past scans so you can reopen their findings."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from raidkit.report import Finding, Severity

HISTORY_FILE = Path(os.environ.get("APPDATA") or Path.home()) / "RaidDeck" / "history.json"
_MAX = 100  # keep the last N scans


def _f2d(f: Finding) -> dict:
    return {
        "check": f.check, "title": f.title, "severity": f.severity.name,
        "detail": f.detail, "evidence": f.evidence, "remediation": f.remediation,
    }


def _d2f(d: dict) -> Finding:
    return Finding(d["check"], d["title"], Severity[d["severity"]],
                   d.get("detail", ""), d.get("evidence", ""), d.get("remediation", ""))


@dataclass
class ScanRecord:
    target: str
    when: str  # ISO timestamp
    findings: list[Finding]


def load() -> list[ScanRecord]:
    try:
        raw = json.loads(HISTORY_FILE.read_text(encoding="utf-8"))
        return [ScanRecord(r["target"], r["when"], [_d2f(x) for x in r["findings"]]) for r in raw]
    except Exception:
        return []


def save(records: list[ScanRecord]) -> None:
    HISTORY_FILE.parent.mkdir(parents=True, exist_ok=True)
    data = [{"target": r.target, "when": r.when,
             "findings": [_f2d(f) for f in r.findings]} for r in records[-_MAX:]]
    HISTORY_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")
