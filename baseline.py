"""
Baseline & drift management.

A baseline is a snapshot of `(rule_id, resource)` tuples representing
the *known-accepted* state of an account. On the next run we diff:

  baseline_findings  vs  current_findings
       │                       │
       └────►  removed         │   (closed — risk went down)
              new      ◄───────┘   (drift — alert)
              unchanged          (still present)

Snapshots are stored as compact JSON under ./baseline/<env>.json.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import dataclass, field
from typing import Iterable


def _fingerprint(finding: dict) -> str:
    """Stable identity for a finding (rule + resource)."""
    raw = f"{finding.get('rule_id', '')}|{finding.get('resource', '')}".lower()
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class Diff:
    new: list[dict] = field(default_factory=list)        # appeared since baseline
    closed: list[dict] = field(default_factory=list)     # in baseline, not now
    unchanged: list[dict] = field(default_factory=list)  # still open

    def as_dict(self) -> dict:
        return {
            "new": self.new,
            "closed": self.closed,
            "unchanged": self.unchanged,
            "summary": {
                "new": len(self.new),
                "closed": len(self.closed),
                "unchanged": len(self.unchanged),
            },
        }


class BaselineStore:
    def __init__(self, dir_path: str = "baseline") -> None:
        self.dir_path = dir_path
        os.makedirs(dir_path, exist_ok=True)

    def _path(self, env: str) -> str:
        return os.path.join(self.dir_path, f"{env}.json")

    def load(self, env: str) -> dict:
        p = self._path(env)
        if not os.path.exists(p):
            return {"env": env, "snapshot_ts": None, "fingerprints": {}}
        with open(p, "r", encoding="utf-8") as fh:
            return json.load(fh)

    def save(self, env: str, findings: Iterable[dict]) -> None:
        snap = {
            "env": env,
            "snapshot_ts": int(time.time()),
            "fingerprints": {_fingerprint(f): {
                "rule_id": f.get("rule_id"),
                "severity": f.get("severity"),
                "resource": f.get("resource"),
                "title": f.get("title"),
            } for f in findings},
        }
        with open(self._path(env), "w", encoding="utf-8") as fh:
            json.dump(snap, fh, indent=2)

    def diff(self, env: str, current: list[dict]) -> Diff:
        baseline = self.load(env)
        prev_fps = set(baseline["fingerprints"].keys())
        now_index = {_fingerprint(f): f for f in current}

        new = [f for fp, f in now_index.items() if fp not in prev_fps]
        unchanged = [f for fp, f in now_index.items() if fp in prev_fps]
        closed = [meta for fp, meta in baseline["fingerprints"].items()
                  if fp not in now_index]

        return Diff(new=new, closed=closed, unchanged=unchanged)
