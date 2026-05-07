#!/usr/bin/env python3
"""
Cloud Misconfiguration Scanner — AWS + Azure CIS baseline validator with
continuous drift detection and Slack alerting.

  $ python scanner.py --aws samples/aws_account.json --env prod
  $ python scanner.py --azure samples/azure_subscription.json --env prod
  $ python scanner.py --aws aws.json --azure az.json --env prod \
                     --baseline --slack "$SLACK_WEBHOOK_URL" --html out.html

Zero dependencies — Python 3.8+ stdlib only.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import Counter
from typing import Any

# Force UTF-8 stdout where the host shell defaulted to cp1252 (Windows).
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except (AttributeError, ValueError):  # pragma: no cover — older Pythons
    pass

from baseline import BaselineStore
from rules import ALL_RULES, AWS_RULES, AZURE_RULES
from report_generator import render as render_html
from slack_notifier import SlackNotifier


# ─── Pretty terminal output ──────────────────────────────────────────────────
_RESET = "\033[0m"
_COL = {
    "CRITICAL": "\033[1;91m",
    "HIGH":     "\033[1;33m",
    "MEDIUM":   "\033[1;36m",
    "LOW":      "\033[0;90m",
    "DIM":      "\033[2m",
    "OK":       "\033[1;92m",
    "TITLE":    "\033[1;94m",
}


def _c(key: str, s: str) -> str:
    if not sys.stdout.isatty() and not os.environ.get("FORCE_COLOR"):
        return s
    return f"{_COL.get(key, '')}{s}{_RESET}"


# ─── Rule runner ─────────────────────────────────────────────────────────────
def run_rules(state: dict, only_cloud: str | None = None) -> list[dict]:
    """Apply all relevant rules to a combined cloud state."""
    rule_set = ALL_RULES
    if only_cloud == "aws":
        rule_set = AWS_RULES
    elif only_cloud == "azure":
        rule_set = AZURE_RULES

    findings: list[dict] = []
    for rule in rule_set:
        try:
            findings.extend(rule(state) or [])
        except Exception as exc:  # pragma: no cover — defensive
            findings.append({
                "rule_id": getattr(rule, "__name__", "unknown"),
                "severity": "LOW",
                "title": "rule errored",
                "control": "internal",
                "cloud": "internal",
                "resource": "scanner",
                "detail": f"{type(exc).__name__}: {exc}",
                "remediation": "Open an issue with the offending state file.",
            })
    return findings


# ─── State loading ───────────────────────────────────────────────────────────
def _load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def merge_states(aws_path: str | None, azure_path: str | None) -> dict:
    """Merge AWS + Azure JSON inventories into one rule-input state."""
    state: dict[str, Any] = {}
    if aws_path:
        state.update(_load(aws_path))
    if azure_path:
        state.update(_load(azure_path))
    return state


# ─── Reporting ───────────────────────────────────────────────────────────────
def print_findings(findings: list[dict], env: str) -> None:
    if not findings:
        print(_c("OK", f"\n[+] {env}: 0 findings — baseline clean.\n"))
        return

    counts = Counter(f.get("severity", "?") for f in findings)
    cloud = Counter(f.get("cloud", "?") for f in findings)
    print(_c("TITLE", "=" * 70))
    print(_c("TITLE", f"  Cloud Misconfiguration Scanner — env={env}"))
    print(_c("TITLE", "=" * 70))
    print(f"[*] Findings    : {len(findings)}")
    print(f"[*] By severity : {dict(counts)}")
    print(f"[*] By cloud    : {dict(cloud)}")
    print()

    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    for f in sorted(findings, key=lambda x: order.index(x.get("severity", "LOW"))):
        sev = f.get("severity", "?")
        print(f"{_c(sev, f'[{sev}]')} "
              f"{f.get('title', '')}  "
              f"{_c('DIM', '(' + f.get('control', '') + ')')}")
        print(f"   {_c('DIM', f.get('resource', ''))}  "
              f"cloud={f.get('cloud', '')}  rule={f.get('rule_id', '')}")
        print(f"   {_c('DIM', '> ' + f.get('detail', ''))}")
        print(f"   {_c('OK', '-> ' + f.get('remediation', ''))}")
        print()


def print_drift(diff: dict) -> None:
    s = diff.get("summary", {})
    print(_c("TITLE", "--- Drift since last baseline " + "-" * 35))
    print(f"   NEW       : {_c('HIGH',   str(s.get('new', 0)))}")
    print(f"   CLOSED    : {_c('OK',     str(s.get('closed', 0)))}")
    print(f"   UNCHANGED : {_c('DIM',    str(s.get('unchanged', 0)))}")
    print()


# ─── CLI ─────────────────────────────────────────────────────────────────────
def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Validate AWS+Azure accounts against CIS baselines with drift detection.",
    )
    p.add_argument("--aws", help="Path to AWS inventory JSON")
    p.add_argument("--azure", help="Path to Azure inventory JSON")
    p.add_argument("--env", default="default",
                   help="Environment label used for baseline storage (e.g. prod, stage)")
    p.add_argument("--baseline", action="store_true",
                   help="Diff against previous baseline; refresh baseline on success")
    p.add_argument("--baseline-dir", default="baseline",
                   help="Where baseline snapshots are stored")
    p.add_argument("--slack", default=os.environ.get("SLACK_WEBHOOK_URL", ""),
                   help="Slack incoming-webhook URL (env: SLACK_WEBHOOK_URL)")
    p.add_argument("--alert-on", default="new",
                   choices=["new", "any", "critical-or-high"],
                   help="When to fire Slack alert")
    p.add_argument("--html", help="Write HTML report to this path")
    p.add_argument("--json", help="Write raw findings JSON to this path")
    p.add_argument("--fail-on", default="critical",
                   choices=["never", "low", "medium", "high", "critical"],
                   help="Exit non-zero when findings of this severity (or worse) exist")
    p.add_argument("--only", choices=["aws", "azure"],
                   help="Restrict rule set to one cloud")
    return p.parse_args(argv)


def _fail_threshold(level: str, findings: list[dict]) -> bool:
    if level == "never":
        return False
    order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    needle = level.upper()
    if needle not in order:
        return False
    cutoff = order.index(needle)
    return any(order.index(f.get("severity", "LOW")) >= cutoff for f in findings)


def _alert_filter(mode: str, current: list[dict], diff_dict: dict | None) -> list[dict]:
    if mode == "any":
        return current
    if mode == "critical-or-high":
        return [f for f in current if f.get("severity") in ("CRITICAL", "HIGH")]
    # mode == "new"
    if diff_dict:
        return diff_dict.get("new", [])
    return current


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    if not args.aws and not args.azure:
        print("error: provide at least one of --aws / --azure", file=sys.stderr)
        return 2

    state = merge_states(args.aws, args.azure)
    findings = run_rules(state, only_cloud=args.only)

    diff_dict: dict | None = None
    if args.baseline:
        store = BaselineStore(args.baseline_dir)
        diff = store.diff(args.env, findings)
        diff_dict = diff.as_dict()
        # Refresh baseline AFTER computing diff so next run measures against this scan.
        store.save(args.env, findings)

    print_findings(findings, args.env)
    if diff_dict:
        print_drift(diff_dict)

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "env": args.env,
                "ts": int(time.time()),
                "findings": findings,
                "drift": diff_dict,
            }, fh, indent=2)
        print(_c("DIM", f"   → wrote {args.json}"))

    if args.html:
        path = render_html(args.env, findings, diff_dict or {}, args.html)
        print(_c("DIM", f"   → wrote {path}"))

    if args.slack:
        notifier = SlackNotifier(args.slack)
        if diff_dict:
            notifier.post_drift(args.env, diff_dict)
        else:
            notifier.post_summary(args.env, _alert_filter(args.alert_on, findings, diff_dict))

    return 1 if _fail_threshold(args.fail_on, findings) else 0


if __name__ == "__main__":
    sys.exit(main())
