"""
Slack webhook poster (stdlib-only — urllib + json).

Usage:
    n = SlackNotifier(webhook_url=os.environ["SLACK_WEBHOOK_URL"])
    n.post_drift(env="prod", diff=diff_obj)

If webhook is empty / unset the notifier becomes a no-op so CI runs
without secrets still work.
"""
from __future__ import annotations

import json
import urllib.request
import urllib.error
from typing import Optional

# Color hex codes in Slack attachment style.
_COLORS = {
    "CRITICAL": "#ff3b30",
    "HIGH":     "#ff9500",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#34d399",
}


class SlackNotifier:
    def __init__(self, webhook_url: Optional[str] = None, channel: Optional[str] = None) -> None:
        self.webhook_url = (webhook_url or "").strip()
        self.channel = channel  # ignored when posting via incoming-webhook URL

    @property
    def enabled(self) -> bool:
        return bool(self.webhook_url)

    def _post(self, payload: dict) -> bool:
        if not self.enabled:
            return False
        body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            self.webhook_url,
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except urllib.error.URLError:
            return False

    def post_drift(self, env: str, diff_dict: dict) -> bool:
        """Post a Slack message summarizing drift since last baseline."""
        s = diff_dict.get("summary", {})
        new = diff_dict.get("new", [])
        closed = diff_dict.get("closed", [])

        # Build a digest of the worst N drift items.
        rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        new_sorted = sorted(new, key=lambda f: rank.get(f.get("severity", "LOW"), 9))
        top = new_sorted[:5]

        attachments = []
        for f in top:
            sev = f.get("severity", "LOW")
            attachments.append({
                "color": _COLORS.get(sev, "#888"),
                "title": f"[{sev}] {f.get('title', '')}",
                "text": (f"*Resource:* `{f.get('resource', '')}`\n"
                         f"*Control:* {f.get('control', '')}\n"
                         f"*Cloud:* {f.get('cloud', '').upper()}\n"
                         f"*Fix:* {f.get('remediation', '')}"),
                "mrkdwn_in": ["text"],
            })

        if not new and not closed:
            text = f":white_check_mark: *{env}* — no drift since last baseline."
        else:
            text = (f":rotating_light: *Cloud baseline drift detected — `{env}`*\n"
                    f"NEW: *{s.get('new', 0)}*  ·  "
                    f"closed: {s.get('closed', 0)}  ·  "
                    f"unchanged: {s.get('unchanged', 0)}")

        return self._post({
            "text": text,
            "attachments": attachments,
        })

    def post_summary(self, env: str, findings: list[dict]) -> bool:
        """Post a one-shot summary of all current findings (no drift baseline)."""
        from collections import Counter
        sev_counts = Counter(f.get("severity", "?") for f in findings)
        total = len(findings)
        if total == 0:
            return self._post({
                "text": f":white_check_mark: *{env}* — clean run. 0 findings.",
            })
        text = (f":mag: *Cloud Misconfig Scan — `{env}`*\n"
                f"Total findings: *{total}*  ·  "
                f"CRITICAL: {sev_counts.get('CRITICAL', 0)}  ·  "
                f"HIGH: {sev_counts.get('HIGH', 0)}  ·  "
                f"MEDIUM: {sev_counts.get('MEDIUM', 0)}  ·  "
                f"LOW: {sev_counts.get('LOW', 0)}")
        return self._post({"text": text})
