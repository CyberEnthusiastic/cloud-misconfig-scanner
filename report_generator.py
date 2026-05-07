"""HTML report renderer (zero deps — single-file output)."""
from __future__ import annotations

import html
import json
import os
import time
from collections import Counter

_BADGE = {
    "CRITICAL": "#ff3b30",
    "HIGH":     "#ff9500",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#34d399",
}


def render(env: str, findings: list[dict], diff: dict, out_path: str) -> str:
    sev_counts = Counter(f.get("severity", "?") for f in findings)
    cloud_counts = Counter(f.get("cloud", "?") for f in findings)
    ctrl_counts = Counter(f.get("control", "?") for f in findings)

    cards = []
    for f in sorted(findings, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW"].index(x.get("severity", "LOW"))):
        sev = f.get("severity", "LOW")
        cards.append(f"""
        <div class="card">
          <div class="card-head">
            <span class="badge" style="background:{_BADGE.get(sev, '#888')}">{sev}</span>
            <span class="ctrl">{html.escape(f.get('control', ''))}</span>
            <span class="cloud">{html.escape(f.get('cloud', '').upper())}</span>
          </div>
          <div class="card-title">{html.escape(f.get('title', ''))}</div>
          <div class="card-resource"><code>{html.escape(f.get('resource', ''))}</code></div>
          <div class="card-detail">{html.escape(f.get('detail', ''))}</div>
          <div class="card-fix">→ {html.escape(f.get('remediation', ''))}</div>
        </div>""")

    drift_block = ""
    if diff:
        s = diff.get("summary", {})
        drift_block = f"""
        <section class="drift">
          <h2>Drift since last baseline</h2>
          <div class="drift-row">
            <div class="drift-stat new"><div class="n">{s.get('new', 0)}</div><div>NEW</div></div>
            <div class="drift-stat closed"><div class="n">{s.get('closed', 0)}</div><div>CLOSED</div></div>
            <div class="drift-stat unchanged"><div class="n">{s.get('unchanged', 0)}</div><div>UNCHANGED</div></div>
          </div>
        </section>"""

    ts = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    page = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Cloud Misconfig Scanner — {html.escape(env)}</title>
<style>
:root{{--bg:#0b0f14;--p:#11161d;--b:#1f2937;--t:#e5e7eb;--m:#9ca3af;--a:#60a5fa}}
*{{box-sizing:border-box;margin:0;padding:0}}
body{{background:var(--bg);color:var(--t);font-family:ui-sans-serif,-apple-system,Segoe UI,Roboto,sans-serif;padding:32px}}
h1{{font-size:22px;margin-bottom:4px}}
.meta{{color:var(--m);font-size:13px;margin-bottom:20px}}
.summary{{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:24px}}
.tile{{background:var(--p);border:1px solid var(--b);padding:16px;border-radius:8px}}
.tile .v{{font-size:28px;font-weight:700;color:var(--a)}}
.tile .l{{font-size:11px;color:var(--m);text-transform:uppercase;letter-spacing:1px;margin-top:4px}}
.drift{{background:var(--p);border:1px solid var(--b);padding:16px;border-radius:8px;margin-bottom:24px}}
.drift h2{{font-size:14px;margin-bottom:10px}}
.drift-row{{display:flex;gap:12px}}
.drift-stat{{flex:1;background:#0a0d12;padding:12px;border-radius:6px;text-align:center}}
.drift-stat .n{{font-size:22px;font-weight:700}}
.drift-stat.new .n{{color:#ff9500}}
.drift-stat.closed .n{{color:#34d399}}
.drift-stat.unchanged .n{{color:var(--m)}}
.cards{{display:grid;gap:10px}}
.card{{background:var(--p);border:1px solid var(--b);padding:14px 16px;border-radius:8px}}
.card-head{{display:flex;align-items:center;gap:10px;margin-bottom:8px}}
.badge{{font-size:10px;color:#000;font-weight:700;padding:3px 8px;border-radius:3px;letter-spacing:1px}}
.ctrl{{font-family:ui-monospace,Menlo,monospace;font-size:11px;color:var(--m)}}
.cloud{{margin-left:auto;font-size:10px;color:var(--a);letter-spacing:1.5px}}
.card-title{{font-weight:600;margin-bottom:4px}}
.card-resource code{{font-family:ui-monospace,Menlo,monospace;font-size:12px;color:#fbbf24;background:rgba(251,191,36,.06);padding:1px 6px;border-radius:3px}}
.card-detail{{color:var(--m);font-size:13px;margin:6px 0}}
.card-fix{{color:#34d399;font-size:13px}}
</style></head>
<body>
<h1>Cloud Misconfig Scanner — <em>{html.escape(env)}</em></h1>
<div class="meta">Generated {ts} · {len(findings)} findings · {sum(cloud_counts.values())} resources scanned</div>
<div class="summary">
  <div class="tile"><div class="v">{sev_counts.get('CRITICAL', 0)}</div><div class="l">Critical</div></div>
  <div class="tile"><div class="v">{sev_counts.get('HIGH', 0)}</div><div class="l">High</div></div>
  <div class="tile"><div class="v">{sev_counts.get('MEDIUM', 0)}</div><div class="l">Medium</div></div>
  <div class="tile"><div class="v">{sev_counts.get('LOW', 0)}</div><div class="l">Low</div></div>
</div>
{drift_block}
<div class="cards">{''.join(cards)}</div>
</body></html>"""

    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as fh:
        fh.write(page)
    return out_path
