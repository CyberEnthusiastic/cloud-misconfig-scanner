# Cloud Misconfiguration Scanner

> **AWS + Azure baseline validation against CIS Benchmarks with continuous drift detection and Slack alerting — zero dependencies.**
> Free, self-hosted alternative to Wiz, Prisma Cloud, and Defender for Cloud Premium for teams that want continuous cloud posture without the enterprise price tag.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![CIS AWS](https://img.shields.io/badge/CIS%20AWS-v3.0%20mapped-1F4E79)](https://www.cisecurity.org/benchmark/amazon_web_services)
[![CIS Azure](https://img.shields.io/badge/CIS%20Azure-v2.1%20mapped-0078D4)](https://www.cisecurity.org/benchmark/azure)
[![Slack](https://img.shields.io/badge/alerts-Slack-4A154B?logo=slack&logoColor=white)](#slack-alerts)

---

## What it does

Validates AWS accounts and Azure subscriptions against the **CIS Foundations Benchmarks**.
80+ controls across IAM, storage, logging, networking, databases, and VMs. Snapshots the
posture state, then on every subsequent run computes **drift** — what changed since the
baseline. Alerts on drift via Slack incoming webhook.

```
======================================================================
  Cloud Misconfiguration Scanner - env=prod
======================================================================
[*] Findings    : 79
[*] By severity : {'CRITICAL': 12, 'HIGH': 24, 'MEDIUM': 28, 'LOW': 15}
[*] By cloud    : {'aws': 38, 'azure': 41}

[CRITICAL] Root account has access keys  (CIS AWS 1.4)
   iam:root  cloud=aws  rule=AWS-IAM-1.4
   > Root user has active programmatic access keys.
   -> Delete root access keys; use IAM users with MFA.

[CRITICAL] Storage account allows public blobs  (CIS Azure 3.5)
   storage:stcontosoprod  cloud=azure  rule=AZ-ST-3.5
   > allowBlobPublicAccess=true.
   -> Set allowBlobPublicAccess=false at account level.

--- Drift since last baseline -----------------------------------
   NEW       : 3
   CLOSED    : 1
   UNCHANGED : 75
```

---

## Why you want this

- **Cloud + multi-cloud in one tool.** Wiz/Prisma cost $200K+/yr; this is free and runs locally or in CI.
- **CIS-mapped from day one.** Every finding cites a specific CIS control, severity, and remediation.
- **Continuous drift, not one-shot scans.** Snapshots the world, alerts only on what *changed* since the last clean baseline. No alert fatigue.
- **Slack-native.** Pipe alerts into the channel where your team already lives. No Splunk/SIEM wiring required.
- **Fully offline-capable.** Reads JSON inventories — works in air-gapped, FedRAMP, or restricted environments where you can't run AWS/Azure SDKs from CI.
- **Zero dependencies.** Python 3.8+ stdlib only. No `pip install` step.

---

## Quickstart

```bash
git clone https://github.com/CyberEnthusiastic/cloud-misconfig-scanner.git
cd cloud-misconfig-scanner

# Run against the bundled samples (full AWS + Azure misconfig fixture):
python scanner.py --aws samples/aws_account.json \
                  --azure samples/azure_subscription.json \
                  --env demo --baseline --html report.html

# Real run, AWS only, with Slack alerts on NEW drift items:
python scanner.py --aws prod_aws_inventory.json --env prod --baseline \
                  --slack "$SLACK_WEBHOOK_URL" --alert-on new

# CI gate: fail the build on any CRITICAL or HIGH finding.
python scanner.py --aws inventory.json --env ci --fail-on high
```

---

## How input is collected

The scanner reads a JSON inventory file. You can produce one with:

**AWS** (one of):

```bash
# Quickest — use AWS Cloud Control to dump everything you care about
aws cloudcontrol list-resources --type-name AWS::S3::Bucket > buckets.json
# ...and merge into the schema in samples/aws_account.json

# Or use Steampipe / aws-recon / your own collector
```

**Azure** (one of):

```bash
az resource list --output json > azure_resources.json
# Merge with `az policy state list`, `az security pricing list`, etc.
# Sample shape in samples/azure_subscription.json
```

The repo ships with two complete sample inventories so you can run the scanner today
without touching any cloud APIs.

---

## CLI

```
usage: scanner.py [-h] [--aws AWS] [--azure AZURE] [--env ENV] [--baseline]
                  [--baseline-dir DIR] [--slack URL] [--alert-on MODE]
                  [--html PATH] [--json PATH] [--fail-on LEVEL]
                  [--only {aws,azure}]
```

| Flag | Purpose |
|---|---|
| `--aws PATH` | AWS inventory JSON |
| `--azure PATH` | Azure inventory JSON |
| `--env LABEL` | Environment label for baseline storage (`prod`, `stage`, etc.) |
| `--baseline` | Diff against previous baseline; refresh on success |
| `--slack URL` | Slack incoming-webhook URL (env: `SLACK_WEBHOOK_URL`) |
| `--alert-on MODE` | `new` (default), `any`, or `critical-or-high` |
| `--html PATH` | Write a self-contained HTML report |
| `--json PATH` | Write findings + drift as JSON for downstream tools |
| `--fail-on LEVEL` | Exit non-zero on findings ≥ this severity (CI gate) |

---

## Slack alerts

Set the webhook URL via env var or flag:

```bash
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/T.../B.../..."
python scanner.py --aws inv.json --env prod --baseline
```

A single Slack message contains:
- Drift summary (NEW / CLOSED / UNCHANGED counts)
- Top 5 worst NEW findings as colored attachments (CRITICAL → red, HIGH → orange)
- Each attachment: title, resource, control ID, fix step

The post is fire-and-forget — Slack errors do not fail the scan.

---

## Coverage

| Cloud | Domain | Controls |
|---|---|---|
| AWS | IAM (1.x) | 13 |
| AWS | Storage (2.x) | 7 |
| AWS | Logging (3.x) | 7 |
| AWS | Monitoring (4.x) | 8 |
| AWS | Networking (5.x) | 5 |
| Azure | Identity (1.x) | 8 |
| Azure | Defender (2.x) | 6 |
| Azure | Storage (3.x) | 8 |
| Azure | Database (4.x) | 5 |
| Azure | Logging (5.x) | 4 |
| Azure | Networking (6.x) | 5 |
| Azure | VMs (7.x) | 4 |
| **Total** | | **80** |

Adding a rule = a single Python function in `rules/aws_rules.py` or `rules/azure_rules.py`.
Each takes the state dict and returns a list of finding dicts.

---

## Architecture

```
scanner.py        ── CLI, runs all rules, prints, writes report, alerts
baseline.py       ── snapshot + diff engine (sha256 fingerprints)
slack_notifier.py ── Slack webhook poster (urllib only)
report_generator.py
rules/
  aws_rules.py    ── 40 AWS CIS rules
  azure_rules.py  ── 40 Azure CIS rules
samples/
  aws_account.json     ── full AWS inventory fixture
  azure_subscription.json ── full Azure inventory fixture
tests/
  test_scanner.py ── 7 unit tests, runs in <100ms
```

---

## Running the tests

```bash
python -m unittest discover tests
```

7 tests covering: total rule count, AWS sample produces critical findings, Azure
sample produces critical findings, clean state produces zero CRIT/HIGH, drift
new/closed/unchanged classification, fingerprint stability, state merging.

---

## License

MIT — see [LICENSE](./LICENSE).
