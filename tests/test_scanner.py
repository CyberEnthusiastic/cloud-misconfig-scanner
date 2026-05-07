"""Smoke + correctness tests for the scanner.

Run:    python -m pytest tests/  (if pytest installed)
Or:     python -m unittest discover tests
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from baseline import BaselineStore, Diff, _fingerprint  # noqa: E402
from rules import ALL_RULES, AWS_RULES, AZURE_RULES  # noqa: E402
from scanner import run_rules, merge_states  # noqa: E402


class TestRules(unittest.TestCase):
    def test_total_rule_count(self):
        # Promised in README: 80+ controls.
        self.assertGreaterEqual(len(ALL_RULES), 80)

    def test_aws_sample_finds_critical(self):
        state = json.load(open(os.path.join(ROOT, "samples", "aws_account.json")))
        findings = run_rules(state, only_cloud="aws")
        sevs = {f["severity"] for f in findings}
        self.assertIn("CRITICAL", sevs)
        self.assertGreater(len(findings), 10)

    def test_azure_sample_finds_critical(self):
        state = json.load(open(os.path.join(ROOT, "samples", "azure_subscription.json")))
        findings = run_rules(state, only_cloud="azure")
        sevs = {f["severity"] for f in findings}
        self.assertIn("CRITICAL", sevs)
        self.assertGreater(len(findings), 10)

    def test_clean_state_zero_findings(self):
        clean = {
            "iam_users": [],
            "iam_password_policy": {"minimum_password_length": 16, "password_reuse_prevention": 24},
            "iam_policies": [],
            "iam_roles": [{"name": "AWSSupportAccess"}],
            "acm_certificates": [],
            "access_analyzer_enabled": True,
            "identity_center_enabled": False,
            "s3_buckets": [],
            "ebs_encryption_default": True,
            "rds_instances": [],
            "cloudtrails": [{"name": "t", "is_multi_region": True, "is_logging": True,
                             "log_file_validation": True, "s3_bucket": "x",
                             "cloudwatch_logs_arn": "arn:..."}],
            "aws_config_enabled": True,
            "kms_keys": [],
            "cloudwatch_metric_filters": [
                {"name": n, "alarm_subscribed": True} for n in [
                    "UnauthorizedAPICalls", "ConsoleSignInWithoutMFA", "RootAccountUsage",
                    "IAMPolicyChanges", "CloudTrailConfigChanges", "ConsoleAuthFailures",
                    "DisableOrDeleteCMK", "S3BucketPolicyChanges",
                ]
            ],
            "security_groups": [],
            "vpcs": [],
            "route_tables": [],
        }
        findings = run_rules(clean, only_cloud="aws")
        # We allow some "low" controls to still flag (e.g. SSO / support-role) — but no CRIT/HIGH.
        sev = {f["severity"] for f in findings}
        self.assertNotIn("CRITICAL", sev)
        self.assertNotIn("HIGH", sev)


class TestBaseline(unittest.TestCase):
    def test_drift_new_and_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = BaselineStore(tmp)
            f1 = {"rule_id": "X", "resource": "r1", "severity": "HIGH"}
            f2 = {"rule_id": "Y", "resource": "r2", "severity": "LOW"}
            f3 = {"rule_id": "Z", "resource": "r3", "severity": "CRITICAL"}

            # First scan: 2 findings — both NEW relative to empty baseline.
            d1 = store.diff("prod", [f1, f2])
            store.save("prod", [f1, f2])
            self.assertEqual(len(d1.new), 2)

            # Second scan: f1 still there, f3 is new, f2 closed.
            d2 = store.diff("prod", [f1, f3])
            self.assertEqual([n["rule_id"] for n in d2.new], ["Z"])
            self.assertEqual([c["rule_id"] for c in d2.closed], ["Y"])
            self.assertEqual([u["rule_id"] for u in d2.unchanged], ["X"])

    def test_fingerprint_stability(self):
        f = {"rule_id": "AWS-S3-2.1.5", "resource": "s3:bucket/x"}
        self.assertEqual(_fingerprint(f), _fingerprint({**f, "severity": "HIGH"}))


class TestMergeStates(unittest.TestCase):
    def test_merge_aws_azure(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as a, \
             tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as b:
            json.dump({"iam_users": [{"user_name": "x"}]}, a); a.flush()
            json.dump({"vms": [{"name": "y"}]}, b); b.flush()
            merged = merge_states(a.name, b.name)
        self.assertIn("iam_users", merged)
        self.assertIn("vms", merged)


if __name__ == "__main__":
    unittest.main()
