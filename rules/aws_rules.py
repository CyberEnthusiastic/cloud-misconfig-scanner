"""
AWS CIS Foundations Benchmark v3.0 rules.

Each rule is a pure function: rule(account_state: dict) -> list[Finding].
account_state is the JSON output from `aws cloudcontrol list-resources`
or any equivalent inventory dump (see samples/aws_account.json).

These rules cover:
  IAM (1.x)        13 controls
  Storage (2.x)     6 controls
  Logging (3.x)     7 controls
  Monitoring (4.x)  8 controls
  Networking (5.x)  6 controls
                  --
                   40 AWS controls
"""
from __future__ import annotations

from typing import Any, Callable

# Severity weights drive risk scores in the engine.
CRIT, HIGH, MED, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"


def _f(rid: str, sev: str, title: str, ctrl: str, resource: str, detail: str, fix: str) -> dict:
    """Construct a finding dict in the canonical shape."""
    return {
        "rule_id": rid,
        "severity": sev,
        "title": title,
        "control": ctrl,
        "cloud": "aws",
        "resource": resource,
        "detail": detail,
        "remediation": fix,
    }


# ─── 1.x  IAM ────────────────────────────────────────────────────────────────
def cis_aws_1_4_root_access_keys(state: dict) -> list[dict]:
    out = []
    for u in state.get("iam_users", []):
        if u.get("user_name") == "<root>" and u.get("access_keys"):
            out.append(_f("AWS-IAM-1.4", CRIT,
                          "Root account has access keys",
                          "CIS AWS 1.4", "iam:root",
                          "Root user has active programmatic access keys.",
                          "Delete root access keys; use IAM users with MFA."))
    return out


def cis_aws_1_5_root_mfa(state: dict) -> list[dict]:
    out = []
    for u in state.get("iam_users", []):
        if u.get("user_name") == "<root>" and not u.get("mfa_enabled"):
            out.append(_f("AWS-IAM-1.5", CRIT,
                          "Root account MFA disabled",
                          "CIS AWS 1.5", "iam:root",
                          "Root account does not have MFA enabled.",
                          "Enable hardware or virtual MFA for the root user."))
    return out


def cis_aws_1_8_password_policy_length(state: dict) -> list[dict]:
    p = state.get("iam_password_policy") or {}
    if (p.get("minimum_password_length") or 0) < 14:
        return [_f("AWS-IAM-1.8", MED,
                   "Password policy minimum length < 14",
                   "CIS AWS 1.8", "iam:password-policy",
                   f"Current minimum: {p.get('minimum_password_length', 'unset')}",
                   "Set MinimumPasswordLength to 14 or greater.")]
    return []


def cis_aws_1_9_password_reuse(state: dict) -> list[dict]:
    p = state.get("iam_password_policy") or {}
    if (p.get("password_reuse_prevention") or 0) < 24:
        return [_f("AWS-IAM-1.9", LOW,
                   "Password reuse prevention < 24",
                   "CIS AWS 1.9", "iam:password-policy",
                   f"Current: {p.get('password_reuse_prevention', 'unset')}",
                   "Set PasswordReusePrevention to 24.")]
    return []


def cis_aws_1_12_unused_credentials_90d(state: dict) -> list[dict]:
    out = []
    for u in state.get("iam_users", []):
        if (u.get("days_since_last_use") or 0) > 90 and u.get("access_keys"):
            out.append(_f("AWS-IAM-1.12", MED,
                          "IAM credentials unused > 90 days",
                          "CIS AWS 1.12", f"iam:user/{u.get('user_name')}",
                          f"Last used {u.get('days_since_last_use')} days ago.",
                          "Disable or delete unused credentials."))
    return out


def cis_aws_1_14_access_key_rotation_90d(state: dict) -> list[dict]:
    out = []
    for u in state.get("iam_users", []):
        for k in (u.get("access_keys") or []):
            if (k.get("age_days") or 0) > 90:
                out.append(_f("AWS-IAM-1.14", HIGH,
                              "Access key not rotated in 90 days",
                              "CIS AWS 1.14",
                              f"iam:user/{u.get('user_name')}/key/{k.get('id', '')}",
                              f"Key age {k.get('age_days')} days.",
                              "Rotate keys at least every 90 days."))
    return out


def cis_aws_1_15_user_inline_policies(state: dict) -> list[dict]:
    out = []
    for u in state.get("iam_users", []):
        if u.get("inline_policies"):
            out.append(_f("AWS-IAM-1.15", MED,
                          "IAM user has inline policies (use groups)",
                          "CIS AWS 1.15", f"iam:user/{u.get('user_name')}",
                          f"Inline policies: {len(u.get('inline_policies') or [])}",
                          "Move policies to a group, attach via group membership."))
    return out


def cis_aws_1_16_full_admin_policy(state: dict) -> list[dict]:
    out = []
    for p in state.get("iam_policies", []):
        for stmt in (p.get("document", {}).get("Statement") or []):
            actions = stmt.get("Action")
            resources = stmt.get("Resource")
            if (actions in ("*", ["*"]) and resources in ("*", ["*"])
                    and stmt.get("Effect") == "Allow"):
                out.append(_f("AWS-IAM-1.16", CRIT,
                              "IAM policy with Action:* + Resource:*",
                              "CIS AWS 1.16", f"iam:policy/{p.get('name')}",
                              "Policy grants full admin (effectively *:*).",
                              "Scope down to least-privilege actions and resources."))
    return out


def cis_aws_1_17_support_role(state: dict) -> list[dict]:
    has = any(r.get("name") == "AWSSupportAccess" for r in state.get("iam_roles", []))
    if not has:
        return [_f("AWS-IAM-1.17", LOW,
                   "Support role for incident handling missing",
                   "CIS AWS 1.17", "iam:role/AWSSupportAccess",
                   "No role with AWSSupportAccess managed policy.",
                   "Create role with AWSSupportAccess for incident response.")]
    return []


def cis_aws_1_19_expired_certs(state: dict) -> list[dict]:
    out = []
    for c in state.get("acm_certificates", []):
        if c.get("expired") or (c.get("days_until_expiry") or 9999) < 0:
            out.append(_f("AWS-IAM-1.19", HIGH,
                          "Expired SSL/TLS certificate in IAM/ACM",
                          "CIS AWS 1.19", f"acm:certificate/{c.get('arn', '')}",
                          "Certificate expired and still attached.",
                          "Remove expired certs or renew via ACM."))
    return out


def cis_aws_1_20_iam_access_analyzer(state: dict) -> list[dict]:
    if not state.get("access_analyzer_enabled"):
        return [_f("AWS-IAM-1.20", MED,
                   "IAM Access Analyzer not enabled",
                   "CIS AWS 1.20", "access-analyzer:account",
                   "Access Analyzer disabled for this account.",
                   "Enable IAM Access Analyzer in every active region.")]
    return []


def cis_aws_1_22_admin_privileges_users(state: dict) -> list[dict]:
    out = []
    for u in state.get("iam_users", []):
        if u.get("attached_managed_policies") and "AdministratorAccess" in u["attached_managed_policies"]:
            out.append(_f("AWS-IAM-1.22", HIGH,
                          "User has AdministratorAccess attached directly",
                          "CIS AWS 1.22", f"iam:user/{u.get('user_name')}",
                          "AdministratorAccess attached to user, not group/role.",
                          "Use roles for admin access; require MFA + STS."))
    return out


def cis_aws_1_24_sso_only(state: dict) -> list[dict]:
    if (state.get("iam_users_count") or 0) > 0 and state.get("identity_center_enabled"):
        return [_f("AWS-IAM-1.24", LOW,
                   "Long-lived IAM users despite Identity Center",
                   "CIS AWS 1.24", "iam:account",
                   f"{state.get('iam_users_count')} IAM users alongside SSO.",
                   "Migrate humans to SSO; delete static IAM user logins.")]
    return []


# ─── 2.x  Storage ────────────────────────────────────────────────────────────
def cis_aws_2_1_1_s3_encryption(state: dict) -> list[dict]:
    out = []
    for b in state.get("s3_buckets", []):
        if not b.get("default_encryption"):
            out.append(_f("AWS-S3-2.1.1", HIGH,
                          "S3 bucket without default encryption",
                          "CIS AWS 2.1.1", f"s3:bucket/{b.get('name')}",
                          "Default encryption not configured.",
                          "Enable SSE-S3 or SSE-KMS default encryption."))
    return out


def cis_aws_2_1_2_s3_mfa_delete(state: dict) -> list[dict]:
    out = []
    for b in state.get("s3_buckets", []):
        if not b.get("mfa_delete"):
            out.append(_f("AWS-S3-2.1.2", LOW,
                          "S3 bucket MFA delete disabled",
                          "CIS AWS 2.1.2", f"s3:bucket/{b.get('name')}",
                          "MFA delete is not enabled on versioned bucket.",
                          "Enable MFA delete for buckets with sensitive data."))
    return out


def cis_aws_2_1_5_s3_block_public(state: dict) -> list[dict]:
    out = []
    for b in state.get("s3_buckets", []):
        if not (b.get("public_access_block") or {}).get("block_public_acls"):
            out.append(_f("AWS-S3-2.1.5", CRIT,
                          "S3 Block Public Access not enforced",
                          "CIS AWS 2.1.5", f"s3:bucket/{b.get('name')}",
                          "Bucket-level Block Public Access disabled.",
                          "Enable all four BlockPublicAccess settings."))
    return out


def cis_aws_2_2_1_ebs_encryption(state: dict) -> list[dict]:
    if not state.get("ebs_encryption_default"):
        return [_f("AWS-EBS-2.2.1", HIGH,
                   "EBS encryption-by-default disabled",
                   "CIS AWS 2.2.1", "ec2:account",
                   "Account-level EBS encryption-by-default off.",
                   "Enable EBS encryption-by-default in every region.")]
    return []


def cis_aws_2_3_1_rds_encryption(state: dict) -> list[dict]:
    out = []
    for db in state.get("rds_instances", []):
        if not db.get("storage_encrypted"):
            out.append(_f("AWS-RDS-2.3.1", HIGH,
                          "RDS instance storage not encrypted",
                          "CIS AWS 2.3.1", f"rds:db/{db.get('db_id')}",
                          "StorageEncrypted=false on RDS instance.",
                          "Enable storage encryption (snapshot+restore)."))
    return out


def cis_aws_2_2_2_ebs_public_snapshots(state: dict) -> list[dict]:
    out = []
    for s in state.get("ebs_snapshots", []):
        if s.get("public"):
            out.append(_f("AWS-EBS-2.2.2", CRIT,
                          "EBS snapshot is public",
                          "CIS AWS 2.2.2", f"ec2:snapshot/{s.get('id', '')}",
                          "Snapshot CreateVolumePermission group=all.",
                          "Remove 'all' group from snapshot permissions."))
    return out


def cis_aws_2_3_3_rds_public(state: dict) -> list[dict]:
    out = []
    for db in state.get("rds_instances", []):
        if db.get("publicly_accessible"):
            out.append(_f("AWS-RDS-2.3.3", CRIT,
                          "RDS instance publicly accessible",
                          "CIS AWS 2.3.3", f"rds:db/{db.get('db_id')}",
                          "PubliclyAccessible=true exposes DB to internet.",
                          "Set PubliclyAccessible=false; use VPC peering/SGs."))
    return out


# ─── 3.x  Logging ────────────────────────────────────────────────────────────
def cis_aws_3_1_cloudtrail_all_regions(state: dict) -> list[dict]:
    multi = any(t.get("is_multi_region") and t.get("is_logging")
                for t in state.get("cloudtrails", []))
    if not multi:
        return [_f("AWS-CT-3.1", CRIT,
                   "No multi-region CloudTrail trail",
                   "CIS AWS 3.1", "cloudtrail:account",
                   "No active multi-region trail with logging on.",
                   "Create a multi-region trail with management events.")]
    return []


def cis_aws_3_2_cloudtrail_log_validation(state: dict) -> list[dict]:
    out = []
    for t in state.get("cloudtrails", []):
        if not t.get("log_file_validation"):
            out.append(_f("AWS-CT-3.2", MED,
                          "CloudTrail log validation disabled",
                          "CIS AWS 3.2", f"cloudtrail:trail/{t.get('name')}",
                          "EnableLogFileValidation=false.",
                          "Set EnableLogFileValidation=true for tamper-evidence."))
    return out


def cis_aws_3_3_cloudtrail_bucket_public(state: dict) -> list[dict]:
    out = []
    by_name = {b["name"]: b for b in state.get("s3_buckets", [])}
    for t in state.get("cloudtrails", []):
        b = by_name.get(t.get("s3_bucket"))
        if b and (b.get("acl_public") or b.get("policy_public")):
            out.append(_f("AWS-CT-3.3", CRIT,
                          "CloudTrail S3 bucket is publicly accessible",
                          "CIS AWS 3.3", f"s3:bucket/{b.get('name')}",
                          "Trail bucket is public — audit data exposed.",
                          "Restrict bucket policy and ACL to log archive role."))
    return out


def cis_aws_3_4_cloudtrail_to_cloudwatch(state: dict) -> list[dict]:
    out = []
    for t in state.get("cloudtrails", []):
        if not t.get("cloudwatch_logs_arn"):
            out.append(_f("AWS-CT-3.4", MED,
                          "CloudTrail not integrated with CloudWatch Logs",
                          "CIS AWS 3.4", f"cloudtrail:trail/{t.get('name')}",
                          "CloudWatchLogsLogGroupArn unset.",
                          "Send trail events to CloudWatch for alerting."))
    return out


def cis_aws_3_5_config_enabled(state: dict) -> list[dict]:
    if not state.get("aws_config_enabled"):
        return [_f("AWS-CFG-3.5", HIGH,
                   "AWS Config disabled in account",
                   "CIS AWS 3.5", "config:account",
                   "ConfigurationRecorder is not active.",
                   "Enable AWS Config in all regions with global resources.")]
    return []


def cis_aws_3_6_s3_access_logging(state: dict) -> list[dict]:
    out = []
    for b in state.get("s3_buckets", []):
        if not b.get("server_access_logging"):
            out.append(_f("AWS-S3-3.6", LOW,
                          "S3 bucket access logging disabled",
                          "CIS AWS 3.6", f"s3:bucket/{b.get('name')}",
                          "Server access logging not configured.",
                          "Enable access logging to a separate audit bucket."))
    return out


def cis_aws_3_7_kms_key_rotation(state: dict) -> list[dict]:
    out = []
    for k in state.get("kms_keys", []):
        if k.get("manageable") and not k.get("rotation_enabled"):
            out.append(_f("AWS-KMS-3.7", MED,
                          "KMS CMK rotation disabled",
                          "CIS AWS 3.7", f"kms:key/{k.get('id')}",
                          "Annual key rotation disabled on customer CMK.",
                          "Enable automatic key rotation."))
    return out


# ─── 4.x  Monitoring ────────────────────────────────────────────────────────
def cis_aws_4_x_metric_filter(name: str, label: str, ctrl: str):
    """Build a 4.x monitoring rule from a metric filter name."""
    def _rule(state):
        filters = state.get("cloudwatch_metric_filters", []) or []
        if not any(f.get("name") == name and f.get("alarm_subscribed") for f in filters):
            return [_f(f"AWS-MON-{ctrl}", MED,
                       f"No alarm for {label}",
                       f"CIS AWS {ctrl}", "cloudwatch:filter",
                       f"Metric filter {name!r} missing or unsubscribed.",
                       f"Create metric filter+alarm for {label} (SNS topic).")]
        return []
    _rule.__name__ = f"cis_aws_4_{ctrl}_{name}"
    return _rule


# ─── 5.x  Networking ────────────────────────────────────────────────────────
def cis_aws_5_2_sg_ingress_22(state: dict) -> list[dict]:
    out = []
    for sg in state.get("security_groups", []):
        for rule in (sg.get("ingress") or []):
            cidrs = rule.get("cidr_blocks") or []
            if rule.get("from_port") == 22 and ("0.0.0.0/0" in cidrs or "::/0" in cidrs):
                out.append(_f("AWS-NET-5.2", CRIT,
                              "Security group exposes SSH (22) to 0.0.0.0/0",
                              "CIS AWS 5.2", f"sg:{sg.get('id')}",
                              "Public ingress on port 22.",
                              "Restrict 22 to bastion/VPN CIDRs only."))
    return out


def cis_aws_5_3_sg_ingress_3389(state: dict) -> list[dict]:
    out = []
    for sg in state.get("security_groups", []):
        for rule in (sg.get("ingress") or []):
            cidrs = rule.get("cidr_blocks") or []
            if rule.get("from_port") == 3389 and ("0.0.0.0/0" in cidrs or "::/0" in cidrs):
                out.append(_f("AWS-NET-5.3", CRIT,
                              "Security group exposes RDP (3389) to 0.0.0.0/0",
                              "CIS AWS 5.3", f"sg:{sg.get('id')}",
                              "Public ingress on port 3389.",
                              "Restrict 3389 to bastion/VPN CIDRs only."))
    return out


def cis_aws_5_4_default_sg_traffic(state: dict) -> list[dict]:
    out = []
    for sg in state.get("security_groups", []):
        if sg.get("name") == "default" and (sg.get("ingress") or sg.get("egress")):
            out.append(_f("AWS-NET-5.4", HIGH,
                          "Default security group allows traffic",
                          "CIS AWS 5.4", f"sg:{sg.get('id')}",
                          "Default SG should have zero rules.",
                          "Strip all rules from default SGs in every VPC."))
    return out


def cis_aws_5_5_vpc_flow_logs(state: dict) -> list[dict]:
    out = []
    for v in state.get("vpcs", []):
        if not v.get("flow_logs_enabled"):
            out.append(_f("AWS-NET-5.5", HIGH,
                          "VPC flow logs disabled",
                          "CIS AWS 5.5", f"vpc:{v.get('id')}",
                          "No FlowLogs configured for VPC.",
                          "Enable VPC flow logs (REJECT or ALL) to S3/CW."))
    return out


def cis_aws_5_6_route_table_igw(state: dict) -> list[dict]:
    out = []
    for rt in state.get("route_tables", []):
        for r in (rt.get("routes") or []):
            if r.get("destination") == "0.0.0.0/0" and r.get("target", "").startswith("igw-") \
                    and rt.get("attached_to_private_subnet"):
                out.append(_f("AWS-NET-5.6", HIGH,
                              "Private subnet routed to IGW",
                              "CIS AWS 5.6", f"rtb:{rt.get('id')}",
                              "0.0.0.0/0 → IGW from a private subnet.",
                              "Route private subnets via NAT, not IGW."))
    return out


# Register all rules.
AWS_RULES: list[Callable[[dict], list[dict]]] = [
    cis_aws_1_4_root_access_keys,
    cis_aws_1_5_root_mfa,
    cis_aws_1_8_password_policy_length,
    cis_aws_1_9_password_reuse,
    cis_aws_1_12_unused_credentials_90d,
    cis_aws_1_14_access_key_rotation_90d,
    cis_aws_1_15_user_inline_policies,
    cis_aws_1_16_full_admin_policy,
    cis_aws_1_17_support_role,
    cis_aws_1_19_expired_certs,
    cis_aws_1_20_iam_access_analyzer,
    cis_aws_1_22_admin_privileges_users,
    cis_aws_1_24_sso_only,
    cis_aws_2_1_1_s3_encryption,
    cis_aws_2_1_2_s3_mfa_delete,
    cis_aws_2_1_5_s3_block_public,
    cis_aws_2_2_1_ebs_encryption,
    cis_aws_2_2_2_ebs_public_snapshots,
    cis_aws_2_3_1_rds_encryption,
    cis_aws_2_3_3_rds_public,
    cis_aws_3_1_cloudtrail_all_regions,
    cis_aws_3_2_cloudtrail_log_validation,
    cis_aws_3_3_cloudtrail_bucket_public,
    cis_aws_3_4_cloudtrail_to_cloudwatch,
    cis_aws_3_5_config_enabled,
    cis_aws_3_6_s3_access_logging,
    cis_aws_3_7_kms_key_rotation,
    # 4.x — metric-filter family
    cis_aws_4_x_metric_filter("UnauthorizedAPICalls",     "unauthorized API calls",      "4.1"),
    cis_aws_4_x_metric_filter("ConsoleSignInWithoutMFA",  "console sign-in without MFA", "4.2"),
    cis_aws_4_x_metric_filter("RootAccountUsage",         "root account usage",          "4.3"),
    cis_aws_4_x_metric_filter("IAMPolicyChanges",         "IAM policy changes",          "4.4"),
    cis_aws_4_x_metric_filter("CloudTrailConfigChanges",  "CloudTrail config changes",   "4.5"),
    cis_aws_4_x_metric_filter("ConsoleAuthFailures",      "console auth failures",       "4.6"),
    cis_aws_4_x_metric_filter("DisableOrDeleteCMK",       "KMS CMK disable/delete",      "4.7"),
    cis_aws_4_x_metric_filter("S3BucketPolicyChanges",    "S3 bucket policy changes",    "4.8"),
    cis_aws_5_2_sg_ingress_22,
    cis_aws_5_3_sg_ingress_3389,
    cis_aws_5_4_default_sg_traffic,
    cis_aws_5_5_vpc_flow_logs,
    cis_aws_5_6_route_table_igw,
]
