"""
Azure CIS Foundations Benchmark v2.1 rules.

Each rule is a pure function: rule(subscription_state: dict) -> list[Finding].
subscription_state is the JSON output from `az resource list` joined with
config dumps (see samples/azure_subscription.json).

Coverage:
  Identity (1.x)     8 controls
  Defender (2.x)     6 controls
  Storage (3.x)      8 controls
  Database (4.x)     5 controls
  Logging (5.x)      4 controls
  Networking (6.x)   5 controls
  VMs (7.x)          4 controls
                    --
                    40 Azure controls
"""
from __future__ import annotations

from typing import Any, Callable

CRIT, HIGH, MED, LOW = "CRITICAL", "HIGH", "MEDIUM", "LOW"


def _f(rid: str, sev: str, title: str, ctrl: str, resource: str, detail: str, fix: str) -> dict:
    return {
        "rule_id": rid,
        "severity": sev,
        "title": title,
        "control": ctrl,
        "cloud": "azure",
        "resource": resource,
        "detail": detail,
        "remediation": fix,
    }


# ─── 1.x  Identity ──────────────────────────────────────────────────────────
def cis_az_1_1_security_defaults(state: dict) -> list[dict]:
    if not (state.get("entra") or {}).get("security_defaults_enabled"):
        return [_f("AZ-IAM-1.1", HIGH,
                   "Entra ID security defaults disabled",
                   "CIS Azure 1.1", "entra:tenant",
                   "Security defaults off and no equivalent CA policy.",
                   "Enable Security Defaults or block legacy auth via CA.")]
    return []


def cis_az_1_3_admin_mfa(state: dict) -> list[dict]:
    out = []
    for u in state.get("entra_users", []):
        if u.get("is_privileged") and not u.get("mfa_enforced"):
            out.append(_f("AZ-IAM-1.3", CRIT,
                          "Privileged user without MFA",
                          "CIS Azure 1.3", f"entra:user/{u.get('upn')}",
                          "Global / Privileged Role admin lacks MFA.",
                          "Require MFA via CA on Directory Roles."))
    return out


def cis_az_1_5_guests(state: dict) -> list[dict]:
    invites = (state.get("entra") or {}).get("guest_invite_setting")
    if invites == "Everyone":
        return [_f("AZ-IAM-1.5", MED,
                   "Anyone can invite guests",
                   "CIS Azure 1.5", "entra:tenant/external",
                   "GuestInviteSettings is set to Everyone.",
                   "Restrict to admins or specific roles only.")]
    return []


def cis_az_1_8_self_serve_signup(state: dict) -> list[dict]:
    if (state.get("entra") or {}).get("user_can_create_apps"):
        return [_f("AZ-IAM-1.8", LOW,
                   "Users can register applications",
                   "CIS Azure 1.8", "entra:tenant/app-reg",
                   "UsersCanRegisterApplications=Yes.",
                   "Set to No; delegate via app-developer role.")]
    return []


def cis_az_1_10_legacy_auth(state: dict) -> list[dict]:
    blocked = (state.get("entra") or {}).get("block_legacy_auth")
    if not blocked:
        return [_f("AZ-IAM-1.10", HIGH,
                   "Legacy authentication not blocked",
                   "CIS Azure 1.10", "entra:tenant/ca",
                   "Legacy/basic auth still allowed (POP, IMAP, SMTP).",
                   "Create CA policy to block legacy authentication.")]
    return []


def cis_az_1_22_pim_assignments(state: dict) -> list[dict]:
    out = []
    for u in state.get("entra_users", []):
        if u.get("is_privileged") and u.get("assignment_type") == "permanent":
            out.append(_f("AZ-IAM-1.22", MED,
                          "Permanent privileged role assignment",
                          "CIS Azure 1.22", f"entra:user/{u.get('upn')}",
                          "Privileged role assigned permanently (no PIM).",
                          "Use Privileged Identity Management (eligible/JIT)."))
    return out


def cis_az_1_23_admin_review(state: dict) -> list[dict]:
    if not (state.get("entra") or {}).get("access_review_enabled"):
        return [_f("AZ-IAM-1.23", LOW,
                   "Privileged role access reviews disabled",
                   "CIS Azure 1.23", "entra:tenant/access-review",
                   "No periodic access review on Directory Roles.",
                   "Enable PIM access reviews for all Directory Roles.")]
    return []


def cis_az_1_25_subscription_owner_count(state: dict) -> list[dict]:
    n = (state.get("subscription") or {}).get("owner_count", 0)
    if n > 3:
        return [_f("AZ-IAM-1.25", MED,
                   f"Subscription has {n} Owners (>3)",
                   "CIS Azure 1.25", "subscription:rbac",
                   f"{n} principals hold Owner role.",
                   "Reduce to ≤3 break-glass + use Contributor for ops.")]
    return []


# ─── 2.x  Defender for Cloud ────────────────────────────────────────────────
def cis_az_2_1_defender_servers(state: dict) -> list[dict]:
    plans = (state.get("defender") or {}).get("plans", {})
    if plans.get("VirtualMachines") != "Standard":
        return [_f("AZ-DEF-2.1", HIGH,
                   "Defender for Servers not Standard tier",
                   "CIS Azure 2.1", "defender:plan/VirtualMachines",
                   "Free tier — no MDE/threat protection on VMs.",
                   "Upgrade Defender for Servers to Plan 2.")]
    return []


def cis_az_2_2_defender_storage(state: dict) -> list[dict]:
    plans = (state.get("defender") or {}).get("plans", {})
    if plans.get("StorageAccounts") != "Standard":
        return [_f("AZ-DEF-2.2", MED,
                   "Defender for Storage disabled",
                   "CIS Azure 2.2", "defender:plan/StorageAccounts",
                   "Free tier — no malware/anomaly detection on blobs.",
                   "Enable Defender for Storage v2.")]
    return []


def cis_az_2_3_defender_sql(state: dict) -> list[dict]:
    plans = (state.get("defender") or {}).get("plans", {})
    if plans.get("SqlServers") != "Standard":
        return [_f("AZ-DEF-2.3", HIGH,
                   "Defender for SQL disabled",
                   "CIS Azure 2.3", "defender:plan/SqlServers",
                   "No threat detection on SQL Server / SQL DB.",
                   "Enable Defender for SQL Servers + SQL on machines.")]
    return []


def cis_az_2_4_defender_keyvault(state: dict) -> list[dict]:
    plans = (state.get("defender") or {}).get("plans", {})
    if plans.get("KeyVaults") != "Standard":
        return [_f("AZ-DEF-2.4", MED,
                   "Defender for Key Vault disabled",
                   "CIS Azure 2.4", "defender:plan/KeyVaults",
                   "No anomaly detection on key/secret access.",
                   "Enable Defender for Key Vault.")]
    return []


def cis_az_2_5_defender_appservice(state: dict) -> list[dict]:
    plans = (state.get("defender") or {}).get("plans", {})
    if plans.get("AppServices") != "Standard":
        return [_f("AZ-DEF-2.5", MED,
                   "Defender for App Service disabled",
                   "CIS Azure 2.5", "defender:plan/AppServices",
                   "No web-app threat detection or runtime visibility.",
                   "Enable Defender for App Service.")]
    return []


def cis_az_2_6_auto_provision_ama(state: dict) -> list[dict]:
    if not (state.get("defender") or {}).get("auto_provisioning_ama"):
        return [_f("AZ-DEF-2.6", LOW,
                   "Auto-provisioning of AMA disabled",
                   "CIS Azure 2.6", "defender:auto-provisioning",
                   "Azure Monitor Agent not auto-deployed.",
                   "Enable auto-provisioning for AMA + dependency agent.")]
    return []


# ─── 3.x  Storage ───────────────────────────────────────────────────────────
def cis_az_3_1_secure_transfer(state: dict) -> list[dict]:
    out = []
    for s in state.get("storage_accounts", []):
        if not s.get("supports_https_traffic_only"):
            out.append(_f("AZ-ST-3.1", HIGH,
                          "Storage account allows HTTP",
                          "CIS Azure 3.1", f"storage:{s.get('name')}",
                          "supportsHttpsTrafficOnly=false.",
                          "Set supportsHttpsTrafficOnly=true."))
    return out


def cis_az_3_3_storage_logging(state: dict) -> list[dict]:
    out = []
    for s in state.get("storage_accounts", []):
        if not (s.get("blob_logging_read") and s.get("blob_logging_write")):
            out.append(_f("AZ-ST-3.3", LOW,
                          "Storage logging incomplete (Read/Write)",
                          "CIS Azure 3.3", f"storage:{s.get('name')}",
                          "Diagnostic logging not capturing R/W ops.",
                          "Enable Read+Write+Delete in diagnostic settings."))
    return out


def cis_az_3_5_blob_anonymous(state: dict) -> list[dict]:
    out = []
    for s in state.get("storage_accounts", []):
        if s.get("allow_blob_public_access"):
            out.append(_f("AZ-ST-3.5", CRIT,
                          "Storage account allows public blobs",
                          "CIS Azure 3.5", f"storage:{s.get('name')}",
                          "allowBlobPublicAccess=true.",
                          "Set allowBlobPublicAccess=false at account level."))
    return out


def cis_az_3_7_storage_default_deny(state: dict) -> list[dict]:
    out = []
    for s in state.get("storage_accounts", []):
        if (s.get("network_default_action") or "Allow") != "Deny":
            out.append(_f("AZ-ST-3.7", HIGH,
                          "Storage default firewall action is Allow",
                          "CIS Azure 3.7", f"storage:{s.get('name')}",
                          "networkAcls.defaultAction != Deny.",
                          "Default-deny + allowlist trusted vnets/services."))
    return out


def cis_az_3_8_storage_trusted_microsoft(state: dict) -> list[dict]:
    out = []
    for s in state.get("storage_accounts", []):
        if not s.get("bypass_azure_services"):
            out.append(_f("AZ-ST-3.8", LOW,
                          "Trusted Microsoft services bypass off",
                          "CIS Azure 3.8", f"storage:{s.get('name')}",
                          "Bypass=None — breaks Azure Backup/Monitor/etc.",
                          "Set Bypass=AzureServices on networkAcls."))
    return out


def cis_az_3_9_storage_minimum_tls(state: dict) -> list[dict]:
    out = []
    for s in state.get("storage_accounts", []):
        if (s.get("minimum_tls_version") or "1.0") < "1.2":
            out.append(_f("AZ-ST-3.9", MED,
                          "Storage account minimum TLS < 1.2",
                          "CIS Azure 3.9", f"storage:{s.get('name')}",
                          f"minimumTlsVersion={s.get('minimum_tls_version')}",
                          "Set minimumTlsVersion=TLS1_2."))
    return out


def cis_az_3_10_keyvault_cmk(state: dict) -> list[dict]:
    out = []
    for s in state.get("storage_accounts", []):
        if not s.get("encryption_keysource_kv"):
            out.append(_f("AZ-ST-3.10", LOW,
                          "Storage encryption uses Microsoft-managed keys",
                          "CIS Azure 3.10", f"storage:{s.get('name')}",
                          "Encryption keySource is Microsoft.Storage.",
                          "Use Customer-Managed Keys (Key Vault)."))
    return out


def cis_az_3_15_soft_delete(state: dict) -> list[dict]:
    out = []
    for s in state.get("storage_accounts", []):
        sd = s.get("blob_soft_delete") or {}
        if not sd.get("enabled") or (sd.get("retention_days") or 0) < 7:
            out.append(_f("AZ-ST-3.15", MED,
                          "Blob soft delete <7 days or disabled",
                          "CIS Azure 3.15", f"storage:{s.get('name')}",
                          f"Soft delete: {sd}",
                          "Enable soft delete with ≥7 day retention."))
    return out


# ─── 4.x  Database ──────────────────────────────────────────────────────────
def cis_az_4_1_sql_audit(state: dict) -> list[dict]:
    out = []
    for s in state.get("sql_servers", []):
        if not s.get("auditing_enabled"):
            out.append(_f("AZ-SQL-4.1", HIGH,
                          "SQL Server auditing disabled",
                          "CIS Azure 4.1", f"sql:{s.get('name')}",
                          "Auditing extension is off.",
                          "Enable auditing to Storage / Log Analytics."))
    return out


def cis_az_4_3_sql_tde(state: dict) -> list[dict]:
    out = []
    for db in state.get("sql_databases", []):
        if not db.get("tde_enabled"):
            out.append(_f("AZ-SQL-4.3", HIGH,
                          "SQL DB transparent data encryption off",
                          "CIS Azure 4.3", f"sqldb:{db.get('name')}",
                          "TDE disabled on user database.",
                          "Enable TDE on every SQL database."))
    return out


def cis_az_4_4_sql_aad_admin(state: dict) -> list[dict]:
    out = []
    for s in state.get("sql_servers", []):
        if not s.get("aad_admin_set"):
            out.append(_f("AZ-SQL-4.4", MED,
                          "SQL Server has no Entra ID admin",
                          "CIS Azure 4.4", f"sql:{s.get('name')}",
                          "Only SQL auth — no Entra ID administrator.",
                          "Configure Entra ID admin (group) on SQL Server."))
    return out


def cis_az_4_5_postgres_ssl(state: dict) -> list[dict]:
    out = []
    for s in state.get("postgres_servers", []):
        if not s.get("ssl_enforcement"):
            out.append(_f("AZ-PG-4.5", HIGH,
                          "PostgreSQL SSL enforcement disabled",
                          "CIS Azure 4.5", f"postgres:{s.get('name')}",
                          "sslEnforcement=Disabled.",
                          "Set sslEnforcement=Enabled (TLS1.2+)."))
    return out


def cis_az_4_8_sql_public_network(state: dict) -> list[dict]:
    out = []
    for s in state.get("sql_servers", []):
        if s.get("public_network_access"):
            out.append(_f("AZ-SQL-4.8", HIGH,
                          "SQL Server public network access enabled",
                          "CIS Azure 4.8", f"sql:{s.get('name')}",
                          "publicNetworkAccess=Enabled.",
                          "Disable public network access; use Private Link."))
    return out


# ─── 5.x  Logging & Monitor ─────────────────────────────────────────────────
def cis_az_5_1_subscription_activity_log(state: dict) -> list[dict]:
    if not (state.get("subscription") or {}).get("activity_log_export"):
        return [_f("AZ-LOG-5.1", HIGH,
                   "Subscription activity log not exported",
                   "CIS Azure 5.1", "subscription:activity-log",
                   "No diagnostic setting forwarding to LA/Storage/EH.",
                   "Export activity log to Log Analytics + Storage.")]
    return []


def cis_az_5_2_keyvault_logging(state: dict) -> list[dict]:
    out = []
    for kv in state.get("key_vaults", []):
        if not kv.get("diagnostics_enabled"):
            out.append(_f("AZ-LOG-5.2", MED,
                          "Key Vault diagnostic logs disabled",
                          "CIS Azure 5.2", f"kv:{kv.get('name')}",
                          "AuditEvent diagnostic setting missing.",
                          "Enable AuditEvent → Log Analytics."))
    return out


def cis_az_5_3_log_alerts(state: dict) -> list[dict]:
    expected = (state.get("monitor") or {}).get("expected_alert_rules") or []
    present = (state.get("monitor") or {}).get("alert_rules") or []
    missing = [a for a in expected if a not in present]
    if missing:
        return [_f("AZ-LOG-5.3", MED,
                   f"Missing activity log alerts: {len(missing)}",
                   "CIS Azure 5.3", "monitor:alerts",
                   f"Missing: {missing}",
                   "Create activity log alerts for control-plane changes.")]
    return []


def cis_az_5_4_la_retention(state: dict) -> list[dict]:
    out = []
    for w in state.get("log_analytics_workspaces", []):
        if (w.get("retention_days") or 0) < 365:
            out.append(_f("AZ-LOG-5.4", LOW,
                          "Log Analytics retention < 365 days",
                          "CIS Azure 5.4", f"la:{w.get('name')}",
                          f"Retention: {w.get('retention_days')} days.",
                          "Set retention to ≥365 days for compliance."))
    return out


# ─── 6.x  Networking ────────────────────────────────────────────────────────
def cis_az_6_1_nsg_ingress_22(state: dict) -> list[dict]:
    out = []
    for nsg in state.get("nsgs", []):
        for rule in (nsg.get("rules") or []):
            if (rule.get("direction") == "Inbound"
                    and rule.get("access") == "Allow"
                    and "22" in str(rule.get("destination_port_range", ""))
                    and rule.get("source_address_prefix") in ("*", "Internet", "0.0.0.0/0")):
                out.append(_f("AZ-NET-6.1", CRIT,
                              "NSG exposes SSH (22) to Internet",
                              "CIS Azure 6.1", f"nsg:{nsg.get('name')}",
                              f"Rule {rule.get('name')} allows 22 from *.",
                              "Restrict to specific source CIDRs / Bastion."))
    return out


def cis_az_6_2_nsg_ingress_3389(state: dict) -> list[dict]:
    out = []
    for nsg in state.get("nsgs", []):
        for rule in (nsg.get("rules") or []):
            if (rule.get("direction") == "Inbound"
                    and rule.get("access") == "Allow"
                    and "3389" in str(rule.get("destination_port_range", ""))
                    and rule.get("source_address_prefix") in ("*", "Internet", "0.0.0.0/0")):
                out.append(_f("AZ-NET-6.2", CRIT,
                              "NSG exposes RDP (3389) to Internet",
                              "CIS Azure 6.2", f"nsg:{nsg.get('name')}",
                              f"Rule {rule.get('name')} allows 3389 from *.",
                              "Restrict to specific source CIDRs / Bastion."))
    return out


def cis_az_6_3_network_watcher(state: dict) -> list[dict]:
    if not (state.get("monitor") or {}).get("network_watcher_enabled"):
        return [_f("AZ-NET-6.3", LOW,
                   "Network Watcher disabled",
                   "CIS Azure 6.3", "network-watcher:region",
                   "Network Watcher not enabled in active region.",
                   "Enable Network Watcher per region.")]
    return []


def cis_az_6_4_nsg_flow_logs(state: dict) -> list[dict]:
    out = []
    for nsg in state.get("nsgs", []):
        if not nsg.get("flow_logs_enabled"):
            out.append(_f("AZ-NET-6.4", MED,
                          "NSG flow logs disabled",
                          "CIS Azure 6.4", f"nsg:{nsg.get('name')}",
                          "Flow logs not configured.",
                          "Enable flow logs (v2) → Storage + Traffic Analytics."))
    return out


def cis_az_6_5_udp_internet_egress(state: dict) -> list[dict]:
    out = []
    for nsg in state.get("nsgs", []):
        for rule in (nsg.get("rules") or []):
            if (rule.get("direction") == "Outbound"
                    and rule.get("protocol") == "UDP"
                    and rule.get("destination_address_prefix") == "*"):
                out.append(_f("AZ-NET-6.5", LOW,
                              "Unrestricted UDP egress to Internet",
                              "CIS Azure 6.5", f"nsg:{nsg.get('name')}",
                              f"Rule {rule.get('name')} allows UDP egress *.",
                              "Restrict UDP egress to required destinations."))
    return out


# ─── 7.x  VMs ───────────────────────────────────────────────────────────────
def cis_az_7_1_vm_disk_encryption(state: dict) -> list[dict]:
    out = []
    for vm in state.get("vms", []):
        if not vm.get("os_disk_encrypted"):
            out.append(_f("AZ-VM-7.1", HIGH,
                          "VM OS disk not encrypted",
                          "CIS Azure 7.1", f"vm:{vm.get('name')}",
                          "ADE/SSE-with-CMK not configured for OS disk.",
                          "Enable Azure Disk Encryption + CMK."))
    return out


def cis_az_7_2_vm_data_disk_encryption(state: dict) -> list[dict]:
    out = []
    for vm in state.get("vms", []):
        if any(not d.get("encrypted") for d in (vm.get("data_disks") or [])):
            out.append(_f("AZ-VM-7.2", HIGH,
                          "VM data disk not encrypted",
                          "CIS Azure 7.2", f"vm:{vm.get('name')}",
                          "One or more attached data disks unencrypted.",
                          "Encrypt all data disks via ADE / CMK."))
    return out


def cis_az_7_4_vm_endpoint_protection(state: dict) -> list[dict]:
    out = []
    for vm in state.get("vms", []):
        if not vm.get("endpoint_protection_installed"):
            out.append(_f("AZ-VM-7.4", MED,
                          "VM missing endpoint protection",
                          "CIS Azure 7.4", f"vm:{vm.get('name')}",
                          "No MDE/AV agent reported.",
                          "Deploy Defender for Endpoint via auto-provision."))
    return out


def cis_az_7_5_vm_only_ssh_keys(state: dict) -> list[dict]:
    out = []
    for vm in state.get("vms", []):
        if vm.get("os_type") == "Linux" and vm.get("password_auth_enabled"):
            out.append(_f("AZ-VM-7.5", MED,
                          "Linux VM allows password SSH login",
                          "CIS Azure 7.5", f"vm:{vm.get('name')}",
                          "PasswordAuthentication enabled.",
                          "Disable password auth; require SSH keys / Bastion."))
    return out


AZURE_RULES: list[Callable[[dict], list[dict]]] = [
    cis_az_1_1_security_defaults,
    cis_az_1_3_admin_mfa,
    cis_az_1_5_guests,
    cis_az_1_8_self_serve_signup,
    cis_az_1_10_legacy_auth,
    cis_az_1_22_pim_assignments,
    cis_az_1_23_admin_review,
    cis_az_1_25_subscription_owner_count,
    cis_az_2_1_defender_servers,
    cis_az_2_2_defender_storage,
    cis_az_2_3_defender_sql,
    cis_az_2_4_defender_keyvault,
    cis_az_2_5_defender_appservice,
    cis_az_2_6_auto_provision_ama,
    cis_az_3_1_secure_transfer,
    cis_az_3_3_storage_logging,
    cis_az_3_5_blob_anonymous,
    cis_az_3_7_storage_default_deny,
    cis_az_3_8_storage_trusted_microsoft,
    cis_az_3_9_storage_minimum_tls,
    cis_az_3_10_keyvault_cmk,
    cis_az_3_15_soft_delete,
    cis_az_4_1_sql_audit,
    cis_az_4_3_sql_tde,
    cis_az_4_4_sql_aad_admin,
    cis_az_4_5_postgres_ssl,
    cis_az_4_8_sql_public_network,
    cis_az_5_1_subscription_activity_log,
    cis_az_5_2_keyvault_logging,
    cis_az_5_3_log_alerts,
    cis_az_5_4_la_retention,
    cis_az_6_1_nsg_ingress_22,
    cis_az_6_2_nsg_ingress_3389,
    cis_az_6_3_network_watcher,
    cis_az_6_4_nsg_flow_logs,
    cis_az_6_5_udp_internet_egress,
    cis_az_7_1_vm_disk_encryption,
    cis_az_7_2_vm_data_disk_encryption,
    cis_az_7_4_vm_endpoint_protection,
    cis_az_7_5_vm_only_ssh_keys,
]
