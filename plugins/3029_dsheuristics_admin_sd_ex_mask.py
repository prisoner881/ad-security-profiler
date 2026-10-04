"""
Plugin 3029: dSHeuristics dwAdminSDExMask Excludes Operator Groups from SDProp

Detects a non-zero dwAdminSDExMask -- the 16th character of the
dSHeuristics attribute on CN=Directory Service,CN=Windows NT,
CN=Services,<configuration NC>, stored as
ad_domain.dsheuristics_admin_sd_ex_mask. Each bit removes one operator
group from AdminSDHolder / SDProp protection:
  0x1 Account Operators, 0x2 Server Operators, 0x4 Print Operators,
  0x8 Backup Operators.

Why it matters: SDProp re-applies the AdminSDHolder security descriptor
to protected groups and their members every hour, undoing ACL changes
made to them. Excluding an operator group means its object and its
members' accounts keep whatever DACL they are given -- a delegated
helpdesk right or an attacker's backdoor ACE (e.g. GenericAll for a
low-privileged account) on a Backup or Server Operators member then
persists, although those groups can still log on to and back up
domain controllers. Microsoft documents the setting in "Appendix C:
Protected Accounts and Groups in Active Directory"; PingCastle reports
it as A-DsHeuristicsAdminSDExMask. Plugins 3005/3021 read the value to
avoid false positives but nothing else reports it.

NULL (dSHeuristics unreadable) and 0 are not reported. Bits outside
0x1-0x8 are shown in detail.raw_mask. One row, keyed on the domain
root object. medium.
"""

PLUGIN = {
    "plugin_id": 3029,
    "category": "Groups",
    "name": "dSHeuristics dwAdminSDExMask Excludes Operator Groups from SDProp",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "PRIV-3029",
    "framework_tags": [
        "MITRE-ATTCK-T1098",
        "NIST-800-53-CM-6", "NIST-CSF-2.0-PR.PS-01", "PCI-DSS-4.0-2.2.1", "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9", "SOC2-CC7.1",
        "NIST-800-53-AC-6(5)", "NIST-CSF-2.0-PR.AA-05", "CIS-CSC-8-5.4", "ISO-27001-2022-A.8.2",
    ],
    "references": [
        {"title": "Microsoft: Appendix C - Protected Accounts and Groups in Active Directory",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory"},
        {"title": "PingCastle health check rules",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "Flags a non-zero dwAdminSDExMask (16th character of dSHeuristics), which "
        "removes Account, Server, Print and/or Backup Operators from AdminSDHolder / "
        "SDProp protection, so ACL changes on those groups and their members are no "
        "longer reverted every hour."
    ),
    "remediation": (
        "Reset the 16th character of dSHeuristics to 0 (keep the other characters, "
        "including the check digit at positions 10 and 20, as they are): read the "
        "current value with `Get-ADObject \"CN=Directory Service,CN=Windows NT,"
        "CN=Services,$((Get-ADRootDSE).configurationNamingContext)\" -Properties "
        "dSHeuristics`, then `Set-ADObject ... -Replace @{dSHeuristics='<value>'}`. "
        "If the exclusion was made to delegate management of operator-group members, "
        "empty those groups instead (plugins 3014, 3015, 3017, 3018) and delegate "
        "the needed rights on non-protected accounts. Afterwards review the ACLs of "
        "the excluded groups and their members for rights added while unprotected."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'dSHeuristics dwAdminSDExMask excludes from SDProp protection: '
                || COALESCE(NULLIF(concat_ws(', ',
                       CASE WHEN (d.dsheuristics_admin_sd_ex_mask & 1) <> 0 THEN 'Account Operators' END,
                       CASE WHEN (d.dsheuristics_admin_sd_ex_mask & 2) <> 0 THEN 'Server Operators' END,
                       CASE WHEN (d.dsheuristics_admin_sd_ex_mask & 4) <> 0 THEN 'Print Operators' END,
                       CASE WHEN (d.dsheuristics_admin_sd_ex_mask & 8) <> 0 THEN 'Backup Operators' END
                   ), ''), 'unknown bits') AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'raw_mask', d.dsheuristics_admin_sd_ex_mask,
                'excluded_groups', to_jsonb(array_remove(ARRAY[
                       CASE WHEN (d.dsheuristics_admin_sd_ex_mask & 1) <> 0 THEN 'Account Operators (S-1-5-32-548)' END,
                       CASE WHEN (d.dsheuristics_admin_sd_ex_mask & 2) <> 0 THEN 'Server Operators (S-1-5-32-549)' END,
                       CASE WHEN (d.dsheuristics_admin_sd_ex_mask & 4) <> 0 THEN 'Print Operators (S-1-5-32-550)' END,
                       CASE WHEN (d.dsheuristics_admin_sd_ex_mask & 8) <> 0 THEN 'Backup Operators (S-1-5-32-551)' END
                   ], NULL))
            ) AS detail
        FROM ad_domain d
        WHERE d.client_id = %(client_id)s
          AND d.valid_to IS NULL
          AND d.dsheuristics_admin_sd_ex_mask > 0
        ORDER BY d.object_guid
    """,
}
