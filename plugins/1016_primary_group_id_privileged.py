"""
Plugin 1016: Primary Group ID Set to a Privileged Group (Hidden Membership)

Group membership via primaryGroupID doesn't appear in the group's own
member attribute -- a well-documented stealth persistence technique.
Admins reviewing "who's in Domain Admins" via the group's member list
alone would never see an account holding that privilege exclusively
through primaryGroupID.

[v1.5] Disabled accounts are now reported (the query had AND u.is_enabled,
contradicting the documented "not downgraded when disabled" design; since
plugin 1023 excludes these RIDs, a disabled account with hidden DA/EA
membership was reported by neither plugin). Their summary ends
" (account disabled)"; enabled summaries are unchanged. Also checks RID
516 (Domain Controllers -- holds DCSync, rated critical), 521 (Read-only
Domain Controllers) and 498 (Enterprise Read-only Domain Controllers). RID
544 (BUILTIN Administrators) is kept although it cannot be a primary group
(domain-local), to stay aligned with plugin 1023's exclusion list.
"""

PLUGIN = {
    "plugin_id": 1016,
    "category": "User Accounts",
    "name": "Primary Group ID Set to a Privileged Group",
    "version": "1.5",
    "revision_date": "2026-10-04",
    "remediation": (
    'Investigate immediately -- this is a known attacker persistence technique, '
    'not a benign misconfiguration in most cases. Determine who or what set '
    'this value and when (check msDS-ReplAttributeMetaData / replication '
    "metadata for the attribute's last-changed timestamp and originating DC as "
    'a starting point). If not traceable to a deliberate, documented '
    'administrative action, treat this as a probable compromise indicator and '
    'follow incident response procedures before simply correcting it. Once '
    'confirmed benign or after investigation concludes, reset primaryGroupID '
    'back to the standard default (513, Domain Users) via `Set-ADUser -Replace '
    '@{primaryGroupID=513}`.'
),
    "control_id": "PRIV-107",
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1098.007",
    ],
    "references": [],
    "description": (
        "AD group membership can be granted two ways: the visible "
        "'member' attribute on the group, or the 'primaryGroupID' "
        "attribute on the user -- and the two are checked independently. "
        "An account can hold privileged-group membership via "
        "primaryGroupID alone, in which case it will NOT appear in that "
        "group's member list at all, and reviewing membership the normal "
        "way (via the group) would miss it entirely. This is a "
        "well-documented stealth persistence technique. Directly "
        "comparable to PingCastle's own rule for exactly this condition "
        "([FR]ANSSI - Accounts with modified PrimaryGroupID, "
        "vuln3_primary_group_id_nochange), quoted from a real PingCastle "
        "report. Checks the most commonly-abused sensitive RIDs (512 "
        "Domain Admins, 516 Domain Controllers -- critical, it holds "
        "DCSync -- 518 Schema Admins, 519 Enterprise Admins, 520 Group "
        "Policy Creator Owners, 521 Read-only Domain Controllers, 498 "
        "Enterprise Read-only Domain Controllers; 544 Administrators is "
        "listed for completeness although a domain-local group cannot be "
        "a primary group) -- not an exhaustive list of every sensitive "
        "group RID. Disabled accounts are reported and NOT downgraded "
        "when the account is disabled: primaryGroupID is a persistent "
        "configuration value, not something that requires the account "
        "to be currently usable -- it survives disablement and "
        "reactivates immediately on re-enable."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            'high' AS tool_severity,
            'PingCastle / ANSSI: "Accounts with modified PrimaryGroupID" '
                '(vuln3_primary_group_id_nochange) -- membership via primaryGroupID '
                'does not appear in the target group''s own member list' AS tool_reference,
            -- [v1.5] Domain Controllers (516) holds DCSync: DC-equivalent.
            CASE WHEN u.primary_group_id = 516 THEN 'critical' ELSE 'high' END AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has primaryGroupID set to a privileged group (RID '
                || u.primary_group_id || ')'
                || CASE WHEN u.is_enabled IS NOT TRUE
                        THEN ' (account disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'primary_group_id', u.primary_group_id,
                'is_enabled', u.is_enabled,
                'admin_count', u.admin_count
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          -- [v1.5] disabled accounts included (no is_enabled filter);
          -- 516/521/498 added.
          AND u.primary_group_id IN (498, 512, 516, 518, 519, 520, 521, 544)
    """,
}
