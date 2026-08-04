"""
Plugin 1016: Primary Group ID Set to a Privileged Group (Hidden Membership)

Group membership via primaryGroupID doesn't appear in the group's own
member attribute -- a well-documented stealth persistence technique.
Admins reviewing "who's in Domain Admins" via the group's member list
alone would never see an account holding that privilege exclusively
through primaryGroupID.
"""

PLUGIN = {
    "plugin_id": 1016,
    "category": "User Accounts",
    "name": "Primary Group ID Set to a Privileged Group",
    "version": "1.4",
    "revision_date": "2026-07-15",
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
    "framework_tags": ["ANSSI"],
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
        "Domain Admins, 518 Schema Admins, 519 Enterprise Admins, 520 "
        "Group Policy Creator Owners, 544 Administrators) -- not an "
        "exhaustive list of every sensitive group RID. NOT downgraded "
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
            'high' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has primaryGroupID set to a privileged group (RID '
                || u.primary_group_id || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'primary_group_id', u.primary_group_id,
                'admin_count', u.admin_count
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND u.primary_group_id IN (512, 518, 519, 520, 544)
    """,
}
