"""
Plugin 1015: Privileged Account Not a Member of Protected Users

The Protected Users group (Windows Server 2012 R2+) forces a bundle of
hardening on its members simultaneously: no NTLM, no DES/RC4 Kerberos,
no delegation of any kind, shorter ticket lifetimes, no cached
credentials. Microsoft's own recommended hardening step for Tier-0
accounts specifically. Soft recommendation, not a hard finding.

[v1.6] "Privileged" now comes from the shared Tier 0 view
v_privileged_principal (schema v34) instead of an inline subquery that
counted GenericAll/GenericWrite/WriteDACL/WriteOwner on, or ownership of,
ANY object with a collected ACL -- every OU, every certificate template --
so OU delegates and whoever created an OU were treated as privileged.
Protected-group membership, control of or ownership of a Tier 0 object
(domain root, AdminSDHolder, DCs, CAs, ...), DCSync, and membership in a
group holding any of those still count. detail gains privilege_sources
(the view's reasons, sorted); summary wording is unchanged.
"""

PLUGIN = {
    "plugin_id": 1015,
    "category": "User Accounts",
    "name": "Privileged Account Not a Member of Protected Users",
    "version": "1.6",
    "revision_date": "2026-10-03",
    "remediation": (
    'Add the account to the Protected Users group -- but test in a '
    'non-production/staging context first. Protected Users membership disables '
    'NTLM, DES/RC4 Kerberos, delegation, and credential caching for the account '
    'entirely; any legacy application or workflow depending on those will break '
    'immediately upon membership. A phased rollout starting with the '
    'highest-value Tier-0 accounts, with monitoring for authentication failures '
    'after each addition, is the standard recommended approach rather than '
    'adding every privileged account at once.'
),
    "control_id": "PRIV-106",
    "framework_tags": ["CISA-AA26-237A"],
    "references": [
        {"title": "Microsoft: Protected Users Security Group in Windows Server",
         "url": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"},
    ],
    "description": (
        "The Protected Users group forces a bundle of hardening on its "
        "members: no NTLM authentication, no DES or RC4 Kerberos "
        "encryption, no Kerberos delegation of any kind, shorter maximum "
        "ticket lifetimes, and no cached credentials on the "
        "authenticating host. This is Microsoft's own recommended "
        "hardening step specifically for Tier-0/highly-privileged "
        "accounts. Soft recommendation -- adopting Protected Users has "
        "real operational implications (some legacy auth stops working "
        "entirely for members) and needs deliberate rollout, not blanket "
        "enablement."
    ),
    "base_severity": "low",
    "query": """
        WITH privileged_check AS (
            -- [v1.6] "Privileged" is the shared Tier 0 definition in
            -- v_privileged_principal (schema v34): membership, direct or
            -- nested, in an AdminSDHolder-protected group; a control right
            -- (GenericAll/GenericWrite/WriteDACL/WriteOwner) on, or
            -- ownership of, a Tier 0 object; DCSync on the domain root; or
            -- membership in a group that holds any of those. The inline
            -- subquery this replaces counted such a right on, or ownership
            -- of, ANY object with a collected ACL, so every OU delegate and
            -- OU creator was treated as privileged.
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        )
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN u.is_enabled THEN 'low' ELSE 'info' END AS fd_severity,
            'Privileged User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' is not a member of the Protected Users group'
                || CASE WHEN NOT u.is_enabled
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'is_enabled', u.is_enabled,
                'admin_count', u.admin_count,
                'privileged_group_member', pc.object_guid IS NOT NULL,
                'privilege_sources', pc.privilege_sources
            ) AS detail
        FROM ad_user u
        LEFT JOIN privileged_check pc
            ON pc.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND NOT u.protected_users_member
          AND (u.admin_count = 1 OR pc.object_guid IS NOT NULL)
    """,
}
