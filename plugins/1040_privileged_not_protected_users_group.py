"""
Plugin 1040: Privileged Account Not a Member of the Protected Users Group

Protected Users (well-known RID 525, confirmed directly against
Microsoft's own documentation before building this) is a
non-configurable protection group introduced in Windows Server 2012
R2: membership disables NTLM authentication for the account, prevents
credential caching, disables Kerberos delegation entirely (unconstrained
and constrained alike), shortens the maximum Kerberos ticket lifetime,
and mandates strong (AES) encryption. It's a strictly stronger,
built-in alternative to manually managing several of these protections
individually.

Deliberately checks EVERY privileged account rather than building in
an "allow one exception" tolerance some guidance suggests (keeping one
admin account outside the group as a fallback in case of unexpected
lockout) -- that operational tradeoff is a legitimate decision for a
security team to make deliberately, not something this plugin should
silently decide on their behalf by suppressing findings.
"""

PLUGIN = {
    "plugin_id": 1040,
    "category": "User Accounts",
    "name": "Privileged Account Not a Member of the Protected Users Group",
    "version": "1.0",
    "revision_date": "2026-08-05",
    "remediation": (
        "Add this account to the built-in Protected Users group, "
        "provided the domain functional level is at least Windows "
        "Server 2012 R2 (required for DC-side enforcement; client-side "
        "protections work from Windows 8.1/Server 2012 R2 onward "
        "regardless of domain functional level). Test in a controlled "
        "way first -- Protected Users disables NTLM and all Kerberos "
        "delegation for the account, which can break legacy "
        "applications relying on either. Many organizations "
        "deliberately keep one break-glass admin account outside the "
        "group as an operational safety net; if that's the intent "
        "here, no action is needed for that specific account."
    ),
    "control_id": "USR-140",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Protected Users Security Group",
         "url": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"},
        {"title": "PingCastle: Privileged Accounts rules -- P-ProtectedUsers",
         "url": "https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "A privileged account (effective member of an AdminSDHolder-"
        "protected group, or otherwise privileged via ACL/ownership --"
        " the same broadened definition used throughout this project) "
        "is not a member of the built-in Protected Users group (RID "
        "525). Membership disables NTLM, prevents credential caching, "
        "disables all Kerberos delegation, shortens maximum ticket "
        "lifetime, and mandates AES -- a strictly stronger built-in "
        "alternative to managing these protections individually."
    ),
    "base_severity": "medium",
    "query": """
        WITH privileged_check AS (
            SELECT DISTINCT vem.member_guid AS object_guid
            FROM v_effective_group_membership vem
            JOIN directory_object pgo
                ON pgo.object_guid = vem.group_guid AND pgo.client_id = vem.client_id
            JOIN ad_group pg
                ON pg.object_guid = pgo.object_guid AND pg.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
              AND pg.is_protected_group
            UNION
            SELECT do_acl.object_guid
            FROM acl_edge a
            JOIN directory_object do_acl ON do_acl.object_sid = a.trustee_sid AND do_acl.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                               '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                  )
            UNION
            SELECT do_owner.object_guid
            FROM directory_object owned_target
            JOIN directory_object do_owner
                ON do_owner.object_sid = owned_target.owner_sid AND do_owner.client_id = owned_target.client_id
            WHERE owned_target.client_id = %(client_id)s
              AND owned_target.owner_sid IS NOT NULL
        ),
        protected_users_members AS (
            SELECT DISTINCT vem.member_guid AS object_guid
            FROM v_effective_group_membership vem
            JOIN directory_object pu ON pu.object_guid = vem.group_guid AND pu.client_id = vem.client_id
            WHERE vem.client_id = %(client_id)s
              AND pu.object_sid LIKE '%%-525'
        )
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Privileged User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' is not a member of Protected Users' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'admin_count', u.admin_count,
                'is_enabled', u.is_enabled
            ) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
        JOIN privileged_check pc ON pc.object_guid = u.object_guid
        LEFT JOIN protected_users_members pum ON pum.object_guid = u.object_guid
        WHERE u.client_id = %(client_id)s
          AND u.valid_to IS NULL
          AND u.is_enabled
          AND pum.object_guid IS NULL
          -- [v1.0] krbtgt (RID 502) is, by design, always disabled and
          -- structurally cannot be a normal Protected Users member --
          -- same exclusion precedent already established in plugin
          -- 1025 for the same account, applied here rather than
          -- treated as a fresh judgment call.
          AND COALESCE(udo.object_sid, '') NOT LIKE '%%-502'
    """,
}
