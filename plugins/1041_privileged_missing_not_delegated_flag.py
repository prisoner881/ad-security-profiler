"""
Plugin 1041: Privileged Account Missing the "Cannot Be Delegated" Protection Flag

userAccountControl bit 0x100000 (1048576, NOT_DELEGATED) -- when set,
prevents the account from being used as the target of ANY Kerberos
delegation, constrained or unconstrained, by any other service, even
one the account's owner never configured themselves. Without it, a
privileged account's ticket can be captured and delegated by a
compromised service the account happened to authenticate to, entirely
independent of whether the privileged account itself was ever directly
configured for delegation.

Deliberately independent from plugin 1040 (Protected Users membership,
which also disables delegation as one of several bundled protections):
this flag is available on every domain functional level with no
prerequisite, doesn't touch NTLM or credential caching, and is the
narrower, purpose-built tool for exactly this one protection --
checked on its own rather than assuming Protected Users membership
alone covers it, since an organization may have valid operational
reasons to use one protection without the other.
"""

PLUGIN = {
    "plugin_id": 1041,
    "category": "User Accounts",
    "name": "Privileged Account Missing the \"Cannot Be Delegated\" Protection Flag",
    "version": "1.0",
    "revision_date": "2026-08-05",
    "remediation": (
        "Set the flag: check \"This account is sensitive and cannot be "
        "delegated\" on the account's Account tab (or add 1048576 to "
        "the account's userAccountControl value directly via ADSI Edit "
        "if the checkbox isn't available, e.g. for gMSA accounts). "
        "This has no meaningful compatibility downside for a genuinely "
        "privileged account -- unlike Protected Users, it doesn't "
        "disable NTLM or alter credential caching, only Kerberos "
        "delegation targeting."
    ),
    "control_id": "USR-141",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "PingCastle: Privileged Accounts rules -- P-Delegated",
         "url": "https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "DISA Active Directory Domain STIG V-243470: Delegation of privileged accounts must be prohibited",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243470"},
    ],
    "description": (
        "A privileged account (same broadened definition used "
        "throughout this project: AdminSDHolder-protected group "
        "membership, or otherwise privileged via ACL/ownership) does "
        "not have userAccountControl's NOT_DELEGATED bit (0x100000) "
        "set. Without it, the account's ticket can be captured and "
        "delegated by any service it authenticates to, independent of "
        "whether the account itself was ever configured for "
        "delegation."
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
        )
        SELECT
            'warn' AS status,
            u.object_guid,
            'CAT_I' AS stig_severity,
            'DISA Active Directory Domain STIG V-243470' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Privileged User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' can be delegated (NOT_DELEGATED flag not set)' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'admin_count', u.admin_count,
                'is_enabled', u.is_enabled
            ) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
        JOIN privileged_check pc ON pc.object_guid = u.object_guid
        WHERE u.client_id = %(client_id)s
          AND u.valid_to IS NULL
          AND u.is_enabled
          AND (COALESCE(u.user_account_control, 0) & 1048576) = 0
          AND COALESCE(udo.object_sid, '') NOT LIKE '%%-502'
    """,
}
