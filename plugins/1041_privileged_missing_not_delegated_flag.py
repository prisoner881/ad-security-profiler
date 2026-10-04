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

[v1.2] "Privileged" now comes from the shared Tier 0 view
v_privileged_principal (schema v34) instead of an inline subquery that
counted GenericAll/GenericWrite/WriteDACL/WriteOwner on, or ownership of,
ANY object with a collected ACL -- every OU, every certificate template --
so OU delegates and whoever created an OU were treated as privileged.
Protected-group membership, control of or ownership of a Tier 0 object
(domain root, AdminSDHolder, DCs, CAs, ...), DCSync, and membership in a
group holding any of those still count. detail gains privilege_sources
(the view's reasons, sorted); summary wording is unchanged.

[v1.3] Absorbs plugin 1014 (Privileged Account Missing NOT_DELEGATED
Protection), now retired with superseded_by=1041. 1014 reported the
same missing bit on the same accounts at 'low'. Its extra coverage is
deliberately not merged: disabled privileged accounts are plugin 1042's
finding, and accounts privileged only by a leftover admin_count=1 are
not privileged (plugin 1025 reports the stale marker). Carried over:
the `Set-ADAccountControl -AccountNotDelegated $true` remediation and
the MITRE ATT&CK T1558 reference. Query, summary and severity are
unchanged, so existing 1041 findings do not churn.

[v1.4] An account that is an effective (nested) member of Protected
Users (RID 525), or carries the direct memberOf flag, already cannot be
delegated (KDC-enforced, 2012 R2+ DCs), so "can be delegated" was false
for it. It is still reported -- the STIG asks for the flag itself, and
the protection disappears if the account leaves the group -- but at
'low' and worded "lacks the NOT_DELEGATED flag (delegation currently
blocked only by Protected Users membership)". detail gains
protected_users_member.
"""

PLUGIN = {
    "plugin_id": 1041,
    "category": "User Accounts",
    "name": "Privileged Account Missing the \"Cannot Be Delegated\" Protection Flag",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Set the flag: check \"This account is sensitive and cannot be "
        "delegated\" on the account's Account tab, or run "
        "`Set-ADAccountControl -Identity <name> -AccountNotDelegated $true` "
        "(or add 1048576 to "
        "the account's userAccountControl value directly via ADSI Edit "
        "if the checkbox isn't available, e.g. for gMSA accounts). "
        "This has no meaningful compatibility downside for a genuinely "
        "privileged account -- unlike Protected Users, it doesn't "
        "disable NTLM or alter credential caching, only Kerberos "
        "delegation targeting."
    ),
    "control_id": "USR-141",
    "framework_tags": ["DISA-STIG", "CISA-AA26-237A"],
    "references": [
        {"title": "PingCastle: Privileged Accounts rules -- P-Delegated",
         "url": "https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "DISA Active Directory Domain STIG V-243470: Delegation of privileged accounts must be prohibited",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243470"},
        {"title": "MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets",
         "url": "https://attack.mitre.org/techniques/T1558/"},
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
            -- [v1.2] "Privileged" is the shared Tier 0 definition in
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
        ),
        protected_users_members AS (
            -- [v1.4] Same test as plugin 1040: effective membership in
            -- Protected Users (RID 525).
            SELECT DISTINCT vem.member_guid AS object_guid
            FROM v_effective_group_membership vem
            JOIN directory_object pu ON pu.object_guid = vem.group_guid AND pu.client_id = vem.client_id
            WHERE vem.client_id = %(client_id)s
              AND pu.object_sid LIKE '%%-525'
        )
        SELECT
            'warn' AS status,
            u.object_guid,
            'CAT_I' AS stig_severity,
            'DISA Active Directory Domain STIG V-243470' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN pum.object_guid IS NOT NULL OR u.protected_users_member THEN 'low'
                 ELSE 'medium' END AS fd_severity,
            'Privileged User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || CASE WHEN pum.object_guid IS NOT NULL OR u.protected_users_member
                        THEN ' lacks the NOT_DELEGATED flag (delegation currently blocked only by '
                             'Protected Users membership)'
                        ELSE ' can be delegated (NOT_DELEGATED flag not set)' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'admin_count', u.admin_count,
                'is_enabled', u.is_enabled,
                'privilege_sources', pc.privilege_sources,
                'protected_users_member', (pum.object_guid IS NOT NULL OR u.protected_users_member)
            ) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
        JOIN privileged_check pc ON pc.object_guid = u.object_guid
        LEFT JOIN protected_users_members pum ON pum.object_guid = u.object_guid
        WHERE u.client_id = %(client_id)s
          AND u.valid_to IS NULL
          AND u.is_enabled
          AND (COALESCE(u.user_account_control, 0) & 1048576) = 0
          AND COALESCE(udo.object_sid, '') NOT LIKE '%%-502'
    """,
}
