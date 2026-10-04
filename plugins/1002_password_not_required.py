"""
Plugin 1002: Password Not Required (PASSWD_NOTREQD)

The PASSWD_NOTREQD UAC bit (0x0020) permits an account to be assigned a
blank password, bypassing the domain password policy entirely -- not just
weakening it the way pwd_never_expires does. Confirmed as a real,
well-known finding by BloodHound's own Cypher query for this exact
condition (MATCH (n:User {enabled: True, passwordnotreqd: True})).

[v1.5] "Privileged" now comes from the shared Tier 0 view
v_privileged_principal (schema v34) instead of an inline subquery that
counted GenericAll/GenericWrite/WriteDACL/WriteOwner on, or ownership of,
ANY object with a collected ACL -- every OU, every certificate template --
so OU delegates and whoever created an OU were treated as privileged.
Protected-group membership, control of or ownership of a Tier 0 object
(domain root, AdminSDHolder, DCs, CAs, ...), DCSync, and membership in a
group holding any of those still count. detail gains privilege_sources
(the view's reasons, sorted); summary wording is unchanged.

[v1.6] Interdomain trust accounts (UAC INTERDOMAIN_TRUST_ACCOUNT 0x0800,
the TRUSTEDDOMAIN$ user objects AD creates for every trust with
PASSWD_NOTREQD set by default, UAC 0x820) are excluded -- a default-config
false positive on every domain with a trust, also excluded by PingCastle and
BloodHound. The disabled built-in Guest account (RID 501, default UAC
0x222) is excluded too; an ENABLED Guest is still reported (and is plugin
1005's subject as well). The severity CASE now differentiates: high for
an ordinary account, high for a privileged account or Tier 1 (unchanged
outcome), critical for Tier 0 -- the former "ELSE 3" in both branches made
the privilege test dead code; written out explicitly now. Plugin name no
longer says "Enabled" (disabled accounts are reported, at reduced
severity, by design).
"""

PLUGIN = {
    "plugin_id": 1002,
    "category": "User Accounts",
    "name": "User Account Does Not Require a Password",
    "version": "1.6",
    "revision_date": "2026-10-04",
    "remediation": (
    'Remove the PASSWD_NOTREQD flag (`Set-ADAccountControl -PasswordNotRequired '
    '$false` or the equivalent ADUC checkbox), then immediately force a '
    'policy-compliant password reset on the account -- removing the flag alone '
    'does not retroactively validate whatever password (if any) is currently '
    'set. Investigate why the flag was set in the first place; a legacy '
    'application requirement is the most common legitimate reason, and if '
    "that's confirmed still necessary, document it explicitly as an accepted "
    'exception rather than leaving it unexplained.'
),
    "control_id": "CRED-002",
    "framework_tags": [
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-5(1)",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.6",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(5)(ii)(D)",
        "MITRE-ATTCK-T1078.002",
    ],
    "references": [],
    "description": (
        "The PASSWD_NOTREQD flag (userAccountControl bit 0x0020) permits "
        "this account to be assigned a blank password, bypassing the "
        "domain's password policy entirely -- not merely weakening it. "
        "No DISA AD STIG rule directly and solely covers this specific "
        "flag; BloodHound's own attack-path tooling checks for this exact "
        "condition (enabled + passwordnotreqd) as a real attack surface item. "
        "Interdomain trust accounts (which AD creates with this flag) and "
        "the disabled built-in Guest account are excluded as default "
        "configuration; disabled accounts are otherwise reported at "
        "reduced severity."
    ),
    "base_severity": "high",
    # Disabled accounts get a two-level severity downgrade (floored at
    # info), same reasoning and mechanism as plugin 1001: this finding is
    # about being able to authenticate with a blank password, which a
    # disabled account cannot do regardless of what its password is.
    "query": """
        WITH privileged_check AS (
            -- [v1.5] "Privileged" is the shared Tier 0 definition in
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
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            'high' AS tool_severity,
            'BloodHound: attack-path query for enabled + PASSWD_NOTREQD accounts '
                '(a blank-password-eligible account is directly requestable without '
                'any credential guess)' AS tool_reference,
            -- [v1.6] Base is already high (3); only Tier 0 raises it, so
            -- the former privileged branch (3 vs 3) is folded away.
            CASE GREATEST(0,
                (CASE WHEN oc.tier = 0 THEN 4 ELSE 3 END)
                - (CASE WHEN u.is_enabled THEN 0 ELSE 2 END)
            )
                WHEN 4 THEN 'critical'
                WHEN 3 THEN 'high'
                WHEN 2 THEN 'medium'
                WHEN 1 THEN 'low'
                ELSE 'info'
            END AS fd_severity,
            (CASE
                WHEN oc.tier = 0 THEN 'Tier-0 '
                WHEN oc.tier = 1 THEN 'Tier-1 '
                WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 'Privileged '
                ELSE ''
             END)
                || 'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' does not require a password (PASSWD_NOTREQD)'
                || CASE WHEN NOT u.is_enabled
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'user_account_control', u.user_account_control,
                'is_enabled', u.is_enabled,
                'last_logon_timestamp', u.last_logon_timestamp,
                'admin_count', u.admin_count,
                'tier', oc.tier,
                'privileged_group_member', pc.object_guid IS NOT NULL,
                'privilege_sources', pc.privilege_sources
            ) AS detail
        FROM ad_user u
        LEFT JOIN object_classification oc
            ON oc.object_guid = u.object_guid AND oc.client_id = u.client_id
        LEFT JOIN privileged_check pc
            ON pc.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND (u.user_account_control & 32) != 0
          -- [v1.6] Interdomain trust accounts (TRUSTEDDOMAIN$, UAC 0x820)
          -- carry PASSWD_NOTREQD by default.
          AND (u.user_account_control & 2048) = 0
          -- [v1.6] The disabled built-in Guest (RID 501, default UAC 0x222)
          -- is default configuration; an enabled Guest is still reported.
          AND NOT (NOT COALESCE(u.is_enabled, false) AND EXISTS (
                SELECT 1 FROM directory_object o
                WHERE o.object_guid = u.object_guid
                  AND o.client_id = u.client_id
                  AND o.object_sid LIKE '%%-501'))
    """,
}
