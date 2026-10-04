"""
Plugin 1001: User Account Password Set to Never Expire

Enabled user accounts configured to never require a password change bypass
the domain's maximum password age policy entirely, regardless of how that
policy is configured.

[v1.5] "Privileged" now comes from the shared Tier 0 view
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
    "plugin_id": 1001,
    "category": "User Accounts",
    "name": "User Account Password Set to Never Expire",
    "version": "1.5",
    "revision_date": "2026-10-03",
    "remediation": (
    'Remove the DONT_EXPIRE_PASSWORD flag (uncheck "Password never expires" in '
    'ADUC, or `Set-ADUser -PasswordNeverExpires $false`) and let the account '
    "fall under the domain's standard password expiration policy or an "
    'appropriate Fine-Grained Password Policy. For service accounts '
    'specifically -- the most common legitimate reason this flag gets set, '
    'usually to avoid an outage from an expired password -- the better '
    'long-term fix is migrating to a Group Managed Service Account (gMSA), '
    'which handles its own automatic password rotation with no service downtime '
    'risk, removing the need for this flag entirely rather than just tolerating '
    'it.'
),

    # Optional -- used for compliance-framework mapping (control_catalog).
    # A plugin doesn't need one if it isn't tied to a formal control.
    "control_id": "CRED-001",
    "framework_tags": [
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-5(1)",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.9",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(5)(ii)(D)",
        "DISA-STIG",
        "DISA-STIG-V-254289",
        "MITRE-ATTCK-T1078.002",
    ],
    "references": [],
    "description": (
        "Enabled user accounts configured to never require a password "
        "change bypass the domain's maximum password age policy entirely, "
        "regardless of how that policy is configured. Comparable to DISA "
        "Windows Server STIG WN22-AC-000050 (V-254289, CAT II) at the "
        "individual-account level, and to PingCastle's \"non-expiring "
        "password\" rule (Stale Objects)."
    ),

    # This control's baseline severity before any tier-based adjustment --
    # what fd_severity resolves to for an account with no tier classification.
    "base_severity": "medium",

    # The plugin itself. Must return zero or more rows shaped exactly as:
    # (status, object_guid, stig_severity, stig_reference, tool_severity,
    #  tool_reference, fd_severity, summary, detail). Zero rows = clean
    # pass. May reference %(client_id)s / %(run_id)s as bound parameters --
    # always parameter-bound by the runner, never string-interpolated.
    #
    # fd_severity is escalated by two independent signals, combined as
    # worst-of-two (not stacked/summed):
    #   - object_classification.tier (0 -> critical, 1 -> high) -- the
    #     authoritative signal, once populated; currently unpopulated on
    #     every real deployment so far, which is why this alone wasn't
    #     enough to differentiate real findings.
    #   - "privileged" via admin_count=1 OR current/nested membership in
    #     an AdminSDHolder-protected group (ad_group.is_protected_group,
    #     already verified against real data; membership resolved through
    #     v_effective_group_membership so nested privilege is caught, not
    #     just direct) -- treated as 'high', available today with no
    #     dependency on tier ever being populated.
    #
    # A disabled account is then floor(0)-capped two severity levels
    # DOWN from whatever the above computed: this finding is fundamentally
    # about being able to authenticate as the account, and a disabled
    # account cannot authenticate via normal logon at all, regardless of
    # whether the password is known -- a near-complete closure of the
    # specific risk, not a marginal one. Never dropped from the report
    # entirely, since the account could be re-enabled at any time, at
    # which point the next collection run naturally restores full
    # severity with no extra logic needed.
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
            'CAT_II' AS stig_severity,
            'DISA Windows Server STIG WN22-AC-000050 (V-254289): maximum '
                'password age must be 60 days or less -- pwd_never_expires '
                'bypasses this control entirely at the account level' AS stig_reference,
            'medium' AS tool_severity,
            'PingCastle: "Non expiring password" (Stale Objects category)' AS tool_reference,
            CASE GREATEST(0,
                GREATEST(
                    CASE WHEN oc.tier = 0 THEN 4 WHEN oc.tier = 1 THEN 3 ELSE 2 END,
                    CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 3 ELSE 2 END
                ) - (CASE WHEN u.is_enabled THEN 0 ELSE 2 END)
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
                || ' has a password set to never expire'
                || CASE WHEN NOT u.is_enabled
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'is_enabled', u.is_enabled,
                'pwd_last_set', u.pwd_last_set,
                'password_age_days', CASE WHEN u.pwd_last_set IS NOT NULL
                                           THEN EXTRACT(DAY FROM now() - u.pwd_last_set)::int
                                           ELSE NULL END,
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
          AND u.pwd_never_expires
    """,
}
