"""
Plugin 1013: AS-REP Roastable Account (Kerberos Pre-Authentication Disabled)

DONT_REQ_PREAUTH (0x400000) lets anyone who knows or guesses this
account's username request an AS-REP from the KDC with zero valid
credentials -- not even a wrong password attempt is needed. The encrypted
portion is derived from the account's password and can be cracked
offline. More dangerous than Kerberoasting in one specific way: no
authentication of any kind is a prerequisite.

[v1.7] "Privileged" now comes from the shared Tier 0 view
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
    "plugin_id": 1013,
    "category": "User Accounts",
    "name": "AS-REP Roastable Account (Kerberos Pre-Authentication Disabled)",
    "version": "1.7",
    "revision_date": "2026-10-03",
    "remediation": (
    'Remove the DONT_REQ_PREAUTH flag to re-enable Kerberos pre-authentication. '
    'There is essentially no legitimate reason to leave this disabled on a '
    'modern, all-Windows-Kerberos-client AD environment -- it historically '
    'existed for certain non-Windows Kerberos client compatibility scenarios '
    'that are now rare; confirm no such legacy client actually depends on it '
    "before assuming it's safe to change, but treat that as the exception to "
    'investigate, not the default assumption.'
),
    "control_id": "CRED-007",
    "framework_tags": [
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-SC-28",
        "NIST-800-53-IA-2(8)",
        "NIST-CSF-2.0-PR.DS-01",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.3.2",
        "PCI-DSS-4.0-8.6.2",
        "CIS-CSC-8-3.11",
        "ISO-27001-2022-A.5.17",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "HIPAA-164.312(a)(2)(iv)",
        "MITRE-ATTCK-T1558.004",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1558.004: Steal or Forge Kerberos Tickets -- AS-REP Roasting",
         "url": "https://attack.mitre.org/techniques/T1558/004/"},
    ],
    "description": (
        "The DONT_REQ_PREAUTH UAC bit (0x400000) lets anyone who knows or "
        "guesses this account's username request an AS-REP from the KDC "
        "without presenting any credentials at all -- not even a failed "
        "password attempt occurs. The encrypted portion of that response "
        "is derived from the account's password and can be extracted and "
        "cracked entirely offline. This is operationally more dangerous "
        "than Kerberoasting in one specific respect: Kerberoasting "
        "requires a valid authenticated domain identity to request a "
        "service ticket; this does not require any valid credentials at "
        "all, only a correctly-guessed username."
    ),
    "base_severity": "high",
    # Even though disabled accounts genuinely cannot be AS-REP roasted
    # (KDC_ERR_CLIENT_REVOKED fires on the AS-REQ itself -- this is
    # foundational Kerberos protocol behavior, not tool-dependent), the
    # finding is still shown at floored severity rather than excluded
    # entirely, for audit completeness and because the account could be
    # re-enabled at any time.
    "query": """
        WITH privileged_check AS (
            -- [v1.7] "Privileged" is the shared Tier 0 definition in
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
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE GREATEST(0,
                GREATEST(
                    CASE WHEN oc.tier = 0 THEN 4 WHEN oc.tier = 1 THEN 4 ELSE 3 END,
                    CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 4 ELSE 3 END
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
                || ' does not require Kerberos pre-authentication (AS-REP roastable)'
                || CASE WHEN NOT u.is_enabled
                        THEN ' (Disabled Account)'
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
          AND u.user_account_control IS NOT NULL
          AND (u.user_account_control & 4194304) != 0
    """,
}
