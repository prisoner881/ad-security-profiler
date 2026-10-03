"""
Plugin 1009: Kerberoastable User Account (SPN Set on a User Account)

Any user account with a registered SPN can be Kerberoasted by any
authenticated domain user -- request a service ticket for it, take the
ticket offline, and attempt to crack it without triggering a single
failed logon. This is normal/expected for computer accounts (excluded
here) but is a real, well-known finding whenever it occurs on a user
account, and considerably more severe when that user account is also
privileged.

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
    "plugin_id": 1009,
    "category": "User Accounts",
    "name": "Kerberoastable User Account (SPN Registered)",
    "version": "1.5",
    "revision_date": "2026-10-03",
    "remediation": (
    'Where possible, eliminate the need for this account to be a standalone '
    'service account with an SPN at all by migrating to a Group Managed Service '
    'Account (gMSA) -- gMSA passwords are long, random, and automatically '
    'rotated, making them impractical to crack offline even if Kerberoasted. '
    "Where gMSA migration isn't feasible, ensure the account has a long, "
    'high-entropy password (25+ characters) and AES-only Kerberos encryption '
    '(disable RC4 support specifically) so an obtained ticket is not '
    'realistically crackable even if captured.'
),
    "control_id": "CRED-005",
    "framework_tags": ["MITRE-ATTCK-T1558.003", "CISA-AA26-237A"],
    "references": [
        {"title": "MITRE ATT&CK T1558.003: Kerberoasting",
         "url": "https://attack.mitre.org/techniques/T1558/003/"},
    ],
    "description": (
        "Any authenticated domain user can request a Kerberos service "
        "ticket for an account with a registered SPN and attempt to crack "
        "it offline (Kerberoasting) -- no failed logon is generated in "
        "the process. This is routine for computer accounts (excluded "
        "here) but a genuine finding on a user account, since it means "
        "that account's effective password strength is the only defense "
        "against offline cracking. Comparable to PingCastle's "
        "Kerberoasting-relevant checks in its Privileged Accounts "
        "category (exact rule name/points not independently confirmed "
        "this session -- general comparability noted, not a precise "
        "citation)."
    ),
    "base_severity": "medium",
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
            'medium' AS tool_severity,
            'Comparable to PingCastle''s Kerberoasting-relevant privileged-account '
                'checks (general comparability, not an exact quoted rule)' AS tool_reference,
            CASE GREATEST(
                CASE WHEN oc.tier = 0 THEN 4 WHEN oc.tier = 1 THEN 3 ELSE 2 END,
                CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 3 ELSE 2 END
            )
                WHEN 4 THEN 'critical'
                WHEN 3 THEN 'high'
                ELSE 'medium'
            END AS fd_severity,
            (CASE
                WHEN oc.tier = 0 THEN 'Tier-0 '
                WHEN oc.tier = 1 THEN 'Tier-1 '
                WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 'Privileged '
                ELSE ''
             END)
                || 'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' is Kerberoastable (SPN registered on a user account)' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'service_principal_names', u.service_principal_names,
                'pwd_last_set', u.pwd_last_set,
                'supported_encryption_types', u.supported_encryption_types,
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
          AND u.is_enabled
          AND u.service_principal_names IS NOT NULL
          AND array_length(u.service_principal_names, 1) > 0
    """,
}
