"""
Plugin 4005: Domain Minimum Password Age Is Zero

Directly cited against DISA STIG guidance requiring at least a 1-day
minimum password age. A minimum age of zero lets a user change their
password repeatedly in immediate succession specifically to cycle
through and defeat the password history requirement, landing right back
on their preferred password with the history check never actually
blocking the reuse.

[v1.3] Until collector 0.5.15 this plugin could never fire:
ad_interval_to_seconds() turned a minPwdAge of 0 into NULL, so
min_pwd_age_seconds = 0 never matched. The collector now stores 0 as 0
(NULL means absent or unreadable), so the predicate is unchanged and
NULL is still not reported. Cites DISA STIG V-254290. The detail also
reports enabled_users_on_domain_default (enabled users with no
Fine-Grained Password Policy, who actually get this default).
"""

PLUGIN = {
    "plugin_id": 4005,
    "category": "Domain",
    "name": "Domain Minimum Password Age Is Zero",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Set the domain-wide minimum password age to at least 1 day "
        "(Computer Configuration >> Windows Settings >> Security "
        "Settings >> Account Policies >> Password Policy >> \"Minimum "
        "password age\"). This is what makes the password history "
        "requirement actually effective -- without it, history is "
        "easily defeated by rapid successive changes."
    ),
    "control_id": "POLICY-005",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "Microsoft: Minimum password age",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-age"},
    ],
    "description": (
        "DISA STIG guidance requires a minimum password age of at "
        "least 1 day. A minimum age of zero lets a user change their "
        "password repeatedly in immediate succession specifically to "
        "cycle through and defeat the password history requirement -- "
        "with a history depth of N, changing the password N+1 times in "
        "a row lands right back on the original password with the "
        "history check never having actually blocked the reuse. This "
        "finding is meaningfully more useful when read alongside "
        "plugin 4006 (password history depth): a short minimum age "
        "combined with a short history is the weakest practical "
        "combination."
    ),
    "base_severity": "medium",
    "query": """
        -- [v1.3] Users a PSO reaches through a global security group (PSOs
        -- ignore other group types), nested and primary-group membership
        -- included, plus users a PSO targets directly. Everyone else gets
        -- the domain default.
        WITH RECURSIVE pso_group_members AS (
            SELECT gme.member_guid
            FROM fgpp_applies_to_edge e
            JOIN ad_fgpp f ON f.object_guid = e.pso_guid AND f.client_id = e.client_id AND f.valid_to IS NULL
            JOIN ad_group g ON g.object_guid = e.target_guid AND g.client_id = e.client_id AND g.valid_to IS NULL
            JOIN group_member_edge gme ON gme.group_guid = g.object_guid AND gme.client_id = g.client_id
                                      AND gme.valid_to IS NULL
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
              AND (g.group_type & 2) <> 0 AND g.group_type < 0
            UNION
            SELECT gme.member_guid
            FROM pso_group_members m
            JOIN group_member_edge gme ON gme.group_guid = m.member_guid AND gme.client_id = %(client_id)s
                                      AND gme.valid_to IS NULL
        ),
        pso_covered_users AS (
            SELECT member_guid AS user_guid FROM pso_group_members
            UNION
            SELECT e.target_guid
            FROM fgpp_applies_to_edge e
            JOIN ad_fgpp f ON f.object_guid = e.pso_guid AND f.client_id = e.client_id AND f.valid_to IS NULL
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL
        )
        SELECT
            'fail' AS status,
            d.object_guid,
            'CAT_III' AS stig_severity,
            'DISA Windows Server STIG V-254290: minimum password age must be at least 1 day, to make '
                'the password history requirement actually effective' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' has a minimum password age of 0' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'min_pwd_age_seconds', d.min_pwd_age_seconds,
                'enabled_users_on_domain_default', (
                    SELECT count(*) FROM ad_user u
                    WHERE u.client_id = d.client_id AND u.valid_to IS NULL AND u.is_enabled
                      AND NOT EXISTS (SELECT 1 FROM pso_covered_users c WHERE c.user_guid = u.object_guid))
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.min_pwd_age_seconds = 0
    """,
}
