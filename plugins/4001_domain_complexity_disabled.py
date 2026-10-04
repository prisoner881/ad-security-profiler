"""
Plugin 4001: Domain Password Complexity Requirements Disabled

The domain-wide default password complexity requirement is off. This is
a single setting that affects every account in the domain that doesn't
have a Fine-Grained Password Policy overriding it -- the most
consequential password-policy setting in this whole category by reach,
since a single domain object holds it, unlike per-account findings.

[v1.2] Cites DISA STIG V-254292 (CAT II). The detail now also reports
enabled_users_on_domain_default: how many enabled users have no
Fine-Grained Password Policy applied (directly, or through a global
security group, nested and primary-group membership included) and so
actually get this default. The finding itself still reports the
domain default, as the STIG and PingCastle do.
"""

PLUGIN = {
    "plugin_id": 4001,
    "category": "Domain",
    "name": "Domain Password Complexity Requirements Disabled",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Enable password complexity requirements in the Default Domain "
        "Policy (Computer Configuration >> Windows Settings >> Security "
        "Settings >> Account Policies >> Password Policy >> \"Password "
        "must meet complexity requirements\"). This affects every "
        "account in the domain that doesn't have a Fine-Grained "
        "Password Policy overriding it -- verify FGPP coverage "
        "separately if any accounts need different handling."
    ),
    "control_id": "POLICY-001",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "Microsoft: Password must meet complexity requirements",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/password-must-meet-complexity-requirements"},
    ],
    "description": (
        "The domain-wide default password complexity requirement "
        "(DOMAIN_PASSWORD_COMPLEX, pwdProperties bit 0x1) is disabled. "
        "This is a single setting on the domain object that governs "
        "every account without a Fine-Grained Password Policy override "
        "-- among the highest-reach findings in this entire project, "
        "since one misconfigured value here affects the whole domain "
        "at once rather than one account at a time. The detail reports "
        "how many enabled users have no FGPP applied and so actually "
        "get this default (enabled_users_on_domain_default)."
    ),
    "base_severity": "high",
    "query": """
        -- [v1.2] Users a PSO reaches through a global security group (PSOs
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
            'CAT_II' AS stig_severity,
            'DISA Windows Server STIG V-254292: the built-in Windows password complexity '
                'policy must be enabled' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' does not require password complexity by default' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'pwd_policy_complexity', d.pwd_policy_complexity,
                'enabled_users_on_domain_default', (
                    SELECT count(*) FROM ad_user u
                    WHERE u.client_id = d.client_id AND u.valid_to IS NULL AND u.is_enabled
                      AND NOT EXISTS (SELECT 1 FROM pso_covered_users c WHERE c.user_guid = u.object_guid))
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND NOT d.pwd_policy_complexity
    """,
}
