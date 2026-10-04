"""
Plugin 4004: Domain Maximum Password Age Exceeds Recommended Threshold or Never Expires

Directly cited against DISA Windows Server STIG V-254289 (60 days or
less; a value of 0/never-expires is explicitly called out as
unacceptable in the STIG's own check text, not merely "not ideal").
NULL in this project's own schema represents "AD reports no maximum" --
the domain-wide equivalent of the never-expires condition, flagged here
distinctly from merely-too-long.

[v1.2] NULL max_pwd_age_seconds also results when maxPwdAge was absent
or unreadable, which is a collection gap, not "never expires". The
never-expires branch now requires the raw maxPwdAge kept in the domain
object's attributes_full to be one of AD's "never" values (0 or
INT64_MIN); when the raw value is missing the domain is not flagged.
Only when no attribute snapshot exists at all (older data) does NULL
still count as never-expires. The detail also reports
enabled_users_on_domain_default (enabled users with no Fine-Grained
Password Policy, who actually get this default).
"""

PLUGIN = {
    "plugin_id": 4004,
    "category": "Domain",
    "name": "Domain Maximum Password Age Exceeds Recommended Threshold or Never Expires",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Set the domain-wide maximum password age to 60 days or less "
        "(Computer Configuration >> Windows Settings >> Security "
        "Settings >> Account Policies >> Password Policy >> \"Maximum "
        "password age\"). If currently set to never expire, this is "
        "explicitly called out as unacceptable by DISA STIG, not merely "
        "suboptimal -- prioritize fixing this over the exceeds-60-days "
        "case if both would otherwise apply."
    ),
    "control_id": "POLICY-004",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "Microsoft: Maximum password age",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/maximum-password-age"},
    ],
    "description": (
        "Directly cited against DISA Windows Server STIG V-254289: "
        "\"If the value for the Maximum password age is greater than "
        "60 days, this is a finding. If the value is set to 0 (never "
        "expires), this is a finding\" -- the STIG's own text "
        "explicitly and separately calls out never-expires as "
        "unacceptable, not just a milder version of exceeding 60 days. "
        "This project's schema represents that never-expires condition "
        "as NULL (AD reports no maximum), matched here distinctly from "
        "the merely-too-long case with a higher severity. A NULL caused "
        "by an absent or unreadable maxPwdAge (raw value missing) is "
        "not reported."
    ),
    "base_severity": "medium",
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
            'DISA Windows Server STIG V-254289: maximum password age must be 60 days '
                'or less; a value of 0/never-expires is explicitly unacceptable' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN d.max_pwd_age_seconds IS NULL THEN 'high' ELSE 'medium' END AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || CASE
                     WHEN d.max_pwd_age_seconds IS NULL
                       THEN ' has domain-wide passwords set to never expire'
                     ELSE ' maximum password age is '
                          || (d.max_pwd_age_seconds / 86400) || ' days, exceeding the 60-day STIG maximum'
                   END AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'max_pwd_age_seconds', d.max_pwd_age_seconds,
                'max_pwd_age_days', d.max_pwd_age_seconds / 86400,
                'max_pwd_age_raw', dov.attributes_full ->> 'maxPwdAge',
                'enabled_users_on_domain_default', (
                    SELECT count(*) FROM ad_user u
                    WHERE u.client_id = d.client_id AND u.valid_to IS NULL AND u.is_enabled
                      AND NOT EXISTS (SELECT 1 FROM pso_covered_users c WHERE c.user_guid = u.object_guid))
            ) AS detail
        FROM ad_domain d
        LEFT JOIN directory_object_version dov
               ON dov.object_guid = d.object_guid AND dov.client_id = d.client_id AND dov.valid_to IS NULL
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND (d.max_pwd_age_seconds > 60 * 86400
               -- [v1.2] NULL is "never expires" only when the raw value says
               -- so; an absent/unreadable maxPwdAge is not a finding.
               OR (d.max_pwd_age_seconds IS NULL
                   AND (dov.object_guid IS NULL
                        OR dov.attributes_full ->> 'maxPwdAge' IN ('0', '-9223372036854775808'))))
    """,
}
