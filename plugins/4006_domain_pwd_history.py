"""
Plugin 4006: Domain Password History Below Recommended Depth

24 is both AD's own configurable maximum for this setting and the
depth commonly cited in DISA STIG guidance -- a domain configured below
this (including the default of 24 itself, worth double-checking hasn't
been reduced) allows faster cycling back to a previously-used password.

[v1.2] Cites DISA STIG V-254288. The detail now also reports
enabled_users_on_domain_default: how many enabled users have no
Fine-Grained Password Policy applied and so actually get this default.
"""

PLUGIN = {
    "plugin_id": 4006,
    "category": "Domain",
    "name": "Domain Password History Below Recommended Depth",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Increase the domain-wide password history to 24 (Computer "
        "Configuration >> Windows Settings >> Security Settings >> "
        "Account Policies >> Password Policy >> \"Enforce password "
        "history\") -- 24 is both AD's own configurable maximum for "
        "this setting and the depth commonly cited in DISA STIG "
        "guidance, so this represents the practical ceiling, not an "
        "arbitrary target."
    ),
    "control_id": "POLICY-006",
    "framework_tags": [
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-5(1)",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.7",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(5)(ii)(D)",
        "DISA-STIG-V-254288",
        "MITRE-ATTCK-T1078.002",
    ],
    "references": [
        {"title": "Microsoft: Enforce password history",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/enforce-password-history"},
    ],
    "description": (
        "Password history depth below 24 allows a user to cycle back "
        "to a previously-used password sooner. 24 is both Active "
        "Directory's own configurable maximum for this setting and the "
        "depth commonly cited in DISA STIG guidance -- this check flags "
        "anything below that practical ceiling, not an arbitrarily "
        "chosen number."
    ),
    "base_severity": "low",
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
            'warn' AS status,
            d.object_guid,
            'CAT_III' AS stig_severity,
            'DISA Windows Server STIG V-254288: password history must be 24, matching '
                'Active Directory''s own configurable maximum for this setting' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' password history is set to ' || d.pwd_history_count
                || ', below the recommended depth of 24' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'pwd_history_count', d.pwd_history_count,
                'enabled_users_on_domain_default', (
                    SELECT count(*) FROM ad_user u
                    WHERE u.client_id = d.client_id AND u.valid_to IS NULL AND u.is_enabled
                      AND NOT EXISTS (SELECT 1 FROM pso_covered_users c WHERE c.user_guid = u.object_guid))
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.pwd_history_count IS NOT NULL
          AND d.pwd_history_count < 24
    """,
}
