"""
Plugin 4003: Domain Account Lockout Disabled

lockout_threshold = 0 means account lockout is completely disabled
domain-wide -- every account in the domain (except the built-in
Administrator, which is hardcoded lockout-immune regardless of this
setting -- see plugin 1004) can be password-guessed indefinitely with no
automatic mitigation whatsoever.

[v1.3] Cites DISA STIG V-254286 explicitly. The detail now also reports
enabled_users_on_domain_default: how many enabled users have no
Fine-Grained Password Policy applied and so actually get this default
lockout policy. The finding still reports the domain default itself.
"""

PLUGIN = {
    "plugin_id": 4003,
    "category": "Domain",
    "name": "Domain Account Lockout Disabled",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Enable account lockout by setting a nonzero lockout threshold "
        "(Computer Configuration >> Windows Settings >> Security "
        "Settings >> Account Policies >> Account Lockout Policy >> "
        "\"Account lockout threshold\"). DISA STIG guidance specifies 3 "
        "or fewer invalid attempts. Pair this with a reasonable lockout "
        "duration (see the companion finding, plugin 4007, if also "
        "flagged) -- a lockout policy with no duration or an "
        "auto-unlock time that's too short provides little real "
        "protection."
    ),
    "control_id": "POLICY-003",
    "framework_tags": [
        "NIST-800-53-AC-7",
        "NIST-800-53-IA-5",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.4",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(5)(ii)(D)",
        "DISA-STIG-V-254286",
        "MITRE-ATTCK-T1110.001",
    ],
    "references": [
        {"title": "Microsoft: Account lockout threshold",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-threshold"},
    ],
    "description": (
        "lockout_threshold = 0 disables account lockout completely, "
        "domain-wide. Every account in the domain -- with the specific "
        "exception of the built-in Administrator account, which is "
        "hardcoded lockout-immune regardless of this setting (see "
        "plugin 1004) -- can have its password guessed indefinitely "
        "with no automatic mitigation at all. DISA STIG guidance "
        "commonly specifies a threshold of 3 or fewer invalid attempts; "
        "0 (disabled entirely) is a materially worse condition than "
        "merely having a threshold above that recommendation. The "
        "detail reports how many enabled users have no Fine-Grained "
        "Password Policy and so actually get this default "
        "(enabled_users_on_domain_default)."
    ),
    "base_severity": "high",
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
            'CAT_II' AS stig_severity,
            'DISA Windows Server STIG V-254286: account lockout threshold must be '
                '3 or fewer invalid attempts and not 0; '
                '0 (disabled) is a distinctly worse condition than an elevated '
                'but nonzero threshold' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' has account lockout completely disabled (lockout_threshold=0)' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'lockout_threshold', d.lockout_threshold,
                'enabled_users_on_domain_default', (
                    SELECT count(*) FROM ad_user u
                    WHERE u.client_id = d.client_id AND u.valid_to IS NULL AND u.is_enabled
                      AND NOT EXISTS (SELECT 1 FROM pso_covered_users c WHERE c.user_guid = u.object_guid))
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.lockout_threshold = 0
    """,
}
