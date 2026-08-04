"""
Plugin 4006: Domain Password History Below Recommended Depth

24 is both AD's own configurable maximum for this setting and the
depth commonly cited in DISA STIG guidance -- a domain configured below
this (including the default of 24 itself, worth double-checking hasn't
been reduced) allows faster cycling back to a previously-used password.
"""

PLUGIN = {
    "plugin_id": 4006,
    "category": "Domain",
    "name": "Domain Password History Below Recommended Depth",
    "version": "1.1",
    "revision_date": "2026-07-15",
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
    "framework_tags": ["DISA-STIG"],
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
        SELECT
            'warn' AS status,
            d.object_guid,
            'CAT_III' AS stig_severity,
            'DISA STIG guidance: password history should be set to 24, matching '
                'Active Directory''s own configurable maximum for this setting' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' password history is set to ' || d.pwd_history_count
                || ', below the recommended depth of 24' AS summary,
            jsonb_build_object('dns_root', d.dns_root, 'pwd_history_count', d.pwd_history_count) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.pwd_history_count IS NOT NULL
          AND d.pwd_history_count < 24
    """,
}
