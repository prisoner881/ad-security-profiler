"""
Plugin 4005: Domain Minimum Password Age Is Zero

Directly cited against DISA STIG guidance requiring at least a 1-day
minimum password age. A minimum age of zero lets a user change their
password repeatedly in immediate succession specifically to cycle
through and defeat the password history requirement, landing right back
on their preferred password with the history check never actually
blocking the reuse.
"""

PLUGIN = {
    "plugin_id": 4005,
    "category": "Domain",
    "name": "Domain Minimum Password Age Is Zero",
    "version": "1.2",
    "revision_date": "2026-07-15",
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
        SELECT
            'fail' AS status,
            d.object_guid,
            'CAT_III' AS stig_severity,
            'DISA STIG guidance: minimum password age must be at least 1 day, to make '
                'the password history requirement actually effective' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' has a minimum password age of 0' AS summary,
            jsonb_build_object('dns_root', d.dns_root, 'min_pwd_age_seconds', d.min_pwd_age_seconds) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.min_pwd_age_seconds = 0
    """,
}
