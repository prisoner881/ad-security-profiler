"""
Plugin 4001: Domain Password Complexity Requirements Disabled

The domain-wide default password complexity requirement is off. This is
a single setting that affects every account in the domain that doesn't
have a Fine-Grained Password Policy overriding it -- the most
consequential password-policy setting in this whole category by reach,
since a single domain object holds it, unlike per-account findings.
"""

PLUGIN = {
    "plugin_id": 4001,
    "category": "Domain",
    "name": "Domain Password Complexity Requirements Disabled",
    "version": "1.1",
    "revision_date": "2026-07-15",
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
        "at once rather than one account at a time."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' does not require password complexity by default' AS summary,
            jsonb_build_object('dns_root', d.dns_root, 'pwd_policy_complexity', d.pwd_policy_complexity) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND NOT d.pwd_policy_complexity
    """,
}
