"""
Plugin 4002: Domain Minimum Password Length Below Recommended Threshold

Directly cited against DISA Windows Server STIG V-254291 (minimum 14
characters), confirmed across multiple STIG versions (Server 2016, 2019,
2022, and the Windows 10/11 client equivalents all specify the same 14).
"""

PLUGIN = {
    "plugin_id": 4002,
    "category": "Domain",
    "name": "Domain Minimum Password Length Below Recommended Threshold",
    "version": "1.1",
    "revision_date": "2026-07-15",
    "remediation": (
        "Increase the domain-wide minimum password length to at least "
        "14 characters (Computer Configuration >> Windows Settings >> "
        "Security Settings >> Account Policies >> Password Policy >> "
        "\"Minimum password length\"). Consider going further -- modern "
        "guidance increasingly favors longer passphrases over shorter "
        "complex strings, and Windows now supports minimum lengths up "
        "to 128 characters when the corresponding policy is enabled."
    ),
    "control_id": "POLICY-002",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "Microsoft: Minimum password length",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/minimum-password-length"},
    ],
    "description": (
        "Directly cited against DISA Windows Server STIG V-254291: "
        "\"If the value for the Minimum password length is less than "
        "14 characters, this is a finding.\" Confirmed consistent "
        "across multiple STIG versions (Server 2016, 2019, 2022, and "
        "the Windows 10/11 client-side equivalents all specify the "
        "same 14-character minimum)."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            d.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Windows Server STIG V-254291: minimum password length must be '
                'at least 14 characters' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN d.pwd_policy_min_length < 8 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' minimum password length is ' || d.pwd_policy_min_length
                || ' characters, below the 14-character STIG minimum' AS summary,
            jsonb_build_object('dns_root', d.dns_root, 'pwd_policy_min_length', d.pwd_policy_min_length) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.pwd_policy_min_length IS NOT NULL
          AND d.pwd_policy_min_length < 14
    """,
}
