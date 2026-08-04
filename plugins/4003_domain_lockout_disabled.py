"""
Plugin 4003: Domain Account Lockout Disabled

lockout_threshold = 0 means account lockout is completely disabled
domain-wide -- every account in the domain (except the built-in
Administrator, which is hardcoded lockout-immune regardless of this
setting -- see plugin 1004) can be password-guessed indefinitely with no
automatic mitigation whatsoever.
"""

PLUGIN = {
    "plugin_id": 4003,
    "category": "Domain",
    "name": "Domain Account Lockout Disabled",
    "version": "1.2",
    "revision_date": "2026-07-15",
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
    "framework_tags": ["DISA-STIG"],
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
        "merely having a threshold above that recommendation."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            d.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Windows Server STIG family: account lockout threshold must be '
                'configured (commonly cited as 3 or fewer invalid attempts); '
                '0 (disabled) is a distinctly worse condition than an elevated '
                'but nonzero threshold' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' has account lockout completely disabled (lockout_threshold=0)' AS summary,
            jsonb_build_object('dns_root', d.dns_root, 'lockout_threshold', d.lockout_threshold) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.lockout_threshold = 0
    """,
}
