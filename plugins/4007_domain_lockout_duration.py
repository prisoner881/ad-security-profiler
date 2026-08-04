"""
Plugin 4007: Domain Account Lockout Duration Too Short

Distinct from lockout being disabled entirely (plugin 4003): this fires
when lockout IS enabled but auto-unlocks quickly enough to provide only
token protection against sustained password-guessing. DISA STIG
guidance commonly specifies a minimum lockout duration of 15 minutes.
Only evaluated when lockout is actually enabled, to avoid double-
reporting the same underlying condition as plugin 4003.
"""

PLUGIN = {
    "plugin_id": 4007,
    "category": "Domain",
    "name": "Domain Account Lockout Duration Too Short",
    "version": "1.1",
    "revision_date": "2026-07-15",
    "remediation": (
        "Increase the domain-wide account lockout duration to at least "
        "15 minutes (Computer Configuration >> Windows Settings >> "
        "Security Settings >> Account Policies >> Account Lockout "
        "Policy >> \"Account lockout duration\"). A very short duration "
        "provides only token protection against a sustained "
        "password-guessing attempt -- the attacker simply waits out the "
        "auto-unlock and resumes."
    ),
    "control_id": "POLICY-007",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "Microsoft: Account lockout duration",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/account-lockout-duration"},
    ],
    "description": (
        "DISA STIG guidance commonly specifies a minimum account "
        "lockout duration of 15 minutes. A shorter duration provides "
        "only token protection -- an attacker running a sustained "
        "password-guessing attempt simply waits out the auto-unlock and "
        "resumes. Only evaluated when lockout is actually enabled "
        "(lockout_threshold > 0); a domain with lockout disabled "
        "entirely is a distinct, more severe condition already covered "
        "by plugin 4003, and this check deliberately doesn't also fire "
        "for that same underlying state."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            d.object_guid,
            'CAT_III' AS stig_severity,
            'DISA STIG guidance: account lockout duration should be at least 15 '
                'minutes' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' account lockout duration is ' || (d.lockout_duration_seconds / 60)
                || ' minutes, below the recommended 15-minute minimum' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'lockout_duration_seconds', d.lockout_duration_seconds,
                'lockout_duration_minutes', d.lockout_duration_seconds / 60
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.lockout_threshold > 0
          AND d.lockout_duration_seconds IS NOT NULL
          AND d.lockout_duration_seconds < 15 * 60
    """,
}
