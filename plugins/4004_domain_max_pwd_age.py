"""
Plugin 4004: Domain Maximum Password Age Exceeds Recommended Threshold or Never Expires

Directly cited against DISA Windows Server STIG V-254289 (60 days or
less; a value of 0/never-expires is explicitly called out as
unacceptable in the STIG's own check text, not merely "not ideal").
NULL in this project's own schema represents "AD reports no maximum" --
the domain-wide equivalent of the never-expires condition, flagged here
distinctly from merely-too-long.
"""

PLUGIN = {
    "plugin_id": 4004,
    "category": "Domain",
    "name": "Domain Maximum Password Age Exceeds Recommended Threshold or Never Expires",
    "version": "1.1",
    "revision_date": "2026-07-15",
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
        "the merely-too-long case with a higher severity."
    ),
    "base_severity": "medium",
    "query": """
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
                'max_pwd_age_days', d.max_pwd_age_seconds / 86400
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND (d.max_pwd_age_seconds IS NULL OR d.max_pwd_age_seconds > 60 * 86400)
    """,
}
