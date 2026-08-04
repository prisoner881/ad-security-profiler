"""
Plugin 2020: Domain Controller Computer Account Password Has Not Rotated Recently

Escalated, DC-specific variant of plugin 2007 (generic computer password
rotation, 90-day threshold). Directly cited from PingCastle's
S-PwdLastSet-DC rule, using its shorter 45-day threshold: a DC's own
computer account password is precisely what DCSync abuses, and a silver
ticket forged from a stale DC password remains valid for as long as that
password stays unrotated -- a categorically more severe consequence than
an ordinary workstation's password going stale.
"""

PLUGIN = {
    "plugin_id": 2020,
    "category": "Computer Accounts",
    "name": "Domain Controller Computer Account Password Has Not Rotated Recently",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Investigate why this DC's computer account password hasn't "
        "rotated on the normal ~30-day cycle -- check the registry "
        "values HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\"
        "Parameters\\DisablePasswordChange (should be 0 or absent) and "
        "MaximumPasswordAge (should be 30) on the DC itself. Some "
        "security teams treat absent password rotation as an indicator "
        "of compromise worth investigating on its own merits, not only "
        "as a hygiene issue."
    ),
    "control_id": "STALE-202",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Machine Account Password Process",
         "url": "https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396026"},
    ],
    "description": (
        "Directly cited from PingCastle's S-PwdLastSet-DC rule, using "
        "its shorter 45-day threshold (versus 90 days for the generic "
        "computer-password-rotation check, plugin 2007): \"using DCSync "
        "to export the hash of a domain controller password, then "
        "reusing it in a silver attack to create Kerberos tickets\" -- "
        "a DC's own computer account password is precisely what a "
        "silver ticket attack forges tickets from, and that forged "
        "access remains valid for as long as the underlying password "
        "stays unrotated. A categorically more severe consequence than "
        "an ordinary workstation's password going stale, which is why "
        "this gets its own DC-specific finding rather than relying on "
        "the generic check alone."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Domain Controller ' || c.sam_account_name || ' computer account password has '
                'not rotated in ' || EXTRACT(DAY FROM now() - c.pwd_last_set)::int
                || ' days' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'pwd_last_set', c.pwd_last_set,
                'days_since_rotation', EXTRACT(DAY FROM now() - c.pwd_last_set)::int
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.is_domain_controller
          AND c.is_enabled
          AND c.pwd_last_set IS NOT NULL
          AND c.pwd_last_set < now() - INTERVAL '45 days'
    """,
}
