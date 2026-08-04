"""
Plugin 1006: krbtgt Password Age Exceeds Recommended Rotation Window

The krbtgt account's password (really its NT hash) is what signs every
Kerberos ticket in the domain. An old, unrotated krbtgt password widens
the historical validity window for Golden Ticket forgery if the hash is
ever compromised (e.g. via DCSync) at any point during that span.
"""

PLUGIN = {
    "plugin_id": 1006,
    "category": "User Accounts",
    "name": "krbtgt Account Password Has Not Been Rotated Recently",
    "version": "1.3",
    "revision_date": "2026-07-15",
    "remediation": (
    'Reset the krbtgt password twice, waiting at least 10 hours between resets '
    "(confirmed directly against Microsoft's own AD Forest Recovery guidance; "
    'several independent sources recommend 24 hours for extra safety) to allow '
    'full replication before the second reset -- resetting twice in rapid '
    'succession will invalidate all outstanding Kerberos tickets immediately '
    'and likely require restarting application services domain-wide, and should '
    'only be done that way during active breach recovery, not routine '
    "maintenance. Use a well-tested reset script (Microsoft's own guidance, or "
    'the community-standard Reset-KrbtgtKeyInteractive.ps1) rather than a '
    'manual ad hoc reset, and verify replication has completed to all DCs '
    'before the second reset.'
),
    "control_id": "CRED-004",
    "framework_tags": [],
    "references": [
        {"title": "MITRE ATT&CK T1558.001: Steal or Forge Kerberos Tickets -- Golden Ticket",
         "url": "https://attack.mitre.org/techniques/T1558/001/"},
    ],
    "description": (
        "The krbtgt account's password (its NT hash, specifically) signs "
        "every Kerberos ticket issued in the domain. An old, unrotated "
        "krbtgt password widens the window during which a compromised "
        "hash (e.g. via DCSync) could have been used to forge a Golden "
        "Ticket. Microsoft's own guidance recommends periodic rotation "
        "(twice, 24 hours apart, to fully invalidate old tickets) rather "
        "than leaving this password unchanged indefinitely. No specific "
        "DISA AD STIG rule with a numeric threshold was identified for "
        "this; the 180-day threshold used here is a reasonable, "
        "commonly-cited interval, not a cited standard. Note: krbtgt is "
        "always disabled by design -- unrelated to the actual risk "
        "(cryptographic exposure of the ticket-signing key), so no "
        "disabled-account severity adjustment applies here the way it "
        "does elsewhere; this account's disabled state is permanent and "
        "normal, not a mitigation being evaluated."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'krbtgt account password has not been changed in '
                || EXTRACT(DAY FROM now() - u.pwd_last_set)::int || ' days' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'pwd_last_set', u.pwd_last_set,
                'password_age_days', EXTRACT(DAY FROM now() - u.pwd_last_set)::int
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.sam_account_name = 'krbtgt'
          AND u.pwd_last_set IS NOT NULL
          AND u.pwd_last_set < now() - interval '180 days'
    """,
}
