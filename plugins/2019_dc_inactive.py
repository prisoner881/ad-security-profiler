"""
Plugin 2019: Domain Controller Computer Account Appears Inactive

Escalated, DC-specific variant of plugin 2006 (generic computer
dormancy). Directly cited from PingCastle's S-DC-Inactive rule: an
inactive domain controller is categorically more severe than an inactive
workstation, since another account with rights over that DC object could
reset its password without anyone noticing, and the DC itself represents
significant standing privilege regardless of whether it's actually being
used.
"""

PLUGIN = {
    "plugin_id": 2019,
    "category": "Computer Accounts",
    "name": "Domain Controller Computer Account Appears Inactive",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "If this DC has genuinely been retired, demote it properly "
        "(`Uninstall-ADDSDomainController`, or metadata cleanup via "
        "`ntdsutil` if it was removed without a clean demotion) rather "
        "than leaving a stale DC computer object in place. If it's "
        "still in active service, investigate why lastLogonTimestamp "
        "hasn't updated recently -- this can indicate a replication or "
        "authentication problem worth its own investigation, "
        "independent of the security concern."
    ),
    "control_id": "STALE-201",
    "framework_tags": [],
    "references": [],
    "description": (
        "Directly cited from PingCastle's S-DC-Inactive rule: \"While "
        "an active Domain Controller changes its password every 30 "
        "days, an inactive account can be involved in a domain "
        "compromise. Indeed, another account, which has rights over "
        "this object, may reset the password of this account without "
        "being noticed.\" An inactive DC is categorically more severe "
        "than an inactive workstation (already covered generically by "
        "plugin 2006) -- the DC computer object itself represents "
        "significant standing privilege in the domain regardless of "
        "whether it's actually in active service, and any account with "
        "rights over it could act on that privilege without the "
        "activity showing up anywhere an admin would normally look."
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
            'Domain Controller ' || c.sam_account_name || ' has not logged on in '
                || EXTRACT(DAY FROM now() - c.last_logon_timestamp)::int
                || ' days' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'last_logon_timestamp', c.last_logon_timestamp,
                'days_since_logon', EXTRACT(DAY FROM now() - c.last_logon_timestamp)::int
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.is_domain_controller
          AND c.is_enabled
          AND c.last_logon_timestamp IS NOT NULL
          AND c.last_logon_timestamp < now() - INTERVAL '45 days'
    """,
}
