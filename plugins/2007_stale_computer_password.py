"""
Plugin 2007: Computer Account Password Not Recently Rotated

Computer accounts rotate their own password automatically (default every
30 days). A password that hasn't changed in a long time suggests the
machine is offline, broken, or decommissioned but its account was never
cleaned up -- a distinct signal from last_logon_timestamp staleness,
since a machine can retain a recent logon while its password rotation
has separately stopped working (e.g. a machine stuck unable to reach a
DC to complete rotation).
"""

PLUGIN = {
    "plugin_id": 2007,
    "category": "Computer Accounts",
    "name": "Computer Account Password Has Not Rotated Recently",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "If the machine still exists, confirm it can actually reach a "
        "domain controller and that its computer account password "
        "rotation isn't silently failing (check the System event log for "
        "Netlogon errors). If the machine is decommissioned, disable and "
        "remove the account rather than leaving a stale credential in "
        "place indefinitely."
    ),
    "control_id": "LIFECYCLE-003",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Machine Account Password Process",
         "url": "https://techcommunity.microsoft.com/blog/askds/machine-account-password-process/396026"},
    ],
    "description": (
        "Computer accounts rotate their own password automatically by "
        "default every 30 days. A password that has not changed in a "
        "long time suggests the machine is offline, broken, or "
        "decommissioned but its account was never cleaned up -- distinct "
        "from last_logon_timestamp staleness (plugin 2006), since a "
        "machine can show a recent logon while password rotation has "
        "separately stopped working, or vice versa. 90 days (3x the "
        "default rotation interval) is used as a conservative threshold "
        "here, not a cited external standard."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_domain_controller THEN 'medium' ELSE 'low' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || c.sam_account_name
                || ' password has not rotated in '
                || EXTRACT(DAY FROM now() - c.pwd_last_set)::int || ' days' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'pwd_last_set', c.pwd_last_set,
                'password_age_days', EXTRACT(DAY FROM now() - c.pwd_last_set)::int,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.pwd_last_set IS NOT NULL
          AND c.pwd_last_set < now() - interval '90 days'
    """,
}
