"""
Plugin 2010: Computer Account Does Not Require Kerberos Pre-Authentication

DONT_REQ_PREAUTH on a computer object is, like PASSWD_NOTREQD, highly
unusual -- normal provisioning never sets this. Same AS-REP Roasting
mechanism as user-account plugin 1013, applied to a computer object.
"""

PLUGIN = {
    "plugin_id": 2010,
    "category": "Computer Accounts",
    "name": "Computer Account Does Not Require Kerberos Pre-Authentication",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Investigate immediately, for the same reason as the companion "
        "PASSWD_NOTREQD finding (plugin 2009) -- this flag is never set "
        "by normal computer account provisioning. Determine when and how "
        "it was set before simply clearing it. If confirmed to be an "
        "unexplained change, treat as a probable persistence or "
        "reconnaissance indicator requiring investigation."
    ),
    "control_id": "CRED-104",
    "framework_tags": [],
    "references": [
        {"title": "MITRE ATT&CK T1558.004: Steal or Forge Kerberos Tickets -- AS-REP Roasting",
         "url": "https://attack.mitre.org/techniques/T1558/004/"},
    ],
    "description": (
        "The DONT_REQ_PREAUTH UAC bit (0x400000) lets anyone who knows or "
        "guesses this computer's account name request an AS-REP with no "
        "credentials at all and attempt to crack it offline -- the same "
        "AS-REP Roasting mechanism covered for user accounts by plugin "
        "1013. Like PASSWD_NOTREQD, this is highly unusual on a computer "
        "object specifically -- no normal domain-join or "
        "endpoint-management process sets this flag, so a match here is "
        "worth treating as a potential persistence or reconnaissance "
        "indicator. Downgraded when disabled: AS-REP Roasting fails "
        "outright against a disabled account (KDC_ERR_CLIENT_REVOKED on "
        "the AS-REQ itself), the same protocol-level reasoning already "
        "established for the user-account equivalent."
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
            CASE GREATEST(0,
                (CASE WHEN c.is_domain_controller THEN 3 ELSE 2 END)
                - (CASE WHEN c.is_enabled THEN 0 ELSE 2 END)
            )
                WHEN 3 THEN 'critical'
                WHEN 2 THEN 'high'
                WHEN 1 THEN 'medium'
                ELSE 'low'
            END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || c.sam_account_name
                || ' does not require Kerberos pre-authentication (AS-REP roastable) '
                || '-- highly unusual for a computer object'
                || CASE WHEN NOT c.is_enabled
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'user_account_control', c.user_account_control,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.user_account_control IS NOT NULL
          AND (c.user_account_control & 4194304) != 0
    """,
}
