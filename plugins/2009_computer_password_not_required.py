"""
Plugin 2009: Computer Account Does Not Require a Password

PASSWD_NOTREQD on a computer object is highly unusual -- normal computer
account provisioning never sets this. Worth treating as a potential
persistence indicator (e.g. an attacker-created computer object with
deliberately weakened auth requirements), not just a routine
misconfiguration.
"""

PLUGIN = {
    "plugin_id": 2009,
    "category": "Computer Accounts",
    "name": "Computer Account Does Not Require a Password",
    "version": "1.3",
    "revision_date": "2026-07-15",
    "remediation": (
        "Investigate immediately -- this flag is never set by normal "
        "computer account provisioning (standard domain join, Autopilot, "
        "SCCM/Intune enrollment, etc. all leave this unset). Determine "
        "when and how it was set (check msDS-ReplAttributeMetaData for "
        "the userAccountControl attribute's last-changed timestamp and "
        "originating DC) before simply clearing it -- treat as a probable "
        "persistence or reconnaissance indicator requiring investigation, "
        "not a routine cleanup item."
    ),
    "control_id": "CRED-103",
    "framework_tags": [],
    "references": [],
    "description": (
        "The PASSWD_NOTREQD UAC bit (0x0020) permits a blank password, "
        "bypassing password policy entirely. This is expected/common on "
        "certain user service accounts (see plugin 1002) but is highly "
        "unusual on a computer object -- no normal domain-join, "
        "Autopilot, or endpoint-management enrollment process sets this "
        "flag. A computer account with this bit set is worth treating as "
        "a potential persistence or reconnaissance indicator (e.g. an "
        "attacker-created computer object with deliberately weakened "
        "authentication requirements), not a routine misconfiguration to "
        "quietly fix. Downgraded when disabled, same reasoning as the "
        "user-account equivalent: exploiting a blank password requires "
        "the ability to actually authenticate, which a disabled account "
        "cannot do."
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
                || ' does not require a password (PASSWD_NOTREQD)'
                || CASE WHEN NOT c.is_enabled
                        THEN ' (Disabled Account)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'user_account_control', c.user_account_control,
                'last_logon_timestamp', c.last_logon_timestamp,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.user_account_control IS NOT NULL
          AND (c.user_account_control & 32) != 0
    """,
}
