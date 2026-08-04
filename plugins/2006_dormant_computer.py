"""
Plugin 2006: Dormant Computer Account

A computer account with no recent logon activity likely represents a
decommissioned or otherwise abandoned machine whose account was never
cleaned up -- unnecessary attack surface (a stale computer account's
credentials are just as usable as an active one's) with nobody watching
for anomalous use.
"""

PLUGIN = {
    "plugin_id": 2006,
    "category": "Computer Accounts",
    "name": "Dormant Computer Account",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Confirm whether the machine still physically exists and is in "
        "active use. If decommissioned, disable and eventually remove the "
        "computer account -- a stale computer account is unnecessary "
        "attack surface, and its credentials remain fully usable "
        "(including for Kerberoasting-style ticket requests) regardless "
        "of whether the physical machine still exists. If the machine is "
        "just rarely powered on (a legitimate but infrequent-use device), "
        "document why rather than leaving it unexplained."
    ),
    "control_id": "LIFECYCLE-002",
    "framework_tags": [],
    "references": [],
    "description": (
        "A computer account with no recent authentication activity "
        "likely represents a decommissioned or abandoned machine whose "
        "account was never cleaned up. This is a standard finding in the "
        "PingCastle 'Stale Objects' category and general AD hygiene "
        "guidance more broadly. A dormant domain controller specifically "
        "would be highly unusual and escalated accordingly -- a DC that "
        "hasn't authenticated in this window likely indicates a bigger "
        "operational problem than simple staleness."
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
            CASE WHEN c.is_domain_controller THEN 'high' ELSE 'low' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || c.sam_account_name
                || CASE
                     WHEN c.last_logon_timestamp IS NULL THEN ' has never logged on'
                     ELSE ' has not logged on in '
                          || EXTRACT(DAY FROM now() - c.last_logon_timestamp)::int || ' days'
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'last_logon_timestamp', c.last_logon_timestamp,
                'operating_system', c.operating_system,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND (
                (c.last_logon_timestamp IS NOT NULL AND c.last_logon_timestamp < now() - interval '90 days')
                OR (c.last_logon_timestamp IS NULL AND c.pwd_last_set IS NOT NULL
                    AND c.pwd_last_set < now() - interval '90 days')
              )
    """,
}
