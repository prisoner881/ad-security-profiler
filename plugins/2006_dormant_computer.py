"""
Plugin 2006: Dormant Computer Account

A computer account with no recent logon activity likely represents a
decommissioned or otherwise abandoned machine whose account was never
cleaned up -- unnecessary attack surface (a stale computer account's
credentials are just as usable as an active one's) with nobody watching
for anomalous use.

[v1.3] The summary now states the last logon time as a date (UTC, to the
day) rather than a day count computed from now(). The count differed on
every run, so an unchanged finding was recorded as 'changed' on every
audit; the date only moves when the underlying attribute does. Severity
and inclusion thresholds are unchanged.

[v1.4] An account with no lastLogonTimestamp and no pwdLastSet (pwdLastSet
0, e.g. a pre-staged account created with "must change password") is now
judged by whenCreated instead of never being reported. Disabled accounts
are kept but rated one step lower (info for a member, low for a DC) and
marked in the summary: a disabled account is already out of use, which is
how PingCastle and most tools treat inactive computers.
"""

PLUGIN = {
    "plugin_id": 2006,
    "category": "Computer Accounts",
    "name": "Dormant Computer Account",
    "version": "1.4",
    "revision_date": "2026-10-04",
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
    "framework_tags": [
        "NIST-800-53-AC-2",
        "NIST-800-53-AC-2(3)",
        "NIST-800-53-CM-8",
        "NIST-CSF-2.0-PR.AA-01",
        "NIST-CSF-2.0-ID.AM-01",
        "PCI-DSS-4.0-8.2.6",
        "PCI-DSS-4.0-12.5.1",
        "CIS-CSC-8-5.3",
        "CIS-CSC-8-1.1",
        "ISO-27001-2022-A.5.18",
        "ISO-27001-2022-A.5.9",
        "SOC2-CC6.2",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(3)(ii)(C)",
        "MITRE-ATTCK-T1078.002",
    ],
    "references": [],
    "description": (
        "A computer account with no recent authentication activity "
        "likely represents a decommissioned or abandoned machine whose "
        "account was never cleaned up. This is a standard finding in the "
        "PingCastle 'Stale Objects' category and general AD hygiene "
        "guidance more broadly. A dormant domain controller specifically "
        "would be highly unusual and escalated accordingly -- a DC that "
        "hasn't authenticated in this window likely indicates a bigger "
        "operational problem than simple staleness. Inactivity is "
        "lastLogonTimestamp older than 90 days or, for an account that "
        "never logged on, pwdLastSet (or whenCreated when pwdLastSet is "
        "0) older than 90 days. Disabled accounts are rated one step "
        "lower (info / low for a DC) and marked in the summary."
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
            CASE
                WHEN c.is_domain_controller AND c.is_enabled IS NOT FALSE THEN 'high'
                WHEN c.is_domain_controller THEN 'low'
                WHEN c.is_enabled IS NOT FALSE THEN 'low'
                ELSE 'info'
            END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || CASE
                     WHEN c.last_logon_timestamp IS NULL THEN ' has never logged on'
                     ELSE ' has not logged on since '
                          || to_char(c.last_logon_timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD')
                   END
                || CASE WHEN c.is_enabled IS FALSE
                        THEN ' (account is disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'last_logon_timestamp', c.last_logon_timestamp,
                'operating_system', c.operating_system,
                'is_enabled', c.is_enabled,
                'pwd_last_set', c.pwd_last_set,
                'when_created', c.when_created,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND (
                (c.last_logon_timestamp IS NOT NULL AND c.last_logon_timestamp < now() - interval '90 days')
                OR (c.last_logon_timestamp IS NULL
                    AND COALESCE(c.pwd_last_set, c.when_created) < now() - interval '90 days')
              )
    """,
}
