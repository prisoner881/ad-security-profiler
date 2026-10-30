"""
Plugin 2007: Computer Account Password Not Recently Rotated

Computer accounts rotate their own password automatically (default every
30 days). A password that hasn't changed in a long time suggests the
machine is offline, broken, or decommissioned but its account was never
cleaned up -- a distinct signal from last_logon_timestamp staleness,
since a machine can retain a recent logon while its password rotation
has separately stopped working (e.g. a machine stuck unable to reach a
DC to complete rotation).

[v1.3] The summary now states the password-last-set time as a date (UTC,
to the day) rather than a day count computed from now(). The count
differed on every run, so an unchanged finding was recorded as 'changed'
on every audit; the date only moves when the underlying attribute does.
Severity and inclusion thresholds are unchanged. The day count is still
reported in detail (password_age_days), which is not part of the
finding's identity because object_guid is always set for this plugin.

[v1.5] Leaves out the Microsoft Entra Kerberos server object
(CN=AzureADKerberos in the Domain Controllers OU, linked to the krbtgt-
AzureAD account), which Microsoft documents as functioning like a read-only
domain controller but which is not a server: it never logs on and its
password is not rotated by a host. Plugin 1006 reports the age of its key.
Requires schema v46.

[v1.6] Leaves out AZUREADSSOACC$, the computer account Microsoft Entra
Seamless SSO creates: it never logs on and its password (the SSO Kerberos
key) is rolled by hand, not by a host. Plugin 10008 reports its key age.
"""

PLUGIN = {
    "plugin_id": 2007,
    "category": "Computer Accounts",
    "name": "Computer Account Password Has Not Rotated Recently",
    "version": "1.6",
    "revision_date": "2026-10-30",
    "remediation": (
        "If the machine still exists, confirm it can actually reach a "
        "domain controller and that its computer account password "
        "rotation isn't silently failing (check the System event log for "
        "Netlogon errors). If the machine is decommissioned, disable and "
        "remove the account rather than leaving a stale credential in "
        "place indefinitely."
    ),
    "control_id": "LIFECYCLE-003",
    "framework_tags": [
        "NIST-800-53-AC-2",
        "NIST-800-53-AC-2(3)",
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-5(1)",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.2.6",
        "PCI-DSS-4.0-8.3.9",
        "CIS-CSC-8-5.3",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.18",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.2",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(3)(ii)(C)",
        "HIPAA-164.308(a)(5)(ii)(D)",
        "MITRE-ATTCK-T1078.002",
    ],
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
        "here, not a cited external standard. Failover cluster name "
        "objects (CNO/VCO, SPN MSClusterVirtualServer or MSServerCluster) "
        "are labelled as such; one whose password is over three years old "
        "while the account is still in use (logged on in the last 45 days) "
        "is medium (PingCastle S-PwdLastSet-Cluster): the cluster service "
        "is not rotating it."
    ),
    "base_severity": "low",
    "query": """
        WITH cluster AS (
            SELECT DISTINCT s.object_guid
            FROM spn_edge s
            WHERE s.client_id = %(client_id)s AND s.valid_to IS NULL
              AND (s.spn ILIKE 'MSClusterVirtualServer/%%' OR s.spn ILIKE 'MSServerCluster/%%')
        )
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_domain_controller THEN 'medium'
                 WHEN cl.object_guid IS NOT NULL AND c.pwd_last_set < now() - interval '3 years'
                      AND c.last_logon_timestamp >= now() - interval '45 days' THEN 'medium'
                 ELSE 'low' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller '
                  WHEN cl.object_guid IS NOT NULL THEN 'Cluster Name Object ' ELSE '' END)
                || 'Computer Account ' || c.sam_account_name
                || ' password has not rotated since '
                || to_char(c.pwd_last_set AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'pwd_last_set', c.pwd_last_set,
                'password_age_days', EXTRACT(DAY FROM now() - c.pwd_last_set)::int,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller,
                'is_cluster_account', (cl.object_guid IS NOT NULL),
                'last_logon_timestamp', c.last_logon_timestamp
            ) AS detail
        FROM ad_computer c
        LEFT JOIN cluster cl ON cl.object_guid = c.object_guid
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND NOT is_entra_kerberos_server(c.sam_account_name, c.krbtgt_link)
          -- [v1.6] the Seamless SSO account: plugin 10008 reports its key age
          AND lower(COALESCE(c.sam_account_name, '')) <> 'azureadssoacc$'
          AND c.pwd_last_set IS NOT NULL
          AND c.pwd_last_set < now() - interval '90 days'
    """,
}
