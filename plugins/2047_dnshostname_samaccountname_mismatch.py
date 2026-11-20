"""
Plugin 2047: Computer dNSHostName Does Not Match Its sAMAccountName

A computer account's dNSHostName normally starts with its own name: host
label = sAMAccountName without the trailing $ (sAMAccountName is limited to
15 characters, so a longer host label only has to start with it). A
mismatch means the attribute was written by hand or by a tool, which is
what Certifried (CVE-2022-26923) and later certificate-impersonation
techniques do: AD CS's Machine template builds the certificate's DNS name
from dNSHostName, so a computer whose dNSHostName names another machine can
be issued a certificate for that machine. PingCastle added this as rule
A-DnsHostnameMismatch in 4.1.2.0 (November 2026). Plugin 2036 already
reports a non-DC carrying a domain controller's dNSHostName (critical) and
duplicate dNSHostNames; this covers the rest.

Legitimate causes exist (a computer renamed outside Windows, some Linux /
NAS joins, cluster or appliance objects), so the finding is an
investigation prompt.

One finding per computer, status 'warn':
  * medium: the host label is another computer account's name (the
    account appears to stand in for that machine);
  * low: any other mismatch.
Domain controllers, gMSA / sMSA objects, the Microsoft Entra Kerberos
server object, and accounts without dNSHostName are not reported; nor are
rows plugin 2036 reports (DC FQDN or duplicate dNSHostName).

Data: ad_computer, directory_object. Identity = the computer. Related:
2036, 6015 (CertiGhost preconditions), 4009 (MachineAccountQuota).
"""

PLUGIN = {
    "plugin_id": 2047,
    "category": "Computer Accounts",
    "name": "Computer dNSHostName Does Not Match Its sAMAccountName",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "COMPUTER-2047",
    "framework_tags": [
        "NIST-800-53-IA-4",
        "NIST-800-53-CM-8",
        "NIST-800-53-SI-4",
        "NIST-CSF-2.0-PR.AA-01",
        "CIS-CSC-8-1.1",
        "ISO-27001-2022-A.5.16",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1649",
        "CVE-2022-26923",
    ],
    "references": [
        {"title": "PingCastle 4.1.2.0 release notes (A-DnsHostnameMismatch)",
         "url": "https://github.com/netwrix/pingcastle/releases/tag/4.1.2.0"},
        {"title": "Microsoft: KB5014754 Certificate-based authentication changes on Windows domain controllers",
         "url": "https://support.microsoft.com/help/5014754"},
        {"title": "MITRE ATT&CK T1649: Steal or Forge Authentication Certificates",
         "url": "https://attack.mitre.org/techniques/T1649/"},
    ],
    "description": (
        "A computer account's dNSHostName does not begin with its own name (sAMAccountName without "
        "$). The attribute was edited, which is how Certifried-style attacks get a certificate "
        "issued in another machine's name. Medium when the host name is another computer's name; "
        "low otherwise (renamed or non-Windows machines also cause it)."
    ),
    "remediation": (
        "For each computer, confirm with its owner why dNSHostName differs from the account name. "
        "If no legitimate reason exists, set dNSHostName back to <name>.<domain>, review "
        "certificates issued to the account (the CA database, by requester), and find who changed "
        "the attribute (replication metadata, event 5136). Restrict who can create computer "
        "accounts (MachineAccountQuota 0, plugin 4009) and who holds write access to dNSHostName "
        "on computer objects."
    ),
    "base_severity": "medium",
    "query": r"""
        WITH
        comp AS (
            SELECT c.object_guid, c.sam_account_name, c.dns_hostname, c.is_enabled, c.is_domain_controller,
                   o.dn_current,
                   lower(regexp_replace(c.sam_account_name, '\$$', '')) AS name_lc,
                   lower(split_part(c.dns_hostname, '.', 1)) AS label_lc,
                   lower(c.dns_hostname) AS fqdn_lc
              FROM ad_computer c
              JOIN directory_object o
                ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
             WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
               AND NOT COALESCE(c.is_gmsa, false)
               AND NOT is_entra_kerberos_server(c.sam_account_name, c.krbtgt_link)
               AND c.sam_account_name IS NOT NULL
        ),
        dc_fqdn AS (
            SELECT fqdn_lc FROM comp WHERE is_domain_controller AND fqdn_lc IS NOT NULL AND fqdn_lc <> ''
        ),
        dup AS (
            SELECT fqdn_lc FROM comp WHERE NOT is_domain_controller AND fqdn_lc IS NOT NULL AND fqdn_lc <> ''
             GROUP BY fqdn_lc HAVING count(*) > 1
        ),
        mism AS (
            SELECT c.*,
                   (SELECT x.sam_account_name FROM comp x
                     WHERE x.name_lc = c.label_lc AND x.object_guid <> c.object_guid
                     ORDER BY x.sam_account_name LIMIT 1) AS other_account
              FROM comp c
             WHERE NOT c.is_domain_controller
               AND c.dns_hostname IS NOT NULL AND c.dns_hostname <> ''
               AND c.label_lc <> c.name_lc
               -- sAMAccountName holds at most 15 characters of a longer host name
               AND NOT (length(c.name_lc) = 15 AND left(c.label_lc, 15) = c.name_lc)
               AND c.fqdn_lc NOT IN (SELECT fqdn_lc FROM dc_fqdn)
               AND c.fqdn_lc NOT IN (SELECT fqdn_lc FROM dup)
        )
        SELECT
            'warn' AS status,
            m.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN m.other_account IS NOT NULL THEN 'medium' ELSE 'low' END AS fd_severity,
            'Computer "' || m.sam_account_name || '" has dNSHostName "' || m.dns_hostname || '"'
                || CASE WHEN m.other_account IS NOT NULL
                        THEN ', the name of another computer account (' || m.other_account || ')'
                        ELSE ', which does not match its account name' END
                || CASE WHEN COALESCE(m.is_enabled, true) THEN '' ELSE ' (account disabled)' END AS summary,
            jsonb_build_object(
                'sam_account_name', m.sam_account_name,
                'dns_hostname', m.dns_hostname,
                'distinguished_name', m.dn_current,
                'enabled', m.is_enabled,
                'host_label_is_other_computer', m.other_account,
                'related_plugins', jsonb_build_array(2036, 4009, 6015)
            ) AS detail
        FROM mism m
    """,
}
