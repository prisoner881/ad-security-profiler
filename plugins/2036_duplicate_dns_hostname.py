"""
Plugin 2036: Duplicate or Domain-Controller-Spoofing dNSHostName (Certifried)

Detects non-DC computer accounts whose dNSHostName (compared
case-insensitively) equals a domain controller's, and non-DC computer
accounts that share a dNSHostName with another non-DC computer.

Why it matters: CVE-2022-26923 ("Certifried"). AD CS's default Machine
template builds the certificate subject from the requesting computer's
dNSHostName, and before the May 2022 updates (KB5014754) certificate
mapping trusted that name. Any user who could create a computer account
(MachineAccountQuota) or write dNSHostName on one could set it to a
DC's FQDN, enroll, and authenticate as the domain controller with
PKINIT -- then DCSync. A non-DC carrying a DC's FQDN is therefore an
attack in progress or left behind (critical). Two ordinary computers
with the same dNSHostName are not an exploit by themselves, but are the
same anomaly (one of them was edited, or a stale duplicate exists) and
make certificate- and Kerberos-name-based trust ambiguous (medium).
CVE-2022-26923 is in CISA's Known Exploited Vulnerabilities catalog.

One row per offending non-DC computer; domain controllers themselves
are never reported. NULL/empty dNSHostName is ignored. Disabled
accounts are reported with the same severity (the edited attribute is
the anomaly); detail.is_enabled says which.
"""

PLUGIN = {
    "plugin_id": 2036,
    "category": "Computer Accounts",
    "name": "Duplicate or Domain-Controller-Spoofing dNSHostName (Certifried)",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "VULN-2036",
    "framework_tags": [
        "CVE-2022-26923", "MITRE-ATTCK-T1649", "MITRE-ATTCK-T1068",
        "NIST-800-53-SI-2", "NIST-800-53-RA-5", "NIST-CSF-2.0-ID.RA-01", "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-7.3", "ISO-27001-2022-A.8.8", "SOC2-CC7.1",
    ],
    "references": [
        {"title": "MSRC: CVE-2022-26923 Active Directory Domain Services Elevation of Privilege",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-26923"},
        {"title": "NVD: CVE-2022-26923", "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-26923"},
        {"title": "CISA Known Exploited Vulnerabilities Catalog",
         "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
        {"title": "MITRE ATT&CK T1649: Steal or Forge Authentication Certificates",
         "url": "https://attack.mitre.org/techniques/T1649/"},
    ],
    "description": (
        "Flags non-DC computer accounts whose dNSHostName equals a domain "
        "controller's (critical: the Certifried / CVE-2022-26923 pattern for "
        "obtaining a certificate that authenticates as the DC) and non-DC computers "
        "sharing a dNSHostName with another non-DC computer (medium: duplicate "
        "names make name-based certificate and Kerberos trust ambiguous)."
    ),
    "remediation": (
        "For a computer carrying a DC's FQDN: treat it as a possible attack -- "
        "disable the account, find who changed dNSHostName (Security event 4742, "
        "`repadmin /showobjmeta`), and revoke any certificate issued to it on the "
        "CA (`certutil -view` filtered on the requester, then `certutil -revoke`). "
        "For duplicates between ordinary computers: correct the wrong value "
        "(`Set-ADComputer <name> -DNSHostName <fqdn>`) or remove the stale account. "
        "Make sure every DC and CA has the May 2022 updates (KB5014754) and that "
        "strong certificate mapping is in Full Enforcement mode; set "
        "ms-DS-MachineAccountQuota to 0."
    ),
    "base_severity": "critical",
    "query": """
        WITH comp AS (
            SELECT c.object_guid, c.sam_account_name, c.dns_hostname, c.is_enabled,
                   c.is_domain_controller, lower(c.dns_hostname) AS host_lc
            FROM ad_computer c
            JOIN directory_object d
              ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
            WHERE c.client_id = %(client_id)s
              AND c.valid_to IS NULL
              AND NULLIF(btrim(c.dns_hostname), '') IS NOT NULL
        ),
        flagged AS (
            SELECT n.object_guid, n.sam_account_name, n.dns_hostname, n.is_enabled,
                   (SELECT string_agg(o.sam_account_name, ', ' ORDER BY o.sam_account_name)
                      FROM comp o
                     WHERE o.host_lc = n.host_lc AND o.is_domain_controller
                       AND o.object_guid <> n.object_guid) AS dc_names,
                   (SELECT string_agg(COALESCE(o.sam_account_name, o.object_guid::text), ', '
                                      ORDER BY COALESCE(o.sam_account_name, o.object_guid::text))
                      FROM comp o
                     WHERE o.host_lc = n.host_lc AND NOT o.is_domain_controller
                       AND o.object_guid <> n.object_guid) AS peer_names
            FROM comp n
            WHERE NOT n.is_domain_controller
        )
        SELECT
            CASE WHEN f.dc_names IS NOT NULL THEN 'fail' ELSE 'warn' END AS status,
            f.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN f.dc_names IS NOT NULL THEN 'critical' ELSE 'medium' END AS fd_severity,
            CASE WHEN f.dc_names IS NOT NULL
                 THEN 'Computer ' || COALESCE(f.sam_account_name, f.object_guid::text)
                      || ' has the dNSHostName of domain controller ' || f.dc_names
                      || ' (' || f.dns_hostname || ')'
                 ELSE 'Computer ' || COALESCE(f.sam_account_name, f.object_guid::text)
                      || ' shares dNSHostName ' || f.dns_hostname || ' with ' || f.peer_names
            END AS summary,
            jsonb_build_object(
                'sam_account_name', f.sam_account_name,
                'dns_hostname', f.dns_hostname,
                'is_enabled', f.is_enabled,
                'matching_domain_controllers', f.dc_names,
                'other_computers_with_same_name', f.peer_names
            ) AS detail
        FROM flagged f
        WHERE f.dc_names IS NOT NULL OR f.peer_names IS NOT NULL
        ORDER BY f.object_guid
    """,
}
