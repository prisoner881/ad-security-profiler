"""
Plugin 2035: Computer Account Name Without a Trailing "$" (noPac)

Detects computer accounts whose sAMAccountName does not end in "$".
Windows creates every machine account name with a trailing "$"; one
without it has been renamed by someone who could write the attribute.

Why it matters: CVE-2021-42278 (sAMAccountName spoofing) and
CVE-2021-42287 (KDC PAC confusion), together "noPac", let any user able
to create or modify a computer account (the default
MachineAccountQuota of 10 is enough) rename it to a domain controller's
name minus the "$", request a TGT, rename it back and then obtain a
service ticket as the domain controller -- full domain compromise from
a standard user. KB5008102 / KB5008380 block it on patched DCs; a
computer account still named like a DC is an attack in progress or
left behind, and any "$"-less machine account is the precondition the
attack needs. Both CVEs are in CISA's Known Exploited Vulnerabilities
catalog.

Severity: critical when the name equals (case-insensitive) some domain
controller's sAMAccountName with its trailing "$" removed; high
otherwise. Disabled accounts are reported with the same severity: the
renamed account is an integrity anomaly / attack indicator whether or
not it can currently authenticate (detail.is_enabled says which).
Accounts with a NULL sAMAccountName (not collected) are skipped.
"""

PLUGIN = {
    "plugin_id": 2035,
    "category": "Computer Accounts",
    "name": "Computer Account Name Without a Trailing \"$\" (noPac)",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "VULN-2035",
    "framework_tags": [
        "CVE-2021-42278", "CVE-2021-42287", "MITRE-ATTCK-T1068", "MITRE-ATTCK-T1558",
        "NIST-800-53-SI-2", "NIST-800-53-RA-5", "NIST-CSF-2.0-ID.RA-01", "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-7.3", "ISO-27001-2022-A.8.8", "SOC2-CC7.1",
    ],
    "references": [
        {"title": "MSRC: CVE-2021-42278 Active Directory Domain Services Elevation of Privilege",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42278"},
        {"title": "MSRC: CVE-2021-42287 Active Directory Domain Services Elevation of Privilege",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-42287"},
        {"title": "NVD: CVE-2021-42278", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42278"},
        {"title": "NVD: CVE-2021-42287", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-42287"},
        {"title": "CISA Known Exploited Vulnerabilities Catalog",
         "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"},
    ],
    "description": (
        "Flags computer accounts whose sAMAccountName does not end in \"$\" -- the "
        "sAMAccountName-spoofing precondition of the noPac attack (CVE-2021-42278 / "
        "CVE-2021-42287), which turns any user who can create or rename a computer "
        "account into a domain admin on unpatched domain controllers. Critical when "
        "the name matches a domain controller's name without its \"$\" (the attack "
        "is in progress or was left behind), high otherwise."
    ),
    "remediation": (
        "Investigate who renamed the account (Security event 4742 / 4781 on the DCs, "
        "directory replication metadata: `repadmin /showobjmeta <DC> \"<computer DN>\"`). "
        "If it matches a DC name, treat it as an active noPac attempt: disable the "
        "account, start incident response, and check for tickets issued to it. "
        "Otherwise restore the name with `Set-ADComputer <name> -SamAccountName "
        "'<NAME>$'` or delete the stale account. Make sure every DC has the November "
        "2021 updates (KB5008102 / KB5008380) or later and is in enforcement mode, "
        "and set ms-DS-MachineAccountQuota to 0 so ordinary users cannot create "
        "computer accounts."
    ),
    "base_severity": "critical",
    "query": """
        WITH dc AS (
            SELECT c.object_guid, c.sam_account_name
            FROM ad_computer c
            JOIN directory_object d
              ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
            WHERE c.client_id = %(client_id)s
              AND c.valid_to IS NULL
              AND c.is_domain_controller
              AND c.sam_account_name LIKE '%%$'
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN m.dc_names IS NOT NULL THEN 'critical' ELSE 'high' END AS fd_severity,
            'Computer account ' || c.sam_account_name || ' has no trailing "$"'
                || CASE WHEN m.dc_names IS NOT NULL
                        THEN ' and impersonates domain controller ' || m.dc_names
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dn', d.dn_current,
                'dns_hostname', c.dns_hostname,
                'is_enabled', c.is_enabled,
                'when_created', c.when_created,
                'impersonated_domain_controllers', m.dc_names
            ) AS detail
        FROM ad_computer c
        JOIN directory_object d
          ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
        LEFT JOIN LATERAL (
            SELECT string_agg(dc.sam_account_name, ', ' ORDER BY dc.sam_account_name) AS dc_names
            FROM dc
            WHERE dc.object_guid <> c.object_guid
              AND lower(left(dc.sam_account_name, -1)) = lower(c.sam_account_name)
        ) m ON true
        WHERE c.client_id = %(client_id)s
          AND c.valid_to IS NULL
          AND c.sam_account_name IS NOT NULL
          AND c.sam_account_name NOT LIKE '%%$'
        ORDER BY c.object_guid
    """,
}
