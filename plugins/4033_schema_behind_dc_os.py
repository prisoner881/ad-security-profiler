"""
Plugin 4033: Schema Version Behind the Newest Domain Controller OS

Compares the forest schema version (objectVersion on CN=Schema,<config>) with
the version the newest domain controller operating system in the domain
requires:

    Windows Server 2025      91
    Windows Server 2022      88
    Windows Server 2019      88
    Windows Server 2016      87
    Windows Server 2012 R2   69
    Windows Server 2012      56

A domain controller can only be promoted after adprep /forestprep has
raised the schema to its version, so a lower schema value means the schema
was rolled back / restored, the DC's operatingSystem attribute is wrong, or
- most often - adprep ran only partly (an interrupted forestprep or a failed
replication of the schema partition). Security features that depend on the
new schema classes and attributes are then unavailable or half-present:
delegated MSAs (dMSA) and the 2025 AD security hardening, authentication
policy claims, the Windows LAPS and KDS updates. The forest/domain update
revisions (revision on CN=ActiveDirectoryUpdate under ForestUpdates and
DomainUpdates) are reported in detail to help diagnose an incomplete
forestprep/domainprep. Microsoft and Purple Knight both flag a mismatch.

Data: ad_domain.schema_object_version (schema v38); NULL (not read / pre-v38
row) -> no finding. DCs are current, non-deleted ad_computer rows with
is_domain_controller; a DC whose operating_system matches none of the
versions above does not set a requirement. Only DCs of the collected domain
are seen, though the schema is forest-wide.
"""

PLUGIN = {
    "plugin_id": 4033,
    "category": "Domain",
    "name": "Schema Version Behind the Newest Domain Controller OS",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "DOM-4033",
    "framework_tags": [
        "NIST-800-53-SI-2", "NIST-800-53-RA-5", "NIST-CSF-2.0-ID.RA-01",
        "PCI-DSS-4.0-6.3.3", "CIS-CSC-8-7.3", "ISO-27001-2022-A.8.8",
        "SOC2-CC7.1", "NIST-800-53-CM-6",
    ],
    "references": [
        {"title": "CISA et al.: Detecting and Mitigating Active Directory Compromises",
         "url": "https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises"},
    ],
    "description": (
        "The forest schema objectVersion is lower than the newest domain "
        "controller's operating system requires (91 for Windows Server "
        "2025, 88 for 2019/2022, 87 for 2016, 69 for 2012 R2, 56 for 2012). "
        "This points to an incomplete or rolled-back adprep and leaves the "
        "schema-dependent security features of that OS unavailable or "
        "half-present. Forest/domain update revisions are given in detail."
    ),
    "remediation": (
        "Confirm the versions: (Get-ADObject (Get-ADRootDSE)."
        "schemaNamingContext -Property objectVersion).objectVersion and "
        "the revision attribute of CN=ActiveDirectoryUpdate,CN=ForestUpdates,"
        "CN=Configuration,<forest> and CN=ActiveDirectoryUpdate,"
        "CN=DomainUpdates,CN=System,<domain>. Check schema replication "
        "(repadmin /showrepl, repadmin /replsummary). Then, as a Schema and "
        "Enterprise Admin on the schema master, run adprep /forestprep from "
        "the newest OS's media and adprep /domainprep in every domain (or "
        "promote a DC of that OS with Install-ADDSDomainController, which "
        "runs them automatically), and review adprep logs under "
        "%SystemRoot%\\debug\\adprep\\logs. If a DC reports a newer OS than "
        "the schema supports, also verify the computer object is a real DC."
    ),
    "base_severity": "low",
    "query": """
        WITH dc AS (
            SELECT c.sam_account_name, c.dns_hostname, c.operating_system,
                   CASE
                       WHEN c.operating_system ILIKE '%%2025%%' THEN 91
                       WHEN c.operating_system ILIKE '%%2022%%' THEN 88
                       WHEN c.operating_system ILIKE '%%2019%%' THEN 88
                       WHEN c.operating_system ILIKE '%%2016%%' THEN 87
                       WHEN c.operating_system ILIKE '%%2012 R2%%' THEN 69
                       WHEN c.operating_system ILIKE '%%2012%%' THEN 56
                   END AS required_version
            FROM ad_computer c
            JOIN directory_object o
              ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
            WHERE c.client_id = %(client_id)s
              AND c.valid_to IS NULL
              AND c.is_domain_controller
        ),
        req AS (
            SELECT max(required_version) AS required_version,
                   jsonb_agg(jsonb_build_object(
                       'dc', COALESCE(dns_hostname, sam_account_name),
                       'operating_system', operating_system,
                       'requires_schema_version', required_version
                   ) ORDER BY COALESCE(dns_hostname, sam_account_name)) AS dcs
            FROM dc
            WHERE required_version IS NOT NULL
        ),
        newest AS (
            SELECT string_agg(DISTINCT operating_system, ', ' ORDER BY operating_system) AS os_names
            FROM dc
            WHERE required_version = (SELECT required_version FROM req)
        )
        SELECT
            'fail' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Schema version ' || d.schema_object_version || ' of domain '
                || COALESCE(d.dns_root, o.dn_current)
                || ' is behind the newest domain controller OS ('
                || COALESCE(n.os_names, 'unknown') || ', requires '
                || r.required_version || '): adprep appears incomplete' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'schema_object_version', d.schema_object_version,
                'required_schema_version', r.required_version,
                'newest_dc_operating_system', n.os_names,
                'forest_updates_revision', d.forest_updates_revision,
                'domain_updates_revision', d.domain_updates_revision,
                'domain_controllers', r.dcs
            ) AS detail
        FROM ad_domain d
        JOIN directory_object o
          ON o.object_guid = d.object_guid AND o.client_id = d.client_id AND NOT o.is_deleted
        CROSS JOIN req r
        CROSS JOIN newest n
        WHERE d.client_id = %(client_id)s
          AND d.valid_to IS NULL
          AND d.schema_object_version IS NOT NULL
          AND r.required_version IS NOT NULL
          AND d.schema_object_version < r.required_version
    """,
}
