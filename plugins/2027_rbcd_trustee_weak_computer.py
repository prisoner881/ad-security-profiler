"""
Plugin 2027: RBCD Trustee Computer Is Itself Unsupported or Dormant

Complements plugin 1031 (a human user account as an RBCD trustee) with
the computer-side equivalent: an RBCD trustee computer that is itself
running an unsupported OS or is dormant is a weak link in the delegation
chain. RBCD grants that trustee the ability to impersonate arbitrary
domain users to the resource computer -- if the trustee itself is easy
to compromise (old, unpatched, or unmonitored), that's a direct,
low-effort route to that impersonation capability.

[v1.4] Emits one finding per trustee computer rather than one per RBCD
edge. The finding is keyed on the trustee's GUID, so a trustee with
RBCD on several resource computers produced several rows with the same
object_guid and broke the one-open-version-per-identity constraint. The
resources are now listed (sorted by name) in the summary and in
detail.resource_computers, which replaces the single-valued
detail.resource_computer.
"""

PLUGIN = {
    "plugin_id": 2027,
    "category": "Computer Accounts",
    "name": "RBCD Trustee Computer Is Itself Unsupported or Dormant",
    "version": "1.4",
    "revision_date": "2026-10-03",
    "remediation": (
        "Prioritize over an ordinary RBCD finding (plugin 2022) -- this "
        "specific trustee is an easier-than-average target due to its "
        "own independent weakness. Patch/upgrade or replace the trustee "
        "machine, or if dormant, investigate whether the RBCD "
        "relationship itself is still needed and remove it if not."
    ),
    "control_id": "CHAIN-205",
    "framework_tags": ["MITRE-ATTCK-T1134", "CISA-AA26-237A", "MITRE-ATTCK-T1098"],
    "references": [
        {"title": "MITRE ATT&CK T1134: Access Token Manipulation",
         "url": "https://attack.mitre.org/techniques/T1134/"},
    ],
    "description": (
        "Complements plugin 1031 (weak user as RBCD trustee) with the "
        "computer-side case: this RBCD trustee (plugin 2022) is itself "
        "running an unsupported operating system (plugin 2003) or is "
        "dormant (plugin 2006). RBCD grants the trustee the ability to "
        "impersonate arbitrary domain users to the resource computer; an "
        "easy-to-compromise trustee is a direct, low-effort route into "
        "that impersonation capability."
    ),
    "base_severity": "high",
    "query": """
        -- [v1.4] One row per trustee computer. The finding is keyed on the
        -- trustee's GUID, so a trustee holding RBCD on several resource
        -- computers used to emit one row per resource with the same
        -- object_guid and collide on idx_cef_one_open_version. Resources are
        -- now aggregated (sorted by name) into the summary and detail.
        WITH trustee_resources AS (
            SELECT de.source_guid,
                   count(*) AS resource_count,
                   string_agg(resource.sam_account_name, ', '
                              ORDER BY resource.sam_account_name, resource.object_guid)
                       AS resource_list,
                   jsonb_agg(resource.sam_account_name
                             ORDER BY resource.sam_account_name, resource.object_guid)
                       AS resource_names
            FROM delegation_edge de
            JOIN ad_computer resource
                ON resource.object_guid = de.target_guid
               AND resource.client_id = de.client_id
               AND resource.valid_to IS NULL
            WHERE de.client_id = %(client_id)s
              AND de.valid_to IS NULL
              AND de.delegation_type = 'rbcd'
            GROUP BY de.source_guid
        )
        SELECT
            'warn' AS status,
            trustee.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'RBCD trustee computer ' || trustee.sam_account_name
                || ' (trusted to impersonate arbitrary domain users to '
                || CASE WHEN tr.resource_count > 1
                        THEN tr.resource_count || ' resource computers: '
                        ELSE '' END
                || tr.resource_list || ') is '
                || (SELECT string_agg(x, ', ') FROM (VALUES
                        (CASE WHEN trustee.operating_system ILIKE '%%windows 10%%' OR trustee.operating_system ILIKE '%%server 2012%%'
                              OR trustee.operating_system ILIKE '%%server 2008%%' OR trustee.operating_system ILIKE '%%server 2003%%'
                              OR trustee.operating_system ILIKE '%%windows 7%%' OR trustee.operating_system ILIKE '%%windows 8%%'
                              OR trustee.operating_system ILIKE '%%windows xp%%' OR trustee.operating_system ILIKE '%%windows vista%%'
                              THEN 'running an unsupported OS (' || trustee.operating_system || ')' END),
                        (CASE WHEN trustee.last_logon_timestamp IS NULL OR trustee.last_logon_timestamp < now() - interval '90 days'
                              THEN 'dormant' END)
                    ) AS v(x) WHERE x IS NOT NULL) AS summary,
            jsonb_build_object(
                'trustee_sam_account_name', trustee.sam_account_name,
                'resource_count', tr.resource_count,
                'resource_computers', tr.resource_names,
                'operating_system', trustee.operating_system,
                'last_logon_timestamp', trustee.last_logon_timestamp
            ) AS detail
        FROM trustee_resources tr
        JOIN ad_computer trustee
            ON trustee.object_guid = tr.source_guid
           AND trustee.client_id = %(client_id)s
           AND trustee.valid_to IS NULL
        WHERE (
                trustee.operating_system ILIKE '%%windows 10%%' OR trustee.operating_system ILIKE '%%server 2012%%'
                OR trustee.operating_system ILIKE '%%server 2008%%' OR trustee.operating_system ILIKE '%%server 2003%%'
                OR trustee.operating_system ILIKE '%%windows 7%%' OR trustee.operating_system ILIKE '%%windows 8%%'
                OR trustee.operating_system ILIKE '%%windows xp%%' OR trustee.operating_system ILIKE '%%windows vista%%'
                OR trustee.last_logon_timestamp IS NULL OR trustee.last_logon_timestamp < now() - interval '90 days'
              )
    """,
}
