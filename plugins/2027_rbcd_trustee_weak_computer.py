"""
Plugin 2027: RBCD Trustee Computer Is Itself Unsupported or Dormant

Complements plugin 1031 (a human user account as an RBCD trustee) with
the computer-side equivalent: an RBCD trustee computer that is itself
running an unsupported OS or is dormant is a weak link in the delegation
chain. RBCD grants that trustee the ability to impersonate arbitrary
domain users to the resource computer -- if the trustee itself is easy
to compromise (old, unpatched, or unmonitored), that's a direct,
low-effort route to that impersonation capability.
"""

PLUGIN = {
    "plugin_id": 2027,
    "category": "Computer Accounts",
    "name": "RBCD Trustee Computer Is Itself Unsupported or Dormant",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Prioritize over an ordinary RBCD finding (plugin 2022) -- this "
        "specific trustee is an easier-than-average target due to its "
        "own independent weakness. Patch/upgrade or replace the trustee "
        "machine, or if dormant, investigate whether the RBCD "
        "relationship itself is still needed and remove it if not."
    ),
    "control_id": "CHAIN-205",
    "framework_tags": ["MITRE-ATTCK-T1134"],
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
        SELECT
            'warn' AS status,
            trustee.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'RBCD trustee computer ' || trustee.sam_account_name
                || ' (trusted to impersonate arbitrary domain users to ' || resource.sam_account_name || ') is '
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
                'resource_computer', resource.sam_account_name,
                'operating_system', trustee.operating_system,
                'last_logon_timestamp', trustee.last_logon_timestamp
            ) AS detail
        FROM delegation_edge de
        JOIN ad_computer trustee ON trustee.object_guid = de.source_guid AND trustee.valid_to IS NULL
        JOIN ad_computer resource ON resource.object_guid = de.target_guid AND resource.valid_to IS NULL
        WHERE de.client_id = %(client_id)s
          AND de.valid_to IS NULL
          AND de.delegation_type = 'rbcd'
          AND (
                trustee.operating_system ILIKE '%%windows 10%%' OR trustee.operating_system ILIKE '%%server 2012%%'
                OR trustee.operating_system ILIKE '%%server 2008%%' OR trustee.operating_system ILIKE '%%server 2003%%'
                OR trustee.operating_system ILIKE '%%windows 7%%' OR trustee.operating_system ILIKE '%%windows 8%%'
                OR trustee.operating_system ILIKE '%%windows xp%%' OR trustee.operating_system ILIKE '%%windows vista%%'
                OR trustee.last_logon_timestamp IS NULL OR trustee.last_logon_timestamp < now() - interval '90 days'
              )
    """,
}
