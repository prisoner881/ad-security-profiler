"""
Plugin 4012: LAPS Schema Extension Not Present in This Forest

Already computed and logged on every single collection run ("LAPS
schema detected: none/legacy/modern"), but never stored -- discarded
after being printed. This is the forest-wide root cause explaining why
nearly every computer trips plugin 2004 (per-machine "no LAPS
configured"): if the schema extension was never installed anywhere in
this forest, no individual machine could ever have LAPS configured, no
matter how that per-machine finding reads.
"""

PLUGIN = {
    "plugin_id": 4012,
    "category": "Domain",
    "name": "LAPS Schema Extension Not Present in This Forest",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Install the LAPS schema extension for this forest -- Windows "
        "LAPS is built into Windows since the April 2023 updates and no "
        "longer requires a separate download, only running "
        "`Update-LapsADSchema` once (schema admin rights required) to "
        "extend the schema. After the schema extension is present, "
        "deploy the corresponding GPO to the OUs containing computers "
        "that need local admin password management -- see the "
        "per-machine findings under plugin 2004 for which computers "
        "specifically still need coverage once this is addressed."
    ),
    "control_id": "POLICY-012",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Windows LAPS overview",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview"},
    ],
    "description": (
        "Whether LAPS (legacy Microsoft LAPS or modern Windows LAPS) "
        "is present anywhere in this forest's schema at all -- already "
        "computed and logged on every collection run, but never stored "
        "until now. This is the forest-wide root cause explaining why "
        "nearly every computer in a forest without LAPS trips plugin "
        "2004 (the per-machine \"no LAPS configured\" check): if the "
        "schema extension itself was never installed, no individual "
        "machine could ever have LAPS configured, regardless of how "
        "many separate per-machine findings that produces. Worth fixing "
        "once at the forest level rather than reading it as hundreds of "
        "independent per-machine problems."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' forest has no LAPS schema extension present at all' AS summary,
            jsonb_build_object('dns_root', d.dns_root, 'laps_schema_present', d.laps_schema_present) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND NOT COALESCE(d.laps_schema_present, FALSE)
    """,
}
