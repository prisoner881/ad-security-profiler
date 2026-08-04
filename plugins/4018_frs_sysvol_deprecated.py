"""
Plugin 4018: SYSVOL Still Replicated via Deprecated FRS, Not DFSR

Confirmed as a genuine gap via a real Purple Knight (Semperis) sample
report's AD Infrastructure Security category, and confirmed the exact
detection mechanism against multiple independent Microsoft/community
sources before building: msDFSR-Flags on
CN=DFSR-GlobalSettings,CN=System,<domain> reads 48 once a domain has
fully completed migration to DFS Replication (FRS retired); any other
value (including the object not existing at all, meaning migration was
never attempted) means SYSVOL is still relying on File Replication
Service, which Microsoft has deprecated for over a decade and which
lacks DFSR's replication integrity and diagnostic improvements.

Collected as a single, targeted read (adprofiler.py v0.5.4), the same
pattern already used for AdminSDHolder and NTAuthCertificates -- one
well-known object, not part of bulk collection.
"""

PLUGIN = {
    "plugin_id": 4018,
    "category": "Domain",
    "name": "SYSVOL Still Replicated via Deprecated FRS, Not DFSR",
    "version": "1.0",
    "revision_date": "2026-07-31",
    "remediation": (
        "Migrate SYSVOL replication from FRS to DFS Replication using "
        "`dfsrmig /CreateGlobalObjects`, followed by `dfsrmig "
        "/SetGlobalState 1` (Prepared), then `2` (Redirected), then `3` "
        "(Eliminated) -- confirming domain-wide replication health with "
        "`dfsrmig /GetMigrationState` between each stage. Microsoft has "
        "deprecated FRS for SYSVOL for years; DFSR provides better "
        "replication integrity checking and is required for continued "
        "support on newer Windows Server versions."
    ),
    "control_id": "DOM-418",
    "framework_tags": [],
    "references": [
        {"title": "Semperis Purple Knight -- Indicators of Exposure",
         "url": "https://www.semperis.com/purple-knight/"},
        {"title": "Microsoft: DFSR migration tool (dfsrmig)",
         "url": "https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr"},
    ],
    "description": (
        "SYSVOL is still (fully or partially) replicated via the "
        "deprecated File Replication Service rather than DFS "
        "Replication, per msDFSR-Flags on the domain's own "
        "DFSR-GlobalSettings object (48 = fully migrated; any other "
        "value, including the object being entirely absent, means FRS "
        "is still involved)."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain ' || d.dns_root || ' has not completed SYSVOL migration to DFSR ('
                || CASE
                     WHEN d.dfsr_migration_flags IS NULL THEN 'DFSR-GlobalSettings not found -- migration never attempted'
                     ELSE 'msDFSR-Flags=' || d.dfsr_migration_flags || ', expected 48'
                   END || ')' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'dfsr_migration_flags', d.dfsr_migration_flags
            ) AS detail
        FROM ad_domain d
        WHERE d.client_id = %(client_id)s
          AND d.valid_to IS NULL
          AND COALESCE(d.dfsr_migration_flags, 0) != 48
    """,
}
