"""
Plugin 10093: Directory Synchronization Stale

Reads /organization (entra_tenant_setting 'organization', source
organization). When onPremisesSyncEnabled is true, the last successful
directory synchronization (onPremisesLastSyncDateTime) should be no older
than the sync cycle (30 minutes by default for Entra Connect, about 2
minutes for Cloud Sync):

- older than 3 hours -> medium;
- older than 24 hours -> high;
- sync enabled but no last-sync time reported -> medium.
Age is measured against the Entra collection time
(entra_tenant_setting.collected_at), not the time this plugin runs, so the
result does not drift between collections. The summary names only the
threshold crossed; the exact time is in detail.

Why: if synchronization has stopped (server down, scheduler disabled,
connector credential expired, staging mode left on), every on-premises
disable, password change and group removal stops reaching the cloud.
Leavers keep cloud access (plugin 10092) and incident-response
containment done on-premises silently does not apply in Entra ID.

Not reported: tenants without directory synchronization
(onPremisesSyncEnabled false or null). Tenant-level finding: object_guid
md5('10093:' || client_id). Requires source organization.
"""

PLUGIN = {
    "plugin_id": 10093,
    "category": "Hybrid Identity",
    "name": "Directory Synchronization Stale",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10093",
    "requires_sources": ["organization"],
    "framework_tags": [
        "NIST-800-53-AC-2",
        "NIST-800-53-AC-2(3)",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.AA-01",
        "CIS-CSC-8-5.3",
        "ISO-27001-2022-A.5.18",
        "SOC2-CC6.2",
    ],
    "references": [
        {"title": "Microsoft: Microsoft Entra Connect Sync: Scheduler",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-feature-scheduler"},
        {"title": "Microsoft: Monitor Microsoft Entra Connect Sync with Microsoft Entra Connect Health",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-health-sync"},
        {"title": "Microsoft Graph: organization resource type (onPremisesLastSyncDateTime)",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/organization"},
    ],
    "description": (
        "Directory synchronization is enabled for the tenant but the last "
        "successful sync is more than 3 hours (medium) or 24 hours (high) "
        "older than the Entra collection, or no sync time is reported "
        "(medium). On-premises disables, password changes and group "
        "removals are not reaching the cloud."
    ),
    "remediation": (
        "On the Entra Connect server: Get-ADSyncScheduler (SyncCycleEnabled "
        "must be True, StagingModeEnabled False), check the "
        "Synchronization Service Manager for failed runs and connector "
        "errors, and Entra Connect Health alerts; for Cloud Sync, check "
        "the provisioning agent status and the configuration's "
        "quarantine state in the Entra admin center. Restart with "
        "Start-ADSyncSyncCycle -PolicyType Delta once fixed, and set up "
        "alerting (Connect Health) so a stopped sync is noticed."
    ),
    "base_severity": "medium",
    "query": """
        WITH org AS (
            SELECT ts.client_id, ts.collected_at, ts.content,
                   CASE WHEN ts.content ->> 'onPremisesLastSyncDateTime' ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}'
                        THEN (ts.content ->> 'onPremisesLastSyncDateTime')::timestamptz END AS last_sync
              FROM entra_tenant_setting ts
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'organization'
               AND jsonb_typeof(ts.content) = 'object'
               AND ts.content ->> 'onPremisesSyncEnabled' = 'true'
               AND EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = ts.client_id
                              AND s.source = 'organization' AND s.status = 'ok')
        ),
        judged AS (
            SELECT o.*,
                   CASE WHEN o.last_sync IS NULL THEN 'none'
                        WHEN o.last_sync < o.collected_at - interval '24 hours' THEN 'over_24h'
                        WHEN o.last_sync < o.collected_at - interval '3 hours' THEN 'over_3h'
                   END AS state
              FROM org o
        )
        SELECT
            'fail' AS status,
            md5('10093:' || j.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE j.state WHEN 'over_24h' THEN 'high' ELSE 'medium' END AS fd_severity,
            CASE j.state
                WHEN 'none' THEN 'Directory synchronization is enabled but the tenant reports no last synchronization time'
                WHEN 'over_24h' THEN 'Directory synchronization is stale: last successful sync more than 24 hours before the Entra collection'
                ELSE 'Directory synchronization is stale: last successful sync more than 3 hours before the Entra collection'
            END AS summary,
            jsonb_build_object(
                'on_premises_sync_enabled', j.content -> 'onPremisesSyncEnabled',
                'on_premises_last_sync_date_time', j.content -> 'onPremisesLastSyncDateTime',
                'entra_collected_at', j.collected_at,
                'hours_since_last_sync',
                    CASE WHEN j.last_sync IS NULL THEN NULL
                         ELSE round((extract(epoch FROM j.collected_at - j.last_sync) / 3600)::numeric, 1) END,
                'thresholds', jsonb_build_object('medium_hours', 3, 'high_hours', 24),
                'related_plugins', jsonb_build_array(10092)
            ) AS detail
        FROM judged j
        WHERE j.state IS NOT NULL
    """,
}
