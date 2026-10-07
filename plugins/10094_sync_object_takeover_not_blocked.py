"""
Plugin 10094: Cloud Object Takeover Through Hard or Soft Match Not Blocked

Reads directory/onPremisesSynchronization (entra_tenant_setting
'onprem_sync', source onprem_sync, beta) and reports the two sync
"matching" protections that are off:

- features.blockCloudObjectTakeoverThroughHardMatchEnabled false -> high.
  An on-premises object whose sourceAnchor (ms-DS-ConsistencyGuid /
  objectGUID) is set to a cloud user's onPremisesImmutableId takes that
  cloud user over at the next sync -- including a cloud-only
  administrator whose immutable ID was ever set.
- features.blockSoftMatchEnabled false -> medium. Sync joins an
  on-premises user to an existing cloud-only user whose UPN or primary
  SMTP address matches, after which the on-premises side controls the
  account (and, with password hash sync, its password).
Microsoft blocks soft and hard match onto accounts holding admin roles,
but not onto other valuable accounts (application owners, members of
role-assignable or Conditional Access exclusion groups). Anyone with
write access to user objects in a synced OU can attempt this ("SyncJacking",
Semperis 2022-23; MITRE T1556.007).

When /organization was read (source organization 'ok') and the tenant
does not synchronize (onPremisesSyncEnabled false or null), the exposure exists
only once sync is switched on, so the finding is lowered to low ('warn').
A key Graph did not return (null) is skipped, not guessed.

Tenant-level finding: object_guid md5('10094:' || client_id), every issue
listed. Requires source onprem_sync.
"""

PLUGIN = {
    "plugin_id": 10094,
    "category": "Hybrid Identity",
    "name": "Cloud Object Takeover Through Hard or Soft Match Not Blocked",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10094",
    "requires_sources": ["onprem_sync"],
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-IA-2",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.PS-01",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1556.007",
        "MITRE-ATTCK-T1098",
    ],
    "references": [
        {"title": "Microsoft: Microsoft Entra Connect: When you have an existing tenant (hard and soft match)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-existing-tenant"},
        {"title": "Microsoft Graph: onPremisesDirectorySynchronizationFeature resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/onpremisesdirectorysynchronizationfeature"},
        {"title": "MITRE ATT&CK T1556.007 Modify Authentication Process: Hybrid Identity",
         "url": "https://attack.mitre.org/techniques/T1556/007/"},
    ],
    "description": (
        "Directory synchronization may take over existing cloud accounts: "
        "hard-match takeover is not blocked (high) and/or soft match by "
        "UPN or SMTP address is enabled (medium). Someone able to create "
        "or edit users in a synced OU can then attach an on-premises "
        "object to a valuable cloud-only account and control its password "
        "(SyncJacking, MITRE T1556.007). Low when the tenant does not "
        "currently synchronize."
    ),
    "remediation": (
        "Microsoft Graph PowerShell (beta): $s = Get-MgBetaDirectoryOnPremiseSynchronization; "
        "Update-MgBetaDirectoryOnPremiseSynchronization "
        "-OnPremisesDirectorySynchronizationId $s.Id -Features "
        "@{BlockCloudObjectTakeoverThroughHardMatchEnabled=$true; "
        "BlockSoftMatchEnabled=$true}. Turn soft match back on only for "
        "a planned migration window. Also restrict who can write "
        "ms-DS-ConsistencyGuid, userPrincipalName and proxyAddresses on "
        "synced users on-premises."
    ),
    "base_severity": "high",
    "query": """
        WITH st AS (
            SELECT ts.client_id, ts.content -> 'features' AS f
              FROM entra_tenant_setting ts
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'onprem_sync'
               AND jsonb_typeof(ts.content -> 'features') = 'object'
               AND EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = ts.client_id
                              AND s.source = 'onprem_sync' AND s.status = 'ok')
        ),
        org AS (
            SELECT COALESCE((o.content ->> 'onPremisesSyncEnabled') = 'true', FALSE) AS syncing
              FROM entra_tenant_setting o
             WHERE o.client_id = %(client_id)s
               AND o.setting_name = 'organization'
               AND jsonb_typeof(o.content) = 'object'
               AND EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = o.client_id
                              AND s.source = 'organization' AND s.status = 'ok')
        ),
        issue AS (
            SELECT st.client_id, 3 AS rank,
                   'cloud object takeover through hard match is not blocked' AS issue
              FROM st WHERE st.f ->> 'blockCloudObjectTakeoverThroughHardMatchEnabled' = 'false'
            UNION ALL
            SELECT st.client_id, 2, 'soft match (UPN / SMTP address) is not blocked'
              FROM st WHERE st.f ->> 'blockSoftMatchEnabled' = 'false'
        ),
        agg AS (
            SELECT i.client_id, max(i.rank) AS rank,
                   string_agg(i.issue, '; ' ORDER BY i.rank DESC) AS summary_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC) AS issues
              FROM issue i
             GROUP BY i.client_id
        ),
        ctx AS (
            SELECT (SELECT syncing FROM org) AS syncing
        )
        SELECT
            CASE WHEN c.syncing IS FALSE THEN 'warn' ELSE 'fail' END AS status,
            md5('10094:' || a.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.syncing IS FALSE THEN 'low'
                 WHEN a.rank = 3 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Directory synchronization can take over existing cloud accounts: ' || a.summary_text
                || CASE WHEN c.syncing IS FALSE THEN ' (tenant does not currently synchronize)' ELSE '' END
                AS summary,
            jsonb_build_object(
                'issues', a.issues,
                'block_cloud_object_takeover_through_hard_match_enabled',
                    st.f -> 'blockCloudObjectTakeoverThroughHardMatchEnabled',
                'block_soft_match_enabled', st.f -> 'blockSoftMatchEnabled',
                'password_sync_enabled', st.f -> 'passwordSyncEnabled',
                'tenant_synchronizes', c.syncing
            ) AS detail
        FROM agg a
        JOIN st ON st.client_id = a.client_id
        CROSS JOIN ctx c
    """,
}
