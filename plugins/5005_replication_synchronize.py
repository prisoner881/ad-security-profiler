"""
Plugin 5005: Replication Synchronization Rights Held by an Unexpected Principal

DS-Replication-Synchronize (1131f6ab-9c07-11d1-f79f-00c04fc2dcd2),
confirmed directly against Microsoft's own Win32 AD schema
documentation: "Extended right needed to synchronize replication from a
given NC." Lower severity than plugins 5001/5004 deliberately -- this
mostly grants the ability to manually trigger/force a replication sync,
a real but comparatively limited capability on its own. Still worth
knowing about: an unexpected holder of ANY replication-family right is
worth a second look collectively, even if this specific one isn't
independently as dangerous as DCSync or topology management.

Uses the same well-known-holder exclusion list as plugins 5001/5004.
"""

PLUGIN = {
    "plugin_id": 5005,
    "category": "ACLs",
    "name": "Replication Synchronization Rights Held by an Unexpected Principal",
    "version": "1.1",
    "revision_date": "2026-07-17",
    "remediation": (
        "Confirm this grant was deliberate. Lower urgency than plugins "
        "5001/5004 -- this right mostly enables manually triggering a "
        "replication sync, not independently extracting secrets or "
        "manipulating topology -- but any unexpected holder of a "
        "replication-family right is worth a second look, and removing "
        "unneeded standing access is good practice regardless of "
        "severity."
    ),
    "control_id": "ACL-005",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: DS-Replication-Synchronize extended right",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-synchronize"},
    ],
    "description": (
        "DS-Replication-Synchronize, confirmed directly against "
        "Microsoft's own Win32 AD schema documentation: \"Extended right "
        "needed to synchronize replication from a given NC.\" Lower "
        "severity than plugins 5001/5004 deliberately -- this mostly "
        "grants the ability to manually trigger a replication sync, a "
        "real but comparatively limited capability standing alone. "
        "Still worth surfacing: an unexpected holder of any "
        "replication-family right is worth reviewing collectively, even "
        "when this specific one isn't independently as dangerous as "
        "DCSync or topology management."
    ),
    "base_severity": "low",
    "query": """
        WITH expected_holders AS (
            SELECT do2.object_guid
            FROM directory_object do2
            WHERE do2.client_id = %(client_id)s
              AND (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-519'
                   OR do2.object_sid LIKE '%%-544' OR do2.object_sid LIKE '%%-498'
                   OR do2.object_sid = 'S-1-5-9')
            UNION
            SELECT c.object_guid
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
              AND c.is_domain_controller
        )
        SELECT
            'warn' AS status,
            do2.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Principal ' || COALESCE(do2.sam_account_name, a.trustee_sid)
                || ' holds DS-Replication-Synchronize on the domain root and is not a '
                'recognized default holder' AS summary,
            jsonb_build_object('trustee_sid', a.trustee_sid, 'sam_account_name', do2.sam_account_name, 'object_class', do2.object_class) AS detail
        FROM acl_edge a
        JOIN ad_domain d ON d.object_guid = a.object_guid AND d.valid_to IS NULL
        JOIN directory_object do2 ON do2.object_sid = a.trustee_sid AND do2.client_id = %(client_id)s
        WHERE a.client_id = %(client_id)s
          AND a.valid_to IS NULL
          AND a.ace_type = 'allow'
          AND a.object_type_guid = '1131f6ab-9c07-11d1-f79f-00c04fc2dcd2'
          AND NOT EXISTS (SELECT 1 FROM expected_holders eh WHERE eh.object_guid = do2.object_guid)
    """,
}
