"""
Plugin 5004: Replication Topology Management Rights Held by an Unexpected Principal

DS-Replication-Manage-Topology (1131f6ac-9c07-11d1-f79f-00c04fc2dcd2),
confirmed directly against Microsoft's own Win32 AD schema
documentation: "Extended right needed to update the replication
topology for a given NC." Distinct from DCSync (plugin 5001): this
doesn't grant the ability to pull secrets directly, but grants the
ability to modify WHICH DCs replicate with which other DCs -- a holder
could redirect, disrupt, or manipulate replication flow, a real
capability for interfering with or subverting the replication process
itself, independent of any single DCSync-style secret-extraction event.

Uses the same well-known-holder exclusion list as plugin 5001, since
this is also a replication-family right legitimately held by the same
DC-related principals by default.
"""

PLUGIN = {
    "plugin_id": 5004,
    "category": "ACLs",
    "name": "Replication Topology Management Rights Held by an Unexpected Principal",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Confirm this grant was deliberate and is still needed -- this "
        "right is not part of the core DCSync-enabling pair (plugin "
        "5001), but grants a real, distinct capability: modifying which "
        "domain controllers replicate with which other domain "
        "controllers. Remove the grant if not needed rather than "
        "leaving standing access broader than required."
    ),
    "control_id": "ACL-004",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: DS-Replication-Manage-Topology extended right",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-manage-topology"},
    ],
    "description": (
        "DS-Replication-Manage-Topology, confirmed directly against "
        "Microsoft's own Win32 AD schema documentation: \"Extended right "
        "needed to update the replication topology for a given NC.\" "
        "Distinct from DCSync (plugin 5001): doesn't grant the ability "
        "to pull secrets directly, but grants the ability to modify "
        "which DCs replicate with which other DCs -- a real capability "
        "for redirecting, disrupting, or otherwise manipulating the "
        "replication process itself. Uses the same well-known-holder "
        "exclusion list as plugin 5001, since this is also a "
        "replication-family right legitimately held by the same "
        "DC-related principals by default."
    ),
    "base_severity": "high",
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
            'high' AS fd_severity,
            'Principal ' || COALESCE(do2.sam_account_name, a.trustee_sid)
                || ' holds DS-Replication-Manage-Topology on the domain root' AS summary,
            jsonb_build_object('trustee_sid', a.trustee_sid, 'sam_account_name', do2.sam_account_name, 'object_class', do2.object_class) AS detail
        FROM acl_edge a
        JOIN ad_domain d ON d.object_guid = a.object_guid AND d.valid_to IS NULL
        JOIN directory_object do2 ON do2.object_sid = a.trustee_sid AND do2.client_id = %(client_id)s
        WHERE a.client_id = %(client_id)s
          AND a.valid_to IS NULL
          AND a.ace_type = 'allow'
          AND a.object_type_guid = '1131f6ac-9c07-11d1-f79f-00c04fc2dcd2'
          AND NOT EXISTS (SELECT 1 FROM expected_holders eh WHERE eh.object_guid = do2.object_guid)
    """,
}
