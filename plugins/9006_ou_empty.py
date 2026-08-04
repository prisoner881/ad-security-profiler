"""
Plugin 9006: Organizational Unit Contains No Objects

Same hygiene reasoning as plugin 3007 (empty security groups), applied
to OUs: a container with nothing in it -- no users, computers, groups,
or child OUs -- is either leftover from a reorganization that never
finished, or was created for a purpose that never materialized. Not a
security risk by itself, but unmanaged structure: any ACL delegation
or GPO links on an empty OU (see plugins 9001-9003) are pure overhead,
and an empty OU is one less thing to account for when someone new is
trying to understand the actual OU structure during a review.
"""

PLUGIN = {
    "plugin_id": 9006,
    "category": "Organizational Units",
    "name": "Organizational Unit Contains No Objects",
    "version": "1.0",
    "revision_date": "2026-07-19",
    "remediation": (
        "If this OU is genuinely no longer needed, delete it (Active "
        "Directory Users and Computers -> right-click -> Delete; "
        "protected OUs will need 'Protect object from accidental "
        "deletion' unchecked first under the Object tab with Advanced "
        "Features enabled). If it's intentionally staged for future "
        "use, that's fine -- just worth confirming it's not simply "
        "forgotten leftover structure."
    ),
    "control_id": "HYGIENE-901",
    "framework_tags": [],
    "references": [],
    "description": (
        "Same reasoning as plugin 3007 (empty security groups), "
        "applied to OUs: a container with no users, computers, groups, "
        "or child OUs inside it is either leftover from an unfinished "
        "reorganization or created for a purpose that never "
        "materialized. Not a security risk by itself -- unmanaged "
        "structure. Any ACL delegation or GPO links on an empty OU are "
        "pure overhead."
    ),
    "base_severity": "info",
    "query": """
        SELECT
            'warn' AS status,
            o.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'info' AS fd_severity,
            'OU "' || o.ou_name || '" contains no objects' AS summary,
            jsonb_build_object('ou_name', o.ou_name) AS detail
        FROM ad_ou o
        JOIN directory_object odo ON odo.object_guid = o.object_guid AND odo.client_id = %(client_id)s
        WHERE o.valid_to IS NULL
          AND o.client_id = %(client_id)s
          AND NOT EXISTS (
                SELECT 1 FROM directory_object child
                WHERE child.client_id = %(client_id)s
                  AND child.object_guid != o.object_guid
                  AND NOT child.is_deleted
                  AND substring(child.dn_current FROM position(',' IN child.dn_current) + 1) = odo.dn_current
              )
    """,
}
