"""
Plugin 3011: Group Has BUILTIN_LOCAL_GROUP Flag Set But Is Not a Genuine Built-in Group

GROUP_TYPE_BUILTIN_LOCAL_GROUP (0x1) is documented as reserved for
system-created Builtin objects and cannot be set by ordinary clients
through normal tooling. Every genuine builtin local group carries a SID
in the well-known BUILTIN domain (S-1-5-32-*). A group with this bit set
but a SID outside that pattern is a real anomaly -- either forensic
residue of something unusual, or a sign of direct low-level data
manipulation that bypassed normal validation. Rare by design; this
finding firing at all is itself the signal worth investigating,
independent of what else the group looks like.
"""

PLUGIN = {
    "plugin_id": 3011,
    "category": "Groups",
    "name": "Group Has BUILTIN_LOCAL_GROUP Flag Set But Is Not a Genuine Built-in Group",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Investigate immediately -- this flag is documented as reserved "
        "for system-created Builtin objects and is not something normal "
        "administrative tooling sets. Determine when and how it was set "
        "(check msDS-ReplAttributeMetaData for the userAccountControl-"
        "equivalent attribute's last-changed timestamp and originating "
        "DC) before assuming routine misconfiguration. This finding "
        "firing at all, on any group, is itself the anomaly worth "
        "treating seriously -- it is expected to never fire in a normal "
        "environment."
    ),
    "control_id": "HYGIENE-305",
    "framework_tags": [],
    "references": [],
    "description": (
        "GROUP_TYPE_BUILTIN_LOCAL_GROUP (groupType bit 0x1) is "
        "documented in Microsoft's own protocol specification as "
        "reserved for system-created Builtin objects, explicitly noting "
        "it \"cannot be set by clients.\" Every genuine builtin local "
        "group carries a SID in the well-known BUILTIN domain "
        "(S-1-5-32-*, e.g. Administrators, Account Operators). A group "
        "with this bit set but a SID outside that specific pattern is a "
        "real anomaly -- either forensic residue of something unusual "
        "or a sign of direct, low-level data manipulation that bypassed "
        "normal validation and tooling. This is expected to essentially "
        "never fire in a normal environment; the finding firing at all "
        "is itself the signal worth investigating, independent of "
        "anything else about the group in question."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Group ' || g.sam_account_name || ' has the BUILTIN_LOCAL_GROUP flag set '
                '(groupType bit 0x1) but its SID (' || do2.object_sid || ') is not in '
                'the well-known BUILTIN domain' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'group_type', g.group_type,
                'object_sid', do2.object_sid
            ) AS detail
        FROM ad_group g
        JOIN directory_object do2
            ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND g.group_type IS NOT NULL
          AND (g.group_type & 1) != 0
          AND NOT COALESCE(do2.object_sid LIKE 'S-1-5-32-%%', FALSE)
    """,
}
