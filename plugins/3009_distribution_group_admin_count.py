"""
Plugin 3009: Distribution Group Has admin_count Set (Anomalous)

Distribution groups are not security-enabled and cannot be used as a
security principal in an ACL -- Windows itself enforces this. There is
no ordinary mechanism by which the AdminSDHolder/SDProp process should
ever set admin_count=1 on one, since SDProp exists specifically to
protect security principals' ACLs from inheritance, a concept that
doesn't apply to a group that was never usable in an ACL in the first
place. Genuinely unusual; worth investigating rather than assuming
routine, though this is stated with appropriate humility rather than
asserted as definitively impossible.
"""

PLUGIN = {
    "plugin_id": 3009,
    "category": "Groups",
    "name": "Distribution Group Has admin_count Set",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Investigate how and when admin_count was set on this group -- "
        "check msDS-ReplAttributeMetaData for the attribute's "
        "last-changed timestamp and originating DC as a starting point. "
        "This is not a routine or expected state for a distribution "
        "group, so treat it as worth understanding before simply "
        "clearing the value. If the group was previously security-"
        "enabled and later converted to a distribution group, that "
        "history would explain a stale admin_count value (see plugin "
        "3005 for the general stale-marker case) -- confirm that "
        "explanation rather than assuming it."
    ),
    "control_id": "HYGIENE-303",
    "framework_tags": [],
    "references": [],
    "description": (
        "Distribution groups are not security-enabled and cannot be "
        "used as a security principal in an Access Control List -- "
        "Windows itself enforces this restriction. There is no ordinary "
        "mechanism by which the AdminSDHolder/SDProp process, which "
        "exists specifically to protect security principals' ACLs from "
        "inheritance, should set admin_count=1 on a group that was "
        "never usable in an ACL to begin with. This is genuinely "
        "unusual and worth investigating rather than assuming routine -- "
        "stated with appropriate humility rather than asserted as "
        "definitively impossible, since a group could plausibly have "
        "been security-enabled in the past (when SDProp legitimately "
        "set the marker) and later converted to a distribution group "
        "without admin_count being cleared."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Distribution Group ' || g.sam_account_name || ' has admin_count=1 set' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'group_type', g.group_type,
                'admin_count', g.admin_count
            ) AS detail
        FROM ad_group g
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND g.group_type >= 0
          AND g.is_protected_group
    """,
}
