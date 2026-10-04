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

[v1.3] Lowered to low: the usual cause is a security group converted to
distribution with its sticky marker left behind -- the same mechanism
plugin 3005 rates low -- and a distribution group cannot appear in a
token or an ACL. SDProp can also stamp a distribution group that is
nested in a protected group, so detail.currently_nested_in_protected_root
says whether that explains the marker. Plugin 3005 now skips distribution
groups, so each such group is reported once (here).
"""

PLUGIN = {
    "plugin_id": 3009,
    "category": "Groups",
    "name": "Distribution Group Has admin_count Set",
    "version": "1.3",
    "revision_date": "2026-10-04",
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
        "without admin_count being cleared, or be nested (as a member) "
        "inside a protected group, which SDProp also stamps. Rated low: "
        "the same sticky-marker hygiene issue as plugin 3005 (which "
        "leaves distribution groups to this plugin), with no direct "
        "security impact since the group cannot grant access."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Distribution Group ' || COALESCE(g.sam_account_name, g.object_guid::text)
                || ' has admin_count=1 set' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'group_type', g.group_type,
                'admin_count', g.admin_count,
                'currently_nested_in_protected_root', EXISTS (
                    SELECT 1
                    FROM v_effective_group_membership vem
                    JOIN directory_object rdo
                        ON rdo.object_guid = vem.group_guid AND rdo.client_id = vem.client_id
                    WHERE vem.client_id = g.client_id
                      AND vem.member_guid = g.object_guid
                      AND rdo.object_sid ~ '-(512|516|518|519|521|526|527|544|548|549|550|551|552)$'
                )
            ) AS detail
        FROM ad_group g
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND g.group_type >= 0
          AND g.is_protected_group
    """,
}
