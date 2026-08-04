"""
Plugin 3007: Empty Security Group

An empty security group is low-severity hygiene, not a vulnerability --
but it's a real, common source of confusion (an ACL referencing a group
everyone assumes grants access to someone, when it grants access to
nobody) and clutters the picture when reviewing what actually has access
to something. Scoped to security-enabled groups specifically (group_type
< 0, the sign bit per ADS_GROUP_TYPE_SECURITY_ENABLED); an empty
distribution list is just an unused mailing list, not a security-relevant
condition.
"""

PLUGIN = {
    "plugin_id": 3007,
    "category": "Groups",
    "name": "Empty Security Group",
    "version": "1.1",
    "revision_date": "2026-07-15",
    "remediation": (
        "Confirm the group is genuinely unused -- check whether it's "
        "referenced in any ACL, GPO security filtering, or application "
        "role mapping before removing it (an empty group can still be "
        "doing something even with zero current members, e.g. gating "
        "access that simply nobody currently needs). If confirmed "
        "unused, remove it to reduce clutter when reviewing what "
        "actually has access to something."
    ),
    "control_id": "HYGIENE-302",
    "framework_tags": [],
    "references": [],
    "description": (
        "An empty security group is low-severity hygiene, not a "
        "vulnerability by itself -- but it's a common source of "
        "confusion (an ACL referencing a group everyone assumes grants "
        "access to someone, when it currently grants access to nobody) "
        "and adds clutter when auditing what actually has access to "
        "something. Scoped to security-enabled groups specifically "
        "(groupType's sign bit, ADS_GROUP_TYPE_SECURITY_ENABLED -- a "
        "security-enabled group's groupType value is always negative as "
        "a signed 32-bit integer); an empty distribution list is simply "
        "an unused mailing list, not a security-relevant condition."
    ),
    "base_severity": "info",
    "query": """
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'info' AS fd_severity,
            'Security Group ' || g.sam_account_name || ' has no members' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'group_type', g.group_type
            ) AS detail
        FROM ad_group g
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND g.group_type < 0
          AND NOT g.is_protected_group
          AND COALESCE(g.member_count_direct, 0) = 0
    """,
}
