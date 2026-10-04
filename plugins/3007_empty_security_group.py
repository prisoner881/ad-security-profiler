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

[v1.2] A group counts as empty only if it also has no current membership
edge -- including primaryGroupID edges (schema v36) -- so Domain Users,
Domain Computers and Domain Guests, whose members live in primaryGroupID
rather than the member attribute, are no longer reported as "has no
members". Built-in (S-1-5-32-*) groups and domain groups with a
well-known RID below 1000 are excluded: they are created by Windows,
are empty by default and cannot (or should not) be deleted.
detail.referenced_in_collected_acls says whether the group is a trustee
on any collected ACE (the "ACL grants nobody" case).
"""

PLUGIN = {
    "plugin_id": 3007,
    "category": "Groups",
    "name": "Empty Security Group",
    "version": "1.2",
    "revision_date": "2026-10-04",
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
        "an unused mailing list, not a security-relevant condition. "
        "Membership through primaryGroupID counts as membership, and "
        "Windows-created built-in / well-known groups (S-1-5-32-*, "
        "domain RIDs below 1000), which are empty by default and not "
        "removable, are excluded."
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
            'Security Group ' || COALESCE(g.sam_account_name, do2.object_sid, g.object_guid::text)
                || ' has no members' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'group_type', g.group_type,
                'referenced_in_collected_acls', EXISTS (
                    SELECT 1 FROM acl_edge a
                    WHERE a.client_id = g.client_id AND a.valid_to IS NULL
                      AND a.trustee_sid = do2.object_sid
                )
            ) AS detail
        FROM ad_group g
        JOIN directory_object do2
            ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND g.group_type < 0
          AND NOT g.is_protected_group
          AND COALESCE(g.member_count_direct, 0) = 0
          -- [v1.2] no current membership edge of any kind, incl. primaryGroupID
          AND NOT EXISTS (
              SELECT 1 FROM group_member_edge gme
              WHERE gme.group_guid = g.object_guid AND gme.client_id = g.client_id
                AND gme.valid_to IS NULL
          )
          -- [v1.2] Windows-created built-in / well-known groups (empty by default)
          AND COALESCE(do2.object_sid, '') NOT LIKE 'S-1-5-32-%%'
          AND NOT (do2.object_sid ~ '^S-1-5-21-\\d+-\\d+-\\d+-\\d+$'
                   AND substring(do2.object_sid from '(\\d+)$')::bigint < 1000)
    """,
}
