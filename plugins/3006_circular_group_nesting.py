"""
Plugin 3006: Circular Group Nesting Detected

A group that is transitively a member of itself (Group A contains Group
B contains Group A) is a data-hygiene problem with real downstream
consequences: it can confuse permission auditing, break naive
group-enumeration tooling, and makes "who is ultimately a member of this
group" a genuinely harder question to answer correctly. Detected
directly off the existing recursive membership view rather than a new
recursive query -- a group appearing as its own transitive member IS the
definition of a cycle.
"""

PLUGIN = {
    "plugin_id": 3006,
    "category": "Groups",
    "name": "Circular Group Nesting Detected",
    "version": "1.1",
    "revision_date": "2026-07-15",
    "remediation": (
        "Identify and remove at least one edge in the nesting cycle -- "
        "review the full chain of group memberships involved (available "
        "in this finding's detail) and determine which nesting "
        "relationship was unintentional or is no longer needed. There is "
        "no legitimate reason for a group to be a member of itself, "
        "directly or through any chain of nested groups."
    ),
    "control_id": "HYGIENE-301",
    "framework_tags": [],
    "references": [],
    "description": (
        "A group that is transitively a member of itself (Group A "
        "contains Group B contains Group A) has no legitimate purpose "
        "and is a genuine data-hygiene problem: it can confuse "
        "permission auditing and reasoning, break naive "
        "group-enumeration tooling that doesn't defend against cycles, "
        "and makes \"who is ultimately a member of this group\" a "
        "harder question to answer correctly than it should be. "
        "Detected directly off this project's own recursive membership "
        "view (v_effective_group_membership) -- a group appearing as its "
        "own transitive member (group_guid = member_guid at a depth "
        "greater than 1) is definitionally a cycle."
    ),
    "base_severity": "medium",
    "query": """
        WITH RECURSIVE cycle_path AS (
            SELECT
                group_guid, member_guid, client_id,
                ARRAY[group_guid]::UUID[] AS path_guids,
                1 AS depth
            FROM group_member_edge
            WHERE valid_to IS NULL AND client_id = %(client_id)s

            UNION ALL

            SELECT
                cp.group_guid, gme.member_guid, cp.client_id,
                cp.path_guids || gme.group_guid,
                cp.depth + 1
            FROM cycle_path cp
            JOIN group_member_edge gme
              ON gme.group_guid = cp.member_guid
             AND gme.valid_to IS NULL
             AND gme.client_id = cp.client_id
            WHERE NOT gme.group_guid = ANY(cp.path_guids)
              AND cp.depth < 20
        ),
        cycles AS (
            SELECT DISTINCT ON (group_guid) group_guid, path_guids || member_guid AS full_path_guids, depth
            FROM cycle_path
            WHERE group_guid = member_guid
            ORDER BY group_guid, depth ASC
        )
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Group ' || g.sam_account_name || ' is involved in a circular nesting '
                'chain (transitively a member of itself, shortest cycle length '
                || c.depth || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'cycle_length', c.depth,
                'cycle_chain', (
                    SELECT array_agg(cdo.sam_account_name ORDER BY u.ord)
                    FROM unnest(c.full_path_guids) WITH ORDINALITY AS u(guid, ord)
                    JOIN directory_object cdo ON cdo.object_guid = u.guid AND cdo.client_id = %(client_id)s
                )
            ) AS detail
        FROM cycles c
        JOIN ad_group g ON g.object_guid = c.group_guid AND g.valid_to IS NULL
        WHERE g.client_id = %(client_id)s
    """,
}
