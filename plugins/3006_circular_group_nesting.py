"""
Plugin 3006: Circular Group Nesting Detected

A group that is transitively a member of itself (Group A contains Group
B contains Group A) is a data-hygiene problem with real downstream
consequences: it can confuse permission auditing, break naive
group-enumeration tooling, and makes "who is ultimately a member of this
group" a genuinely harder question to answer correctly. Detected with
the plugin's own recursive CTE over group-to-group edges (the shared
v_effective_group_membership view drops the self-row it would need, and
can't report the chain) -- a group appearing as its own transitive member
IS the definition of a cycle.

[v1.2] Rated warn/low (hygiene, not an exploitable path -- in line with
PingCastle/Purple Knight). The recursion now walks group-to-group edges
only (cycles can only pass through groups), which bounds the work on
large directories, and the reported chain is chosen deterministically
among equal-length cycles. Docstring corrected (it does not use the
shared view).
"""

PLUGIN = {
    "plugin_id": 3006,
    "category": "Groups",
    "name": "Circular Group Nesting Detected",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Identify and remove at least one edge in the nesting cycle -- "
        "review the full chain of group memberships involved (available "
        "in this finding's detail) and determine which nesting "
        "relationship was unintentional or is no longer needed. There is "
        "no legitimate reason for a group to be a member of itself, "
        "directly or through any chain of nested groups."
    ),
    "control_id": "HYGIENE-301",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
    ],
    "references": [],
    "description": (
        "A group that is transitively a member of itself (Group A "
        "contains Group B contains Group A) has no legitimate purpose "
        "and is a genuine data-hygiene problem: it can confuse "
        "permission auditing and reasoning, break naive "
        "group-enumeration tooling that doesn't defend against cycles, "
        "and makes \"who is ultimately a member of this group\" a "
        "harder question to answer correctly than it should be. "
        "Detected with a recursive walk of current group-to-group "
        "membership edges -- a group appearing as its own transitive "
        "member is definitionally a cycle. A hygiene issue rather than "
        "an exploitable path, so rated low."
    ),
    "base_severity": "low",
    "query": """
        WITH RECURSIVE cycle_path AS (
            SELECT
                group_guid, member_guid, client_id,
                ARRAY[group_guid]::UUID[] AS path_guids,
                1 AS depth
            FROM group_member_edge e
            WHERE e.valid_to IS NULL AND e.client_id = %(client_id)s
              -- [v1.2] cycles can only run through groups
              AND EXISTS (SELECT 1 FROM ad_group mg
                           WHERE mg.object_guid = e.member_guid
                             AND mg.client_id = e.client_id AND mg.valid_to IS NULL)

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
            JOIN ad_group mg
              ON mg.object_guid = gme.member_guid
             AND mg.client_id = gme.client_id
             AND mg.valid_to IS NULL
            WHERE NOT gme.group_guid = ANY(cp.path_guids)
              AND cp.depth < 20
        ),
        cycles AS (
            SELECT DISTINCT ON (group_guid) group_guid, path_guids || member_guid AS full_path_guids, depth
            FROM cycle_path
            WHERE group_guid = member_guid
            ORDER BY group_guid, depth ASC, (path_guids || member_guid)::text
        )
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Group ' || COALESCE(g.sam_account_name, g.object_guid::text) || ' is involved in a circular nesting '
                'chain (transitively a member of itself, shortest cycle length '
                || c.depth || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'cycle_length', c.depth,
                'cycle_chain', (
                    SELECT array_agg(COALESCE(cdo.sam_account_name, cdo.object_guid::text) ORDER BY u.ord)
                    FROM unnest(c.full_path_guids) WITH ORDINALITY AS u(guid, ord)
                    JOIN directory_object cdo ON cdo.object_guid = u.guid AND cdo.client_id = %(client_id)s
                )
            ) AS detail
        FROM cycles c
        JOIN ad_group g ON g.object_guid = c.group_guid AND g.valid_to IS NULL
        WHERE g.client_id = %(client_id)s
    """,
}
