"""
Plugin 8003: Group Inventory

A utility plugin, not a finding plugin: see plugin 8001's docstring
for the full design rationale of this second, parallel plugin type.
Runs fresh every invocation, no persistence, no change tracking.

Only groups with more than zero direct members are listed, per the
original requirement -- an empty group contributes nothing to a
membership inventory (plugin 3007 already covers empty groups as a
hygiene finding on the finding-plugin side, if that's what's needed).

[v1.1] A member can be a foreign security principal (e.g. the
well-known Everyone/Anonymous Logon SIDs, as flagged by plugin 3012)
rather than an ordinary user/computer/group -- those don't carry a
sam_account_name at all, which produced a literal "None" in the
member list before this fix. Falls back to the FSP's well_known_name,
and to the object's DN as a last resort, so every member always
renders as something identifiable.

[v1.2] Primary-group members are included. Since schema v36 the
collector records primaryGroupID membership as group_member_edge rows
(is_primary_group = TRUE), so the member list already contains them, but
the "member_count_direct > 0" filter (which counts only the member
attribute) left out Domain Users / Domain Computers and every other
group whose members are all primary-group members. A group is now listed
when its member attribute is non-empty OR it has any current membership
edge. Two trailing columns are added: primary_group_member_count (members
via primaryGroupID, not in member_count_direct) and members_unresolved
(member_count_direct minus the member-attribute entries resolved to
collected objects -- contacts, objects in other domains and other
out-of-scope members are counted by member_count_direct but cannot be
listed).
"""

PLUGIN = {
    "plugin_id": 8003,
    "plugin_type": "inventory",
    "category": "Inventory",
    "name": "Group Inventory",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "description": (
        "Snapshot listing of every group with one or more members: "
        "name, object creation date, direct member count (member "
        "attribute), the full list of direct members including "
        "primary-group (primaryGroupID) members, the number of "
        "primary-group members, and the number of member-attribute "
        "entries that could not be resolved to a collected object."
    ),
    "query": """
        SELECT
            g.sam_account_name,
            g.when_created,
            g.member_count_direct,
            m.members,
            COALESCE(m.primary_members, 0) AS primary_group_member_count,
            GREATEST(COALESCE(g.member_count_direct, 0) - COALESCE(m.attribute_members, 0), 0)
                AS members_unresolved
        FROM ad_group g
        LEFT JOIN LATERAL (
            SELECT
                array_agg(
                    COALESCE(mdo.sam_account_name, fsp.well_known_name, mdo.dn_current)
                    ORDER BY COALESCE(mdo.sam_account_name, fsp.well_known_name, mdo.dn_current)
                ) AS members,
                count(*) FILTER (WHERE gme.is_primary_group) AS primary_members,
                count(*) FILTER (WHERE NOT gme.is_primary_group) AS attribute_members
            FROM group_member_edge gme
            JOIN directory_object mdo ON mdo.object_guid = gme.member_guid AND mdo.client_id = gme.client_id
            LEFT JOIN ad_foreign_security_principal fsp
                ON fsp.object_guid = mdo.object_guid AND fsp.client_id = mdo.client_id AND fsp.valid_to IS NULL
            WHERE gme.group_guid = g.object_guid AND gme.client_id = g.client_id AND gme.valid_to IS NULL
        ) m ON TRUE
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          -- [v1.2] member attribute non-empty, or any edge (primary-group members)
          AND (COALESCE(g.member_count_direct, 0) > 0 OR m.members IS NOT NULL)
        ORDER BY g.sam_account_name
    """,
}
