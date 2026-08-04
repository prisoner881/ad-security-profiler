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
"""

PLUGIN = {
    "plugin_id": 8003,
    "plugin_type": "inventory",
    "category": "Inventory",
    "name": "Group Inventory",
    "version": "1.1",
    "revision_date": "2026-07-18",
    "description": (
        "Snapshot listing of every group with one or more members: "
        "name, object creation date, direct member count, and the "
        "full list of direct members."
    ),
    "query": """
        SELECT
            g.sam_account_name,
            g.when_created,
            g.member_count_direct,
            (
                SELECT array_agg(
                    COALESCE(mdo.sam_account_name, fsp.well_known_name, mdo.dn_current)
                    ORDER BY COALESCE(mdo.sam_account_name, fsp.well_known_name, mdo.dn_current)
                )
                FROM group_member_edge gme
                JOIN directory_object mdo ON mdo.object_guid = gme.member_guid AND mdo.client_id = gme.client_id
                LEFT JOIN ad_foreign_security_principal fsp
                    ON fsp.object_guid = mdo.object_guid AND fsp.client_id = mdo.client_id AND fsp.valid_to IS NULL
                WHERE gme.group_guid = g.object_guid AND gme.client_id = g.client_id AND gme.valid_to IS NULL
            ) AS members
        FROM ad_group g
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND COALESCE(g.member_count_direct, 0) > 0
        ORDER BY g.sam_account_name
    """,
}
