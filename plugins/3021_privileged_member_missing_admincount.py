"""
Plugin 3021: Privileged Group Member Missing the AdminSDHolder Protection Marker

The inverse of this project's existing stale-admin_count checks
(plugins 1025/3005, which look for admin_count=1 on accounts that are
NO LONGER privileged): this looks for accounts that ARE currently
privileged -- effective members of an AdminSDHolder-protected group,
including through nested group membership -- but whose admin_count is
NOT set to 1. SDProp runs on a fixed interval (roughly every 60
minutes by default), so a small window of legitimate lag after a
membership change is normal and expected. Outside that window,
though, this is worth investigating: it can mean SDProp itself isn't
running correctly, or that the object's ACL was deliberately rewritten
after the marker was applied to remove protections SDProp would
otherwise enforce -- a documented defense-evasion technique.

[v1.1] Now covers computers as well as users and groups -- previously
excluded because this project didn't collect admin_count for computer
objects at all; that gap is closed as of adprofiler.py v0.5.2. A
domain controller's own computer object is the clearest example of a
computer that's an effective member of a Tier-0 group.

[v1.3] Key Admins (526) and Enterprise Key Admins (527) added to the
roots (both are on Microsoft's AdminSDHolder protected list since
Windows Server 2016). Membership through primaryGroupID is now covered
(schema v36 records it as a membership edge), which also catches the
"primaryGroupID=512" stealth trick; detail carries primary_group_id.
Domain controllers' own computer objects are not reported for their
default Domain Controllers (516) / Read-only Domain Controllers (521)
membership: that membership is via primaryGroupID and DC objects
commonly carry no adminCount, so it is expected, not a symptom.
Known limitation: operator groups excluded from SDProp via dSHeuristics
dwAdminSDExMask are not modelled (the collector does not parse it).

[v1.4] dwAdminSDExMask is now modelled. Collector 0.5.16 records
dSHeuristics character 16 as ad_domain.dsheuristics_admin_sd_ex_mask
(bits 1 Account Operators S-1-5-32-548, 2 Server Operators -549, 4 Print
Operators -550, 8 Backup Operators -551; NULL = unknown, treated as none
excluded). SDProp does not protect an excluded operator group or its
members, so a member whose ONLY privileged path is an excluded operator
group legitimately has no adminCount and is no longer reported. A member
that is also in a protected group is still reported; the excluded groups
are left out of the summary's group list and named in
detail.sdprop_excluded_operator_groups (detail also carries
admin_sd_ex_mask).
"""

PLUGIN = {
    "plugin_id": 3021,
    "category": "Groups",
    "name": "Privileged Group Member Missing the AdminSDHolder Protection Marker",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "If this membership was added very recently (within the last "
        "hour or so), this may simply be normal SDProp propagation lag "
        "-- re-check after the next SDProp cycle completes. If the "
        "membership is not recent, investigate why admin_count was not "
        "set: confirm SDProp is running (check for AdminSDHolder-"
        "related errors in the directory service event log on each "
        "DC), and review the object's current ACL for any deviation "
        "from the standard AdminSDHolder template, which would suggest "
        "deliberate tampering rather than a simple propagation delay."
    ),
    "control_id": "PRIV-309",
    "framework_tags": [],
    "references": [],
    "description": (
        "The inverse of plugins 1025/3005 (which look for admin_count=1 "
        "on accounts no longer privileged): finds accounts that ARE "
        "currently privileged -- effective members of an AdminSDHolder-"
        "protected group, including through nested membership -- but "
        "whose admin_count is not set to 1. A small window of lag "
        "after a membership change is normal, since SDProp runs on a "
        "fixed interval rather than instantly. Outside that window, "
        "this can indicate SDProp isn't running correctly, or that the "
        "object's ACL was deliberately rewritten after protection was "
        "applied -- a documented defense-evasion technique. Covers "
        "users, groups, and computers, nested membership and "
        "membership through primaryGroupID; roots are the 11 classic "
        "protected groups plus Key Admins / Enterprise Key Admins, by "
        "RID. A domain controller's default Domain Controllers / "
        "Read-only DCs membership is not reported. Operator groups "
        "excluded from SDProp via dSHeuristics dwAdminSDExMask (collector "
        "0.5.16+) are honoured: membership only through such a group is "
        "not reported, since SDProp deliberately does not protect it."
    ),
    "base_severity": "medium",
    "query": """
        WITH sd_ex AS (
            -- [v1.4] dSHeuristics dwAdminSDExMask (collector 0.5.16, schema
            -- v37): operator groups excluded from AdminSDHolder/SDProp.
            -- NULL = unknown, treated as "none excluded".
            SELECT max(d.dsheuristics_admin_sd_ex_mask) AS mask
            FROM ad_domain d
            WHERE d.client_id = %(client_id)s
              AND d.valid_to IS NULL
        ),
        well_known_roots AS (
            SELECT g.object_guid, COALESCE(g.sam_account_name, do2.object_sid) AS sam_account_name,
                   do2.object_sid ~ '-(516|521)$' AS is_dc_group,
                   -- [v1.4] bits: 1 Account Operators, 2 Server Operators,
                   -- 4 Print Operators, 8 Backup Operators
                   COALESCE(CASE do2.object_sid
                                WHEN 'S-1-5-32-548' THEN (sx.mask & 1) <> 0
                                WHEN 'S-1-5-32-549' THEN (sx.mask & 2) <> 0
                                WHEN 'S-1-5-32-550' THEN (sx.mask & 4) <> 0
                                WHEN 'S-1-5-32-551' THEN (sx.mask & 8) <> 0
                            END, false) AS sdprop_excluded
            FROM ad_group g
            JOIN directory_object do2
                ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
            CROSS JOIN sd_ex sx
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              -- [v1.3] + Key Admins (526) / Enterprise Key Admins (527)
              AND do2.object_sid ~ '-(512|516|518|519|521|526|527|544|548|549|550|551|552)$'
        ),
        matches AS (
            SELECT mdo.object_guid,
                   COALESCE(mdo.sam_account_name, mdo.object_sid, mdo.object_guid::text) AS sam_account_name,
                   mdo.object_class,
                   COALESCE(u.primary_group_id, c.primary_group_id) AS primary_group_id,
                   wkr.sam_account_name AS privileged_group_name,
                   wkr.sdprop_excluded,
                   COALESCE(u.admin_count, g.admin_count, c.admin_count) AS admin_count
            FROM v_effective_group_membership vem
            JOIN well_known_roots wkr ON wkr.object_guid = vem.group_guid
            JOIN directory_object mdo ON mdo.object_guid = vem.member_guid AND mdo.client_id = vem.client_id
            LEFT JOIN ad_user u ON u.object_guid = mdo.object_guid AND u.client_id = mdo.client_id AND u.valid_to IS NULL
            LEFT JOIN ad_group g ON g.object_guid = mdo.object_guid AND g.client_id = mdo.client_id AND g.valid_to IS NULL
            LEFT JOIN ad_computer c ON c.object_guid = mdo.object_guid AND c.client_id = mdo.client_id AND c.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
              AND mdo.object_class IN ('user', 'group', 'computer')
              AND COALESCE(u.admin_count, g.admin_count, c.admin_count, 0) != 1
              -- [v1.3] a DC's default (primaryGroupID) DC-group membership
              AND NOT (c.is_domain_controller AND wkr.is_dc_group)
        ),
        -- [fix, caught by this project's own defensive savepoint
        -- isolation during a routine regression run, not by a client
        -- report -- a member effectively in more than one
        -- well-known-root privileged group (plausible with nested
        -- membership at real-world scale) collided on identity_guid,
        -- the same class of bug already found and fixed elsewhere
        -- this session.] Aggregated to one row per member.
        aggregated AS (
            SELECT object_guid, max(sam_account_name) AS sam_account_name,
                   max(object_class) AS object_class, max(admin_count) AS admin_count,
                   max(primary_group_id) AS primary_group_id,
                   array_agg(DISTINCT privileged_group_name ORDER BY privileged_group_name)
                       FILTER (WHERE NOT sdprop_excluded) AS privileged_group_names,
                   array_agg(DISTINCT privileged_group_name ORDER BY privileged_group_name)
                       FILTER (WHERE sdprop_excluded) AS sdprop_excluded_groups
            FROM matches
            GROUP BY object_guid
            -- [v1.4] membership only through operator groups excluded from
            -- SDProp by dwAdminSDExMask legitimately carries no adminCount
            HAVING bool_or(NOT sdprop_excluded)
        )
        SELECT
            'warn' AS status,
            a.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            (CASE WHEN a.object_class = 'user' THEN 'User '
                  WHEN a.object_class = 'computer' THEN 'Computer '
                  ELSE 'Group ' END)
                || a.sam_account_name || ' is an effective member of privileged group(s) '
                || array_to_string(a.privileged_group_names, ', ')
                || ' but does not carry the admin_count=1 protection marker' AS summary,
            jsonb_build_object(
                'sam_account_name', a.sam_account_name,
                'object_class', a.object_class,
                'privileged_groups', a.privileged_group_names,
                'sdprop_excluded_operator_groups', a.sdprop_excluded_groups,
                'admin_sd_ex_mask', (SELECT mask FROM sd_ex),
                'admin_count', a.admin_count,
                'primary_group_id', a.primary_group_id
            ) AS detail
        FROM aggregated a
    """,
}
