"""
Plugin 3005: Group Has a Stale admin_count Protection Marker

admin_count=1 is set by the AdminSDHolder/SDProp process when a group is
(or was) nested under a protected group -- but it is a STICKY marker.
Microsoft's own SDProp implementation does not automatically clear it
when the group is later removed from that nesting. This means
is_protected_group (admin_count=1, used pervasively throughout this
plugin set as the signal for "this is a privileged group") can itself be
stale: true of the group's history, not necessarily its current state.

This plugin cross-checks admin_count against genuinely CURRENT nesting
under a curated, non-circular list of well-known privileged root groups
(identified by RID, not by is_protected_group -- using is_protected_group
here would be circular, since it's the exact value this plugin exists to
validate).
"""

PLUGIN = {
    "plugin_id": 3005,
    "category": "Groups",
    "name": "Group Has a Stale AdminSDHolder Protection Marker",
    "version": "1.4",
    "revision_date": "2026-07-15",
    "remediation": (
        "Investigate why this group is no longer nested under a "
        "privileged group despite carrying the AdminSDHolder protection "
        "marker -- this is usually genuinely stale historical residue "
        "(the group was privileged at some point, was later removed from "
        "that nesting, and admin_count was simply never reset), not "
        "itself a vulnerability. Confirm the group's ACLs don't still "
        "reflect protected-object hardening that's no longer appropriate "
        "for its current, non-privileged role, then clear the marker "
        "(`Set-ADGroup -Clear adminCount`, and separately re-enable ACL "
        "inheritance if SDProp had disabled it) once confirmed safe to "
        "do so."
    ),
    "control_id": "PRIV-304",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Five common questions about AdminSDHolder and SDProp",
         "url": "https://techcommunity.microsoft.com/blog/askds/five-common-questions-about-adminsdholder-and-sdprop/396293"},
    ],
    "description": (
        "admin_count=1 is set by the AdminSDHolder/SDProp process when a "
        "group is (or was) nested under a protected group, but it is a "
        "sticky marker that Microsoft's own SDProp implementation does "
        "not automatically clear when the group is later removed from "
        "that nesting. This means the exact signal used pervasively "
        "throughout this plugin set as \"is this a privileged group\" "
        "(is_protected_group, computed as admin_count=1) can itself be "
        "stale -- true of a group's history, not necessarily its "
        "current state. This plugin cross-checks admin_count against "
        "genuinely current nesting under a curated set of well-known "
        "privileged root groups, identified by RID rather than by "
        "is_protected_group itself, specifically to avoid the circular "
        "reasoning that would result from validating a signal against "
        "itself. Usually benign residue rather than an active "
        "vulnerability, but worth surfacing since it means the group's "
        "ACLs may still reflect hardening appropriate to a privileged "
        "role it no longer actually holds. "
        "[v1.1] Corrected against a real false-positive found in "
        "production: the well-known-root RID list originally omitted "
        "Domain Controllers, Read-only Domain Controllers, and "
        "Replicator (all genuinely part of the canonical AdminSDHolder "
        "list) and incorrectly included Group Policy Creator Owners "
        "(which is not). Also excludes Key Admins/Enterprise Key Admins "
        "by name -- see the query for why."
    ),
    "base_severity": "low",
    "query": """
        WITH well_known_roots AS (
            SELECT g.object_guid
            FROM ad_group g
            JOIN directory_object do2
                ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              -- Verified against multiple independent, mutually-consistent
              -- sources (including a real PowerShell module's actual
              -- output showing exact RIDs): the canonical AdminSDHolder-
              -- protected group list is exactly these 11 -- Account
              -- Operators(548), Administrators(544), Backup
              -- Operators(551), Domain Admins(512), Domain
              -- Controllers(516), Enterprise Admins(519), Print
              -- Operators(550), Read-only Domain Controllers(521),
              -- Replicator(552), Schema Admins(518). Group Policy
              -- Creator Owners(520), used in an earlier version of this
              -- check, is NOT actually part of this list and was removed.
              AND (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-516'
                   OR do2.object_sid LIKE '%%-518' OR do2.object_sid LIKE '%%-519'
                   OR do2.object_sid LIKE '%%-521' OR do2.object_sid LIKE '%%-544'
                   OR do2.object_sid LIKE '%%-548' OR do2.object_sid LIKE '%%-549'
                   OR do2.object_sid LIKE '%%-550' OR do2.object_sid LIKE '%%-551'
                   OR do2.object_sid LIKE '%%-552')
        ),
        currently_nested AS (
            SELECT DISTINCT vem.member_guid AS object_guid
            FROM v_effective_group_membership vem
            WHERE vem.client_id = %(client_id)s
              AND vem.group_guid IN (SELECT object_guid FROM well_known_roots)
        ),
        acl_privileged_groups AS (
            -- [v1.x, ACL-aware] A group can be genuinely, currently
            -- privileged without any group nesting at all, if it
            -- directly holds dangerous or DCSync rights on the domain
            -- root/AdminSDHolder, or owns either object outright. Such
            -- a group's admin_count=1 is NOT stale -- excluding it here
            -- avoids a real false positive this check would otherwise
            -- produce, same reasoning already applied on the user side
            -- (plugin 1025) and the group-membership side (plugin 3004).
            SELECT do_acl.object_guid
            FROM acl_edge a
            JOIN directory_object do_acl ON do_acl.object_sid = a.trustee_sid AND do_acl.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                               '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                  )
            UNION
            SELECT do_owner.object_guid
            FROM directory_object owned_target
            JOIN directory_object do_owner
                ON do_owner.object_sid = owned_target.owner_sid AND do_owner.client_id = owned_target.client_id
            WHERE owned_target.client_id = %(client_id)s
              AND owned_target.owner_sid IS NOT NULL
        )
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Group ' || g.sam_account_name || ' carries the AdminSDHolder protection '
                'marker (admin_count=1) but is not currently nested, directly or '
                'indirectly, under any well-known privileged root group' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'admin_count', g.admin_count,
                'member_count_direct', g.member_count_direct
            ) AS detail
        FROM ad_group g
        LEFT JOIN currently_nested cn ON cn.object_guid = g.object_guid
        LEFT JOIN well_known_roots wkr ON wkr.object_guid = g.object_guid
        LEFT JOIN acl_privileged_groups apg ON apg.object_guid = g.object_guid
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND g.is_protected_group
          AND cn.object_guid IS NULL
          AND wkr.object_guid IS NULL
          AND apg.object_guid IS NULL
          -- Key Admins / Enterprise Key Admins are genuinely not part of
          -- the classic AdminSDHolder-protected list (confirmed against
          -- the same sources used for well_known_roots above) and hold
          -- domain-wide write access to msDS-KeyCredentialLink -- their
          -- admin_count=1 status may plausibly be by-design given that
          -- sensitivity, not necessarily stale nesting residue the way
          -- it would be for a classic protected group. Excluded here
          -- rather than force-fit into either bucket under genuine
          -- uncertainty about the actual mechanism.
          AND g.sam_account_name NOT IN ('Key Admins', 'Enterprise Key Admins')
    """,
}
