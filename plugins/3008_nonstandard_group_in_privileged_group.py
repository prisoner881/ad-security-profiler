"""
Plugin 3008: Non-Standard Group Nested Inside a Privileged Group

Windows' own default configuration nests certain well-known groups
inside other well-known groups as a matter of course (e.g. Domain Admins
and Enterprise Admins are both, by default, members of the built-in
Administrators group) -- that nesting is normal and deliberately
excluded here to avoid flagging expected, out-of-the-box Windows
behavior as if it were anomalous. What this specifically flags is a
CUSTOM group (anything not itself one of the well-known RID-identified
groups) nested inside a privileged group -- a genuinely non-default
administrative action worth a second look, since indirect privilege
granted this way is easy to overlook when reviewing the privileged
group's own direct member list.
"""

PLUGIN = {
    "plugin_id": 3008,
    "category": "Groups",
    "name": "Non-Standard Group Nested Inside a Privileged Group",
    "version": "1.5",
    "revision_date": "2026-08-04",
    "remediation": (
        "Confirm this nesting was a deliberate, documented administrative "
        "decision. Anyone added to the nested group inherits the outer "
        "privileged group's rights without ever appearing in that "
        "group's own direct member list -- reviewing 'who is in Domain "
        "Admins' by looking only at its direct members would miss this "
        "entirely. If not deliberate or no longer needed, remove the "
        "nested group from the privileged group rather than leaving "
        "indirect privilege in place unexplained."
    ),
    "control_id": "PRIV-305",
    "framework_tags": [],
    "references": [],
    "description": (
        "Windows' own default configuration nests certain well-known "
        "groups inside other well-known groups as a matter of course "
        "(e.g. Domain Admins and Enterprise Admins are both, by default, "
        "members of the built-in Administrators group) -- deliberately "
        "excluded here to avoid flagging expected, out-of-the-box "
        "behavior as anomalous. What this specifically flags is a "
        "CUSTOM group (not itself one of the well-known RID-identified "
        "groups: 512, 518, 519, 520, 544, 548-551) nested inside a "
        "privileged group -- a genuinely non-default administrative "
        "action worth reviewing, since anyone later added to the nested "
        "group inherits the outer group's privilege without appearing "
        "in that privileged group's own direct member list at all."
    ),
    "base_severity": "high",
    "query": """
        WITH well_known_rids AS (
            SELECT g.object_guid
            FROM ad_group g
            JOIN directory_object do2
                ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              -- Same corrected, verified list as plugin 3005 -- see that
              -- plugin for the source citations. Group Policy Creator
              -- Owners(520) removed (not actually on the canonical list);
              -- Domain Controllers(516), Read-only Domain
              -- Controllers(521), and Replicator(552) added (genuinely
              -- on the list, previously missing).
              AND (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-516'
                   OR do2.object_sid LIKE '%%-518' OR do2.object_sid LIKE '%%-519'
                   OR do2.object_sid LIKE '%%-521' OR do2.object_sid LIKE '%%-544'
                   OR do2.object_sid LIKE '%%-548'
                   OR do2.object_sid LIKE '%%-549' OR do2.object_sid LIKE '%%-550'
                   OR do2.object_sid LIKE '%%-551' OR do2.object_sid LIKE '%%-552')
        ),
        acl_privileged_groups AS (
            -- [v1.x, ACL-aware] A group can grant real privilege to
            -- everyone nested inside it without being one of the
            -- classic RID-identified protected groups at all, if it
            -- directly holds dangerous or DCSync rights on the domain
            -- root/AdminSDHolder, or owns either object outright.
            -- Broadens "privileged group" (outer_g) the same way
            -- already applied to individual accounts and to plugin
            -- 3004's own membership-bloat check.
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
        ),
        nestings AS (
            SELECT inner_g.object_guid AS inner_guid, inner_g.sam_account_name AS inner_name,
                   inner_g.member_count_direct,
                   outer_g.sam_account_name AS outer_name,
                   outer_g.is_protected_group,
                   apg.object_guid IS NOT NULL AS via_acl_or_ownership
            FROM v_effective_group_membership vem
            JOIN ad_group outer_g
                ON outer_g.object_guid = vem.group_guid AND outer_g.valid_to IS NULL
            JOIN ad_group inner_g
                ON inner_g.object_guid = vem.member_guid AND inner_g.valid_to IS NULL
            LEFT JOIN acl_privileged_groups apg ON apg.object_guid = outer_g.object_guid
            WHERE vem.client_id = %(client_id)s
              AND outer_g.client_id = %(client_id)s
              AND (outer_g.is_protected_group OR apg.object_guid IS NOT NULL)
              AND inner_g.object_guid NOT IN (SELECT object_guid FROM well_known_rids)
        ),
        -- [fix, caught via a real production crash at large scale
        -- (2086 groups) that this project's own small test lab never
        -- exposed] identity_guid is the nested group's object_guid --
        -- the original version produced one row per (outer, inner)
        -- pair, and any non-standard group nested inside more than one
        -- privileged group (plausible with overlapping group
        -- membership at real-world scale) collided on identity_guid.
        -- Aggregated here instead: one finding per nested group,
        -- listing every privileged group it's nested inside.
        aggregated AS (
            SELECT inner_guid, inner_name, member_count_direct,
                   array_agg(DISTINCT outer_name ORDER BY outer_name) AS outer_names,
                   bool_or(is_protected_group) AS any_via_group_rid,
                   bool_or(via_acl_or_ownership) AS any_via_acl_or_ownership
            FROM nestings
            GROUP BY inner_guid, inner_name, member_count_direct
        )
        SELECT
            'fail' AS status,
            a.inner_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Group ' || a.inner_name || ' is nested inside privileged group(s): '
                || array_to_string(a.outer_names, ', ') AS summary,
            jsonb_build_object(
                'nested_group', a.inner_name,
                'privileged_groups', a.outer_names,
                'privileged_via_group_rid', a.any_via_group_rid,
                'privileged_via_acl_or_ownership', a.any_via_acl_or_ownership,
                'nested_group_member_count', a.member_count_direct
            ) AS detail
        FROM aggregated a
    """,
}
