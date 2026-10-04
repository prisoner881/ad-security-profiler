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

[v1.5] The "currently privileged without group nesting" exclusion now
uses the shared Tier 0 view v_privileged_principal (schema v34), minus
its protected_group_member rows (they rest on is_protected_group, which
would be circular here). The old inline subquery treated a dangerous
right on, or ownership of, ANY object as privilege, so a stale group that
merely held OU delegation or had created an OU was never reported.

[v1.6] Key Admins (526) and Enterprise Key Admins (527) are now
well-known roots by RID instead of being excluded by English name: a
group nested in Key Admins carries a legitimate adminCount=1 and was
reported as stale, and renamed/localized KA/EKA groups were reported
too. Distribution groups (group_type >= 0) are left to plugin 3009 so
the same marker isn't reported twice. Known limitation: operator groups
excluded from SDProp via dSHeuristics dwAdminSDExMask are not modelled
(the collector does not parse that character).

[v1.7] dwAdminSDExMask is now modelled. Collector 0.5.16 records
dSHeuristics character 16 as ad_domain.dsheuristics_admin_sd_ex_mask
(bits 1 Account Operators S-1-5-32-548, 2 Server Operators -549, 4 Print
Operators -550, 8 Backup Operators -551; NULL = unknown, treated as none
excluded). An excluded operator group is not protected by SDProp, so it
no longer counts as a well-known root: a group whose only privileged
nesting is under an excluded operator group now has a stale marker and
is reported (summary names the excluded group(s)), and an excluded
operator group carrying adminCount=1 itself is reported as stale too.
detail gains sdprop_excluded_operator_group,
nested_only_under_sdprop_excluded_groups and admin_sd_ex_mask. Findings
without an excluded group keep the previous summary.
"""

PLUGIN = {
    "plugin_id": 3005,
    "category": "Groups",
    "name": "Group Has a Stale AdminSDHolder Protection Marker",
    "version": "1.7",
    "revision_date": "2026-10-04",
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
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
    ],
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
        "(which is not). [v1.6] Key Admins/Enterprise Key Admins are "
        "treated as roots by RID (526/527), and distribution groups are "
        "left to plugin 3009. [v1.7] Operator groups excluded from SDProp "
        "by dSHeuristics dwAdminSDExMask (collector 0.5.16+) are not "
        "protected roots: a marker that rests only on nesting under one -- "
        "or on such a group itself -- is reported as stale."
    ),
    "base_severity": "low",
    "query": """
        WITH sd_ex AS (
            -- [v1.7] dSHeuristics dwAdminSDExMask (collector 0.5.16, schema
            -- v37). NULL = unknown, treated as "none excluded".
            SELECT max(d.dsheuristics_admin_sd_ex_mask) AS mask
            FROM ad_domain d
            WHERE d.client_id = %(client_id)s
              AND d.valid_to IS NULL
        ),
        well_known_roots AS (
            SELECT g.object_guid,
                   COALESCE(g.sam_account_name, do2.object_sid) AS sam_account_name,
                   -- [v1.7] operator groups the mask excludes from SDProp
                   -- (1 Account, 2 Server, 4 Print, 8 Backup Operators)
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
              -- Verified against multiple independent, mutually-consistent
              -- sources (including a real PowerShell module's actual
              -- output showing exact RIDs): the canonical AdminSDHolder-
              -- protected group list is exactly these 11 -- Account
              -- Operators(548), Administrators(544), Backup
              -- Operators(551), Domain Admins(512), Domain
              -- Controllers(516), Enterprise Admins(519), Print
              -- Operators(550), Read-only Domain Controllers(521),
              -- Replicator(552), Schema Admins(518), Server
              -- Operators(549). Group Policy Creator Owners(520), used in
              -- an earlier version of this check, is NOT actually part of
              -- this list and was removed. [v1.6] Key Admins(526) and
              -- Enterprise Key Admins(527) are added: they carry
              -- adminCount=1 by design on 2016+ domains, so groups nested
              -- in them are legitimately marked, not stale.
              AND (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-516'
                   OR do2.object_sid LIKE '%%-518' OR do2.object_sid LIKE '%%-519'
                   OR do2.object_sid LIKE '%%-521' OR do2.object_sid LIKE '%%-544'
                   OR do2.object_sid LIKE '%%-548' OR do2.object_sid LIKE '%%-549'
                   OR do2.object_sid LIKE '%%-550' OR do2.object_sid LIKE '%%-551'
                   OR do2.object_sid LIKE '%%-526' OR do2.object_sid LIKE '%%-527'
                   OR do2.object_sid LIKE '%%-552')
        ),
        currently_nested AS (
            -- nesting under a root SDProp actually protects
            SELECT DISTINCT vem.member_guid AS object_guid
            FROM v_effective_group_membership vem
            JOIN well_known_roots wkr ON wkr.object_guid = vem.group_guid
            WHERE vem.client_id = %(client_id)s
              AND NOT wkr.sdprop_excluded
        ),
        excluded_nested AS (
            -- [v1.7] nesting only under operator groups excluded by the mask
            SELECT vem.member_guid AS object_guid,
                   array_agg(DISTINCT wkr.sam_account_name ORDER BY wkr.sam_account_name) AS via_groups
            FROM v_effective_group_membership vem
            JOIN well_known_roots wkr ON wkr.object_guid = vem.group_guid
            WHERE vem.client_id = %(client_id)s
              AND wkr.sdprop_excluded
            GROUP BY vem.member_guid
        ),
        acl_privileged_groups AS (
            -- [v1.5] A group can be genuinely, currently privileged
            -- without any protected-group nesting, if it holds control
            -- rights on, or owns, a Tier 0 object, or holds DCSync (directly
            -- or through a group). Such a group's admin_count=1 is NOT
            -- stale. Taken from the shared Tier 0 view (schema v34) rather
            -- than the old inline subquery, which counted a dangerous right
            -- on or ownership of ANY object. The view's
            -- protected_group_member rows are excluded: they rest on
            -- is_protected_group (admin_count=1), the very signal this
            -- plugin validates -- currently_nested covers real
            -- protected-group nesting by RID instead.
            SELECT DISTINCT object_guid
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
              AND privilege_source <> 'protected_group_member'
        )
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Group ' || COALESCE(g.sam_account_name, g.object_guid::text) || ' carries the AdminSDHolder protection '
                'marker (admin_count=1) but '
                || CASE
                       WHEN wkr.object_guid IS NOT NULL
                           THEN 'is itself excluded from AdminSDHolder protection by dSHeuristics '
                                'dwAdminSDExMask'
                       WHEN en.object_guid IS NOT NULL
                           THEN 'its only privileged nesting is under '
                                || array_to_string(en.via_groups, ', ')
                                || ', excluded from AdminSDHolder protection by dSHeuristics '
                                   'dwAdminSDExMask'
                       ELSE 'is not currently nested, directly or indirectly, under any '
                            'well-known privileged root group'
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'admin_count', g.admin_count,
                'member_count_direct', g.member_count_direct,
                'sdprop_excluded_operator_group', wkr.object_guid IS NOT NULL,
                'nested_only_under_sdprop_excluded_groups', en.via_groups,
                'admin_sd_ex_mask', (SELECT mask FROM sd_ex)
            ) AS detail
        FROM ad_group g
        LEFT JOIN currently_nested cn ON cn.object_guid = g.object_guid
        -- a root group itself: not stale unless the mask excludes it
        LEFT JOIN well_known_roots wkr_any ON wkr_any.object_guid = g.object_guid
        LEFT JOIN well_known_roots wkr ON wkr.object_guid = g.object_guid AND wkr.sdprop_excluded
        LEFT JOIN excluded_nested en ON en.object_guid = g.object_guid
        LEFT JOIN acl_privileged_groups apg ON apg.object_guid = g.object_guid
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND g.is_protected_group
          AND cn.object_guid IS NULL
          AND (wkr_any.object_guid IS NULL OR wkr_any.sdprop_excluded)
          AND apg.object_guid IS NULL
          -- [v1.6] Distribution groups with the marker are reported by
          -- plugin 3009; Key Admins / Enterprise Key Admins are roots above.
          AND (g.group_type IS NULL OR g.group_type < 0)
    """,
}
