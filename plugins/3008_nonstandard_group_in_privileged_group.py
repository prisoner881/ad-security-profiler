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

[v1.7] The ACL/ownership half of "privileged group" (outer group) now
comes from the shared Tier 0 view v_privileged_principal (schema v34),
limited to its direct sources. The old inline subquery counted
GenericAll/GenericWrite/WriteDACL/WriteOwner on, or ownership of, ANY
object, so a custom group nested in a helpdesk group with OU delegation
was reported as nested inside a privileged group. AdminSDHolder-protected
outer groups are still matched via is_protected_group.

[v1.8] Two precision fixes. (1) Only the actual Windows default nestings
are exempt -- Domain Admins (512) and Enterprise Admins (519) inside
Administrators (544) -- instead of exempting every well-known group as
an inner group wherever it sits, so a non-default nesting such as
Account Operators inside Domain Admins is now reported. (2) An outer
group's adminCount=1 is only trusted when the group is a well-known
privileged root by RID (512/516/518/519/521/526/527/544/548-552) or is
currently nested under one -- a group with a stale marker (plugin 3005's
population) no longer makes its members "privileged". A group in a
nesting cycle is no longer reported as nested inside itself.
"""

PLUGIN = {
    "plugin_id": 3008,
    "category": "Groups",
    "name": "Non-Standard Group Nested Inside a Privileged Group",
    "version": "1.8",
    "revision_date": "2026-10-04",
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
        "MITRE-ATTCK-T1078.002",
        "CISA-AA26-237A",
    ],
    "references": [],
    "description": (
        "Windows' own default configuration nests certain well-known "
        "groups inside other well-known groups as a matter of course "
        "(e.g. Domain Admins and Enterprise Admins are both, by default, "
        "members of the built-in Administrators group) -- deliberately "
        "excluded here to avoid flagging expected, out-of-the-box "
        "behavior as anomalous. Only those default nestings (Domain "
        "Admins and Enterprise Admins inside Administrators) are "
        "exempt; any other group -- custom or well-known -- nested "
        "inside a privileged group is flagged. A privileged group is a "
        "well-known protected group by RID (or an adminCount=1 group "
        "currently nested under one) or a direct Tier 0 ACL/owner/DCSync "
        "holder. Such a nesting is a genuinely non-default administrative "
        "action worth reviewing, since anyone later added to the nested "
        "group inherits the outer group's privilege without appearing "
        "in that privileged group's own direct member list at all."
    ),
    "base_severity": "high",
    "query": """
        WITH well_known_roots AS (
            SELECT g.object_guid, do2.object_sid
            FROM ad_group g
            JOIN directory_object do2
                ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              -- Same corrected, verified list as plugin 3005 -- see that
              -- plugin for the source citations (the 11 AdminSDHolder-
              -- protected groups plus Key Admins 526 / Enterprise Key
              -- Admins 527).
              AND do2.object_sid ~ '-(512|516|518|519|521|526|527|544|548|549|550|551|552)$'
        ),
        protected_outer AS (
            -- [v1.8] adminCount=1 is sticky, so is_protected_group is no
            -- longer the test: a root itself, or any group currently
            -- nested under a root (whatever its adminCount).
            SELECT object_guid FROM well_known_roots
            UNION
            SELECT vem.member_guid
            FROM v_effective_group_membership vem
            JOIN well_known_roots r ON r.object_guid = vem.group_guid
            WHERE vem.client_id = %(client_id)s
        ),
        acl_privileged_groups AS (
            -- [v1.7] A group can grant real privilege to everyone nested
            -- inside it without being one of the classic protected groups,
            -- if it directly holds control rights on, or owns, a Tier 0
            -- object, or holds DCSync -- taken from the shared Tier 0 view
            -- (schema v34). The old inline subquery counted a dangerous
            -- right on or ownership of ANY object, so a group with OU
            -- delegation was treated as a privileged outer group. Only the
            -- view's direct sources: protected_group_member is covered by
            -- is_protected_group below, and a *_via_group outer group's
            -- nested members are already effective members of the holder
            -- group itself, which is reported in its place.
            SELECT DISTINCT object_guid
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
              AND privilege_source IN ('tier0_acl_control', 'dcsync', 'tier0_ownership')
        ),
        nestings AS (
            SELECT inner_g.object_guid AS inner_guid,
                   COALESCE(inner_g.sam_account_name, inner_do.object_sid, inner_g.object_guid::text) AS inner_name,
                   inner_g.member_count_direct,
                   COALESCE(outer_g.sam_account_name, outer_g.object_guid::text) AS outer_name,
                   po.object_guid IS NOT NULL AS is_protected_group,
                   apg.object_guid IS NOT NULL AS via_acl_or_ownership
            FROM v_effective_group_membership vem
            JOIN ad_group outer_g
                ON outer_g.object_guid = vem.group_guid AND outer_g.valid_to IS NULL
            JOIN directory_object outer_do
                ON outer_do.object_guid = outer_g.object_guid AND outer_do.client_id = outer_g.client_id
            JOIN ad_group inner_g
                ON inner_g.object_guid = vem.member_guid AND inner_g.valid_to IS NULL
            JOIN directory_object inner_do
                ON inner_do.object_guid = inner_g.object_guid AND inner_do.client_id = inner_g.client_id
            LEFT JOIN protected_outer po ON po.object_guid = outer_g.object_guid
            LEFT JOIN acl_privileged_groups apg ON apg.object_guid = outer_g.object_guid
            WHERE vem.client_id = %(client_id)s
              AND outer_g.client_id = %(client_id)s
              AND vem.group_guid <> vem.member_guid      -- [v1.8] cycle back to itself
              AND (po.object_guid IS NOT NULL OR apg.object_guid IS NOT NULL)
              -- [v1.8] Windows default nestings only: Domain Admins and
              -- Enterprise Admins inside the builtin Administrators group.
              AND NOT (COALESCE(inner_do.object_sid, '') ~ '-(512|519)$'
                       AND outer_do.object_sid = 'S-1-5-32-544')
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
