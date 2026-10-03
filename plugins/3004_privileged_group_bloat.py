"""
Plugin 3004: Privileged Group Has an Unusually Large Number of Members

Every additional member of a privileged group is another account whose
compromise directly grants that privilege -- membership bloat in these
groups is a direct, linear expansion of attack surface. Complementary to
plugin 3003 (which is specific to Schema/Enterprise Admins and flags any
nonzero membership): this applies more broadly to any AdminSDHolder-
protected group, at a higher, "handful of administrators" threshold
rather than zero.

[v1.5] The ACL/ownership half of "privileged group" now comes from the
shared Tier 0 view v_privileged_principal (schema v34). The old inline
subquery counted GenericAll/GenericWrite/WriteDACL/WriteOwner on, or
ownership of, ANY object, so a helpdesk group with OU delegation (or a
group that had created an OU) was reported as a privileged group.
AdminSDHolder-protected groups are still included via is_protected_group
(the view lists their members, not the groups themselves). detail gains
privilege_sources.
"""

PLUGIN = {
    "plugin_id": 3004,
    "category": "Groups",
    "name": "Privileged Group Has an Unusually Large Number of Members",
    "version": "1.5",
    "revision_date": "2026-10-03",
    "remediation": (
        "Review the full membership list and confirm each member "
        "genuinely needs this level of access on an ongoing, standing "
        "basis. Per Microsoft's own guidance on securing privileged "
        "administrative groups: membership should be limited to either "
        "empty (temporary elevation only, added and removed as needed) "
        "or a handful of administrators responsible for the overall "
        "health of the service the group governs. Consider an "
        "administrative delegation model (custom groups with narrowly "
        "scoped permissions) for anyone who only needs a subset of what "
        "this group actually grants."
    ),
    "control_id": "PRIV-303",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1078.002"],
    "references": [
        {"title": "DISA STIG V-243467: Domain Admins group membership must be restricted",
         "url": "https://www.stigviewer.com/stigs/active_directory_domain/2024-02-26/finding/V-243467"},
    ],
    "description": (
        "Directly reflects Microsoft's own guidance on securing "
        "high-level administrative groups: \"We recommend limiting "
        "membership in these groups to either empty (temporary "
        "membership only) or a handful of administrators who are "
        "responsible for the overall health of Active Directory "
        "Service.\" Every additional standing member of a privileged "
        "group is a direct, linear expansion of attack surface -- "
        "compromising any one of them grants that privilege outright. "
        "The threshold used here (member_count_direct > 5) is a literal "
        "reading of \"a handful\" from that same guidance, not an "
        "independently cited external standard."
    ),
    "base_severity": "medium",
    "query": """
        WITH acl_privileged_groups AS (
            -- [v1.5] "Privileged group" is the classic is_protected_group
            -- definition OR the shared Tier 0 view (schema v34): the group
            -- holds control rights on, or owns, a Tier 0 object, holds
            -- DCSync, or is nested in a group that does -- every member
            -- inherits that power. The old inline subquery counted a
            -- dangerous right on or ownership of ANY object, so any group
            -- with OU delegation (or that created an OU) was reported as a
            -- bloated privileged group. One row per group; the view's
            -- reasons are carried into detail.
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources,
                   bool_or(privilege_source <> 'protected_group_member') AS via_acl_or_ownership
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        )
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Privileged Group ' || g.sam_account_name || ' has '
                || g.member_count_direct || ' direct member(s)' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'member_count_direct', g.member_count_direct,
                'privileged_via_group_rid', g.is_protected_group,
                'privileged_via_acl_or_ownership', COALESCE(apg.via_acl_or_ownership, FALSE),
                'privilege_sources', apg.privilege_sources,
                'members', (
                    SELECT array_agg(mdo.sam_account_name ORDER BY mdo.sam_account_name)
                    FROM group_member_edge gme
                    JOIN directory_object mdo ON mdo.object_guid = gme.member_guid AND mdo.client_id = gme.client_id
                    WHERE gme.group_guid = g.object_guid AND gme.client_id = g.client_id AND gme.valid_to IS NULL
                )
            ) AS detail
        FROM ad_group g
        LEFT JOIN acl_privileged_groups apg ON apg.object_guid = g.object_guid
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND (g.is_protected_group OR apg.object_guid IS NOT NULL)
          AND COALESCE(g.member_count_direct, 0) > 5
    """,
}
