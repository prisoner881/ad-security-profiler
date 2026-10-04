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

[v1.6] The threshold now applies to the EFFECTIVE membership: enabled
user and computer accounts that are members directly, through any chain
of nested groups, or through primaryGroupID (schema v36 edges). Domain
Admins holding one nested group of 200 users previously counted as 1.
Domain controllers are not counted (they are expected members of the
Domain Controllers / Read-only DCs / Administrators-via-EDC paths).
A group qualifying only through a possibly stale adminCount=1 must now
also be a well-known privileged root by RID (512/516/518/519/521/526/
527/544/548-552) or appear in v_privileged_principal (currently nested
in a protected group, or a Tier 0 ACL/owner/DCSync holder). Summary
reports the effective and direct counts; detail.members falls back to
SID for members without a sAMAccountName.
"""

PLUGIN = {
    "plugin_id": 3004,
    "category": "Groups",
    "name": "Privileged Group Has an Unusually Large Number of Members",
    "version": "1.6",
    "revision_date": "2026-10-04",
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
        "DISA-STIG",
        "DISA-STIG-V-243467",
        "MITRE-ATTCK-T1078.002",
        "CISA-AA26-237A",
    ],
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
        "The threshold used here (more than 5 enabled user/computer "
        "accounts holding the membership directly, through nested groups "
        "or through primaryGroupID; domain controllers not counted) is a "
        "literal reading of \"a handful\" from that same guidance, not "
        "an independently cited external standard."
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
        ),
        effective AS (
            -- [v1.6] Accounts whose compromise grants the group's privilege:
            -- enabled users and enabled non-DC computers (incl. gMSAs) that
            -- are members directly, via nesting or via primaryGroupID.
            SELECT vem.group_guid,
                   count(*) AS n,
                   (array_agg(COALESCE(mdo.sam_account_name, mdo.object_sid, mdo.object_guid::text)
                              ORDER BY COALESCE(mdo.sam_account_name, mdo.object_sid, mdo.object_guid::text)))[1:200]
                       AS names
            FROM v_effective_group_membership vem
            JOIN directory_object mdo
                ON mdo.object_guid = vem.member_guid AND mdo.client_id = vem.client_id
               AND NOT mdo.is_deleted
            LEFT JOIN ad_user u
                ON u.object_guid = vem.member_guid AND u.client_id = vem.client_id AND u.valid_to IS NULL
            LEFT JOIN ad_computer c
                ON c.object_guid = vem.member_guid AND c.client_id = vem.client_id AND c.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
              AND ((u.object_guid IS NOT NULL AND u.is_enabled IS NOT FALSE)
                   OR (c.object_guid IS NOT NULL AND c.is_enabled IS NOT FALSE
                       AND NOT c.is_domain_controller))
            GROUP BY vem.group_guid
        )
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Privileged Group ' || COALESCE(g.sam_account_name, do2.object_sid, g.object_guid::text)
                || ' has ' || eff.n || ' effective enabled member account(s) ('
                || COALESCE(g.member_count_direct, 0) || ' direct member(s))' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'member_count_direct', g.member_count_direct,
                'effective_member_account_count', eff.n,
                'effective_member_accounts', eff.names,
                'privileged_via_group_rid', g.is_protected_group,
                'privileged_via_acl_or_ownership', COALESCE(apg.via_acl_or_ownership, FALSE),
                'privilege_sources', apg.privilege_sources,
                'members', (
                    SELECT array_agg(COALESCE(mdo.sam_account_name, mdo.object_sid, mdo.object_guid::text)
                                     ORDER BY COALESCE(mdo.sam_account_name, mdo.object_sid, mdo.object_guid::text))
                    FROM group_member_edge gme
                    JOIN directory_object mdo ON mdo.object_guid = gme.member_guid AND mdo.client_id = gme.client_id
                    WHERE gme.group_guid = g.object_guid AND gme.client_id = g.client_id AND gme.valid_to IS NULL
                      AND gme.is_primary_group IS NOT TRUE
                )
            ) AS detail
        FROM ad_group g
        JOIN directory_object do2
            ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
        JOIN effective eff ON eff.group_guid = g.object_guid
        LEFT JOIN acl_privileged_groups apg ON apg.object_guid = g.object_guid
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND (apg.object_guid IS NOT NULL
               OR (g.is_protected_group
                   AND do2.object_sid ~ '-(512|516|518|519|521|526|527|544|548|549|550|551|552)$'))
          AND eff.n > 5
    """,
}
