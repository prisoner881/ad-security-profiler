"""
Plugin 3004: Privileged Group Has an Unusually Large Number of Members

Every additional member of a privileged group is another account whose
compromise directly grants that privilege -- membership bloat in these
groups is a direct, linear expansion of attack surface. Complementary to
plugin 3003 (which is specific to Schema/Enterprise Admins and flags any
nonzero membership): this applies more broadly to any AdminSDHolder-
protected group, at a higher, "handful of administrators" threshold
rather than zero.
"""

PLUGIN = {
    "plugin_id": 3004,
    "category": "Groups",
    "name": "Privileged Group Has an Unusually Large Number of Members",
    "version": "1.3",
    "revision_date": "2026-07-15",
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
    "framework_tags": [],
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
            -- [v1.x, ACL-aware] "Privileged group" now means the classic,
            -- RID-based is_protected_group definition OR ACL-derived
            -- privilege: the group directly holds a dangerous right or
            -- DCSync rights on the domain root/AdminSDHolder, or owns
            -- either object outright. A group with none of the classic
            -- protected-group RIDs but that itself directly holds
            -- GenericAll on the domain root is privileged in every
            -- meaningful sense, and every member of it inherits that
            -- power -- exactly the same reasoning already applied to
            -- individual user and computer accounts (plugins 1001-1024,
            -- 2008), now extended to groups acting as the trustee.
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
            'medium' AS fd_severity,
            'Privileged Group ' || g.sam_account_name || ' has '
                || g.member_count_direct || ' direct member(s)' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'member_count_direct', g.member_count_direct,
                'privileged_via_group_rid', g.is_protected_group,
                'privileged_via_acl_or_ownership', apg.object_guid IS NOT NULL,
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
