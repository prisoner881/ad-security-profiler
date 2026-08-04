"""
Plugin 1025: User Account Has a Stale AdminSDHolder Protection Marker

Direct port of the same insight built for groups (plugin 3005, ad_group)
to user accounts. admin_count=1 is set by the AdminSDHolder/SDProp
process when an account is (or was) a member of a protected group, but
it is a sticky marker that SDProp does not automatically clear when the
account is later removed from that group. Same non-circular RID-based
root-group list used for the group-side version, verified against the
same sources (see plugin 3005 for the full citation).

[v1.1] Excludes krbtgt (RID 502), found firing against real production
data: krbtgt is, by design, always disabled and always carries
admin_count=1, completely independent of group nesting. Same precedent
already established for Key Admins/Enterprise Key Admins in plugin
3005 -- applied here rather than treated as a fresh judgment call.
"""

PLUGIN = {
    "plugin_id": 1025,
    "category": "User Accounts",
    "name": "User Account Has a Stale AdminSDHolder Protection Marker",
    "version": "1.4",
    "revision_date": "2026-07-15",
    "remediation": (
        "Investigate why this account is no longer a member of a "
        "privileged group despite carrying the AdminSDHolder protection "
        "marker -- usually genuinely stale historical residue (the "
        "account was privileged at some point, was later removed from "
        "that group, and admin_count was simply never reset), not "
        "itself a vulnerability. Confirm the account's ACLs don't still "
        "reflect protected-object hardening that's no longer "
        "appropriate for its current, non-privileged role, then clear "
        "the marker (`Set-ADUser -Clear adminCount`, and separately "
        "re-enable ACL inheritance if SDProp had disabled it) once "
        "confirmed safe to do so."
    ),
    "control_id": "PRIV-109",
    "framework_tags": [],
    "references": [],
    "description": (
        "Same reasoning as plugin 3005 (the group-side version of this "
        "check), applied to user accounts. admin_count=1 is set by the "
        "AdminSDHolder/SDProp process when an account is (or was) a "
        "member of a protected group, but is a sticky marker that "
        "SDProp does not automatically clear when the account is later "
        "removed from that group. Cross-checked against genuinely "
        "current effective membership in a curated, non-circular list "
        "of well-known privileged root groups (identified by RID, not "
        "by admin_count itself, for the same reason described in "
        "plugin 3005) rather than assuming the marker still reflects "
        "reality."
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
              -- Same verified 11-group AdminSDHolder-protected list as
              -- plugin 3005 -- see that plugin for source citations.
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
        acl_privileged_users AS (
            -- [v1.x, ACL-aware] Same fix just applied to plugin 3005's
            -- group-side version: an account can be genuinely, currently
            -- privileged without any group nesting at all, if it
            -- directly holds dangerous or DCSync rights on the domain
            -- root/AdminSDHolder, or owns either object outright. Such
            -- an account's admin_count=1 is NOT stale -- excluding it
            -- here avoids a real false positive.
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
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' carries the AdminSDHolder protection marker (admin_count=1) but is '
                'not currently a member, directly or indirectly, of any well-known '
                'privileged root group' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'admin_count', u.admin_count
            ) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
        LEFT JOIN currently_nested cn ON cn.object_guid = u.object_guid
        LEFT JOIN acl_privileged_users apu ON apu.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.admin_count = 1
          AND cn.object_guid IS NULL
          AND apu.object_guid IS NULL
          -- [v1.1] krbtgt (RID 502) is, by design, always disabled and
          -- always carries admin_count=1, completely independent of
          -- group nesting -- fundamental to how Kerberos operates, not
          -- residue from removal from a privileged group. Same
          -- precedent already established for Key Admins/Enterprise Key
          -- Admins in plugin 3005: excluded here rather than treated as
          -- a fresh judgment call, since without this exclusion the
          -- finding would fire in literally every domain and add noise
          -- rather than signal. RID-based (not name-based) to match the
          -- established rename-resistant detection pattern used
          -- throughout this project.
          AND COALESCE(udo.object_sid, '') NOT LIKE '%%-502'
    """,
}
