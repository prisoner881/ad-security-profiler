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

[v1.5] The "currently privileged without group nesting" exclusion now
uses the shared Tier 0 view v_privileged_principal (schema v34), minus
its protected_group_member rows (circular here). The old inline subquery
treated a dangerous right on, or ownership of, ANY object as privilege,
so an account that merely had OU delegation or had created an OU was
wrongly treated as currently privileged and its stale marker was hidden.

[v1.6] Excludes the built-in Administrator (RID 500): it is itself an
AdminSDHolder-protected account, so admin_count=1 on it is never stale
even when it has been removed from every protected group. Also treats a
primaryGroupID of a protected global group (512/516/518/519/521) as
current membership. Since schema v36 primary-group membership is also an
edge in group_member_edge (so currently_nested sees it); the explicit
test keeps that right even if the edge is missing.
"""

PLUGIN = {
    "plugin_id": 1025,
    "category": "User Accounts",
    "name": "User Account Has a Stale AdminSDHolder Protection Marker",
    "version": "1.6",
    "revision_date": "2026-10-04",
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
            -- [v1.5] An account can be genuinely, currently privileged
            -- without any protected-group nesting, if it holds control
            -- rights on, or owns, a Tier 0 object, or holds DCSync (directly
            -- or through a group). Such an account's admin_count=1 is NOT
            -- stale. Taken from the shared Tier 0 view (schema v34) rather
            -- than the old inline subquery, which counted a dangerous right
            -- on or ownership of ANY object and so hid genuinely stale
            -- markers on OU delegates and OU creators. The view's
            -- protected_group_member rows are excluded: they rest on
            -- is_protected_group (admin_count=1), the circular signal this
            -- plugin exists to validate -- currently_nested covers real
            -- protected-group membership by RID instead.
            SELECT DISTINCT object_guid
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
              AND privilege_source <> 'protected_group_member'
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
          -- [v1.6] The built-in Administrator (RID 500) is itself an
          -- AdminSDHolder-protected account: its marker is never stale.
          AND COALESCE(udo.object_sid, '') NOT LIKE '%%-500'
          -- [v1.6] A protected global group as primary group is current
          -- protected-group membership (SDProp counts it).
          AND COALESCE(u.primary_group_id, 0) NOT IN (512, 516, 518, 519, 521)
    """,
}
