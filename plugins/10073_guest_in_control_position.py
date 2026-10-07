"""
Plugin 10073: Guest Owns a Sensitive Group or Application, or Sits in a Role-Assignable Group

Reports B2B guest accounts that hold a control position plugin 10006 does
not see (10006 only reports directory roles the guest actually holds):

- Owner of a sensitive group (entra_group_owner; sensitive = role-assignable,
  holds a role, named in Conditional Access, or granted a privileged app
  role -- see entra_group.sensitive_reasons). An owner can change the
  group's membership, so it controls whatever the group grants or is
  excluded from. High when the group is role-assignable or holds a
  directory role (entra_group.is_assignable_to_role, sensitive_reasons
  'role_assignable' / 'holds_role', or the group appears as a role
  member); medium otherwise.
- Owner of an application registration or service principal
  (entra_app_owner). An owner can add credentials and act as the
  application. High when the application is privileged: its service
  principal holds a highly privileged (Tier 0) directory role or one of the
  dangerous Graph application permissions of plugin 10007
  (entra_dangerous_permission_grant); medium otherwise. For an application
  registration the service principal is found by appId in
  entra_service_principal (source service_principals); without that
  source an owned registration is medium and detail.coverage_notes says
  privilege could not be checked.
- Member of a role-assignable group while holding no directory role at
  all (not in entra_directory_role_member) -> medium: a latent path (a
  role assigned to the group later, or a PIM-for-groups activation)
  that 10006 cannot show yet. Guests that do hold a role are 10006's.

Guest = entra_user.user_type 'Guest', the owner/member row's user type
'Guest', or an #EXT# UPN. One finding per guest (object_guid = the guest's
Entra object id), worst severity wins, every item listed sorted. A
disabled guest is reported low ('warn').

Requires sources groups and app_owners; each half is also only evaluated
when its own source is 'ok'.
"""

PLUGIN = {
    "plugin_id": 10073,
    "category": "Hybrid Identity",
    "name": "Guest Owns a Sensitive Group or Application, or Sits in a Role-Assignable Group",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10073",
    "requires_sources": ["groups", "app_owners"],
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-20",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-8.2.7",
        "CIS-CSC-8-6.7",
        "ISO-27001-2022-A.5.19",
        "ISO-27001-2022-A.5.23",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1098.001",
        "MITRE-ATTCK-T1098.003",
    ],
    "references": [
        {"title": "Microsoft: Use Microsoft Entra groups to manage role assignments",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/groups-concept"},
        {"title": "Microsoft: Overview of enterprise application ownership",
         "url": "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/overview-assign-app-owners"},
        {"title": "Microsoft: Properties of a B2B guest user",
         "url": "https://learn.microsoft.com/en-us/entra/external-id/user-properties"},
    ],
    "description": (
        "A B2B guest -- an identity whose credentials and lifecycle are "
        "governed by another organization -- owns a sensitive group (can "
        "change who holds what it grants), owns an application or service "
        "principal (can add credentials and act as it), or is a member of "
        "a role-assignable group without currently holding a role. High "
        "when the owned group is role-assignable or holds a role, or the "
        "owned application holds a Tier 0 role or a dangerous Graph "
        "permission; medium otherwise; low when the guest is disabled. "
        "One finding per guest."
    ),
    "remediation": (
        "Remove the guest as owner (Remove-MgGroupOwnerByRef / "
        "Remove-MgApplicationOwnerByRef / Remove-MgServicePrincipalOwnerByRef) "
        "and assign ownership to an internal, ideally cloud-only, account; "
        "remove guests from role-assignable groups "
        "(Remove-MgGroupMemberByRef). If an external administrator is "
        "genuinely required, give them a member account in this tenant "
        "under your own MFA and lifecycle controls rather than a guest. "
        "Set 'AllowGuestsToBeGroupOwner' to false in the Group.Unified "
        "directory setting."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0_role(role_template_id) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid), ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid), ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid), ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid), ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid), ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid), ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid)
        ),
        src AS (
            SELECT bool_or(s.source = 'groups' AND s.status = 'ok') AS groups_ok,
                   bool_or(s.source = 'app_owners' AND s.status = 'ok') AS owners_ok,
                   bool_or(s.source = 'service_principals' AND s.status = 'ok') AS sps_ok
              FROM (SELECT 1) one
              LEFT JOIN entra_collection_status s ON s.client_id = %(client_id)s
        ),
        priv_sp AS (
            SELECT rm.member_id AS sp_id, 'holds ' || COALESCE(rm.role_display_name, rm.role_template_id::text) AS why
              FROM entra_directory_role_member rm
              JOIN tier0_role t ON t.role_template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.servicePrincipal'
            UNION
            SELECT g.principal_id, 'has Graph application permission ' || g.permission_name
              FROM entra_dangerous_permission_grant g
             WHERE g.client_id = %(client_id)s
        ),
        role_holder AS (
            SELECT DISTINCT rm.member_id FROM entra_directory_role_member rm WHERE rm.client_id = %(client_id)s
        ),
        group_holds_role AS (
            SELECT DISTINCT COALESCE(rm.via_group_id, rm.member_id) AS group_id
              FROM entra_directory_role_member rm
             WHERE rm.client_id = %(client_id)s
               AND (rm.member_type = '#microsoft.graph.group' OR rm.via_group_id IS NOT NULL)
        ),
        item AS (
            -- owner of a sensitive group
            SELECT go.owner_id AS guest_id, go.owner_upn AS upn, go.owner_display_name AS display_name,
                   go.owner_account_enabled AS account_enabled,
                   CASE WHEN g.is_assignable_to_role IS TRUE
                          OR g.sensitive_reasons && ARRAY['role_assignable', 'holds_role']
                          OR ghr.group_id IS NOT NULL THEN 3 ELSE 2 END AS rank,
                   ('owns group "' || COALESCE(g.display_name, go.group_id::text) || '"'
                    || CASE WHEN g.is_assignable_to_role IS TRUE
                              OR g.sensitive_reasons && ARRAY['role_assignable', 'holds_role']
                              OR ghr.group_id IS NOT NULL
                            THEN ' (role-assignable or holds a directory role)'
                            ELSE ' (sensitive: ' || COALESCE(array_to_string(g.sensitive_reasons, ', '), '') || ')' END
                   ) COLLATE "C" AS label,
                   NULL::text AS note
              FROM entra_group_owner go
              CROSS JOIN src
              LEFT JOIN entra_group g ON g.client_id = go.client_id AND g.entra_object_id = go.group_id
              LEFT JOIN group_holds_role ghr ON ghr.group_id = go.group_id
              LEFT JOIN entra_user eu ON eu.client_id = go.client_id AND eu.entra_object_id = go.owner_id
             WHERE go.client_id = %(client_id)s
               AND src.groups_ok
               AND COALESCE(go.owner_type, '#microsoft.graph.user') = '#microsoft.graph.user'
               AND (go.owner_user_type = 'Guest' OR eu.user_type = 'Guest'
                    OR COALESCE(go.owner_upn, eu.user_principal_name) ILIKE '%%#EXT#%%')
            UNION ALL
            -- owner of an application registration or service principal
            SELECT ao.owner_id, ao.owner_upn, ao.owner_display_name, ao.owner_account_enabled,
                   CASE WHEN p.why IS NOT NULL THEN 3 ELSE 2 END,
                   ('owns ' || CASE ao.owned_object_type WHEN 'application' THEN 'application registration'
                                                         ELSE 'service principal' END
                    || ' "' || COALESCE(ao.owned_display_name, ao.owned_object_id::text) || '"'
                    || CASE WHEN p.why IS NOT NULL THEN ' (privileged: ' || p.why || ')' ELSE '' END
                   ) COLLATE "C",
                   CASE WHEN ao.owned_object_type = 'application' AND NOT src.sps_ok
                        THEN 'service principals were not collected, so the privilege of owned application '
                             || 'registrations could not be checked' END
              FROM entra_app_owner ao
              CROSS JOIN src
              LEFT JOIN entra_user eu ON eu.client_id = ao.client_id AND eu.entra_object_id = ao.owner_id
              LEFT JOIN LATERAL (
                  SELECT string_agg(DISTINCT ps.why, ', ' ORDER BY ps.why) AS why
                    FROM priv_sp ps
                   WHERE ps.sp_id = ao.owned_object_id AND ao.owned_object_type = 'servicePrincipal'
                      OR (ao.owned_object_type = 'application' AND src.sps_ok
                          AND ps.sp_id IN (SELECT sp.entra_object_id FROM entra_service_principal sp
                                            WHERE sp.client_id = ao.client_id AND sp.app_id = ao.owned_app_id))
              ) p ON TRUE
             WHERE ao.client_id = %(client_id)s
               AND src.owners_ok
               AND COALESCE(ao.owner_type, '#microsoft.graph.user') = '#microsoft.graph.user'
               AND (ao.owner_user_type = 'Guest' OR eu.user_type = 'Guest'
                    OR COALESCE(ao.owner_upn, eu.user_principal_name) ILIKE '%%#EXT#%%')
            UNION ALL
            -- member of a role-assignable group without holding any role
            SELECT gm.member_id, gm.member_upn, gm.member_display_name, gm.account_enabled,
                   2,
                   ('member of role-assignable group "' || COALESCE(g.display_name, gm.group_id::text)
                    || '" without a directory role yet') COLLATE "C",
                   NULL
              FROM entra_group_member gm
              CROSS JOIN src
              JOIN entra_group g ON g.client_id = gm.client_id AND g.entra_object_id = gm.group_id
              LEFT JOIN entra_user eu ON eu.client_id = gm.client_id AND eu.entra_object_id = gm.member_id
             WHERE gm.client_id = %(client_id)s
               AND src.groups_ok
               AND (g.is_assignable_to_role IS TRUE OR 'role_assignable' = ANY (g.sensitive_reasons))
               AND COALESCE(gm.member_type, '#microsoft.graph.user') = '#microsoft.graph.user'
               AND (gm.member_user_type = 'Guest' OR eu.user_type = 'Guest'
                    OR COALESCE(gm.member_upn, eu.user_principal_name) ILIKE '%%#EXT#%%')
               AND NOT EXISTS (SELECT 1 FROM role_holder rh WHERE rh.member_id = gm.member_id)
        ),
        agg AS (
            SELECT i.guest_id,
                   COALESCE(min(eu.user_principal_name), min(i.upn)) AS upn,
                   COALESCE(min(eu.display_name), min(i.display_name)) AS display_name,
                   COALESCE(bool_or(eu.account_enabled), bool_or(i.account_enabled)) AS account_enabled,
                   max(i.rank) AS rank,
                   string_agg(DISTINCT i.label, '; ' ORDER BY i.label) AS items_text,
                   jsonb_agg(DISTINCT i.label ORDER BY i.label) AS items,
                   jsonb_agg(DISTINCT i.note) FILTER (WHERE i.note IS NOT NULL) AS notes
              FROM item i
              LEFT JOIN entra_user eu ON eu.client_id = %(client_id)s AND eu.entra_object_id = i.guest_id
             GROUP BY i.guest_id
        )
        SELECT
            CASE WHEN a.account_enabled IS FALSE THEN 'warn' ELSE 'fail' END AS status,
            a.guest_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN a.account_enabled IS FALSE THEN 'low'
                 WHEN a.rank = 3 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Guest ' || COALESCE(a.upn, a.display_name, a.guest_id::text) || ' '
                || a.items_text
                || CASE WHEN a.account_enabled IS FALSE THEN ' (account disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'guest_id', a.guest_id,
                'user_principal_name', a.upn,
                'display_name', a.display_name,
                'account_enabled', a.account_enabled,
                'control_positions', a.items,
                'coverage_notes', COALESCE(a.notes, '[]'::jsonb),
                'related_plugins', jsonb_build_array(10006)
            ) AS detail
        FROM agg a
    """,
}
