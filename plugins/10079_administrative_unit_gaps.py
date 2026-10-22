"""
Plugin 10079: Sensitive Groups Not Protected by a Restricted Management Administrative Unit

Uses the tenant's administrative units (entra_administrative_unit /
entra_administrative_unit_member, source administrative_units,
entra_graph_collector 0.9.0) and reports:

- a group named in a Conditional Access policy's exclude list
  (entra_group.sensitive_reasons 'ca_exclude') that is not
  role-assignable and is not a member of a restricted management
  administrative unit -> fail / medium. Groups Administrators, User
  Administrators with group rights, Intune administrators and the group's
  owners can change its members, so anyone holding one of those can add
  an account to the exclusion group and walk around the policy. A
  restricted management AU (isMemberManagementRestricted) limits changes
  to administrators scoped to that AU; a role-assignable group is limited
  to Privileged Role Administrators.
- the same for groups used in CA include lists or holding an app role on
  a privileged application ('ca_include', 'app_role') -> warn / low.
- an administrative unit with hidden membership (visibility
  'HiddenMembership') -> warn / low: only its members and AU-scoped
  administrators can see who is in it, which also hides it from reviews.
- a dynamic administrative unit whose rule tests e-mail, UPN or display
  name text without requiring userType Member (same heuristic as plugin
  10075) -> warn / low: guests invited with a matching address come under
  the AU's scoped administrators.

Maester MT.1035, Microsoft Zero Trust assessment 21832, Purple Knight.
One finding per object (object_guid md5('10079:' || client_id || ':' ||
kind || ':' || id)). Requires sources administrative_units and groups.
"""

PLUGIN = {
    "plugin_id": 10079,
    "category": "Hybrid Identity",
    "name": "Sensitive Groups Not Protected by a Restricted Management Administrative Unit",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10079",
    "requires_sources": ["administrative_units", "groups"],
    "framework_tags": [
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-3",
        "NIST-CSF-2.0-PR.AA-05",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1098",
    ],
    "references": [
        {"title": "Microsoft: Restricted management administrative units in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/admin-units-restricted-management"},
        {"title": "Microsoft: Administrative units in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/administrative-units"},
        {"title": "Maester MT.1035: Security groups assigned to Conditional Access policies should be protected by a restricted management AU",
         "url": "https://maester.dev/docs/tests/MT.1035"},
        {"title": "MITRE ATT&CK T1098: Account Manipulation",
         "url": "https://attack.mitre.org/techniques/T1098/"},
    ],
    "description": (
        "A group excluded from Conditional Access (or used to grant a privileged application) "
        "is neither role-assignable nor in a restricted management administrative unit, so "
        "group and user administrators or its owners can add accounts to it. Also lists "
        "administrative units with hidden membership and dynamic ones guests can be pulled "
        "into."
    ),
    "remediation": (
        "Create a restricted management administrative unit (Entra admin center > Roles & "
        "admins > Admin units > Add, 'Restricted management administrative unit' = Yes) and "
        "add the Conditional Access exclusion groups and break-glass accounts to it, or make "
        "the exclusion groups role-assignable (only at creation). Keep exclusion groups "
        "small, owned by the identity team, and under access review. Give AUs visible "
        "membership unless hiding it is required, and require userType Member in dynamic AU "
        "rules."
    ),
    "base_severity": "medium",
    "query": """
        WITH rmau_member AS (
            SELECT DISTINCT m.member_id
              FROM entra_administrative_unit_member m
              JOIN entra_administrative_unit u
                ON u.client_id = m.client_id AND u.unit_id = m.unit_id
             WHERE m.client_id = %(client_id)s
               AND u.is_member_management_restricted IS TRUE
        ),
        grp AS (
            SELECT g.entra_object_id, g.display_name, g.sensitive_reasons,
                   'ca_exclude' = ANY(g.sensitive_reasons) AS ca_exclude
              FROM entra_group g
             WHERE g.client_id = %(client_id)s
               AND g.sensitive_reasons && ARRAY['ca_exclude', 'ca_include', 'app_role']
               AND g.is_assignable_to_role IS NOT TRUE
               AND NOT EXISTS (SELECT 1 FROM rmau_member r WHERE r.member_id = g.entra_object_id)
        ),
        au AS (
            SELECT u.*, lower(regexp_replace(COALESCE(u.membership_rule, ''), '[[:space:]]+', ' ', 'g')) AS r
              FROM entra_administrative_unit u
             WHERE u.client_id = %(client_id)s
        )
        SELECT
            CASE WHEN g.ca_exclude THEN 'fail' ELSE 'warn' END AS status,
            md5('10079:' || %(client_id)s::text || ':group:' || g.entra_object_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.ca_exclude THEN 'medium' ELSE 'low' END AS fd_severity,
            'Group "' || COALESCE(g.display_name, g.entra_object_id::text) || '" ('
                || array_to_string(g.sensitive_reasons, ', ')
                || ') is not role-assignable and not in a restricted management administrative unit; '
                || 'group or user administrators and its owners can change its members' AS summary,
            jsonb_build_object('group', g.display_name, 'group_id', g.entra_object_id,
                               'sensitive_reasons', g.sensitive_reasons) AS detail
        FROM grp g
        UNION ALL
        SELECT
            'warn',
            md5('10079:' || %(client_id)s::text || ':hidden:' || a.unit_id::text)::uuid,
            NULL, NULL, NULL, NULL,
            'low',
            'Administrative unit "' || COALESCE(a.display_name, a.unit_id::text)
                || '" hides its membership (HiddenMembership)',
            jsonb_build_object('administrative_unit', a.display_name, 'unit_id', a.unit_id,
                               'visibility', a.visibility,
                               'restricted_management', a.is_member_management_restricted)
        FROM au a
        WHERE a.visibility = 'HiddenMembership'
        UNION ALL
        SELECT
            'warn',
            md5('10079:' || %(client_id)s::text || ':dynamic:' || a.unit_id::text)::uuid,
            NULL, NULL, NULL, NULL,
            'low',
            'Dynamic administrative unit "' || COALESCE(a.display_name, a.unit_id::text)
                || '" can take in guests invited with a matching address (rule tests e-mail, UPN or display '
                || 'name text and does not require userType Member)',
            jsonb_build_object('administrative_unit', a.display_name, 'unit_id', a.unit_id,
                               'membership_rule', a.membership_rule,
                               'restricted_management', a.is_member_management_restricted)
        FROM au a
        WHERE lower(COALESCE(a.membership_type, '')) = 'dynamic'
          AND lower(COALESCE(a.membership_rule_processing_state, 'on')) = 'on'
          AND (a.r ~ 'user[.](mail|othermails|userprincipalname|displayname) -(contains|match|startswith)'
               OR a.r ~ 'user[.]othermails -any')
          AND NOT a.r ~ 'user[.]usertype -eq "member"'
          AND NOT a.r ~ 'user[.]usertype -ne "guest"'
    """,
}
