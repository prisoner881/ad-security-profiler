"""
Plugin 10026: Users Excluded from MFA Conditional Access Coverage

Reports each enabled user (members and guests) who is not covered by ANY of
the tenant's enabled "all users, all resources" MFA Conditional Access
policies because every one of them excludes the user -- directly
(excludeUsers), through an excluded group (excludeGroups, transitive
membership), through an excluded directory role (excludeRoles, active
assignment), or as a guest (excludeUsers 'GuestsOrExternalUsers' or an
excludeGuestsOrExternalUsers object).

Why it matters: plugin 10004 only checks that some MFA policy exists.
Exclusions accumulate over the years (migrations, service accounts, a
"temporary" exception group) and an excluded account signs in with a
password alone -- the first target of a password spray (MITRE T1110.003).
CISA SCuBA MS.AAD.3.1 / 3.2 require MFA to be enforced for ALL users.

Scope:
- Only evaluated when at least one enabled policy includes all users
  (includeUsers 'All'), targets all resources (includeApplications 'All')
  and blocks or requires MFA mandatorily ('mfa' or an authentication
  strength, under operator AND or as the only grant control). Otherwise
  nothing is returned: plugin 10004 already reports the missing (or
  optional) MFA policy.
- A user counts as covered when at least one such policy does not exclude
  them. Per-app policies are not credited.
- Break-glass (emergency access) accounts are exempt, by the shared
  definition: the client's declared accounts (entra_breakglass_account, by
  UPN) when any are declared; otherwise the heuristic -- enabled cloud-only
  member holding Global Administrator by direct active assignment and
  listed directly in excludeUsers of an enabled policy that includes all
  users. detail.breakglass_mode says which mode applied.
- Disabled accounts are skipped (they can't sign in).

Severity: fail / high for users holding a highly privileged role (the 13
Tier 0 roles of plugin 11020, active or eligible); warn / medium for others.
object_guid = the user's Entra object id.

Group exclusions need group membership (source 'groups'). When an all-users
MFA policy excludes groups and that source is not 'ok', the group exclusions
are not evaluated (users excluded only through such a group are not
reported) and a single warn / low row (object_guid =
md5('10026:' || client_id || ':groups')) says so.

Data caveats: needs the CA policy conditions (entra_graph_collector
0.7.0+); if an enabled policy requiring MFA or blocking has no conditions
object, nothing is returned. Guest exclusion via
excludeGuestsOrExternalUsers is treated as excluding every guest (the
guest-type / external-tenant filter is not evaluated).
"""

PLUGIN = {
    "plugin_id": 10026,
    "category": "Hybrid Identity",
    "name": "Users Excluded from MFA Conditional Access Coverage",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10026",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.3.1",
        "CISA-SCUBA-MS.AAD.3.2",
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-IA-2(2)",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.4.2",
        "PCI-DSS-4.0-8.4.3",
        "CIS-CSC-8-6.3",
        "CIS-CSC-8-6.4",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "HIPAA-164.312(d)",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1110.003",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.3.1, MS.AAD.3.2)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Conditional Access users and groups (include / exclude)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-users-groups"},
        {"title": "Microsoft: Manage emergency access accounts in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access"},
    ],
    "description": (
        "Enabled users (members and guests) that every enabled all-users, "
        "all-resources MFA Conditional Access policy excludes -- directly, "
        "by group, by role or as guests -- so they sign in with a password "
        "alone. Emergency-access accounts are exempt. High for holders of "
        "highly privileged roles, medium otherwise (SCuBA MS.AAD.3.1/3.2)."
    ),
    "remediation": (
        "For each reported user, find the exclusion (detail.exclusions) and "
        "remove it from the policy, or remove the user from the excluded "
        "group. Keep only the documented emergency-access accounts excluded "
        "(declare them in entra_breakglass_account so this check recognises "
        "them). For accounts that genuinely cannot do interactive MFA "
        "(service accounts), replace them with workload identities (managed "
        "identities / service principals) rather than excluding them, and "
        "for guests prefer cross-tenant MFA trust over exclusion."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0(role_template_id) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid), ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid), ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid), ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid), ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid), ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid), ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid)
        ),
        posture AS (
            SELECT sp.client_id, sp.ca_policies
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
        ),
        raw AS (
            SELECT p->>'id' AS id,
                   COALESCE(p->>'display_name', p->>'id') COLLATE "C" AS name,
                   COALESCE(jsonb_typeof(p->'conditions') = 'object', FALSE) AS evaluable,
                   CASE WHEN jsonb_typeof(p->'grant_controls'->'builtInControls') = 'array'
                        THEN p->'grant_controls'->'builtInControls' ELSE '[]'::jsonb END AS builtin,
                   upper(COALESCE(p->'grant_controls'->>'operator', 'OR')) AS operator,
                   COALESCE(jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object', FALSE) AS has_strength,
                   (CASE WHEN jsonb_typeof(p->'grant_controls'->'customAuthenticationFactors') = 'array'
                         THEN jsonb_array_length(p->'grant_controls'->'customAuthenticationFactors') ELSE 0 END
                    + CASE WHEN jsonb_typeof(p->'grant_controls'->'termsOfUse') = 'array'
                           THEN jsonb_array_length(p->'grant_controls'->'termsOfUse') ELSE 0 END) AS other_controls,
                   COALESCE(p->'conditions'->'users'->'includeUsers', '[]'::jsonb) ? 'All' AS all_users,
                   COALESCE(p->'conditions'->'applications'->'includeApplications', '[]'::jsonb) ? 'All' AS all_apps,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeUsers') = 'array'
                        THEN p->'conditions'->'users'->'excludeUsers' ELSE '[]'::jsonb END AS ex_users,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeGroups') = 'array'
                        THEN p->'conditions'->'users'->'excludeGroups' ELSE '[]'::jsonb END AS ex_groups,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeRoles') = 'array'
                        THEN p->'conditions'->'users'->'excludeRoles' ELSE '[]'::jsonb END AS ex_roles,
                   COALESCE(jsonb_typeof(p->'conditions'->'users'->'excludeGuestsOrExternalUsers') = 'object', FALSE)
                       AS ex_guest_obj
              FROM posture po
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(po.ca_policies) = 'array' THEN po.ca_policies ELSE '[]'::jsonb END) p
             WHERE p->>'state' = 'enabled'
        ),
        pol AS (
            SELECT r.*,
                   (r.builtin ? 'block'
                    OR ((r.builtin ? 'mfa' OR r.has_strength)
                        AND (r.operator = 'AND'
                             OR jsonb_array_length(r.builtin) + CASE WHEN r.has_strength THEN 1 ELSE 0 END
                                + r.other_controls <= 1))) AS protects,
                   (r.builtin ? 'block' OR r.builtin ? 'mfa' OR r.has_strength) AS mfa_or_block
              FROM raw r
        ),
        q AS (
            -- the all-users, all-resources MFA (or block) policies
            SELECT * FROM pol WHERE evaluable AND all_users AND all_apps AND protects
        ),
        state AS (
            SELECT po.client_id,
                   EXISTS (SELECT 1 FROM pol WHERE NOT evaluable AND mfa_or_block) AS unevaluable,
                   EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = po.client_id AND s.source = 'groups' AND s.status = 'ok') AS groups_ok,
                   EXISTS (SELECT 1 FROM entra_breakglass_account b WHERE b.client_id = po.client_id) AS bg_declared,
                   (SELECT count(*) FROM q) AS n_q
              FROM posture po
        ),
        usr AS (
            SELECT u.entra_object_id AS uid, u.user_principal_name AS upn, u.user_type,
                   u.on_premises_sync_enabled
              FROM entra_user u
             WHERE u.client_id = %(client_id)s
               AND u.account_enabled IS TRUE
        ),
        active_role AS (
            SELECT DISTINCT m.member_id AS uid, m.role_template_id
              FROM entra_directory_role_member m
             WHERE m.client_id = %(client_id)s
               AND m.assignment_type = 'active'
               AND m.role_template_id IS NOT NULL
        ),
        tier0_holder AS (
            SELECT m.member_id AS uid,
                   jsonb_agg(DISTINCT m.role_display_name ORDER BY m.role_display_name) AS roles
              FROM entra_directory_role_member m
              JOIN tier0 t ON t.role_template_id = m.role_template_id
             WHERE m.client_id = %(client_id)s
             GROUP BY m.member_id
        ),
        grp AS (
            SELECT gm.member_id AS uid, gm.group_id
              FROM entra_group_member gm
              CROSS JOIN state s
             WHERE gm.client_id = %(client_id)s AND s.groups_ok
        ),
        excl AS (
            -- why policy q excludes user u (empty array = not excluded)
            SELECT u.uid, qq.id, qq.name,
                   array_remove(ARRAY[
                       CASE WHEN EXISTS (SELECT 1 FROM jsonb_array_elements_text(qq.ex_users) e
                                          WHERE lower(e) = u.uid::text) THEN 'user' END,
                       CASE WHEN u.user_type = 'Guest'
                                 AND (qq.ex_users ? 'GuestsOrExternalUsers' OR qq.ex_guest_obj) THEN 'guest' END,
                       (SELECT 'group:' || string_agg(g.group_id::text, ',' ORDER BY g.group_id)
                          FROM grp g
                         WHERE g.uid = u.uid
                           AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(qq.ex_groups) e
                                        WHERE lower(e) = g.group_id::text)),
                       (SELECT 'role:' || string_agg(ar.role_template_id::text, ',' ORDER BY ar.role_template_id)
                          FROM active_role ar
                         WHERE ar.uid = u.uid
                           AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(qq.ex_roles) e
                                        WHERE lower(e) = ar.role_template_id::text))
                   ], NULL) AS reasons
              FROM usr u
              CROSS JOIN q qq
        ),
        uncovered AS (
            SELECT e.uid,
                   jsonb_agg(jsonb_build_object('policy', e.name, 'id', e.id, 'excluded_by', to_jsonb(e.reasons))
                             ORDER BY e.name, e.id) AS exclusions
              FROM excl e
             GROUP BY e.uid
            HAVING bool_and(cardinality(e.reasons) > 0)
        ),
        breakglass AS (
            SELECT u.uid
              FROM usr u
              CROSS JOIN state s
             WHERE (s.bg_declared
                    AND EXISTS (SELECT 1 FROM entra_breakglass_account b
                                 WHERE b.client_id = %(client_id)s
                                   AND lower(b.user_principal_name) = lower(u.upn)))
                OR (NOT s.bg_declared
                    AND u.user_type = 'Member'
                    AND u.on_premises_sync_enabled IS NOT TRUE
                    AND EXISTS (SELECT 1 FROM entra_directory_role_member m
                                 WHERE m.client_id = %(client_id)s AND m.member_id = u.uid
                                   AND m.role_template_id = '62e90394-69f5-4237-9190-012177145e10'
                                   AND m.assignment_type = 'active' AND m.via_group_id IS NULL)
                    AND EXISTS (SELECT 1 FROM pol p
                                 WHERE p.evaluable AND p.all_users
                                   AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(p.ex_users) e
                                                WHERE lower(e) = u.uid::text)))
        )
        SELECT
            CASE WHEN th.uid IS NOT NULL THEN 'fail' ELSE 'warn' END AS status,
            u.uid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN th.uid IS NOT NULL THEN 'high' ELSE 'medium' END AS fd_severity,
            CASE WHEN u.user_type = 'Guest' THEN 'Guest user ' ELSE 'User ' END
                || COALESCE(u.upn, u.uid::text)
                || ' is excluded from every all-users MFA Conditional Access policy'
                || CASE WHEN th.uid IS NOT NULL THEN ' and holds a highly privileged role' ELSE '' END AS summary,
            jsonb_build_object(
                'user_principal_name', u.upn,
                'user_type', u.user_type,
                'on_premises_sync_enabled', u.on_premises_sync_enabled,
                'privileged_roles', th.roles,
                'exclusions', uc.exclusions,
                'group_exclusions_evaluated', s.groups_ok,
                'breakglass_mode', CASE WHEN s.bg_declared THEN 'declared' ELSE 'heuristic' END
            ) AS detail
        FROM uncovered uc
        JOIN usr u ON u.uid = uc.uid
        CROSS JOIN state s
        LEFT JOIN tier0_holder th ON th.uid = u.uid
        WHERE NOT s.unevaluable
          AND s.n_q > 0
          AND NOT EXISTS (SELECT 1 FROM breakglass b WHERE b.uid = u.uid)
        UNION ALL
        SELECT
            'warn',
            md5('10026:' || s.client_id::text || ':groups')::uuid,
            NULL, NULL, NULL, NULL,
            'low',
            'Group exclusions from the all-users MFA Conditional Access policies could not be evaluated -- '
                || 'group membership was not collected',
            jsonb_build_object(
                'policies_excluding_groups',
                    (SELECT jsonb_agg(jsonb_build_object('policy', qq.name, 'id', qq.id, 'excluded_groups', qq.ex_groups)
                                      ORDER BY qq.name, qq.id)
                       FROM q qq WHERE jsonb_array_length(qq.ex_groups) > 0),
                'note', 'Users excluded only through these groups are not reported; collect the groups source '
                        || '(Directory.Read.All) to evaluate them.'
            )
        FROM state s
        WHERE NOT s.unevaluable
          AND NOT s.groups_ok
          AND EXISTS (SELECT 1 FROM q WHERE jsonb_array_length(q.ex_groups) > 0)
    """,
}
