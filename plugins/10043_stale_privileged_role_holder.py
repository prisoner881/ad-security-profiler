"""
Plugin 10043: Stale Privileged Entra ID Role Holder

Detects enabled users holding a highly privileged Entra role (TIER0 set:
Global, Privileged Role, Privileged Authentication, Security, Hybrid
Identity, Application, Cloud Application, Exchange, SharePoint, User,
Conditional Access, Authentication and Intune Administrator; active or
PIM-eligible, directly or via a role-assignable group) with no sign-in
activity for 45 days or more: the latest of lastSuccessfulSignInDateTime,
lastSignInDateTime and lastNonInteractiveSignInDateTime is older than 45
days, or none is recorded and the account was created more than 45 days
ago.

Why: standing privilege that nobody uses is pure risk -- an unattended
administrator account is a high-value takeover target whose misuse its
owner will not notice (MITRE ATT&CK T1078.004; CISA AA24-057A). The fix is
to remove the role (or the account), not to sign in.

Data: entra_user signInActivity columns and created_at (schema v42;
AuditLog.Read.All + Entra ID P1) and entra_directory_role_member.
requires_sources ['sign_in_activity']: the query also checks the source is
'ok' and returns nothing otherwise. Microsoft only records sign-ins since
April 2020.

Excluded: disabled accounts (plugin 10045 covers disabled role holders),
accounts without created_at and without activity (age unknown), and
break-glass accounts, which are meant to be unused (plugin 10055 checks
them; declared in entra_breakglass_account, otherwise the heuristic:
cloud-only enabled member with direct active Global Administrator excluded
by name from an enabled Conditional Access policy that targets all users --
the mode used is in the detail). Guests holding privileged roles are
included (plugin 10006 also reports them).

Severity: high (fail), one row per user (identity = Entra object id). The
summary states the threshold, not the age; the exact age is in the detail.
"""

PLUGIN = {
    "plugin_id": 10043,
    "category": "Hybrid Identity",
    "name": "Stale Privileged Entra ID Role Holder",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10043",
    "requires_sources": ["sign_in_activity"],
    "framework_tags": [
        "NIST-800-53-AC-2(3)",
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-CSF-2.0-PR.AA-01",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-8.2.6",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-5.3",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.5.18",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.2",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: How to manage inactive user accounts",
         "url": "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts"},
        {"title": "Microsoft: Best practices for Microsoft Entra roles",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices"},
        {"title": "MITRE ATT&CK T1078.004: Valid Accounts: Cloud Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/004/"},
    ],
    "description": (
        "An enabled user holding a highly privileged Entra role (active or PIM-eligible) "
        "has not signed in for 45 days or more, or has never signed in and was created "
        "more than 45 days ago. Unused standing privilege is an unwatched takeover "
        "target. Break-glass accounts are excluded (plugin 10055). High, one finding per "
        "user listing the roles held."
    ),
    "remediation": (
        "Confirm with the owner whether the role is still needed. Remove unused role "
        "assignments and eligibilities (Entra admin center > Roles and administrators, "
        "or Remove-MgRoleManagementDirectoryRoleAssignment / "
        "Remove-MgRoleManagementDirectoryRoleEligibilityScheduleRequest), and disable "
        "accounts that are no longer needed. Use PIM access reviews for privileged roles "
        "(e.g. quarterly) with auto-removal of members who do not respond, and declare "
        "break-glass accounts in the profiler (entra_breakglass_account) so they are "
        "checked by plugin 10055 instead."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0 (template_id, role_name) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid, 'Global Administrator'),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'Privileged Role Administrator'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'Privileged Authentication Administrator'),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid, 'Security Administrator'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'Hybrid Identity Administrator'),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid, 'Application Administrator'),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid, 'Cloud Application Administrator'),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid, 'Exchange Administrator'),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid, 'SharePoint Administrator'),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid, 'User Administrator'),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid, 'Conditional Access Administrator'),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid, 'Authentication Administrator'),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid, 'Intune Administrator')
        ),
        priv AS (
            SELECT rm.member_id,
                   array_agg(DISTINCT t.role_name || CASE WHEN rm.assignment_type = 'eligible'
                                                          THEN ' (eligible)' ELSE '' END
                             ORDER BY t.role_name || CASE WHEN rm.assignment_type = 'eligible'
                                                          THEN ' (eligible)' ELSE '' END) AS roles
              FROM entra_directory_role_member rm
              JOIN tier0 t ON t.template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.user'
             GROUP BY rm.member_id
        ),
        bg_declared AS (
            SELECT lower(b.user_principal_name) AS upn
              FROM entra_breakglass_account b
             WHERE b.client_id = %(client_id)s
        ),
        bg_mode AS (
            SELECT CASE WHEN EXISTS (SELECT 1 FROM bg_declared) THEN 'declared' ELSE 'heuristic' END AS mode
        ),
        breakglass AS (
            SELECT u.entra_object_id
              FROM entra_user u CROSS JOIN bg_mode m
             WHERE u.client_id = %(client_id)s
               AND m.mode = 'declared'
               AND lower(u.user_principal_name) IN (SELECT upn FROM bg_declared)
            UNION
            SELECT u.entra_object_id
              FROM entra_user u CROSS JOIN bg_mode m
             WHERE u.client_id = %(client_id)s
               AND m.mode = 'heuristic'
               AND u.user_type = 'Member'
               AND u.account_enabled IS TRUE
               AND u.on_premises_sync_enabled IS NOT TRUE
               AND EXISTS (SELECT 1 FROM entra_directory_role_member rm
                            WHERE rm.client_id = u.client_id
                              AND rm.member_id = u.entra_object_id
                              AND rm.role_template_id = '62e90394-69f5-4237-9190-012177145e10'::uuid
                              AND rm.assignment_type = 'active'
                              AND rm.via_group_id IS NULL)
               AND EXISTS (SELECT 1
                             FROM entra_security_posture sp
                            CROSS JOIN LATERAL jsonb_array_elements(
                                  CASE WHEN jsonb_typeof(sp.ca_policies) = 'array'
                                       THEN sp.ca_policies ELSE '[]'::jsonb END) p
                            WHERE sp.client_id = u.client_id
                              AND p->>'state' = 'enabled'
                              AND jsonb_typeof(p->'conditions'->'users'->'includeUsers') = 'array'
                              AND p->'conditions'->'users'->'includeUsers' ? 'All'
                              AND jsonb_typeof(p->'conditions'->'users'->'excludeUsers') = 'array'
                              AND p->'conditions'->'users'->'excludeUsers' ? u.entra_object_id::text)
        ),
        src AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s
                              AND s.source = 'sign_in_activity'
                              AND s.status = 'ok') AS ok
        ),
        users AS (
            SELECT u.*, p.roles,
                   greatest(u.last_successful_sign_in_at, u.last_sign_in_at,
                            u.last_non_interactive_sign_in_at) AS last_activity
              FROM entra_user u
              JOIN priv p ON p.member_id = u.entra_object_id
             CROSS JOIN src
             WHERE u.client_id = %(client_id)s
               AND src.ok
               AND u.account_enabled IS TRUE
               AND u.entra_object_id NOT IN (SELECT entra_object_id FROM breakglass)
        ),
        stale AS (
            SELECT u.*
              FROM users u
             WHERE u.last_activity < now() - interval '45 days'
                OR (u.last_activity IS NULL AND u.created_at < now() - interval '45 days')
        )
        SELECT
            'fail' AS status,
            s.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Privileged user "' || COALESCE(s.user_principal_name, s.entra_object_id::text) || '" '
                || CASE WHEN s.last_activity IS NULL
                        THEN 'has never signed in and was created 45 days or more ago'
                        ELSE 'has not signed in for 45 days or more' END
                || ' (holds ' || array_to_string(s.roles, ', ') || ')' AS summary,
            jsonb_build_object(
                'user_principal_name', s.user_principal_name,
                'display_name', s.display_name,
                'user_type', s.user_type,
                'privileged_roles', to_jsonb(s.roles),
                'created_at', s.created_at,
                'last_activity_at', s.last_activity,
                'days_since_last_activity', floor(extract(epoch FROM now() - s.last_activity) / 86400),
                'last_successful_sign_in_at', s.last_successful_sign_in_at,
                'last_sign_in_at', s.last_sign_in_at,
                'last_non_interactive_sign_in_at', s.last_non_interactive_sign_in_at,
                'on_premises_sync_enabled', s.on_premises_sync_enabled,
                'ad_last_logon_timestamp', (SELECT max(au.last_logon_timestamp)
                                              FROM ad_user au
                                             WHERE au.client_id = s.client_id
                                               AND au.object_guid = s.on_prem_object_guid
                                               AND au.valid_to IS NULL),
                'threshold_days', 45,
                'breakglass_mode', (SELECT mode FROM bg_mode)
            ) AS detail
        FROM stale s
    """,
}
