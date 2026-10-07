"""
Plugin 10055: Emergency-Access (Break-Glass) Accounts Missing or Misconfigured

Identifies the tenant's emergency-access (break-glass) accounts and reports,
in one tenant-level finding, when there are too few of them or when they are
built in a way that makes them unusable in an emergency or attractive to an
attacker.

Which accounts (mode, stated in detail):
- 'declared': when entra_breakglass_account has rows for the client, exactly
  those UPNs (case-insensitive match to entra_user.user_principal_name);
- 'heuristic' otherwise: enabled cloud-only member users (on-premises sync
  not enabled) holding Global Administrator as an active, direct assignment
  (no group) that are listed directly in excludeUsers of at least one
  enabled Conditional Access policy whose includeUsers contains 'All'.

Problems (worst wins: any medium -> medium 'fail', only low -> low 'warn'):
- no identifiable emergency-access account while an enabled CA policy
  requires MFA (or an authentication strength) or blocks for all users ->
  medium (tenant lockout risk if MFA or federation breaks);
- exactly one emergency-access account (Microsoft: at least two) -> medium;
- declared mode only: a declared UPN not found in the tenant, a declared
  account that is disabled, synchronised from on-premises (an AD compromise
  or sync outage takes it too), or does not hold Global Administrator as an
  active direct assignment -> medium; a declared account not excluded from
  any enabled all-users CA policy that enforces MFA/block -> low (a lockout
  risk if that policy misfires);
- a candidate without a phishing-resistant method registered (FIDO2 /
  passkey / Windows Hello / certificate), when registration_details is
  'ok' and the account has a registration row -> medium (Microsoft now
  requires MFA for admin portals; break-glass accounts should use FIDO2 or
  certificate-based authentication);
- a candidate with an Exchange service plan (a mailbox: phishing surface,
  not needed for emergency access) -> low;
- a candidate that signed in during the last 30 days, when sign_in_activity
  is 'ok' -> low (emergency accounts should be used only in emergencies and
  for scheduled tests; unexpected use must be investigated -- Microsoft
  recommends alerting on every sign-in of these accounts).

Why: Microsoft requires two or more cloud-only emergency-access accounts
excluded from Conditional Access; badly built ones are both a lockout risk
and the most attractive CA exclusion to abuse (NIST CP-2, AC-2).

Data caveats: Tier A for the core checks; registration_details and
sign_in_activity are optional enrichment (their status is in detail; the
related checks are skipped when not 'ok'). In heuristic mode, a tenant whose
break-glass accounts are excluded via a group rather than directly is not
recognised; declare them in entra_breakglass_account.

object_guid: md5('10055:' || client_id).
"""

PLUGIN = {
    "plugin_id": 10055,
    "category": "Hybrid Identity",
    "name": "Emergency-Access (Break-Glass) Accounts Missing or Misconfigured",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10055",
    "framework_tags": [
        "NIST-800-53-AC-2",
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-IA-2(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Manage emergency access accounts in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access"},
        {"title": "Microsoft: Planning for mandatory Microsoft Entra multifactor authentication",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-mandatory-multifactor-authentication"},
    ],
    "description": (
        "Emergency-access (break-glass) accounts are missing or badly built: "
        "none identifiable while Conditional Access enforces MFA/block for "
        "all users, only one, or a candidate that is synchronised, disabled, "
        "not a permanent Global Administrator, without a phishing-resistant "
        "method, licensed for Exchange or recently used. Accounts come from "
        "entra_breakglass_account when declared, otherwise from a heuristic "
        "(cloud-only permanent GA excluded from an all-users CA policy). One "
        "tenant-level finding listing every problem."
    ),
    "remediation": (
        "Keep at least two cloud-only (*.onmicrosoft.com) emergency-access "
        "accounts with a permanent, direct Global Administrator assignment, "
        "no licence/mailbox, FIDO2 security keys or certificate-based "
        "authentication stored securely, and excluded from every Conditional "
        "Access policy (directly, or via a dedicated excluded group). Alert "
        "on every sign-in of these accounts (Log Analytics / Sentinel rule) "
        "and test them on a schedule. Record them in "
        "ad_intel.entra_breakglass_account so this and other checks use the "
        "exact accounts rather than the heuristic."
    ),
    "base_severity": "medium",
    "query": """
        WITH declared AS (
            SELECT lower(b.user_principal_name) AS upn, b.user_principal_name AS declared_upn
              FROM entra_breakglass_account b
             WHERE b.client_id = %(client_id)s
        ),
        mode AS (
            SELECT CASE WHEN EXISTS (SELECT 1 FROM declared) THEN 'declared' ELSE 'heuristic' END AS mode
        ),
        src AS (
            SELECT COALESCE(bool_or(s.source = 'registration_details' AND s.status = 'ok'), FALSE) AS reg_ok,
                   COALESCE(bool_or(s.source = 'sign_in_activity' AND s.status = 'ok'), FALSE) AS sia_ok,
                   max(s.status) FILTER (WHERE s.source = 'registration_details') AS reg_status,
                   max(s.status) FILTER (WHERE s.source = 'sign_in_activity') AS sia_status
              FROM entra_collection_status s
             WHERE s.client_id = %(client_id)s
        ),
        all_users_pol AS (
            SELECT p->>'display_name' AS display_name,
                   (COALESCE(p->'grant_controls'->'builtInControls', '[]'::jsonb) ?| ARRAY['mfa', 'block']
                    OR jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object') AS enforcing,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeUsers') = 'array'
                        THEN p->'conditions'->'users'->'excludeUsers' ELSE '[]'::jsonb END AS exclude_users
              FROM entra_security_posture sp
              CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(sp.ca_policies) = 'array'
                                                           THEN sp.ca_policies ELSE '[]'::jsonb END) p
             WHERE sp.client_id = %(client_id)s
               AND p->>'state' = 'enabled'
               AND jsonb_typeof(p->'conditions'->'users'->'includeUsers') = 'array'
               AND p->'conditions'->'users'->'includeUsers' ? 'All'
        ),
        excluded AS (
            SELECT DISTINCT lower(x) AS uid, bool_or(a.enforcing) AS from_enforcing
              FROM all_users_pol a
              CROSS JOIN LATERAL jsonb_array_elements_text(a.exclude_users) x
             GROUP BY lower(x)
        ),
        enforcing AS (
            SELECT EXISTS (SELECT 1 FROM all_users_pol WHERE enforcing IS TRUE) AS present,
                   (SELECT jsonb_agg(DISTINCT display_name) FROM all_users_pol WHERE enforcing IS TRUE) AS policies
        ),
        ga_direct AS (
            SELECT DISTINCT rm.member_id
              FROM entra_directory_role_member rm
             WHERE rm.client_id = %(client_id)s
               AND rm.role_template_id = '62e90394-69f5-4237-9190-012177145e10'
               AND rm.assignment_type = 'active'
               AND rm.via_group_id IS NULL
        ),
        cand AS (
            SELECT u.*
              FROM entra_user u
              CROSS JOIN mode m
             WHERE u.client_id = %(client_id)s
               AND ((m.mode = 'declared'
                     AND lower(u.user_principal_name) IN (SELECT upn FROM declared))
                 OR (m.mode = 'heuristic'
                     AND u.user_type = 'Member'
                     AND u.account_enabled IS TRUE
                     AND u.on_premises_sync_enabled IS NOT TRUE
                     AND u.entra_object_id IN (SELECT member_id FROM ga_direct)
                     AND lower(u.entra_object_id::text) IN (SELECT uid FROM excluded)))
        ),
        cand_x AS (
            SELECT c.entra_object_id, c.user_principal_name COLLATE "C" AS upn, c.account_enabled,
                   c.on_premises_sync_enabled, c.assigned_services,
                   c.entra_object_id IN (SELECT member_id FROM ga_direct) AS ga_permanent_direct,
                   COALESCE((SELECT e.from_enforcing FROM excluded e
                              WHERE e.uid = lower(c.entra_object_id::text)), FALSE) AS excluded_from_enforcing,
                   r.entra_object_id IS NOT NULL AS has_reg_row,
                   r.methods_registered,
                   EXISTS (SELECT 1 FROM unnest(r.methods_registered) mm(method)
                            WHERE lower(mm.method) LIKE 'fido2%%'
                               OR lower(mm.method) LIKE 'passkey%%'
                               OR lower(mm.method) LIKE 'windowshello%%'
                               OR lower(mm.method) LIKE 'x509%%'
                               OR lower(mm.method) = 'macossecureenclavekey') AS has_phishing_resistant,
                   GREATEST(c.last_sign_in_at, c.last_non_interactive_sign_in_at,
                            c.last_successful_sign_in_at) AS last_sign_in
              FROM cand c
              LEFT JOIN entra_user_registration r
                     ON r.client_id = %(client_id)s AND r.entra_object_id = c.entra_object_id
        ),
        counts AS (
            SELECT count(*) FILTER (WHERE account_enabled IS TRUE) AS usable_count FROM cand_x
        ),
        problems AS (
            -- tenant-level
            SELECT 2 AS rank,
                   'no identifiable emergency-access account while Conditional Access enforces MFA or block '
                   || 'for all users' AS problem
              FROM counts k CROSS JOIN enforcing e
             WHERE k.usable_count = 0 AND e.present
            UNION ALL
            SELECT 2, 'only one emergency-access account (at least two are recommended)'
              FROM counts k WHERE k.usable_count = 1
            UNION ALL
            SELECT 2, 'declared account ' || d.declared_upn || ' not found in the tenant'
              FROM declared d
             WHERE NOT EXISTS (SELECT 1 FROM cand_x c WHERE lower(c.upn) = d.upn)
            -- per account, declared mode only
            UNION ALL
            SELECT 2, c.upn || ' is disabled'
              FROM cand_x c CROSS JOIN mode m
             WHERE m.mode = 'declared' AND c.account_enabled IS FALSE
            UNION ALL
            SELECT 2, c.upn || ' is synchronised from on-premises'
              FROM cand_x c CROSS JOIN mode m
             WHERE m.mode = 'declared' AND c.on_premises_sync_enabled IS TRUE
            UNION ALL
            SELECT 2, c.upn || ' does not hold Global Administrator as an active direct assignment'
              FROM cand_x c CROSS JOIN mode m
             WHERE m.mode = 'declared' AND NOT c.ga_permanent_direct
            UNION ALL
            SELECT 1, c.upn || ' is not excluded from the all-users Conditional Access policies enforcing MFA/block'
              FROM cand_x c CROSS JOIN mode m CROSS JOIN enforcing e
             WHERE m.mode = 'declared' AND e.present AND NOT c.excluded_from_enforcing
            -- per account, both modes
            UNION ALL
            SELECT 2, c.upn || ' has no phishing-resistant authentication method registered'
              FROM cand_x c CROSS JOIN src s
             WHERE s.reg_ok AND c.has_reg_row AND NOT c.has_phishing_resistant
            UNION ALL
            SELECT 1, c.upn || ' is licensed for Exchange (has a mailbox)'
              FROM cand_x c
             WHERE 'exchange' = ANY (c.assigned_services)
            UNION ALL
            SELECT 1, c.upn || ' signed in during the last 30 days'
              FROM cand_x c CROSS JOIN src s
             WHERE s.sia_ok AND c.last_sign_in > now() - interval '30 days'
        ),
        agg AS (
            SELECT max(rank) AS rank,
                   string_agg(problem COLLATE "C", '; ' ORDER BY rank DESC, problem COLLATE "C") AS problem_text,
                   jsonb_agg(problem ORDER BY rank DESC, problem COLLATE "C") AS problem_list
              FROM problems
            HAVING count(*) > 0
        )
        SELECT
            CASE WHEN a.rank >= 2 THEN 'fail' ELSE 'warn' END AS status,
            md5('10055:' || %(client_id)s::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN a.rank >= 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Emergency-access accounts (' || m.mode || '): ' || a.problem_text AS summary,
            jsonb_build_object(
                'mode', m.mode,
                'problems', a.problem_list,
                'usable_account_count', k.usable_count,
                'accounts', (SELECT COALESCE(jsonb_agg(jsonb_build_object(
                                    'upn', c.upn,
                                    'entra_object_id', c.entra_object_id,
                                    'account_enabled', c.account_enabled,
                                    'on_premises_sync_enabled', c.on_premises_sync_enabled,
                                    'global_admin_active_direct', c.ga_permanent_direct,
                                    'excluded_from_enforcing_all_users_ca', c.excluded_from_enforcing,
                                    'methods_registered', to_jsonb(c.methods_registered),
                                    'assigned_services', to_jsonb(c.assigned_services),
                                    'last_sign_in', CASE WHEN s.sia_ok THEN c.last_sign_in END)
                                ORDER BY c.upn), '[]'::jsonb) FROM cand_x c),
                'enforcing_all_users_ca_policies', e.policies,
                'registration_details_status', s.reg_status,
                'sign_in_activity_status', s.sia_status
            ) AS detail
        FROM agg a
        CROSS JOIN mode m
        CROSS JOIN counts k
        CROSS JOIN enforcing e
        CROSS JOIN src s
    """,
}
