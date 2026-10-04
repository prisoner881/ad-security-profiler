"""
Plugin 10003: Account Holds Both Domain Admin and Global Administrator Privileges

The third of three findings requiring both on-prem and Entra data
together, and arguably the sharpest one: an account that's both an
AdminSDHolder-protected on-prem privileged account (admin_count=1)
AND a Global Administrator in Entra simultaneously means a single
credential compromise grants full control of BOTH the on-prem domain
and the entire cloud tenant at once -- no lateral movement between
environments required, no second compromise needed. Domain Admin
alone already means full on-prem control; Global Administrator alone
already means full tenant control; the same identity holding both
collapses two supposedly separate blast radii into one.

Not automatically wrong -- a break-glass account or a very small
organization's sole administrator may legitimately need both, and
this finding doesn't assume otherwise. What it does assert is that
this specific combination deserves more scrutiny than either
privilege alone: if this account's credential (or session, or MFA
factor) is compromised once, the attacker doesn't need to pivot from
one environment to the other -- they already have both.

[v1.3] On-prem privilege is now CURRENT Tier 0 privilege
(v_privileged_principal: effective protected-group membership incl.
nested/primary group, Tier 0 ACL control, DCSync, Tier 0 ownership)
instead of the sticky adminCount=1, which stays set on former admins.
The Entra side now also covers the other tenant-takeover roles -- Privileged
Role Administrator, Privileged Authentication Administrator and Hybrid
Identity Administrator -- and rows are aggregated to one finding per
account (roles listed by fixed name, sorted). Severity drops to medium when
either side of the identity is disabled. Not visible (collector
limitation): PIM-eligible assignments and roles held through a
role-assignable group.

[v1.4] Requires entra_graph_collector.py 0.6.0 / schema v37. The Entra side
now counts PIM-eligible assignments and roles held through a role-assignable
group, besides active direct ones; each role is listed with how it's held
("active", "PIM-eligible", "via group <name>", plus a non-tenant-wide
scope), all paths sorted in detail.entra_role_assignments and summarized
deterministically. Still one finding per on-prem account. Severity is high
when some path gives Global Administrator or Privileged Role Administrator
(active or eligible), or an active tenant-wide Privileged Authentication /
Hybrid Identity Administrator; medium when the only paths are eligible or
administrative-unit-scoped assignments of the latter two. A disabled side
lowers it one step (high -> medium, medium -> low). If eligibility or group
membership couldn't be read (e.g. no Entra ID P2), detail.coverage_notes
says so.
"""

PLUGIN = {
    "plugin_id": 10003,
    "category": "Hybrid Identity",
    "name": "Account Holds Both Domain Admin and Global Administrator Privileges",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm this dual privilege is genuinely necessary rather than "
        "incidental (e.g. an account that was made Global Administrator "
        "once for a one-time setup task and never demoted). Where "
        "practical, separate on-prem and cloud administration into "
        "different identities entirely -- a compromise of one no longer "
        "automatically compromises the other. Where separation isn't "
        "practical (a small environment with limited staff), apply the "
        "strongest available protections to this specific account on "
        "both sides: phishing-resistant MFA in Entra, Protected Users "
        "group membership and smartcard-required logon on-prem (see "
        "plugins 1012/1040), and treat any anomaly on this account with "
        "elevated urgency given the combined blast radius."
    ),
    "control_id": "HYBRID-003",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1078.004"],
    "references": [
        "https://learn.microsoft.com/en-us/entra/architecture/protect-m365-from-on-premises-attacks",
        "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions",
    ],
    "description": (
        "An account holding both current on-prem Tier 0 (Domain "
        "Admin-equivalent) privilege, per v_privileged_principal, and "
        "an Entra tenant-takeover role -- active, PIM-eligible, or held "
        "through a role-assignable group -- (Global Administrator, "
        "Privileged Role Administrator, Privileged Authentication "
        "Administrator or Hybrid Identity Administrator) "
        "simultaneously. A single credential compromise grants full "
        "control of both the on-prem domain and the entire cloud "
        "tenant at once, with no lateral movement or second compromise "
        "needed -- collapsing two otherwise-separate blast radii into "
        "one. Not automatically wrong (a small organization's sole "
        "administrator, or an intentional break-glass account, may "
        "legitimately need both), but the combination deserves more "
        "scrutiny than either privilege alone. How each role is held is "
        "listed; eligible-only or administrative-unit-scoped Privileged "
        "Authentication / Hybrid Identity Administrator is one step "
        "lower, and gaps in eligibility/group visibility are noted."
    ),
    "base_severity": "high",
    "query": """
        WITH roles(role_template_id, role_name, always_full) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid, 'Global Administrator', true),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'Privileged Role Administrator', true),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'Privileged Authentication Administrator', false),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'Hybrid Identity Administrator', false)
        ),
        posture AS (
            SELECT array_remove(ARRAY[
                       CASE WHEN sp.role_eligibility_status IS DISTINCT FROM 'ok' THEN
                           'PIM-eligible assignments could not be checked: '
                           || COALESCE(sp.role_eligibility_status, 'not collected (collector older than 0.6.0)') END,
                       CASE WHEN sp.group_expansion_status IS DISTINCT FROM 'ok' THEN
                           'Membership of role-holding groups could not be checked: '
                           || COALESCE(sp.group_expansion_status, 'not collected (collector older than 0.6.0)') END
                   ], NULL) AS notes
              FROM (SELECT 1) one
              LEFT JOIN entra_security_posture sp ON sp.client_id = %(client_id)s
        ),
        paths AS (
            SELECT rm.client_id, rm.on_prem_object_guid, rm.member_display_name, rm.member_upn,
                   rm.account_enabled, r.role_name,
                   -- full severity: GA/PRA by any path, others active + tenant-wide
                   (r.always_full OR rm.assignment_type <> 'eligible')
                       AND rm.directory_scope_id = '/' AS full_strength,
                   (CASE WHEN rm.assignment_type = 'eligible' THEN 'PIM-eligible' ELSE 'active' END
                   || CASE WHEN rm.via_group_id IS NOT NULL
                           THEN ' via group ' || COALESCE(rm.via_group_display_name, rm.via_group_id::text)
                           ELSE '' END
                   || CASE WHEN rm.directory_scope_id <> '/'
                           THEN ' at scope ' || rm.directory_scope_id ELSE '' END) COLLATE "C" AS path
              FROM entra_directory_role_member rm
              JOIN roles r ON r.role_template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.on_prem_object_guid IS NOT NULL
               AND rm.member_type = '#microsoft.graph.user'
        ),
        role_held AS (
            SELECT p.client_id, p.on_prem_object_guid, p.role_name,
                   p.role_name || ' (' || string_agg(DISTINCT p.path, '; ' ORDER BY p.path) || ')' AS role_label,
                   bool_or(p.full_strength) AS full_strength,
                   min(p.member_display_name) AS member_display_name,
                   min(p.member_upn) AS member_upn,
                   bool_or(p.account_enabled) AS any_enabled,
                   bool_or(p.account_enabled IS FALSE) AND NOT bool_or(p.account_enabled IS TRUE) AS disabled
              FROM paths p
             GROUP BY p.client_id, p.on_prem_object_guid, p.role_name
        ),
        sev AS (
            SELECT u.client_id, u.object_guid, u.is_enabled, u.sam_account_name,
                   udo.sam_account_name AS do_sam,
                   CASE WHEN bool_or(rh.full_strength) THEN 3 ELSE 2 END
                   - CASE WHEN u.is_enabled IS FALSE OR bool_and(rh.disabled) THEN 1 ELSE 0 END AS sev_rank,
                   string_agg(rh.role_label, ', ' ORDER BY rh.role_name) AS roles_summary,
                   jsonb_agg(rh.role_name ORDER BY rh.role_name) AS role_names,
                   jsonb_agg(rh.role_label ORDER BY rh.role_name) AS role_assignments,
                   min(rh.member_display_name) AS entra_display_name,
                   min(rh.member_upn) AS entra_upn,
                   bool_or(rh.any_enabled) AS entra_enabled
              FROM ad_user u
              JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
              JOIN role_held rh ON rh.on_prem_object_guid = u.object_guid AND rh.client_id = u.client_id
             WHERE u.valid_to IS NULL
               AND u.client_id = %(client_id)s
               AND EXISTS (SELECT 1 FROM v_privileged_principal pp
                            WHERE pp.client_id = u.client_id AND pp.object_guid = u.object_guid)
             GROUP BY u.client_id, u.object_guid, u.is_enabled, u.sam_account_name, udo.sam_account_name
        )
        SELECT
            'fail' AS status,
            s.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE s.sev_rank WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Account ' || COALESCE(s.do_sam, s.sam_account_name, s.object_guid::text)
                || ' holds both on-prem Domain Admin-equivalent privilege and Entra '
                || s.roles_summary AS summary,
            jsonb_build_object(
                'sam_account_name', s.do_sam,
                'on_prem_enabled', s.is_enabled,
                'entra_display_name', s.entra_display_name,
                'entra_upn', s.entra_upn,
                'entra_account_enabled', s.entra_enabled,
                'entra_roles', s.role_names,
                'entra_role_assignments', s.role_assignments,
                'coverage_notes', to_jsonb(po.notes),
                'on_prem_privilege_sources', (
                    SELECT jsonb_agg(DISTINCT pp.privilege_source ORDER BY pp.privilege_source)
                      FROM v_privileged_principal pp
                     WHERE pp.client_id = s.client_id AND pp.object_guid = s.object_guid)
            ) AS detail
        FROM sev s
        CROSS JOIN posture po
    """,
}
