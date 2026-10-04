"""
Plugin 10011: Global Administrator Count Outside 2-8

Counts the distinct USERS who hold Global Administrator in Entra ID --
active or PIM-eligible, directly or through membership of a
role-assignable group -- and reports when the count is below two or above
eight.

Why it matters: CISA SCuBA MS.AAD.7.1 ("A minimum of two users and a
maximum of eight users SHALL be provisioned with the Global Administrator
role"). Fewer than two leaves no second (break-glass / emergency-access)
account to recover the tenant if the only Global Administrator is locked
out, loses its MFA device or is compromised and disabled. More than eight
widens the set of credentials whose compromise is a full tenant takeover;
Microsoft recommends fewer than five, and SCuBA allows up to eight for
emergency access and operational needs.

Counting follows the SCuBA instructions: each user once, whether assigned
directly or via group membership, active and eligible. A role-assignable
group's own role row is not counted (its expanded members are). Service
principals holding Global Administrator are not users and do not count
toward the 2-8 range; they are listed separately in detail (plugins
10002/10019 report them as findings in their own right).

Data caveats: Entra role membership is replaced on every
entra_graph_collector.py run. When the collector could not read PIM
eligibility or expand role-holding groups (entra_security_posture.
role_eligibility_status / group_expansion_status not 'ok', e.g. no Entra ID
P2 licence), the count is a lower bound: "more than eight" is still certain,
but "fewer than two" is then only a low 'warn' noting the coverage gap.
No row at all when no Global Administrator role data was collected for the
client (a tenant always has at least one Global Administrator, so zero rows
means the Entra side was never collected or failed, not that the role is
empty). Disabled Global Administrator accounts are still counted (SCuBA
counts assignments), but listed as disabled in detail.

Tenant-level finding: object_guid is a fixed per-client value
(md5('10011:' || client_id)), as in plugin 10004, so the count changing does
not open a new finding.
"""

PLUGIN = {
    "plugin_id": 10011,
    "category": "Hybrid Identity",
    "name": "Global Administrator Count Outside 2-8",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "HYBRID-10011",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.7.1",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-2(7)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.7.1)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Best practices for Microsoft Entra roles",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices"},
        {"title": "Microsoft: Manage emergency access accounts in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access"},
    ],
    "description": (
        "The number of distinct users holding Global Administrator -- "
        "active or PIM-eligible, directly or through a role-assignable "
        "group -- is below two (no second emergency-access account to "
        "recover the tenant) or above eight (too many credentials whose "
        "compromise is a full tenant takeover). CISA SCuBA MS.AAD.7.1 "
        "requires two to eight; Microsoft recommends fewer than five. "
        "Service principals holding the role are listed separately and "
        "not counted. When PIM eligibility or group membership could not "
        "be read, the count is a lower bound and a low count is only a "
        "warning."
    ),
    "remediation": (
        "Too many: move day-to-day administrators to finer-grained roles "
        "(User, Exchange, SharePoint, Security, Application "
        "Administrator, ...) and keep Global Administrator for a small "
        "set of PIM-eligible administrators plus two emergency-access "
        "accounts. Review with: Get-MgRoleManagementDirectoryRoleAssignment "
        "-Filter \"roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'\" "
        "and Get-MgRoleManagementDirectoryRoleEligibilitySchedule (same "
        "filter), expanding group assignments. Too few: create a second "
        "(cloud-only) emergency-access Global Administrator following "
        "Microsoft's emergency-access account guidance, so the tenant can "
        "be recovered if the only administrator is unavailable."
    ),
    "base_severity": "medium",
    "query": """
        WITH posture AS (
            SELECT sp.role_eligibility_status, sp.group_expansion_status,
                   array_remove(ARRAY[
                       CASE WHEN sp.role_eligibility_status IS DISTINCT FROM 'ok' THEN
                           'PIM-eligible assignments could not be checked: '
                           || COALESCE(sp.role_eligibility_status, 'not collected') END,
                       CASE WHEN sp.group_expansion_status IS DISTINCT FROM 'ok' THEN
                           'Membership of role-holding groups could not be checked: '
                           || COALESCE(sp.group_expansion_status, 'not collected') END
                   ], NULL) AS notes
              FROM (SELECT 1) one
              LEFT JOIN entra_security_posture sp ON sp.client_id = %(client_id)s
        ),
        ga AS (
            SELECT rm.*,
                   (CASE WHEN rm.assignment_type = 'eligible' THEN 'PIM-eligible' ELSE 'active' END
                    || CASE WHEN rm.via_group_id IS NOT NULL
                            THEN ' via group ' || COALESCE(rm.via_group_display_name, rm.via_group_id::text)
                            ELSE '' END) COLLATE "C" AS path
              FROM entra_directory_role_member rm
             WHERE rm.client_id = %(client_id)s
               AND rm.role_template_id = '62e90394-69f5-4237-9190-012177145e10'
        ),
        principals AS (
            -- one entry per user / service principal, however many paths
            SELECT g.member_id,
                   min(g.member_type) AS member_type,
                   (COALESCE(min(g.member_upn), min(g.member_display_name), g.member_id::text)
                    || CASE WHEN bool_or(g.account_enabled IS FALSE) AND NOT bool_or(g.account_enabled IS TRUE)
                            THEN ' (disabled)' ELSE '' END
                    || ' [' || string_agg(DISTINCT g.path, '; ' ORDER BY g.path) || ']') COLLATE "C" AS label
              FROM ga g
             WHERE g.member_type IN ('#microsoft.graph.user', '#microsoft.graph.servicePrincipal')
             GROUP BY g.member_id
        ),
        counts AS (
            SELECT count(*) FILTER (WHERE member_type = '#microsoft.graph.user') AS user_count,
                   count(*) FILTER (WHERE member_type = '#microsoft.graph.servicePrincipal') AS sp_count,
                   COALESCE(jsonb_agg(label ORDER BY label)
                            FILTER (WHERE member_type = '#microsoft.graph.user'), '[]'::jsonb) AS users,
                   COALESCE(jsonb_agg(label ORDER BY label)
                            FILTER (WHERE member_type = '#microsoft.graph.servicePrincipal'), '[]'::jsonb) AS sps,
                   (SELECT COALESCE(jsonb_agg(DISTINCT COALESCE(g.member_display_name, g.member_id::text) ORDER BY COALESCE(g.member_display_name, g.member_id::text)), '[]'::jsonb)
                      FROM ga g WHERE g.member_type = '#microsoft.graph.group') AS groups
              FROM principals
        ),
        verdict AS (
            SELECT c.*, po.notes, po.role_eligibility_status, po.group_expansion_status,
                   CASE WHEN c.user_count > 8 THEN 'too_many'
                        WHEN c.user_count < 2 THEN 'too_few' END AS problem,
                   cardinality(po.notes) > 0 AS incomplete
              FROM counts c CROSS JOIN posture po
             WHERE EXISTS (SELECT 1 FROM ga)
        )
        SELECT
            CASE WHEN v.problem = 'too_few' AND v.incomplete THEN 'warn' ELSE 'fail' END AS status,
            md5('10011:' || %(client_id)s::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN v.problem = 'too_few' AND v.incomplete THEN 'low' ELSE 'medium' END AS fd_severity,
            CASE WHEN v.problem = 'too_many'
                 THEN 'Global Administrator is held by ' || v.user_count
                      || ' users (more than the SCuBA maximum of 8)'
                 WHEN v.incomplete
                 THEN 'Global Administrator appears to be held by fewer than 2 users ('
                      || v.user_count || ' found; PIM eligibility or group membership could not be read)'
                 ELSE 'Global Administrator is held by ' || v.user_count
                      || ' user(s) (fewer than the SCuBA minimum of 2)'
            END AS summary,
            jsonb_build_object(
                'global_admin_user_count', v.user_count,
                'global_admin_users', v.users,
                'service_principal_count', v.sp_count,
                'service_principals', v.sps,
                'role_holding_groups', v.groups,
                'allowed_range', '2-8',
                'role_eligibility_status', v.role_eligibility_status,
                'group_expansion_status', v.group_expansion_status,
                'coverage_notes', to_jsonb(v.notes)
            ) AS detail
        FROM verdict v
        WHERE v.problem IS NOT NULL
    """,
}
