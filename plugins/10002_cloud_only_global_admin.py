"""
Plugin 10002: Cloud-Only Global Administrator (No On-Prem Account)

The second of three findings requiring both on-prem and Entra data
together. A Global Administrator with no corresponding on-prem AD
account bypasses every on-prem control this project's other 130+
plugins check for -- by construction, not by any specific
misconfiguration. Password policy, account lockout, AdminSDHolder
protection, Kerberos hardening, on-prem MFA/smartcard requirements --
none of it reaches an account that on-prem AD has never heard of.

Not inherently wrong: this is exactly the recommended pattern for
break-glass/emergency-access accounts (Microsoft's own guidance
explicitly recommends at least two cloud-only, excluded-from-
Conditional-Access emergency accounts per tenant), and plenty of
smaller or cloud-first organizations reasonably run some or all of
their admin accounts cloud-only rather than syncing them from an
on-prem AD they may barely still use for anything else. What matters
is knowing this exists and confirming its security posture was set
deliberately (strong, unique password; MFA; monitored sign-in
activity) rather than left at whatever Entra's own defaults happen to
be, since nothing about this project's on-prem hardening reaches it
to compensate.

[v1.1] Stable identity: object_guid is now the Entra user's object id
(member_id) instead of NULL, so renaming or disabling the account no
longer closes the finding and opens a new one. "Cloud-only" is now
on_premises_security_identifier IS NULL (no onPremisesSecurityIdentifier
at all) rather than on_prem_object_guid IS NULL, which was also NULL for
synced users whose SID simply wasn't found in the collected domain (another
domain/forest). Severity lowered to low (cloud-only privileged accounts are
Microsoft's recommended pattern), and info when the account is disabled.
Coverage note (v1.1): only active, direct user assignments were visible.

[v1.2] Requires entra_graph_collector.py 0.6.0 / schema v37. Exposure now
counts every way the principal holds or can obtain Global Administrator:
active, PIM-eligible (can activate on demand), and membership of a
role-assignable group that holds it ("via group <name>"). All paths for one
principal are aggregated into one finding (identity unchanged: member_id),
listed sorted in detail.assignment_paths and summarized in the summary.
Eligible keeps the same severity as active (Global Administrator), an
administrative-unit-only scope is one step lower. Service principals
holding Global Administrator are now reported too, labelled as such, at
medium (a workload identity with GA is protected only by its credential --
no MFA, outside user Conditional Access). The group's own row is not a
finding (its members are). When the collector couldn't read PIM
eligibility or expand role-holding groups (e.g. no Entra ID P2 licence),
detail.coverage_notes says so, and one separate low warn finding per
client records the coverage gap.

[v1.3] The summary adds the UPN after the display name, so two holders
with the same display name (a lab showed two "Eric Smith" accounts) give
two distinguishable findings. Identity is unchanged (member_id).
"""

PLUGIN = {
    "plugin_id": 10002,
    "category": "Hybrid Identity",
    "name": "Cloud-Only Global Administrator (No On-Prem Account)",
    "version": "1.3",
    "revision_date": "2026-10-07",
    "remediation": (
        "Confirm this account's security posture was set deliberately, "
        "not left at defaults: a strong, unique password not reused "
        "anywhere else, MFA enrolled and enforced, and sign-in activity "
        "actually monitored somewhere. If this is meant to be a break-"
        "glass/emergency-access account, follow Microsoft's own "
        "documented pattern for those specifically (excluded from "
        "Conditional Access policies that could otherwise lock everyone "
        "out simultaneously, credentials stored securely offline, "
        "access to sign-in attempts alerted on). If this account is a "
        "day-to-day admin identity rather than break-glass, consider "
        "whether it should be brought into hybrid sync so this "
        "project's on-prem findings can actually cover it. For a "
        "PIM-eligible assignment, confirm activation requires MFA and "
        "approval; for one held via a group, review who can change that "
        "group's membership. A service principal should almost never "
        "hold Global Administrator: grant it the narrowest role or Graph "
        "permission it needs instead, and audit who owns it and its "
        "credentials."
    ),
    "control_id": "HYBRID-002",
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(2)",
        "NIST-800-53-AC-6(5)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.7",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.5.23",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Manage emergency access accounts in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-emergency-access"},
    ],
    "description": (
        "A principal that holds -- or can activate -- Global "
        "Administrator and has no corresponding on-prem AD account "
        "bypasses every on-prem control this project's other plugins "
        "check -- by construction, not misconfiguration. Counts active, "
        "PIM-eligible and role-assignable-group (\"via group\") "
        "assignments, one finding per principal with every path listed. "
        "Not inherently wrong for users (Microsoft's own recommended "
        "pattern for break-glass/emergency-access accounts, and common "
        "for cloud-first organizations), but worth confirming its "
        "security posture was set deliberately. Severity is low for "
        "users (info when disabled or only administrative-unit scoped), "
        "medium for service principals (credential-only protection). "
        "When PIM eligibility or group membership couldn't be read, the "
        "gap is noted in detail and as a separate low finding."
    ),
    "base_severity": "low",
    "query": """
        WITH posture AS (
            SELECT sp.role_eligibility_status, sp.group_expansion_status,
                   array_remove(ARRAY[
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
            SELECT rm.*,
                   (CASE WHEN rm.assignment_type = 'eligible' THEN 'PIM-eligible' ELSE 'active' END
                   || CASE WHEN rm.via_group_id IS NOT NULL
                           THEN ' via group ' || COALESCE(rm.via_group_display_name, rm.via_group_id::text)
                           ELSE '' END
                   || CASE WHEN rm.directory_scope_id <> '/'
                           THEN ' at scope ' || rm.directory_scope_id ELSE '' END) COLLATE "C" AS path
              FROM entra_directory_role_member rm
             WHERE rm.client_id = %(client_id)s
               AND rm.role_template_id = '62e90394-69f5-4237-9190-012177145e10'
               AND rm.member_type IN ('#microsoft.graph.user', '#microsoft.graph.servicePrincipal')
        ),
        holders AS (
            SELECT p.member_id,
                   min(p.member_type) AS member_type,
                   min(p.member_display_name) AS member_display_name,
                   min(p.member_upn) AS member_upn,
                   bool_or(p.account_enabled) AS account_enabled,
                   bool_or(p.account_enabled IS FALSE) AND NOT bool_or(p.account_enabled IS TRUE) AS disabled,
                   bool_or(p.directory_scope_id = '/') AS tenant_wide,
                   jsonb_agg(DISTINCT p.path ORDER BY p.path) AS assignment_paths,
                   string_agg(DISTINCT p.path, '; ' ORDER BY p.path) AS path_summary
              FROM paths p
              LEFT JOIN entra_user eu ON eu.entra_object_id = p.member_id AND eu.client_id = p.client_id
             GROUP BY p.member_id
            HAVING bool_and(p.on_premises_security_identifier IS NULL)
               AND bool_and(eu.on_premises_security_identifier IS NULL)
               AND bool_and(p.on_prem_object_guid IS NULL)
        )
        SELECT
            'warn' AS status,
            h.member_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN h.disabled OR NOT h.tenant_wide THEN
                     CASE WHEN h.member_type = '#microsoft.graph.servicePrincipal' THEN 'low' ELSE 'info' END
                 WHEN h.member_type = '#microsoft.graph.servicePrincipal' THEN 'medium'
                 ELSE 'low' END AS fd_severity,
            CASE WHEN h.member_type = '#microsoft.graph.servicePrincipal'
                 THEN 'Service principal ' ELSE 'User ' END
                || COALESCE(h.member_display_name, h.member_upn, h.member_id::text)
                -- [v1.3] the UPN tells apart two holders with the same display name
                || CASE WHEN h.member_display_name IS NOT NULL AND h.member_upn IS NOT NULL
                        THEN ' (' || h.member_upn || ')' ELSE '' END
                || ' holds Global Administrator (' || h.path_summary
                || ') with no corresponding on-prem AD account' AS summary,
            jsonb_build_object(
                'member_display_name', h.member_display_name,
                'member_upn', h.member_upn,
                'member_id', h.member_id,
                'member_type', h.member_type,
                'principal_kind', CASE WHEN h.member_type = '#microsoft.graph.servicePrincipal'
                                       THEN 'service principal' ELSE 'user' END,
                'account_enabled', h.account_enabled,
                'assignment_paths', h.assignment_paths,
                'coverage_notes', to_jsonb(po.notes)
            ) AS detail
        FROM holders h
        CROSS JOIN posture po
        UNION ALL
        SELECT
            'warn',
            md5(%(client_id)s::text || ':10002:role-coverage')::uuid,
            NULL, NULL, NULL, NULL,
            'low',
            'Global Administrator coverage is incomplete: '
                || array_to_string(po.notes, '; '),
            jsonb_build_object(
                'role_eligibility_status', po.role_eligibility_status,
                'group_expansion_status', po.group_expansion_status,
                'coverage_notes', to_jsonb(po.notes)
            )
        FROM posture po
        WHERE cardinality(po.notes) > 0
          AND EXISTS (SELECT 1 FROM entra_directory_role_member x WHERE x.client_id = %(client_id)s)
    """,
}
