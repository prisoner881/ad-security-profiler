"""
Plugin 11020: New Highly Privileged Entra ID Role Assignment

Change Detection for Microsoft Entra ID: reports active or PIM-eligible
assignments of a highly privileged directory role that were first seen
in the latest Entra collection for the client.

Highly privileged roles (by immutable role template ID): Global
Administrator, Privileged Role Administrator, Privileged Authentication
Administrator, Security Administrator, Hybrid Identity Administrator,
Application Administrator, Cloud Application Administrator, Exchange
Administrator, SharePoint Administrator, User Administrator, Conditional
Access Administrator, Authentication Administrator and Intune
Administrator.

Why: CISA SCuBA MS.AAD.7.7 requires that eligible and active
highly privileged role assignments trigger an alert. Granting a
privileged role -- directly, through a role-assignable group, or as a
PIM eligibility -- is how tenant takeovers are completed and persisted
(Midnight Blizzard, CISA ED 24-02; MITRE ATT&CK T1098.003 Additional
Cloud Roles).

Data: entra_role_assignment_history (schema v38). entra_graph_collector.py
0.7.0 upserts one row per (role template, member, assignment type) seen in
each successful role read -- direct members, role-holding groups and the
groups' members -- setting first_seen_at only on insert and last_seen_at
to that run's collected_at. The latest Entra collection time is therefore
max(last_seen_at) for the client, and an assignment first seen at exactly
that time is new in that collection. Suppressed when the client has no
history row first seen earlier (the first Entra collection, where every
assignment is new by definition). An 'active' row whose member already
held a PIM eligibility for the same role before is a PIM activation, not
a new grant, and is not reported (the eligibility itself was reported when
it appeared). Entra objects are not directory objects, so object_guid is
NULL and the finding is identified by role, member and assignment type.
A finding stays open until the next Entra collection (Entra and AD runs
are independent).

Severity: high; critical for Global Administrator, Privileged Role
Administrator and Privileged Authentication Administrator. One row per
(role, member, assignment type).
"""

PLUGIN = {
    "plugin_id": 11020,
    "category": "Change Detection",
    "name": "New Highly Privileged Entra ID Role Assignment",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11020",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.7.7",
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-AC-2(4)",
        "NIST-800-53-AC-2(7)",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09", "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5", "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-8.11", "CIS-CSC-8-6.7",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.5.23",
        "SOC2-CC7.2", "SOC2-CC6.3",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1098.003",
        "CISA-ED-24-02",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.7.7)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Privileged roles and permissions in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions"},
        {"title": "MITRE ATT&CK T1098.003: Account Manipulation: Additional Cloud Roles",
         "url": "https://attack.mitre.org/techniques/T1098/003/"},
    ],
    "description": (
        "Reports active or PIM-eligible assignments of highly privileged Entra ID "
        "roles (Global, Privileged Role, Privileged Authentication, Security, Hybrid "
        "Identity, Application, Cloud Application, Exchange, SharePoint, User, "
        "Conditional Access, Authentication and Intune Administrator) first seen in "
        "the latest Entra collection, as CISA SCuBA MS.AAD.7.7 requires. Covers direct "
        "assignments, role-assignable groups and their members. PIM activations of an "
        "existing eligibility are not reported. Severity is high, critical for Global "
        "Administrator, Privileged Role Administrator and Privileged Authentication "
        "Administrator. Suppressed on the first Entra collection."
    ),
    "remediation": (
        "Confirm each assignment against an approved request. The Entra audit log "
        "(Audit logs, category RoleManagement: 'Add member to role', 'Add eligible "
        "member to role', 'Add member to group' for role-assignable groups) shows who "
        "made it. Remove unapproved assignments (Entra admin center > Roles and "
        "administrators, or Remove-MgRoleManagementDirectoryRoleAssignment / "
        "Remove-MgRoleManagementDirectoryRoleEligibilitySchedule...), then review the "
        "member's sign-ins and the directory changes made since. Configure PIM alerts "
        "or a Sentinel / Defender rule on role assignments so these are alerted in "
        "real time (SCuBA MS.AAD.7.7), and require approval for activation of the "
        "most privileged roles (MS.AAD.7.6)."
    ),
    "base_severity": "high",
    "query": """
        WITH latest AS (
            SELECT max(h.last_seen_at) AS collected_at
            FROM entra_role_assignment_history h
            WHERE h.client_id = %(client_id)s
        ),
        have_baseline AS (
            SELECT EXISTS (
                SELECT 1 FROM entra_role_assignment_history h
                CROSS JOIN latest l
                WHERE h.client_id = %(client_id)s
                  AND h.first_seen_at < l.collected_at
            ) AS ok
        ),
        priv_role (template_id, role_name, is_critical) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid, 'Global Administrator', true),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'Privileged Role Administrator', true),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'Privileged Authentication Administrator', true),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid, 'Security Administrator', false),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'Hybrid Identity Administrator', false),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid, 'Application Administrator', false),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid, 'Cloud Application Administrator', false),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid, 'Exchange Administrator', false),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid, 'SharePoint Administrator', false),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid, 'User Administrator', false),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid, 'Conditional Access Administrator', false),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid, 'Authentication Administrator', false),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid, 'Intune Administrator', false)
        ),
        new_assignment AS (
            SELECT h.*, r.role_name, r.is_critical
            FROM entra_role_assignment_history h
            JOIN priv_role r ON r.template_id = h.role_template_id
            CROSS JOIN latest l
            CROSS JOIN have_baseline b
            WHERE h.client_id = %(client_id)s
              AND b.ok
              AND h.first_seen_at = l.collected_at
              -- an activation of an eligibility that already existed is not a new grant
              AND NOT (h.assignment_type = 'active'
                       AND EXISTS (SELECT 1 FROM entra_role_assignment_history e
                                   WHERE e.client_id = h.client_id
                                     AND e.role_template_id = h.role_template_id
                                     AND e.member_id = h.member_id
                                     AND e.assignment_type = 'eligible'
                                     AND e.first_seen_at < l.collected_at))
        )
        SELECT
            CASE WHEN n.is_critical THEN 'fail' ELSE 'warn' END AS status,
            NULL::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN n.is_critical THEN 'critical' ELSE 'high' END AS fd_severity,
            'New ' || CASE WHEN n.assignment_type = 'eligible' THEN 'PIM-eligible'
                           ELSE COALESCE(n.assignment_type, 'active') END
                || ' assignment of Entra role "' || n.role_name || '" to '
                || CASE n.member_type
                       WHEN '#microsoft.graph.user' THEN 'user '
                       WHEN '#microsoft.graph.group' THEN 'group '
                       WHEN '#microsoft.graph.servicePrincipal' THEN 'service principal '
                       ELSE '' END
                || '"' || COALESCE(n.member_upn, n.member_display_name, n.member_id::text) || '"'
                || CASE WHEN n.member_upn IS NOT NULL AND n.member_display_name IS NOT NULL
                             AND n.member_display_name <> n.member_upn
                        THEN ' (' || n.member_display_name || ')' ELSE '' END
                || ' since the previous Entra collection' AS summary,
            jsonb_build_object(
                'role_template_id', n.role_template_id,
                'role_name', n.role_name,
                'role_display_name', n.role_display_name,
                'member_id', n.member_id,
                'member_upn', n.member_upn,
                'member_display_name', n.member_display_name,
                'member_type', n.member_type,
                'assignment_type', n.assignment_type,
                'first_seen_at', n.first_seen_at,
                'scuba_policy', 'MS.AAD.7.7'
            ) AS detail
        FROM new_assignment n
    """,
}
