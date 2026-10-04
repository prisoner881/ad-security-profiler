"""
Plugin 10019: Service Principal Holds a Highly Privileged Directory Role

Reports service principals (application / managed identities) that hold a
highly privileged Entra directory role -- active, PIM-eligible, or through
a role-assignable group. One finding per service principal, every role
listed.

Why it matters: a workload identity is protected only by its credential (a
client secret or certificate on the application, which anyone with
Application Administrator / Cloud Application Administrator or ownership of
the app can add) -- no MFA, no interactive sign-in, outside user-targeted
Conditional Access. A service principal holding Global Administrator,
Privileged Role Administrator or Privileged Authentication Administrator is
therefore a standing, credential-only path to full tenant control. In the
Midnight Blizzard intrusion at Microsoft (January 2024), the actor
compromised a legacy test OAuth application with elevated access, added
credentials and used it to reach corporate mailboxes; CISA Emergency
Directive 24-02 directed agencies to review exactly these application
credentials and permissions. MITRE T1098.001/T1098.003. SCuBA MS.AAD.7
restricts highly privileged roles; plugin 10007 covers Graph application
permissions, not directory roles.

Severity: critical for Global Administrator, Privileged Role Administrator
or Privileged Authentication Administrator, high for the other roles in the
highly privileged set (Security, Hybrid Identity, Application, Cloud
Application, Exchange, SharePoint, User, Conditional Access, Authentication,
Intune Administrator -- shared with plugins 10012, 10014, 10018). One step
lower when every assignment is administrative-unit scoped, and one step
lower (status 'warn') when the service principal is disabled (it can be
re-enabled). Microsoft first-party service principals rarely hold these
roles; one that does is still reported (the app owner tenant is not
collected).

Data: entra_directory_role_member rows with member_type
'#microsoft.graph.servicePrincipal'. Identity = the service principal's
object id (member_id), as in plugin 10002 (which also reports a service
principal holding Global Administrator, at lower severity, as part of its
cloud-only GA inventory).
"""

PLUGIN = {
    "plugin_id": 10019,
    "category": "Hybrid Identity",
    "name": "Service Principal Holds a Highly Privileged Directory Role",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "HYBRID-10019",
    "framework_tags": [
        "CISA-ED-24-02",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-2(7)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.5",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1098.003",
        "MITRE-ATTCK-T1098.001",
    ],
    "references": [
        {"title": "CISA ED 24-02: Mitigating the Significant Risk from Nation-State Compromise of Microsoft Corporate Email System",
         "url": "https://www.cisa.gov/news-events/directives/ed-24-02-mitigating-significant-risk-nation-state-compromise-microsoft-corporate-email-system"},
        {"title": "MSRC: Microsoft Actions Following Attack by Nation State Actor Midnight Blizzard",
         "url": "https://msrc.microsoft.com/blog/2024/01/microsoft-actions-following-attack-by-nation-state-actor-midnight-blizzard/"},
        {"title": "Microsoft: Privileged roles and permissions in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions"},
        {"title": "MITRE ATT&CK T1098.003: Additional Cloud Roles",
         "url": "https://attack.mitre.org/techniques/T1098/003/"},
    ],
    "description": (
        "A service principal holds a highly privileged Entra directory "
        "role (active, PIM-eligible or via a role-assignable group). A "
        "workload identity is protected only by its secret or "
        "certificate -- no MFA, outside user Conditional Access -- and "
        "anyone who can add a credential to the application inherits the "
        "role, the technique used against Microsoft by Midnight Blizzard "
        "(CISA ED 24-02). Critical for Global, Privileged Role or "
        "Privileged Authentication Administrator, high for other highly "
        "privileged roles; one step lower when only administrative-unit "
        "scoped or when the service principal is disabled."
    ),
    "remediation": (
        "Identify the application and its owner (Get-MgServicePrincipal "
        "-ServicePrincipalId <id>; Get-MgServicePrincipalOwner). Replace "
        "the directory role with the narrowest Graph application "
        "permission or a scoped/custom role that covers what the "
        "workload actually does, then remove the role assignment "
        "(Remove-MgRoleManagementDirectoryRoleAssignment). Review the "
        "app's credentials (remove unused secrets, prefer certificates or "
        "managed identities), restrict who can manage it (owners, "
        "Application Administrators), and monitor its sign-ins and "
        "credential changes in the audit log."
    ),
    "base_severity": "critical",
    "query": """
        WITH hp_role(role_template_id, role_name, top_tier) AS (
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
        paths AS (
            SELECT rm.member_id, rm.member_display_name, rm.account_enabled,
                   -- 4 = critical, 3 = high; administrative-unit scope one step lower
                   CASE WHEN r.top_tier THEN 4 ELSE 3 END
                   - CASE WHEN rm.directory_scope_id <> '/' THEN 1 ELSE 0 END AS path_rank,
                   (r.role_name || ' ('
                    || CASE WHEN rm.assignment_type = 'eligible' THEN 'PIM-eligible' ELSE 'active' END
                    || CASE WHEN rm.via_group_id IS NOT NULL
                            THEN ' via group ' || COALESCE(rm.via_group_display_name, rm.via_group_id::text)
                            ELSE '' END
                    || CASE WHEN rm.directory_scope_id <> '/'
                            THEN ' at scope ' || rm.directory_scope_id ELSE '' END
                    || ')') COLLATE "C" AS label
              FROM entra_directory_role_member rm
              JOIN hp_role r ON r.role_template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.servicePrincipal'
        ),
        held AS (
            SELECT p.member_id,
                   min(p.member_display_name) AS member_display_name,
                   bool_or(p.account_enabled IS FALSE) AND NOT bool_or(p.account_enabled IS TRUE) AS disabled,
                   max(p.path_rank) AS path_rank,
                   string_agg(DISTINCT p.label, ', ' ORDER BY p.label) AS roles_summary,
                   jsonb_agg(DISTINCT p.label ORDER BY p.label) AS role_assignments
              FROM paths p
             GROUP BY p.member_id
        ),
        graded AS (
            SELECT h.*, greatest(1, h.path_rank - CASE WHEN h.disabled THEN 1 ELSE 0 END) AS sev_rank
              FROM held h
        )
        SELECT
            CASE WHEN g.disabled THEN 'warn' ELSE 'fail' END AS status,
            g.member_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE g.sev_rank WHEN 4 THEN 'critical' WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Service principal ' || COALESCE(g.member_display_name, g.member_id::text)
                || ' holds ' || g.roles_summary
                || CASE WHEN g.disabled THEN ' (disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'service_principal_id', g.member_id,
                'display_name', g.member_display_name,
                'disabled', g.disabled,
                'role_assignments', g.role_assignments
            ) AS detail
        FROM graded g
    """,
}
