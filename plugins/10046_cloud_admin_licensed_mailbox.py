"""
Plugin 10046: Privileged Entra Account Has Productivity Services (Mailbox / Teams / SharePoint)

Detects users holding a highly privileged Entra role (TIER0 set: Global,
Privileged Role, Privileged Authentication, Security, Hybrid Identity,
Application, Cloud Application, Exchange, SharePoint, User, Conditional
Access, Authentication and Intune Administrator; active or PIM-eligible,
directly or via a role-assignable group) whose licence enables Exchange
Online, Teams / Skype for Business Online or SharePoint Online
(assigned_services contains 'exchange', 'MicrosoftCommunicationsOnline' or
'SharePoint', compared case-insensitively).

Why: Microsoft's privileged-access guidance is that administrative accounts
are separate, cloud-only and not used for email or collaboration. A mailbox
and Teams presence make the admin account directly reachable by phishing,
consent phishing and malicious meeting invitations, and inbox rules can be
abused to hide alerts (MITRE ATT&CK T1566.002, T1078.004). This is the
cloud mirror of on-prem plugin 1047 (admin accounts used as daily accounts).
Often it means the administrator's daily-use account was given the role.

Data: entra_user.assigned_services (schema v42: distinct
assignedPlans[].service values with capabilityStatus 'Enabled') and
entra_directory_role_member. Users with assigned_services NULL (not
collected) are skipped; an empty array means unlicensed. Disabled accounts
are not reported (plugin 10045 covers them).

Severity: medium (warn), one row per user (identity = Entra object id)
listing the roles and the services.
"""

PLUGIN = {
    "plugin_id": 10046,
    "category": "Hybrid Identity",
    "name": "Privileged Entra Account Has Productivity Services (Mailbox / Teams / SharePoint)",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10046",
    "framework_tags": [
        "NIST-800-53-AC-6(2)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-2(7)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1566.002",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Securing privileged access for hybrid and cloud deployments in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/security-planning"},
        {"title": "Microsoft: Best practices for Microsoft Entra roles",
         "url": "https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/best-practices"},
    ],
    "description": (
        "A user holding a highly privileged Entra role has Exchange Online, Teams or "
        "SharePoint Online enabled by its licence, i.e. the admin account is also used "
        "(or usable) for email and collaboration. That exposes it to phishing and consent "
        "phishing and usually means a daily-use account was made administrator. "
        "Microsoft recommends separate, cloud-only, unlicensed admin accounts. Medium, "
        "one finding per user."
    ),
    "remediation": (
        "Create a dedicated cloud-only administrative account for each administrator "
        "(e.g. adm-<name>@<tenant>.onmicrosoft.com) without Exchange, Teams or SharePoint "
        "service plans (an Entra ID P1/P2 licence alone is enough for Conditional Access "
        "and PIM), move the role assignments / eligibilities to it, and remove the roles "
        "from the daily-use account. If the account must keep a licence, disable the "
        "Exchange, Teams and SharePoint service plans "
        "(Set-MgUserLicense -AddLicenses @{SkuId=...; DisabledPlans=@(...)})."
    ),
    "base_severity": "medium",
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
        cand AS (
            SELECT u.entra_object_id, u.user_principal_name, u.display_name, u.user_type,
                   u.on_premises_sync_enabled, u.assigned_services, p.roles,
                   ARRAY(SELECT DISTINCT CASE lower(s.svc)
                                             WHEN 'exchange' THEN 'Exchange Online'
                                             WHEN 'microsoftcommunicationsonline' THEN 'Teams / Skype for Business'
                                             ELSE 'SharePoint Online' END
                           FROM unnest(u.assigned_services) s(svc)
                          WHERE lower(s.svc) IN ('exchange', 'microsoftcommunicationsonline', 'sharepoint')
                          ORDER BY 1) AS services
              FROM entra_user u
              JOIN priv p ON p.member_id = u.entra_object_id
             WHERE u.client_id = %(client_id)s
               AND u.account_enabled IS TRUE
               AND u.assigned_services IS NOT NULL
        )
        SELECT
            'warn' AS status,
            c.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Privileged user "' || COALESCE(c.user_principal_name, c.entra_object_id::text)
                || '" (holds ' || array_to_string(c.roles, ', ') || ') is licensed for '
                || array_to_string(c.services, ', ') AS summary,
            jsonb_build_object(
                'user_principal_name', c.user_principal_name,
                'display_name', c.display_name,
                'user_type', c.user_type,
                'on_premises_sync_enabled', c.on_premises_sync_enabled,
                'privileged_roles', to_jsonb(c.roles),
                'productivity_services', to_jsonb(c.services),
                'assigned_services', to_jsonb(c.assigned_services)
            ) AS detail
        FROM cand c
        WHERE cardinality(c.services) > 0
    """,
}
