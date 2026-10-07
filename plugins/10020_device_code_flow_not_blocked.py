"""
Plugin 10020: Device Code Flow Not Blocked by Conditional Access

Reports a tenant where no enabled Conditional Access policy blocks the
OAuth device authorization grant ("device code flow") for all users.

Why it matters: device-code phishing (Microsoft's Storm-2372 write-up,
February 2025, and many follow-on phishing kits) sends the victim to the
genuine microsoft.com/devicelogin page; the victim completes MFA there and
the attacker's device receives the tokens. MFA and even phishing-resistant
methods do not help, because the user authenticates on Microsoft's own page.
CISA SCuBA MS.AAD.3.9: "Device code authentication SHOULD be blocked".
Microsoft recommends blocking the flow everywhere it is not needed.

A policy counts when it is enabled, its conditions.authenticationFlows.
transferMethods (a comma-separated string) includes 'deviceCodeFlow', its
grant controls include 'block', and it targets all resources
(applications.includeApplications contains 'All'; excluded applications are
tolerated). A policy that blocks device code for one application
only leaves the others open, so it does not count.

Results (one tenant-level row, object_guid = md5('10020:' || client_id)):
- fail / high: no such policy for all users (includeUsers 'All'; user,
  group and role exclusions are allowed), and none
  for the highly privileged roles either;
- warn / medium: the flow is blocked only by policies targeting highly
  privileged roles (conditions.users.includeRoles with a Tier 0 role
  template); detail lists the roles covered and not covered.
Policies in report-only mode do not count; they are listed in detail.

Data caveats: needs the CA policy conditions (entra_graph_collector 0.7.0+).
If an enabled blocking policy has no conditions object, coverage can't be
evaluated and no row is returned. No row when no Entra posture was
collected. Security Defaults does not block device code flow, so it is not
considered.
"""

PLUGIN = {
    "plugin_id": 10020,
    "category": "Hybrid Identity",
    "name": "Device Code Flow Not Blocked by Conditional Access",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10020",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.3.9",
        "NIST-800-53-IA-2",
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.AA-03",
        "NIST-CSF-2.0-PR.PS-01",
        "CIS-CSC-8-4.8",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1528",
        "MITRE-ATTCK-T1566.002",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.3.9)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Block authentication flows with Conditional Access",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-block-authentication-flows"},
        {"title": "Microsoft: Conditional Access authentication flows",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-authentication-flows"},
        {"title": "Microsoft Threat Intelligence: Storm-2372 conducts device code phishing campaign",
         "url": "https://www.microsoft.com/en-us/security/blog/2025/02/13/storm-2372-conducts-device-code-phishing-campaign/"},
    ],
    "description": (
        "No enabled Conditional Access policy blocks the device code "
        "authentication flow for all users and all resources (high), or it "
        "is blocked only for highly privileged roles (medium). Device-code "
        "phishing (Storm-2372) has the victim complete sign-in and MFA on "
        "Microsoft's genuine device-login page and hands the tokens to the "
        "attacker, so MFA does not stop it (SCuBA MS.AAD.3.9)."
    ),
    "remediation": (
        "Create a Conditional Access policy: Users = All users (exclude only "
        "the emergency-access accounts and, if truly needed, a group of "
        "users or devices that rely on device code, such as meeting-room "
        "devices); Target resources = All resources; Conditions -> "
        "Authentication flows -> Device code flow; Grant = Block access. "
        "Run it report-only first and review sign-in logs filtered on "
        "'Authentication protocol = Device code' to find legitimate use, "
        "then switch it On. Also block 'Authentication transfer' unless it "
        "is needed."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0(role_template_id, role_name) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10', 'Global Administrator'),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814', 'Privileged Role Administrator'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'Privileged Authentication Administrator'),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d', 'Security Administrator'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2', 'Hybrid Identity Administrator'),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', 'Application Administrator'),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7', 'Cloud Application Administrator'),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de', 'Exchange Administrator'),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c', 'SharePoint Administrator'),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1', 'User Administrator'),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', 'Conditional Access Administrator'),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f', 'Authentication Administrator'),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5', 'Intune Administrator')
        ),
        posture AS (
            SELECT sp.client_id, sp.ca_policies
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
        ),
        pol AS (
            SELECT p->>'id' AS id,
                   COALESCE(p->>'display_name', p->>'id') COLLATE "C" AS name,
                   p->>'state' AS state,
                   COALESCE(jsonb_typeof(p->'conditions') = 'object', FALSE) AS evaluable,
                   position('devicecodeflow' IN lower(COALESCE(
                       p->'conditions'->'authenticationFlows'->>'transferMethods', ''))) > 0 AS device_code,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'includeUsers') = 'array'
                        THEN p->'conditions'->'users'->'includeUsers' ELSE '[]'::jsonb END AS inc_users,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'includeRoles') = 'array'
                        THEN p->'conditions'->'users'->'includeRoles' ELSE '[]'::jsonb END AS inc_roles,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeRoles') = 'array'
                        THEN p->'conditions'->'users'->'excludeRoles' ELSE '[]'::jsonb END AS ex_roles,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeUsers') = 'array'
                        THEN p->'conditions'->'users'->'excludeUsers' ELSE '[]'::jsonb END AS ex_users,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeGroups') = 'array'
                        THEN p->'conditions'->'users'->'excludeGroups' ELSE '[]'::jsonb END AS ex_groups,
                   CASE WHEN jsonb_typeof(p->'conditions'->'applications'->'excludeApplications') = 'array'
                        THEN p->'conditions'->'applications'->'excludeApplications' ELSE '[]'::jsonb END AS ex_apps,
                   COALESCE(p->'conditions'->'applications'->'includeApplications', '[]'::jsonb) ? 'All' AS all_apps
              FROM posture po
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(po.ca_policies) = 'array' THEN po.ca_policies ELSE '[]'::jsonb END) p
             WHERE jsonb_typeof(p->'grant_controls'->'builtInControls') = 'array'
               AND p->'grant_controls'->'builtInControls' ? 'block'
               AND p->>'state' IN ('enabled', 'enabledForReportingButNotEnforced')
        ),
        blocking AS (
            SELECT * FROM pol
             WHERE state = 'enabled' AND evaluable AND device_code AND all_apps
        ),
        all_users AS (
            SELECT * FROM blocking WHERE inc_users ? 'All'
        ),
        role_cov AS (
            SELECT DISTINCT r.role_template_id, r.role_name
              FROM blocking b
              JOIN tier0 r ON b.inc_roles ? r.role_template_id AND NOT b.ex_roles ? r.role_template_id
        ),
        state AS (
            SELECT po.client_id,
                   EXISTS (SELECT 1 FROM pol WHERE state = 'enabled' AND NOT evaluable) AS unevaluable,
                   EXISTS (SELECT 1 FROM all_users) AS all_blocked,
                   EXISTS (SELECT 1 FROM role_cov) AS admins_blocked,
                   (SELECT jsonb_agg(role_name ORDER BY role_name) FROM role_cov) AS roles_blocked,
                   (SELECT jsonb_agg(r.role_name ORDER BY r.role_name) FROM tier0 r
                     WHERE NOT EXISTS (SELECT 1 FROM role_cov c WHERE c.role_template_id = r.role_template_id))
                       AS roles_not_blocked,
                   (SELECT jsonb_agg(jsonb_build_object('policy', b.name, 'id', b.id)
                                     ORDER BY b.name, b.id)
                      FROM blocking b WHERE NOT b.inc_users ? 'All') AS role_or_group_policies,
                   (SELECT jsonb_agg(jsonb_build_object('policy', p.name, 'id', p.id)
                                     ORDER BY p.name, p.id)
                      FROM pol p
                     WHERE p.evaluable AND p.device_code
                       AND (p.state <> 'enabled' OR NOT p.all_apps)) AS not_counted_policies
              FROM posture po
        )
        SELECT
            CASE WHEN s.admins_blocked THEN 'warn' ELSE 'fail' END AS status,
            md5('10020:' || s.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN s.admins_blocked THEN 'medium' ELSE 'high' END AS fd_severity,
            CASE WHEN s.admins_blocked
                 THEN 'Device code flow is blocked by Conditional Access only for highly privileged roles, '
                      || 'not for all users'
                 ELSE 'Device code flow is not blocked -- no enabled Conditional Access policy blocks the '
                      || 'device code authentication flow for all users'
            END AS summary,
            jsonb_build_object(
                'roles_blocked', s.roles_blocked,
                'roles_not_blocked', CASE WHEN s.admins_blocked THEN s.roles_not_blocked END,
                'admin_scoped_blocking_policies', s.role_or_group_policies,
                'report_only_or_partial_app_policies', s.not_counted_policies,
                'note', 'A policy counts when it is enabled, targets device code flow and all resources, '
                        || 'and its grant control is Block.'
            ) AS detail
        FROM state s
        WHERE NOT s.unevaluable
          AND NOT s.all_blocked
    """,
}
