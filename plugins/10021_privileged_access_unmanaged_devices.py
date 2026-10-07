"""
Plugin 10021: Privileged Access Not Restricted to Managed Devices

Reports a tenant where no enabled Conditional Access policy that applies to
the highly privileged directory roles requires a managed device (Intune
compliant or Microsoft Entra hybrid joined).

Why it matters: a stolen administrator password, or a session token
replayed by an adversary-in-the-middle kit, works from any machine unless
administrator sign-in is bound to devices the organisation manages. CISA
SCuBA MS.AAD.3.7 ("Managed devices SHOULD be required for authentication")
and Microsoft's privileged-access guidance (privileged access workstations)
both call for it.

A policy counts when it is enabled, targets all resources
(applications.includeApplications contains 'All'), applies to at least one
highly privileged role (conditions.users.includeRoles contains the role
template, or includeUsers contains 'All') without excluding it
(excludeRoles), and its grant controls make a managed device mandatory:
'compliantDevice' or 'domainJoinedDevice' under operator AND, or the device
controls are the only grant controls offered (e.g. compliant OR hybrid
joined). A blocking policy whose device filter (conditions.devices.
deviceFilter) tests device.isCompliant or device.trustType also counts.
'mfa OR compliantDevice' does not count: the device is optional.

Highly privileged roles: Global, Privileged Role, Privileged
Authentication, Security, Hybrid Identity, Application, Cloud Application,
Exchange, SharePoint, User, Conditional Access, Authentication and Intune
Administrator (same set as plugins 10014 and 11020).

Result: one tenant-level warn / medium row (object_guid =
md5('10021:' || client_id)); detail lists device policies that exist but
do not count (report-only, not all resources, optional device control, or
not applying to the privileged roles).

Data caveats: needs the CA policy conditions (entra_graph_collector
0.7.0+). If an enabled policy requiring a device has no conditions object,
coverage can't be evaluated and no row is returned. No row when no Entra
posture was collected.
"""

PLUGIN = {
    "plugin_id": 10021,
    "category": "Hybrid Identity",
    "name": "Privileged Access Not Restricted to Managed Devices",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10021",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.3.7",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-IA-2(1)",
        "NIST-CSF-2.0-PR.AA-03",
        "NIST-CSF-2.0-PR.AA-05",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.2",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1528",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.3.7)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Conditional Access policy requiring a compliant or hybrid joined device",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-device-compliance"},
        {"title": "Microsoft: Conditional Access filter for devices",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-condition-filters-for-devices"},
        {"title": "Microsoft: Privileged access devices",
         "url": "https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-devices"},
    ],
    "description": (
        "No enabled Conditional Access policy that applies to the highly "
        "privileged roles requires a compliant or hybrid-joined device for "
        "all resources. Without it an administrator's stolen password or "
        "replayed session works from any attacker machine (SCuBA "
        "MS.AAD.3.7)."
    ),
    "remediation": (
        "Enrol administrator workstations in Intune (or hybrid join them) "
        "and create a Conditional Access policy: Users -> Directory roles = "
        "the highly privileged roles (exclude only the emergency-access "
        "accounts); Target resources = All resources; Grant = Require "
        "device to be marked as compliant (and/or Require Microsoft Entra "
        "hybrid joined device) with 'Require all the selected controls' "
        "when combined with MFA or an authentication strength. Test "
        "report-only, then switch it On. Do not offer the device control as "
        "an OR alternative to MFA."
    ),
    "base_severity": "medium",
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
        raw AS (
            SELECT p->>'id' AS id,
                   COALESCE(p->>'display_name', p->>'id') COLLATE "C" AS name,
                   p->>'state' AS state,
                   COALESCE(jsonb_typeof(p->'conditions') = 'object', FALSE) AS evaluable,
                   CASE WHEN jsonb_typeof(p->'grant_controls'->'builtInControls') = 'array'
                        THEN p->'grant_controls'->'builtInControls' ELSE '[]'::jsonb END AS builtin,
                   upper(COALESCE(p->'grant_controls'->>'operator', 'OR')) AS operator,
                   (CASE WHEN jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object' THEN 1 ELSE 0 END
                    + CASE WHEN jsonb_typeof(p->'grant_controls'->'customAuthenticationFactors') = 'array'
                           THEN jsonb_array_length(p->'grant_controls'->'customAuthenticationFactors') ELSE 0 END
                    + CASE WHEN jsonb_typeof(p->'grant_controls'->'termsOfUse') = 'array'
                           THEN jsonb_array_length(p->'grant_controls'->'termsOfUse') ELSE 0 END) AS other_controls,
                   COALESCE(p->'conditions'->'devices'->'deviceFilter'->>'rule', '') AS device_rule,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'includeUsers') = 'array'
                        THEN p->'conditions'->'users'->'includeUsers' ELSE '[]'::jsonb END AS inc_users,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'includeRoles') = 'array'
                        THEN p->'conditions'->'users'->'includeRoles' ELSE '[]'::jsonb END AS inc_roles,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeRoles') = 'array'
                        THEN p->'conditions'->'users'->'excludeRoles' ELSE '[]'::jsonb END AS ex_roles,
                   COALESCE(p->'conditions'->'applications'->'includeApplications', '[]'::jsonb) ? 'All' AS all_apps
              FROM posture po
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(po.ca_policies) = 'array' THEN po.ca_policies ELSE '[]'::jsonb END) p
             WHERE p->>'state' IN ('enabled', 'enabledForReportingButNotEnforced')
        ),
        pol AS (
            SELECT r.*,
                   CASE
                     WHEN r.builtin ?| ARRAY['compliantDevice', 'domainJoinedDevice']
                          AND (r.operator = 'AND'
                               OR (r.other_controls = 0
                                   AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(r.builtin) c
                                                    WHERE c NOT IN ('compliantDevice', 'domainJoinedDevice'))))
                     THEN 'required'
                     WHEN r.builtin ? 'block'
                          AND (position('device.iscompliant' IN lower(r.device_rule)) > 0
                               OR position('device.trusttype' IN lower(r.device_rule)) > 0)
                     THEN 'required'
                     WHEN r.builtin ?| ARRAY['compliantDevice', 'domainJoinedDevice'] THEN 'optional'
                   END AS device_control
              FROM raw r
        ),
        cov AS (
            SELECT DISTINCT p.id, p.name, t.role_template_id
              FROM pol p
              JOIN tier0 t ON (p.inc_users ? 'All' OR p.inc_roles ? t.role_template_id)
                          AND NOT p.ex_roles ? t.role_template_id
             WHERE p.state = 'enabled' AND p.evaluable AND p.all_apps AND p.device_control = 'required'
        ),
        state AS (
            SELECT po.client_id,
                   EXISTS (SELECT 1 FROM pol WHERE state = 'enabled' AND NOT evaluable
                                               AND device_control IS NOT NULL) AS unevaluable,
                   EXISTS (SELECT 1 FROM cov) AS covered,
                   (SELECT jsonb_agg(jsonb_build_object(
                               'policy', p.name, 'id', p.id, 'state', p.state,
                               'device_control', p.device_control, 'all_resources', p.all_apps)
                           ORDER BY p.name, p.id)
                      FROM pol p WHERE p.device_control IS NOT NULL) AS device_policies_not_counted
              FROM posture po
        )
        SELECT
            'warn' AS status,
            md5('10021:' || s.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Privileged access is not restricted to managed devices -- no enabled Conditional Access policy '
                || 'requires a compliant or hybrid-joined device for the highly privileged roles' AS summary,
            jsonb_build_object(
                'device_policies_not_counted', s.device_policies_not_counted,
                'note', 'A policy counts when it is enabled, targets all resources, applies to a highly '
                        || 'privileged role and makes a compliant or hybrid-joined device mandatory.'
            ) AS detail
        FROM state s
        WHERE NOT s.unevaluable
          AND NOT s.covered
    """,
}
