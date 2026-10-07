"""
Plugin 10024: Admin Portals or Azure Management Not Covered by MFA

Reports each of the two Microsoft control-plane targets that no enabled
Conditional Access policy for all users protects with MFA (or blocks):
- Microsoft Admin Portals (includeApplications value 'MicrosoftAdminPortals':
  Entra, Microsoft 365, Exchange, Intune, Defender, Purview admin centers);
- Windows Azure Service Management API (appId
  797f4846-ba00-4fd7-ba43-dac1f8f63013: Azure portal, Azure CLI, Azure
  PowerShell, ARM).

Why it matters: these are the tenant's and the Azure estate's control
planes. A typical "all apps" MFA policy that has grown application
exclusions, or a set of per-app policies, can leave them reachable with a
password alone. Microsoft's Conditional Access templates "Require MFA for
admin portals" and "Require MFA for Azure management" exist for exactly this
reason; from 2024-25 Microsoft also enforces MFA on these portals itself,
but that platform enforcement does not cover every client and is not a
tenant control you can audit.

A target is covered when an enabled policy:
- applies to all users (conditions.users.includeUsers contains 'All';
  user / group / role exclusions are tolerated -- plugin 10026 reports the
  excluded users), and
- includes the target explicitly in applications.includeApplications, or
  includes 'All' without listing the target in excludeApplications, and
- blocks, or requires MFA mandatorily ('mfa' built-in control or an
  authentication strength, under operator AND or as the only grant
  control; 'mfa OR compliantDevice' leaves MFA optional and does not count).

Result: one fail / high row per uncovered target, object_guid =
md5('10024:' || client_id || ':' || target) (target 'MicrosoftAdminPortals'
or the Azure management appId). detail lists policies that reach the target
but do not count (report-only, not all users, optional MFA) and all-users
MFA policies that exclude it.

Data caveats: needs the CA policy conditions (entra_graph_collector
0.7.0+). If an enabled policy requiring MFA or blocking has no conditions
object, coverage can't be evaluated and no row is returned. No row when no
Entra posture was collected. Security Defaults, when enabled, requires MFA
for Azure management and admin roles, so nothing is reported then.
"""

PLUGIN = {
    "plugin_id": 10024,
    "category": "Hybrid Identity",
    "name": "Admin Portals or Azure Management Not Covered by MFA",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10024",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.3.2",
        "NIST-800-53-IA-2(1)",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.4.1",
        "PCI-DSS-4.0-8.4.2",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "HIPAA-164.312(d)",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1110.003",
    ],
    "references": [
        {"title": "Microsoft: Conditional Access target resources (Microsoft Admin Portals, Windows Azure Service Management API)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-cloud-apps"},
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.3.2)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
    ],
    "description": (
        "No enabled Conditional Access policy for all users requires MFA "
        "(or blocks) for Microsoft Admin Portals or the Windows Azure "
        "Service Management API (one row per uncovered target). These are "
        "the tenant and Azure control planes; an all-apps policy with "
        "exclusions or a set of per-app policies often leaves them "
        "reachable with a password alone."
    ),
    "remediation": (
        "Create a Conditional Access policy: Users = All users (exclude only "
        "the emergency-access accounts); Target resources = Select resources "
        "-> Microsoft Admin Portals and Windows Azure Service Management API "
        "(or All resources without excluding them); Grant = Require "
        "multifactor authentication or an authentication strength, as the "
        "only control or with 'Require all the selected controls'. Test "
        "report-only, then switch it On. Remove these two targets from the "
        "application exclusions of any all-resources MFA policy."
    ),
    "base_severity": "high",
    "query": """
        WITH target(key, label) AS (
            VALUES ('MicrosoftAdminPortals', 'Microsoft Admin Portals'),
                   ('797f4846-ba00-4fd7-ba43-dac1f8f63013', 'Windows Azure Service Management API')
        ),
        posture AS (
            SELECT sp.client_id, COALESCE(sp.security_defaults_enabled, FALSE) AS sd, sp.ca_policies
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
                   COALESCE(jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object', FALSE) AS has_strength,
                   (CASE WHEN jsonb_typeof(p->'grant_controls'->'customAuthenticationFactors') = 'array'
                         THEN jsonb_array_length(p->'grant_controls'->'customAuthenticationFactors') ELSE 0 END
                    + CASE WHEN jsonb_typeof(p->'grant_controls'->'termsOfUse') = 'array'
                           THEN jsonb_array_length(p->'grant_controls'->'termsOfUse') ELSE 0 END) AS other_controls,
                   COALESCE(p->'conditions'->'users'->'includeUsers', '[]'::jsonb) ? 'All' AS all_users,
                   CASE WHEN jsonb_typeof(p->'conditions'->'applications'->'includeApplications') = 'array'
                        THEN p->'conditions'->'applications'->'includeApplications' ELSE '[]'::jsonb END AS inc_apps,
                   CASE WHEN jsonb_typeof(p->'conditions'->'applications'->'excludeApplications') = 'array'
                        THEN p->'conditions'->'applications'->'excludeApplications' ELSE '[]'::jsonb END AS ex_apps
              FROM posture po
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(po.ca_policies) = 'array' THEN po.ca_policies ELSE '[]'::jsonb END) p
             WHERE p->>'state' IN ('enabled', 'enabledForReportingButNotEnforced')
        ),
        pol AS (
            SELECT r.*,
                   r.builtin ? 'block' AS blocks,
                   (r.builtin ? 'mfa' OR r.has_strength) AS mfa,
                   (r.builtin ? 'block'
                    OR ((r.builtin ? 'mfa' OR r.has_strength)
                        AND (r.operator = 'AND'
                             OR jsonb_array_length(r.builtin) + CASE WHEN r.has_strength THEN 1 ELSE 0 END
                                + r.other_controls <= 1))) AS protects
              FROM raw r
        ),
        reach AS (
            -- (policy, target) pairs where the policy's application scope includes the target
            SELECT p.*, t.key, t.label,
                   EXISTS (SELECT 1 FROM jsonb_array_elements_text(p.inc_apps) a WHERE lower(a) = lower(t.key))
                   OR (p.inc_apps ? 'All'
                       AND NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(p.ex_apps) a
                                        WHERE lower(a) = lower(t.key))) AS reaches,
                   p.inc_apps ? 'All'
                   AND EXISTS (SELECT 1 FROM jsonb_array_elements_text(p.ex_apps) a
                                WHERE lower(a) = lower(t.key)) AS excludes_target
              FROM pol p
              CROSS JOIN target t
             WHERE p.evaluable AND (p.mfa OR p.blocks)
        ),
        state AS (
            SELECT po.client_id, po.sd,
                   EXISTS (SELECT 1 FROM pol WHERE state = 'enabled' AND NOT evaluable AND (mfa OR blocks))
                       AS unevaluable
              FROM posture po
        )
        SELECT
            'fail' AS status,
            md5('10024:' || s.client_id::text || ':' || t.key)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            t.label || ' is not covered by MFA -- no enabled Conditional Access policy for all users '
                || 'requires MFA or blocks access to it' AS summary,
            jsonb_build_object(
                'target', t.label,
                'target_id', t.key,
                'policies_reaching_target_not_counted',
                    (SELECT jsonb_agg(jsonb_build_object(
                                'policy', r.name, 'id', r.id, 'state', r.state,
                                'all_users', r.all_users, 'mfa_mandatory_or_block', r.protects)
                            ORDER BY r.name, r.id)
                       FROM reach r WHERE r.key = t.key AND r.reaches),
                'all_users_mfa_policies_excluding_target',
                    (SELECT jsonb_agg(jsonb_build_object('policy', r.name, 'id', r.id) ORDER BY r.name, r.id)
                       FROM reach r WHERE r.key = t.key AND r.excludes_target
                        AND r.state = 'enabled' AND r.all_users)
            ) AS detail
        FROM state s
        CROSS JOIN target t
        WHERE NOT s.sd
          AND NOT s.unevaluable
          AND NOT EXISTS (SELECT 1 FROM reach r
                           WHERE r.key = t.key AND r.reaches AND r.state = 'enabled'
                             AND r.all_users AND r.protects)
    """,
}
