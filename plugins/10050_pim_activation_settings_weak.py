"""
Plugin 10050: PIM Activation Settings Weak for Highly Privileged Roles

Reads the Privileged Identity Management (PIM) role settings of every highly
privileged directory role (entra_role_management_policy, schema v42: the
unifiedRoleManagementPolicy rules assigned at scope '/') and reports the roles
whose settings undo the value of just-in-time access.

Checks, per role (one finding per role, every problem listed, worst wins):
- activation does not require MFA: the Enablement_EndUser_Assignment rule's
  enabledRules lacks 'MultiFactorAuthentication' AND the
  AuthenticationContext_EndUser_Assignment rule is not enabled (a Conditional
  Access authentication context can enforce MFA or a stronger method
  instead) -> high. Activation without MFA turns any stolen session of an
  eligible user into a privileged one;
- Global Administrator or Privileged Role Administrator activation needs no
  approval (Approval_EndUser_Assignment setting.isApprovalRequired false)
  -> high (CISA SCuBA MS.AAD.7.6 for Global Administrator);
- maximum activation duration (Expiration_EndUser_Assignment
  maximumDuration, ISO 8601: 'PT8H', 'PT1H30M', 'P1D', ...) longer than
  8 hours -> medium;
- eligible assignments may be permanent (Expiration_Admin_Eligibility
  isExpirationRequired false) -> medium;
- active assignments may be permanent (Expiration_Admin_Assignment
  isExpirationRequired false) -> medium (SCuBA MS.AAD.7.4: permanent active
  assignments SHALL NOT be allowed for highly privileged roles);
- activation does not require a justification (enabledRules lacks
  'Justification') -> low.
status 'fail' when the worst problem is high or medium, 'warn' when low.

Highly privileged set (same as plugins 10012, 10014, 11020): Global,
Privileged Role, Privileged Authentication, Security, Hybrid Identity,
Application, Cloud Application, Exchange, SharePoint, User, Conditional
Access, Authentication and Intune Administrator.

Data caveats: PIM role settings need Entra ID P2 and RoleManagementPolicy.
Read.Directory; requires_sources ['pim_policies'] makes a clean result NOT
ASSESSED when they could not be read. A rule missing from a role's policy, or
a duration that is not a parseable ISO 8601 duration, is treated as unknown
and that check is skipped for the role (the raw value is kept in detail).
Roles with no PIM policy row are not reported.

object_guid: md5('10050:' || client_id || ':' || role template id), one
identity per role.
"""

PLUGIN = {
    "plugin_id": 10050,
    "category": "Hybrid Identity",
    "name": "PIM Activation Settings Weak for Highly Privileged Roles",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10050",
    "requires_sources": ["pim_policies"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.7.4",
        "CISA-SCUBA-MS.AAD.7.6",
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-IA-2(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1098.003",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.7.4, 7.6)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Configure Microsoft Entra role settings in Privileged Identity Management",
         "url": "https://learn.microsoft.com/en-us/entra/id-governance/privileged-identity-management/pim-how-to-change-default-settings"},
        {"title": "Microsoft Graph: unifiedRoleManagementPolicyRule resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/unifiedrolemanagementpolicyrule"},
    ],
    "description": (
        "The PIM role settings of a highly privileged Entra role are weak: "
        "activation without MFA or an authentication context (high), Global "
        "Administrator / Privileged Role Administrator activation without "
        "approval (high, SCuBA MS.AAD.7.6), activation longer than 8 hours, "
        "permanent eligible or permanent active assignments allowed (medium, "
        "SCuBA MS.AAD.7.4), or no justification required (low). One finding "
        "per role listing every problem. Needs the PIM role settings "
        "(Entra ID P2)."
    ),
    "remediation": (
        "Entra admin center -> Identity governance -> Privileged Identity "
        "Management -> Microsoft Entra roles -> Settings -> <role> -> Edit. "
        "Activation: set maximum duration to 8 hours or less, require "
        "'Azure MFA' (or a Conditional Access authentication context that "
        "requires phishing-resistant MFA), require justification, and for "
        "Global Administrator and Privileged Role Administrator require "
        "approval with named approvers. Assignment: clear 'Allow permanent "
        "eligible assignment' and 'Allow permanent active assignment' and set "
        "an expiry. Graph: Update-MgPolicyRoleManagementPolicyRule for the "
        "rules Enablement_EndUser_Assignment, Approval_EndUser_Assignment, "
        "Expiration_EndUser_Assignment, Expiration_Admin_Eligibility and "
        "Expiration_Admin_Assignment."
    ),
    "base_severity": "high",
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
        pol AS (
            SELECT p.client_id, p.role_template_id, p.policy_id, t.role_name,
                   rl.r_enable, rl.r_authctx, rl.r_approval, rl.r_exp_user, rl.r_exp_elig, rl.r_exp_assign
              FROM entra_role_management_policy p
              JOIN tier0 t ON t.template_id = p.role_template_id
              CROSS JOIN LATERAL (
                  SELECT max(r::text) FILTER (WHERE r->>'id' = 'Enablement_EndUser_Assignment')::jsonb AS r_enable,
                         max(r::text) FILTER (WHERE r->>'id' = 'AuthenticationContext_EndUser_Assignment')::jsonb AS r_authctx,
                         max(r::text) FILTER (WHERE r->>'id' = 'Approval_EndUser_Assignment')::jsonb AS r_approval,
                         max(r::text) FILTER (WHERE r->>'id' = 'Expiration_EndUser_Assignment')::jsonb AS r_exp_user,
                         max(r::text) FILTER (WHERE r->>'id' = 'Expiration_Admin_Eligibility')::jsonb AS r_exp_elig,
                         max(r::text) FILTER (WHERE r->>'id' = 'Expiration_Admin_Assignment')::jsonb AS r_exp_assign
                    FROM jsonb_array_elements(CASE WHEN jsonb_typeof(p.rules) = 'array'
                                                   THEN p.rules ELSE '[]'::jsonb END) r
                   WHERE jsonb_typeof(r) = 'object'
              ) rl
             WHERE p.client_id = %(client_id)s
        ),
        parsed AS (
            SELECT p.*,
                   CASE WHEN p.r_enable IS NULL THEN NULL
                        WHEN jsonb_typeof(p.r_enable->'enabledRules') = 'array' THEN p.r_enable->'enabledRules'
                        ELSE '[]'::jsonb END AS enabled_rules,
                   p.r_exp_user->>'maximumDuration' AS max_duration,
                   -- ISO 8601 duration -> seconds (weeks, days, hours, minutes, seconds); NULL = unparseable
                   (SELECT COALESCE(m[1]::numeric, 0) * 604800 + COALESCE(m[2]::numeric, 0) * 86400
                           + COALESCE(m[3]::numeric, 0) * 3600 + COALESCE(m[4]::numeric, 0) * 60
                           + COALESCE(m[5]::numeric, 0)
                      FROM regexp_match(upper(btrim(p.r_exp_user->>'maximumDuration')),
                           '^P(?:(\\d+)W)?(?:(\\d+)D)?(?:T(?:(\\d+)H)?(?:(\\d+)M)?(?:(\\d+(?:\\.\\d+)?)S)?)?$') m
                     WHERE m IS NOT NULL
                       AND upper(btrim(p.r_exp_user->>'maximumDuration')) NOT IN ('P', 'PT')
                       AND upper(btrim(p.r_exp_user->>'maximumDuration')) NOT LIKE '%%T') AS max_duration_seconds
              FROM pol p
        ),
        issues AS (
            SELECT client_id, role_template_id, 3 AS rank,
                   'activation does not require MFA or an authentication context' AS issue
              FROM parsed
             WHERE enabled_rules IS NOT NULL
               AND NOT enabled_rules ? 'MultiFactorAuthentication'
               AND COALESCE(r_authctx->'isEnabled', 'false'::jsonb) <> 'true'::jsonb
            UNION ALL
            SELECT client_id, role_template_id, 3,
                   'activation does not require approval'
              FROM parsed
             WHERE role_template_id IN ('62e90394-69f5-4237-9190-012177145e10',
                                        'e8611ab8-c189-46e8-94e1-60213ab1f814')
               AND r_approval->'setting'->'isApprovalRequired' = 'false'::jsonb
            UNION ALL
            SELECT client_id, role_template_id, 2,
                   'maximum activation duration ' || max_duration || ' exceeds 8 hours'
              FROM parsed
             WHERE max_duration_seconds > 8 * 3600
            UNION ALL
            SELECT client_id, role_template_id, 2,
                   'permanent eligible assignments allowed'
              FROM parsed
             WHERE r_exp_elig->'isExpirationRequired' = 'false'::jsonb
            UNION ALL
            SELECT client_id, role_template_id, 2,
                   'permanent active assignments allowed'
              FROM parsed
             WHERE r_exp_assign->'isExpirationRequired' = 'false'::jsonb
            UNION ALL
            SELECT client_id, role_template_id, 1,
                   'activation does not require a justification'
              FROM parsed
             WHERE enabled_rules IS NOT NULL
               AND NOT enabled_rules ? 'Justification'
        ),
        agg AS (
            SELECT i.client_id, i.role_template_id, max(i.rank) AS rank,
                   string_agg(i.issue COLLATE "C", '; ' ORDER BY i.rank DESC, i.issue COLLATE "C") AS issue_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC, i.issue COLLATE "C") AS issue_list
              FROM issues i
             GROUP BY i.client_id, i.role_template_id
        )
        SELECT
            CASE WHEN a.rank >= 2 THEN 'fail' ELSE 'warn' END AS status,
            md5('10050:' || a.client_id::text || ':' || a.role_template_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE a.rank WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'PIM settings for ' || p.role_name || ' are weak: ' || a.issue_text AS summary,
            jsonb_build_object(
                'role', p.role_name,
                'role_template_id', a.role_template_id,
                'policy_id', p.policy_id,
                'issues', a.issue_list,
                'activation_enabled_rules', p.enabled_rules,
                'authentication_context_enabled', p.r_authctx->'isEnabled',
                'authentication_context_claim', p.r_authctx->'claimValue',
                'approval_required', p.r_approval->'setting'->'isApprovalRequired',
                'max_activation_duration', p.max_duration,
                'eligible_expiration_required', p.r_exp_elig->'isExpirationRequired',
                'eligible_max_duration', p.r_exp_elig->'maximumDuration',
                'active_expiration_required', p.r_exp_assign->'isExpirationRequired',
                'active_max_duration', p.r_exp_assign->'maximumDuration'
            ) AS detail
        FROM agg a
        JOIN parsed p ON p.client_id = a.client_id AND p.role_template_id = a.role_template_id
    """,
}
