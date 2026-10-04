"""
Plugin 10015: Conditional Access Policy Not Enforced

Lists Conditional Access policies whose state is report-only
('enabledForReportingButNotEnforced') or 'disabled' -- one low finding per
policy.

Why it matters: a report-only or disabled policy protects nothing; it only
logs what it would have done. CISA SCuBA recommends report-only only as a
short testing step before switching a policy On ("The policy will only be
enforced when it is set to On"), and baselines are routinely believed to be
in place because the policy exists in the portal. NIST CM-6 (configuration
settings must be implemented, not only defined). Policies left in
report-only for good are a common reason plugins 10004 (MFA), 10013 (legacy
authentication) and 10014 (phishing-resistant MFA for admins) fail; detail
says which of those controls the policy would provide once enforced
(requires MFA / an authentication strength, blocks legacy clients, ...).

Severity: low 'warn' -- the risk itself is reported by the plugin for the
missing control; this keeps the unenforced policy visible as the likely
fix. Microsoft-managed policies (created by Microsoft in report-only first)
and policies deliberately kept disabled as a rollback copy are reported
too; close them as accepted where that is intended.

Identity: one finding per policy, object_guid = md5('10015:' || client_id
|| ':' || policy id) -- renaming the policy or switching it between
report-only and disabled does not open a new finding. Works with rows from
older collectors (only id, display_name, state and grant_controls are
needed; the legacy-auth hint needs "conditions" and is null without it). No
rows when no Entra posture was collected.
"""

PLUGIN = {
    "plugin_id": 10015,
    "category": "Hybrid Identity",
    "name": "Conditional Access Policy Not Enforced",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "HYBRID-10015",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-2",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
    ],
    "references": [
        {"title": "Microsoft: Conditional Access report-only mode",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-conditional-access-report-only"},
        {"title": "CISA SCuBA Microsoft Entra ID baseline (Conditional Access policies)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
    ],
    "description": (
        "A Conditional Access policy is in report-only mode or disabled, "
        "so it enforces nothing -- it only logs what it would have done. "
        "Report-only is meant as a short test before switching a policy "
        "On. One low finding per policy; detail notes whether the policy "
        "would require MFA or an authentication strength, block access, "
        "or block legacy authentication once enforced (the controls "
        "plugins 10004, 10013 and 10014 check)."
    ),
    "remediation": (
        "Review the policy's report-only results (Entra admin center -> "
        "Protection -> Conditional Access -> Insights and reporting, or "
        "the sign-in log's Report-only tab). If it would not lock out "
        "legitimate users, set it On: Update-MgIdentityConditionalAccessPolicy "
        "-ConditionalAccessPolicyId <id> -State enabled. If it is "
        "obsolete, delete it rather than leaving it disabled, so the "
        "policy list reflects what is actually enforced."
    ),
    "base_severity": "low",
    "query": """
        WITH pol AS (
            SELECT sp.client_id,
                   p->>'id' AS id,
                   p->>'display_name' AS name,
                   p->>'state' AS state,
                   COALESCE(p->'grant_controls'->'builtInControls', '[]'::jsonb) AS builtin,
                   COALESCE(jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object', FALSE) AS has_strength,
                   p->'grant_controls'->'authenticationStrength'->>'displayName' AS strength_name,
                   CASE WHEN jsonb_typeof(p->'conditions') = 'object'
                        THEN COALESCE(p->'conditions'->'clientAppTypes', '[]'::jsonb) END AS client_apps
              FROM entra_security_posture sp
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(sp.ca_policies) = 'array' THEN sp.ca_policies ELSE '[]'::jsonb END) p
             WHERE sp.client_id = %(client_id)s
               AND p->>'state' IN ('enabledForReportingButNotEnforced', 'disabled')
        )
        SELECT
            'warn' AS status,
            md5('10015:' || p.client_id::text || ':' || COALESCE(p.id, p.name, ''))::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Conditional Access policy "' || COALESCE(p.name, p.id, '') || '" is not enforced ('
                || CASE p.state WHEN 'disabled' THEN 'disabled' ELSE 'report-only' END || ')' AS summary,
            jsonb_build_object(
                'policy_id', p.id,
                'policy_name', p.name,
                'state', p.state,
                'grant_controls', p.builtin,
                'requires_mfa', (p.builtin ? 'mfa' OR p.has_strength),
                'authentication_strength', p.strength_name,
                'blocks_access', p.builtin ? 'block',
                'blocks_legacy_auth', CASE WHEN p.client_apps IS NULL THEN NULL
                                           ELSE p.builtin ? 'block'
                                                AND p.client_apps ?| ARRAY['exchangeActiveSync', 'other'] END
            ) AS detail
        FROM pol p
    """,
}
