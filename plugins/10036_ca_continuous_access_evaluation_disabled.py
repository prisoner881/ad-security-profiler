"""
Plugin 10036: Conditional Access Policy Turns Off Continuous Access Evaluation

Reports enabled Conditional Access policies whose session control
continuousAccessEvaluation.mode is 'disabled'.

Why: Continuous Access Evaluation (CAE) lets Entra ID and CAE-aware
services (Exchange Online, SharePoint Online, Teams, Microsoft Graph)
revoke an access token within minutes when the user is disabled, their
password is reset, their session is revoked, they are flagged high risk,
or they move to a disallowed network. A CA policy can switch CAE off for
the users and applications it covers; their tokens then stay valid for
their full lifetime (up to 28 hours for CAE-capable clients) after an
account is blocked or its password reset -- the window token-theft and
device-code phishing campaigns rely on (Storm-2372, the 2026 "EvilTokens"
kits; Purple Knight and Tenable both flag it).

The setting is only returned by the beta Conditional Access API:
entra_tenant_setting 'ca_policies_beta' (source ca_policies_beta,
entra_graph_collector 0.9.0). 'strictEnforcement' / 'strictLocation'
(stricter than the default) are not reported. A policy that also sets
disableResilienceDefaults is noted in detail (that choice is about
availability during an Entra outage, not a weakness in itself).

One finding per policy (object_guid md5('10036:' || client_id || ':' ||
policy id)); fail / medium.
"""

PLUGIN = {
    "plugin_id": 10036,
    "category": "Hybrid Identity",
    "name": "Conditional Access Policy Turns Off Continuous Access Evaluation",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10036",
    "requires_sources": ["ca_policies_beta"],
    "framework_tags": [
        "NIST-800-53-AC-12",
        "NIST-800-53-AC-2",
        "NIST-CSF-2.0-PR.AA-05",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1550.001",
        "MITRE-ATTCK-T1528",
    ],
    "references": [
        {"title": "Microsoft: Continuous access evaluation",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation"},
        {"title": "Microsoft Graph (beta): conditionalAccessSessionControls resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-beta"},
        {"title": "MITRE ATT&CK T1550.001: Use Alternate Authentication Material: Application Access Token",
         "url": "https://attack.mitre.org/techniques/T1550/001/"},
    ],
    "description": (
        "An enabled Conditional Access policy disables Continuous Access Evaluation for "
        "the users and applications it covers, so their access tokens stay valid for "
        "their full lifetime after the account is disabled, its password reset or its "
        "sessions revoked -- the window stolen-token and device-code phishing attacks use."
    ),
    "remediation": (
        "Entra admin center > Protection > Conditional Access > open the policy > Session > "
        "Customize continuous access evaluation: clear 'Disable' (or choose strict "
        "enforcement). If an application broke with CAE, scope the exception to that "
        "application and a small group instead of turning CAE off broadly, and track it "
        "for removal."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            md5('10036:' || ts.client_id::text || ':' || lower(COALESCE(p->>'id', p->>'display_name')))::uuid
                AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Conditional Access policy "' || COALESCE(p->>'display_name', p->>'id')
                || '" turns off Continuous Access Evaluation' AS summary,
            jsonb_build_object(
                'policy_id', p->>'id',
                'policy_name', p->>'display_name',
                'continuous_access_evaluation', p->'session_controls'->'continuousAccessEvaluation',
                'disable_resilience_defaults', p->'session_controls'->'disableResilienceDefaults',
                'users', p->'conditions'->'users',
                'applications', p->'conditions'->'applications'
            ) AS detail
        FROM entra_tenant_setting ts
        CROSS JOIN LATERAL jsonb_array_elements(
            CASE WHEN jsonb_typeof(ts.content) = 'array' THEN ts.content ELSE '[]'::jsonb END) p
        WHERE ts.client_id = %(client_id)s
          AND ts.setting_name = 'ca_policies_beta'
          AND p->>'state' = 'enabled'
          AND lower(p->'session_controls'->'continuousAccessEvaluation'->>'mode') = 'disabled'
    """,
}
