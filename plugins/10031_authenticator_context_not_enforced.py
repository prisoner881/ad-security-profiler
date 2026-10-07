"""
Plugin 10031: Microsoft Authenticator Push Not Hardened (Login Context / Number Matching)

Detects Microsoft Authenticator enabled in the authentication methods policy
without the sign-in context features that defeat MFA-fatigue attacks:
featureSettings.displayAppInformationRequiredState (show the application
name) and displayLocationInformationRequiredState (show the geographic
location) not set to 'enabled' for all users, or numberMatchingRequiredState
explicitly 'disabled'.

Why: push approvals without context are how MFA-fatigue / push-bombing
attacks succeed (Lapsus$, Uber 2022; MITRE ATT&CK T1621). CISA SCuBA
MS.AAD.3.3 says that if Microsoft Authenticator is enabled it SHALL show
login context information, with the feature enabled and targeted at all
users. Microsoft enforces number matching for every tenant since May 2023,
so 'default' (Microsoft-managed) is accepted for it; only an explicit
'disabled' is reported. For application name and location 'default' does
not satisfy SCuBA and is reported.

Data: entra_tenant_setting 'auth_methods_policy' (schema v42).
requires_sources ['auth_methods_policy']. No finding when Authenticator is
disabled (SCuBA MS.AAD.3.3 then does not apply). A feature setting that is
'enabled' but whose includeTarget is a group instead of all_users is
reported as partial coverage, as SCuBA's own check requires all users.

Severity: medium (warn), one tenant-level row (identity md5 of plugin and
client) listing every gap.
"""

PLUGIN = {
    "plugin_id": 10031,
    "category": "Hybrid Identity",
    "name": "Microsoft Authenticator Push Not Hardened (Login Context / Number Matching)",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10031",
    "requires_sources": ["auth_methods_policy"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.3.3",
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-IA-2(2)",
        "NIST-800-53-IA-2(8)",
        "NIST-CSF-2.0-PR.AA-03",
        "CIS-CSC-8-6.3",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1621",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.3.3)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Use additional context in Microsoft Authenticator notifications",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-additional-context"},
        {"title": "Microsoft: How number matching works in MFA push notifications",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-number-match"},
        {"title": "MITRE ATT&CK T1621: Multi-Factor Authentication Request Generation",
         "url": "https://attack.mitre.org/techniques/T1621/"},
    ],
    "description": (
        "Microsoft Authenticator is enabled but its push notifications do not show the "
        "application name and/or the sign-in location to all users, or number matching "
        "is explicitly disabled. Without that context users approve attacker-triggered "
        "prompts (MFA fatigue). CISA SCuBA MS.AAD.3.3 requires login context to be shown "
        "when Authenticator is enabled. One tenant-level finding listing each gap; "
        "number matching set to Microsoft-managed ('default') is accepted because "
        "Microsoft enforces it."
    ),
    "remediation": (
        "Entra admin center > Protection > Authentication methods > Microsoft "
        "Authenticator > Configure: set 'Show application name in push and passwordless "
        "notifications' and 'Show geographic location in push and passwordless "
        "notifications' to Status = Enabled, Target = All users, and leave number "
        "matching enabled. Also set 'Allow use of Microsoft Authenticator OTP' to No "
        "(SCuBA MS.AAD.3.3 instructions). With Graph: "
        "Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration "
        "-AuthenticationMethodConfigurationId MicrosoftAuthenticator with featureSettings "
        "displayAppInformationRequiredState / displayLocationInformationRequiredState "
        "= @{state='enabled'; includeTarget=@{targetType='group'; id='all_users'}}."
    ),
    "base_severity": "medium",
    "query": """
        WITH pol AS (
            SELECT ts.client_id, ts.content
              FROM entra_tenant_setting ts
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'auth_methods_policy'
               AND jsonb_typeof(ts.content) = 'object'
        ),
        authn AS (
            SELECT pol.client_id,
                   CASE WHEN jsonb_typeof(m->'featureSettings') = 'object'
                        THEN m->'featureSettings' ELSE '{}'::jsonb END AS fs
              FROM pol
             CROSS JOIN LATERAL jsonb_array_elements(
                   CASE WHEN jsonb_typeof(pol.content->'authenticationMethodConfigurations') = 'array'
                        THEN pol.content->'authenticationMethodConfigurations' ELSE '[]'::jsonb END) m
             WHERE m->>'id' = 'MicrosoftAuthenticator'
               AND lower(COALESCE(m->>'state', '')) = 'enabled'
        ),
        feat AS (
            SELECT a.client_id, a.fs,
                   lower(a.fs->'displayAppInformationRequiredState'->>'state') AS app_state,
                   a.fs->'displayAppInformationRequiredState'->'includeTarget'->>'id' AS app_target,
                   lower(a.fs->'displayLocationInformationRequiredState'->>'state') AS loc_state,
                   a.fs->'displayLocationInformationRequiredState'->'includeTarget'->>'id' AS loc_target,
                   lower(a.fs->'numberMatchingRequiredState'->>'state') AS nm_state
              FROM authn a
        ),
        gaps AS (
            SELECT f.*,
                   array_remove(ARRAY[
                       CASE WHEN f.app_state IS DISTINCT FROM 'enabled'
                            THEN 'application name not shown (state ' || COALESCE(f.app_state, 'not set') || ')'
                            WHEN f.app_target IS DISTINCT FROM 'all_users'
                            THEN 'application name shown to selected users only' END,
                       CASE WHEN f.loc_state IS DISTINCT FROM 'enabled'
                            THEN 'geographic location not shown (state ' || COALESCE(f.loc_state, 'not set') || ')'
                            WHEN f.loc_target IS DISTINCT FROM 'all_users'
                            THEN 'geographic location shown to selected users only' END,
                       CASE WHEN f.nm_state = 'disabled'
                            THEN 'number matching disabled' END
                   ], NULL) AS issues
              FROM feat f
        )
        SELECT
            'warn' AS status,
            md5('10031:' || g.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Microsoft Authenticator push notifications are not hardened: '
                || array_to_string(g.issues, '; ') AS summary,
            jsonb_build_object(
                'issues', to_jsonb(g.issues),
                'display_app_information', g.fs->'displayAppInformationRequiredState',
                'display_location_information', g.fs->'displayLocationInformationRequiredState',
                'number_matching', g.fs->'numberMatchingRequiredState',
                'scuba_policy', 'MS.AAD.3.3'
            ) AS detail
        FROM gaps g
        WHERE cardinality(g.issues) > 0
    """,
}
