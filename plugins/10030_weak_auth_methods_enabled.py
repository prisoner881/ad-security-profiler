"""
Plugin 10030: Weak Authentication Methods Enabled (SMS, Voice Call, Email OTP)

Detects the SMS, Voice call and Email one-time-passcode methods enabled in
the tenant's authentication methods policy
(policies/authenticationMethodsPolicy, authenticationMethodConfigurations[]
with id 'Sms', 'Voice' or 'Email' and state 'enabled').

Why: these are the weakest authenticators. SMS and voice codes are lost to
SIM swapping, number porting and telephony interception, and all three are
relayed in real time by adversary-in-the-middle phishing kits. CISA SCuBA
MS.AAD.3.5 says they SHALL be disabled (BOD 25-01). SMS can also be enabled
as a primary sign-in factor (includeTargets[].isUsableForSignIn), which is
shown in the detail.

Data: entra_tenant_setting 'auth_methods_policy' (schema v42, collector
0.8.0, Policy.Read.All). requires_sources ['auth_methods_policy']: without
a successful read there is no row and the plugin returns nothing, which
adaudit reports as NOT ASSESSED.

Severity: one row per enabled method (identity md5 of plugin, client and
method id). High (fail) when the method targets all users (an includeTargets
element with id 'all_users'); medium (warn) when it targets selected groups
only. Disabled methods are not reported.
"""

PLUGIN = {
    "plugin_id": 10030,
    "category": "Hybrid Identity",
    "name": "Weak Authentication Methods Enabled (SMS, Voice Call, Email OTP)",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10030",
    "requires_sources": ["auth_methods_policy"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.3.5",
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-IA-2(8)",
        "NIST-800-53-IA-5",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.4.2",
        "CIS-CSC-8-6.3",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "HIPAA-164.312(d)",
        "MITRE-ATTCK-T1621",
        "MITRE-ATTCK-T1566.002",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.3.5)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Manage authentication methods for Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-authentication-methods-manage"},
        {"title": "Microsoft: SMS-based authentication",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-sms-signin"},
    ],
    "description": (
        "The SMS, Voice call or Email OTP authentication method is enabled in the "
        "authentication methods policy. These are the weakest authenticators: codes "
        "are intercepted by SIM swapping and relayed by adversary-in-the-middle "
        "phishing. CISA SCuBA MS.AAD.3.5 says they SHALL be disabled. One finding per "
        "enabled method: high when it targets all users, medium when it targets "
        "selected groups. The detail lists the include/exclude targets and whether SMS "
        "is usable as a primary sign-in factor."
    ),
    "remediation": (
        "Make sure users have registered a stronger method first (Microsoft "
        "Authenticator, FIDO2 security keys or passkeys, Windows Hello for Business, "
        "certificate-based authentication), using the registration campaign and the "
        "userRegistrationDetails report. Then, in the Entra admin center, go to "
        "Protection > Authentication methods > Policies and set SMS, Voice call and "
        "Email OTP to Enabled = No (or narrow them to a small exception group), e.g. "
        "Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration "
        "-AuthenticationMethodConfigurationId Sms -BodyParameter @{'@odata.type'="
        "'#microsoft.graph.smsAuthenticationMethodConfiguration'; state='disabled'}. "
        "Email OTP may still be needed for B2B guests without an identity provider; "
        "if so, scope it to them."
    ),
    "base_severity": "high",
    "query": """
        WITH pol AS (
            SELECT ts.client_id, ts.content
              FROM entra_tenant_setting ts
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'auth_methods_policy'
               AND jsonb_typeof(ts.content) = 'object'
        ),
        method AS (
            SELECT pol.client_id,
                   m->>'id' AS method_id,
                   CASE WHEN jsonb_typeof(m->'includeTargets') = 'array'
                        THEN m->'includeTargets' ELSE '[]'::jsonb END AS include_targets,
                   CASE WHEN jsonb_typeof(m->'excludeTargets') = 'array'
                        THEN m->'excludeTargets' ELSE '[]'::jsonb END AS exclude_targets
              FROM pol
             CROSS JOIN LATERAL jsonb_array_elements(
                   CASE WHEN jsonb_typeof(pol.content->'authenticationMethodConfigurations') = 'array'
                        THEN pol.content->'authenticationMethodConfigurations' ELSE '[]'::jsonb END) m
             WHERE m->>'id' IN ('Sms', 'Voice', 'Email')
               AND lower(COALESCE(m->>'state', '')) = 'enabled'
        ),
        scored AS (
            SELECT m.*,
                   EXISTS (SELECT 1 FROM jsonb_array_elements(m.include_targets) t
                            WHERE t->>'id' = 'all_users') AS all_users,
                   EXISTS (SELECT 1 FROM jsonb_array_elements(m.include_targets) t
                            WHERE t->'isUsableForSignIn' = 'true'::jsonb) AS usable_for_sign_in,
                   CASE m.method_id WHEN 'Sms' THEN 'SMS' WHEN 'Voice' THEN 'Voice call'
                                    ELSE 'Email OTP' END AS method_label
              FROM method m
        )
        SELECT
            CASE WHEN s.all_users THEN 'fail' ELSE 'warn' END AS status,
            md5('10030:' || s.client_id::text || ':' || s.method_id)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN s.all_users THEN 'high' ELSE 'medium' END AS fd_severity,
            'Weak authentication method ' || s.method_label || ' is enabled for '
                || CASE WHEN s.all_users THEN 'all users' ELSE 'selected groups' END
                || CASE WHEN s.usable_for_sign_in THEN ' (also usable as a primary sign-in factor)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'method_id', s.method_id,
                'state', 'enabled',
                'targets_all_users', s.all_users,
                'usable_for_sign_in', s.usable_for_sign_in,
                'include_targets', s.include_targets,
                'exclude_targets', s.exclude_targets,
                'scuba_policy', 'MS.AAD.3.5'
            ) AS detail
        FROM scored s
    """,
}
