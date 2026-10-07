"""
Plugin 10035: System-Preferred MFA Disabled

Detects a tenant whose authentication methods policy has
systemCredentialPreferences.state set to 'disabled'.

Why: system-preferred MFA makes Entra prompt each user for the strongest
method they have registered (e.g. passkey or Authenticator push before SMS)
instead of their own default method. With it disabled, users who registered
a strong method but kept SMS or voice as the default keep using the weak
one, which remains open to SIM swapping and real-time phishing relay.
'default' means Microsoft-managed, which Microsoft has enabled for all
tenants, so only an explicit 'disabled' is reported.

Data: entra_tenant_setting 'auth_methods_policy' (schema v42).
requires_sources ['auth_methods_policy'].

Severity: low (warn), one tenant-level row (identity md5 of plugin and
client).
"""

PLUGIN = {
    "plugin_id": 10035,
    "category": "Hybrid Identity",
    "name": "System-Preferred MFA Disabled",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10035",
    "requires_sources": ["auth_methods_policy"],
    "framework_tags": [
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-IA-2(2)",
        "NIST-CSF-2.0-PR.AA-03",
        "CIS-CSC-8-6.3",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
    ],
    "references": [
        {"title": "Microsoft: System-preferred multifactor authentication",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-system-preferred-multifactor-authentication"},
    ],
    "description": (
        "System-preferred multifactor authentication is explicitly disabled, so users "
        "are prompted for their own default method (often SMS or voice) rather than the "
        "strongest method they have registered. Low: weakens the MFA that users "
        "actually perform without disabling it."
    ),
    "remediation": (
        "Entra admin center > Protection > Authentication methods > Settings: set "
        "System-preferred multifactor authentication to Microsoft managed or Enabled, "
        "targeting All users. With Graph: Update-MgPolicyAuthenticationMethodPolicy "
        "-SystemCredentialPreferences @{state='enabled'; includeTargets=@(@{targetType="
        "'group'; id='all_users'})}."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            md5('10035:' || ts.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'System-preferred multifactor authentication is disabled' AS summary,
            jsonb_build_object(
                'system_credential_preferences', ts.content->'systemCredentialPreferences'
            ) AS detail
        FROM entra_tenant_setting ts
        WHERE ts.client_id = %(client_id)s
          AND ts.setting_name = 'auth_methods_policy'
          AND jsonb_typeof(ts.content) = 'object'
          AND jsonb_typeof(ts.content->'systemCredentialPreferences') = 'object'
          AND lower(ts.content->'systemCredentialPreferences'->>'state') = 'disabled'
    """,
}
