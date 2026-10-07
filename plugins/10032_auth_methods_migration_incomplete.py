"""
Plugin 10032: Authentication Methods Policy Migration Not Complete

Detects a tenant whose authentication methods policy reports
policyMigrationState other than 'migrationComplete' (i.e. 'preMigration'
or 'migrationInProgress').

Why: until the migration is marked complete, the legacy per-user MFA and
SSPR method policies are still honoured alongside the authentication
methods policy, so a method disabled in one place can still be enabled in
the other and nobody sees the whole picture. Microsoft retired the legacy
policies in September 2025. CISA SCuBA MS.AAD.3.4 says the Manage Migration
feature SHALL be set to Migration Complete.

Data: entra_tenant_setting 'auth_methods_policy' (schema v42).
requires_sources ['auth_methods_policy']. A policy object without
policyMigrationState (not returned by Graph) is not reported, since the
state is then unknown.

Severity: low (warn), one tenant-level row (identity md5 of plugin and
client).
"""

PLUGIN = {
    "plugin_id": 10032,
    "category": "Hybrid Identity",
    "name": "Authentication Methods Policy Migration Not Complete",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10032",
    "requires_sources": ["auth_methods_policy"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.3.4",
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.PS-01",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.3.4)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: How to migrate MFA and SSPR policy settings to the Authentication methods policy",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-methods-manage"},
    ],
    "description": (
        "The authentication methods policy migration is not marked complete "
        "(policyMigrationState is preMigration or migrationInProgress), so the legacy "
        "MFA and SSPR method settings are still honoured alongside the authentication "
        "methods policy and methods can be enabled where administrators no longer look. "
        "CISA SCuBA MS.AAD.3.4 requires Migration Complete."
    ),
    "remediation": (
        "Review the legacy MFA service settings (per-user MFA > service settings > "
        "verification options) and the SSPR authentication methods, reproduce the "
        "intended methods in Entra admin center > Protection > Authentication methods > "
        "Policies, then set Manage migration to 'Migration Complete' (Authentication "
        "methods > Policies > Manage migration). With Graph: "
        "Update-MgPolicyAuthenticationMethodPolicy -PolicyMigrationState migrationComplete."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            md5('10032:' || ts.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Authentication methods policy migration is not complete (state '
                || (ts.content->>'policyMigrationState') || ')' AS summary,
            jsonb_build_object(
                'policy_migration_state', ts.content->>'policyMigrationState',
                'scuba_policy', 'MS.AAD.3.4'
            ) AS detail
        FROM entra_tenant_setting ts
        WHERE ts.client_id = %(client_id)s
          AND ts.setting_name = 'auth_methods_policy'
          AND jsonb_typeof(ts.content) = 'object'
          AND jsonb_typeof(ts.content->'policyMigrationState') = 'string'
          AND ts.content->>'policyMigrationState' <> 'migrationComplete'
    """,
}
