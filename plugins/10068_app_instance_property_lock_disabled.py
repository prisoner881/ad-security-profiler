"""
Plugin 10068: App Instance Property Lock Disabled on a Multi-Tenant Application

Reports this tenant's multi-tenant application registrations
(signInAudience AzureADMultipleOrgs or AzureADandPersonalMicrosoftAccount)
whose app instance property lock (servicePrincipalLockConfiguration) is
disabled. One finding per application, low, status 'warn'.

Why it matters: when a multi-tenant application is consented in another
tenant, a service principal (the app instance) is created there. Without
the lock, an administrator -- or attacker -- in THAT tenant can change
sensitive properties of the instance, in particular add credentials
(passwordCredentials / keyCredentials) or change the token-signing key, and
so act as your application with the permissions it holds there, under your
application's name and publisher (MITRE T1098.001). The lock makes those
properties read-only outside the owning tenant. Microsoft enables it by
default for applications created since March 2024; older applications need
it switched on.

Excluded: single-tenant applications (AzureADMyOrg) and personal-account-
only applications (PersonalMicrosoftAccount), which have no instances in
other Entra tenants.

Data: entra_application.sign_in_audience and service_principal_lock_enabled
(servicePrincipalLockConfiguration.isEnabled; schema v42, core applications
step). NULL in either = not returned (older collector, or Graph omitted the
configuration) -> not reported. Identity = the application's object id.
"""

PLUGIN = {
    "plugin_id": 10068,
    "category": "Hybrid Identity",
    "name": "App Instance Property Lock Disabled on a Multi-Tenant Application",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10068",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1098.001",
    ],
    "references": [
        {"title": "Microsoft: How to configure app instance property lock for your applications",
         "url": "https://learn.microsoft.com/en-us/entra/identity-platform/howto-configure-app-instance-property-locks"},
        {"title": "Microsoft Graph: servicePrincipalLockConfiguration resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/serviceprincipallockconfiguration"},
        {"title": "MITRE ATT&CK T1098.001: Additional Cloud Credentials",
         "url": "https://attack.mitre.org/techniques/T1098/001/"},
    ],
    "description": (
        "A multi-tenant application registered in this tenant has the app "
        "instance property lock disabled, so administrators in any tenant "
        "where the application is installed can add credentials to its "
        "service principal there and act as your application. Microsoft "
        "enables the lock by default for new applications; older ones "
        "need it switched on. Low."
    ),
    "remediation": (
        "Entra admin center -> App registrations -> the app -> "
        "Authentication -> App instance property lock -> Configure: "
        "enable the lock for all properties. PowerShell: "
        "Update-MgApplication -ApplicationId <object id> "
        "-ServicePrincipalLockConfiguration @{IsEnabled=$true; "
        "AllProperties=$true}. If the application does not need to be "
        "multi-tenant, change its supported account types to this "
        "organisation only."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            a.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Multi-tenant application "' || COALESCE(a.display_name, a.app_id::text, a.entra_object_id::text)
                || '" (' || a.sign_in_audience || ') has the app instance property lock disabled' AS summary,
            jsonb_build_object(
                'application_id', a.entra_object_id,
                'app_id', a.app_id,
                'display_name', a.display_name,
                'sign_in_audience', a.sign_in_audience,
                'service_principal_lock_enabled', a.service_principal_lock_enabled
            ) AS detail
        FROM entra_application a
        WHERE a.client_id = %(client_id)s
          AND a.sign_in_audience IN ('AzureADMultipleOrgs', 'AzureADandPersonalMicrosoftAccount')
          AND a.service_principal_lock_enabled IS FALSE
    """,
}
