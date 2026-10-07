"""
Plugin 10080: Users Can Create Entra Tenants

Reads the tenant authorization policy (entra_security_posture.
authorization_policy, Graph /policies/authorizationPolicy) and reports when
defaultUserRolePermissions.allowedToCreateTenants is true -- the default for
new tenants: any member user can create a new Microsoft Entra tenant from
the Entra admin center and becomes its Global Administrator.

Why it matters: user-created tenants sit outside the organisation's
governance, Conditional Access and logging, yet carry its users' identities
and often its brand. They are convenient staging grounds for consent-
phishing applications and for "trusted" external collaboration that bypasses
cross-tenant controls, and they are not deleted when the creator leaves.
Microsoft's hardening guidance and the CIS Microsoft 365 benchmark recommend
restricting tenant creation to administrators (NIST CM-7 least
functionality).

Result: one tenant-level low 'warn' when the value is JSON true. Tier A data
(no requires_sources): authorization_policy NULL (read failed -- see
authorization_policy_status) or the key absent -> no row.

object_guid: md5('10080:' || client_id).
"""

PLUGIN = {
    "plugin_id": 10080,
    "category": "Hybrid Identity",
    "name": "Users Can Create Entra Tenants",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10080",
    "framework_tags": [
        "NIST-800-53-CM-7",
        "NIST-800-53-CM-6",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.PS-01",
        "NIST-CSF-2.0-PR.AA-05",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.5.23",
        "SOC2-CC6.3",
    ],
    "references": [
        {"title": "Microsoft: Default user permissions in Microsoft Entra ID (restrict non-admin users from creating tenants)",
         "url": "https://learn.microsoft.com/en-us/entra/fundamentals/users-default-permissions"},
        {"title": "Microsoft Graph: authorizationPolicy resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy"},
    ],
    "description": (
        "Non-administrator users can create new Microsoft Entra tenants "
        "(defaultUserRolePermissions.allowedToCreateTenants = true) and "
        "become their Global Administrator: shadow tenants outside the "
        "organisation's governance, useful for staging phishing "
        "applications. Low."
    ),
    "remediation": (
        "Entra admin center -> Identity -> Users -> User settings -> "
        "'Restrict non-admin users from creating tenants' = Yes. PowerShell: "
        "Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions "
        "@{AllowedToCreateTenants=$false}. Users who need a test tenant can "
        "be given the Tenant Creator role."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            md5('10080:' || sp.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Non-administrator users can create Entra tenants (allowedToCreateTenants is true)' AS summary,
            jsonb_build_object(
                'allowed_to_create_tenants', sp.authorization_policy->'defaultUserRolePermissions'->'allowedToCreateTenants'
            ) AS detail
        FROM entra_security_posture sp
        WHERE sp.client_id = %(client_id)s
          AND jsonb_typeof(sp.authorization_policy) = 'object'
          AND sp.authorization_policy->'defaultUserRolePermissions'->'allowedToCreateTenants' = 'true'::jsonb
    """,
}
