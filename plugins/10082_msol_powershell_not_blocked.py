"""
Plugin 10082: Legacy MSOnline PowerShell Not Blocked

Reads the tenant authorization policy (entra_security_posture.
authorization_policy) and reports when blockMsolPowerShell is false.

Why it matters: the MSOnline (MSOL) and AzureAD PowerShell modules use
legacy endpoints that predate several Entra security controls and were a
favourite of attacker tooling (e.g. AADInternals-style enumeration and
federation changes). Setting blockMsolPowerShell stops non-administrator
users from using the MSOnline module against the tenant. Microsoft retired
MSOnline in 2025, so the practical impact is shrinking; the finding is
informational and is kept so the setting is visible (NIST CM-7 least
functionality).

Result: one tenant-level info 'warn' when blockMsolPowerShell is JSON false.
Tier A data (no requires_sources): authorization_policy NULL (read failed,
see authorization_policy_status) or the key absent -> no row.

object_guid: md5('10082:' || client_id).
"""

PLUGIN = {
    "plugin_id": 10082,
    "category": "Hybrid Identity",
    "name": "Legacy MSOnline PowerShell Not Blocked",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10082",
    "framework_tags": [
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.4",
        "CIS-CSC-8-4.8",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
    ],
    "references": [
        {"title": "Microsoft Graph: authorizationPolicy resource type (blockMsolPowerShell)",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy"},
        {"title": "Microsoft: Migrate from MSOnline and AzureAD PowerShell to Microsoft Graph PowerShell",
         "url": "https://learn.microsoft.com/en-us/powershell/microsoftgraph/migration-steps"},
    ],
    "description": (
        "blockMsolPowerShell is false in the tenant authorization policy, "
        "so non-administrator users may use the legacy MSOnline PowerShell "
        "module against the tenant. MSOnline was retired in 2025, so this "
        "is informational."
    ),
    "remediation": (
        "Update-MgPolicyAuthorizationPolicy -BlockMsolPowerShell:$true "
        "(Microsoft Graph PowerShell, Policy.ReadWrite.Authorization). "
        "Migrate any remaining MSOnline / AzureAD module scripts to "
        "Microsoft Graph PowerShell."
    ),
    "base_severity": "info",
    "query": """
        SELECT
            'warn' AS status,
            md5('10082:' || sp.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'info' AS fd_severity,
            'Legacy MSOnline PowerShell is not blocked for users (blockMsolPowerShell is false)' AS summary,
            jsonb_build_object(
                'block_msol_powershell', sp.authorization_policy->'blockMsolPowerShell'
            ) AS detail
        FROM entra_security_posture sp
        WHERE sp.client_id = %(client_id)s
          AND jsonb_typeof(sp.authorization_policy) = 'object'
          AND sp.authorization_policy->'blockMsolPowerShell' = 'false'::jsonb
    """,
}
