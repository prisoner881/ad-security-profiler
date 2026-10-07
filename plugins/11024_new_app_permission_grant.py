"""
Plugin 11024: New Application Permission or Tenant-Wide Delegated Scope

Change Detection for Microsoft Entra ID. Reports application permissions
(app role assignments on Microsoft Graph, Exchange Online, SharePoint Online,
Key Vault, AAD Graph, Teams, Office 365 Management APIs, Dynamics CRM and
Intune) and tenant-wide delegated scopes (oauth2PermissionGrants with
consentType AllPrincipals, i.e. admin consent for every user) that appeared
in the latest Entra collection.

Why: granting an application permission or an admin-consented delegated
scope is consent-based persistence and privilege escalation: an app with
Mail.ReadWrite, full_access_as_app or RoleManagement.ReadWrite.Directory
reads every mailbox or makes itself Global Administrator without any user
interaction (Midnight Blizzard, CISA ED 24-02; illicit consent grants).
MITRE ATT&CK T1098.003 (Additional Cloud Roles) and T1528 (Steal Application
Access Token).

Data: entra_change_history entity_type 'app_permission' (key
<principal id>:<resource app id>:<permission id> for application permissions,
<client sp id>:<resource app id>:AllPrincipals:<scope> for tenant-wide
delegated scopes; content {grant_kind 'application' | 'delegated',
principal_id, principal_display_name, resource_app_id, resource_display_name,
permission_name}) and entra_change_baseline. Only NEW grants (no earlier
version of the key) are reported. Suppressed on the first collection;
findings stay open until the next Entra collection.

Severity: high. One row per grant (object_guid = md5('11024:' || client_id
|| ':' || key)).
"""

PLUGIN = {
    "plugin_id": 11024,
    "category": "Change Detection",
    "name": "New Application Permission or Tenant-Wide Delegated Scope",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "CHANGE-11024",
    "requires_sources": ["app_role_grants", "delegated_grants"],
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-AC-2(4)",
        "NIST-800-53-CM-11",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC7.2",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1098.003", "MITRE-ATTCK-T1528",
        "CISA-ED-24-02",
    ],
    "references": [
        {"title": "Microsoft: Detect and remediate illicit consent grants",
         "url": "https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants"},
        {"title": "Microsoft: Review permissions granted to enterprise applications",
         "url": "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions"},
        {"title": "MITRE ATT&CK T1528: Steal Application Access Token",
         "url": "https://attack.mitre.org/techniques/T1528/"},
    ],
    "description": (
        "Reports application permissions (app roles on Microsoft Graph, Exchange Online, "
        "SharePoint Online and other key resource APIs) and tenant-wide (admin-consented) "
        "delegated scopes granted since the previous Entra collection. A new grant is how a "
        "malicious or compromised application gains standing access to mail, files or the "
        "directory. Suppressed on the first Entra collection."
    ),
    "remediation": (
        "Confirm each grant against an approved consent request: Entra audit log, activities "
        "'Add app role assignment to service principal' and 'Consent to application' / 'Add "
        "delegated permission grant'. Remove unapproved grants "
        "(Remove-MgServicePrincipalAppRoleAssignment, Remove-MgOauth2PermissionGrant), review "
        "the application's sign-ins and activity, and restrict consent to administrators "
        "with an admin consent workflow (SCuBA MS.AAD.5.2 / 5.3)."
    ),
    "base_severity": "high",
    "query": """
        WITH b AS (
            SELECT bl.client_id, bl.last_run_at
            FROM entra_change_baseline bl
            WHERE bl.client_id = %(client_id)s
              AND bl.entity_type = 'app_permission'
              AND bl.first_run_at < bl.last_run_at
        ),
        new_grant AS (
            SELECT h.entity_key, h.entity_label, h.content
            FROM entra_change_history h
            JOIN b ON b.client_id = h.client_id
            WHERE h.entity_type = 'app_permission'
              AND h.valid_from = b.last_run_at
              AND h.valid_to IS NULL
              AND NOT EXISTS (SELECT 1 FROM entra_change_history e
                              WHERE e.client_id = h.client_id AND e.entity_type = h.entity_type
                                AND e.entity_key = h.entity_key AND e.valid_from < b.last_run_at)
        )
        SELECT
            'fail' AS status,
            md5('11024:' || %(client_id)s::text || ':' || n.entity_key)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            CASE WHEN n.content->>'grant_kind' = 'delegated'
                 THEN 'New tenant-wide delegated scope "'
                 ELSE 'New application permission "' END
                || COALESCE(n.content->>'permission_name', split_part(n.entity_key, ':', 3), '?')
                || '" on "' || COALESCE(n.content->>'resource_display_name',
                                        n.content->>'resource_app_id', '?')
                || CASE WHEN n.content->>'grant_kind' = 'delegated'
                        THEN '" admin-consented for "' ELSE '" granted to "' END
                || COALESCE(n.content->>'principal_display_name', n.entity_label,
                            n.content->>'principal_id', '?')
                || '" since the previous Entra collection' AS summary,
            jsonb_build_object(
                'grant_kind', n.content->>'grant_kind',
                'principal_id', n.content->>'principal_id',
                'principal_display_name', n.content->>'principal_display_name',
                'resource_app_id', n.content->>'resource_app_id',
                'resource_display_name', n.content->>'resource_display_name',
                'permission_name', n.content->>'permission_name',
                'entity_key', n.entity_key,
                'detected_at', (SELECT last_run_at FROM b)
            ) AS detail
        FROM new_grant n
    """,
}
