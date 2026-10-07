"""
Plugin 11023: New Credential Added to an Application or Service Principal

Change Detection for Microsoft Entra ID. Reports client secrets and
certificates that appeared on an application registration or a service
principal in the latest Entra collection.

Why: adding a credential to an existing application -- especially a
Microsoft first-party service principal or an app that already holds
powerful Graph / Exchange permissions or a directory role -- is the
persistence technique of the SolarWinds / Solorigate campaign and of
Midnight Blizzard (CISA ED 24-02): the attacker then authenticates as the
application, without any user, MFA or Conditional Access. MITRE ATT&CK
T1098.001 (Additional Cloud Credentials).

Data: entra_change_history entity_type 'app_credential' (key
<owner object id>:<keyId>; content {object_type 'application' |
'servicePrincipal', object_id, app_id, display_name, credential_type
'password' | 'certificate', key_id, credential_display_name,
end_date_time}) and entra_change_baseline. Only NEW credentials are
reported (no earlier version of the key); removals and expiry-date edits are
not. Suppressed on the first collection; findings stay open until the next
Entra collection.

Enrichment from the current snapshot: the service principal (the object
itself, or the SP with the application's appId) -- its owner tenant
(Microsoft first-party when app_owner_organization_id is
f8cdef31-a31e-4b4a-93e4-5f571e91255a or 72f988bf-86f1-41af-91ab-2d7cd011db47),
its highly privileged directory roles (entra_directory_role_member), and its
privileged application permissions (entra_app_role_grant and
entra_dangerous_permission_grant).

Severity: critical for a Microsoft first-party SP or a privileged app/SP;
medium for a certificate on a SAML SSO service principal that is neither
(routine token-signing certificate rollover); high otherwise. One row per
credential (object_guid = md5('11023:' || client_id || ':' || key)).
"""

PLUGIN = {
    "plugin_id": 11023,
    "category": "Change Detection",
    "name": "New Credential Added to an Application or Service Principal",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "CHANGE-11023",
    "requires_sources": ["service_principals"],
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-AC-2(4)",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC7.2",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1098.001",
        "CISA-ED-24-02", "CISA-AA21-008A",
    ],
    "references": [
        {"title": "CISA ED 24-02: Mitigating the Significant Risk from Nation-State Compromise of Microsoft Corporate Email System",
         "url": "https://www.cisa.gov/news-events/directives/ed-24-02-mitigating-significant-risk-nation-state-compromise-microsoft-corporate-email-system"},
        {"title": "MITRE ATT&CK T1098.001: Account Manipulation: Additional Cloud Credentials",
         "url": "https://attack.mitre.org/techniques/T1098/001/"},
        {"title": "Microsoft: Investigate compromised and malicious applications",
         "url": "https://learn.microsoft.com/en-us/security/operations/incident-response-playbook-compromised-malicious-app"},
    ],
    "description": (
        "Reports client secrets and certificates added to application registrations or "
        "service principals since the previous Entra collection. Critical when the target is "
        "a Microsoft first-party service principal or holds a privileged directory role or "
        "application permission (the Solorigate / Midnight Blizzard persistence technique); "
        "medium for a certificate on an ordinary SAML SSO service principal (usually a "
        "signing-certificate rollover); high otherwise. Suppressed on the first collection."
    ),
    "remediation": (
        "Confirm the credential with the application owner: Entra audit log, activities "
        "'Update application -- Certificates and secrets management' and 'Add service "
        "principal credentials', shows who added it. If unexpected, remove it "
        "(Remove-MgApplicationPassword / Remove-MgServicePrincipalKey...), review the "
        "application's sign-ins (service principal sign-in logs) and the actions it took, "
        "and rotate any other credentials. Block credential addition on service principals "
        "(app instance property lock, application management policies; SCuBA MS.AAD.5.5) "
        "and restrict who can manage applications."
    ),
    "base_severity": "high",
    "query": """
        WITH b AS (
            SELECT bl.client_id, bl.last_run_at
            FROM entra_change_baseline bl
            WHERE bl.client_id = %(client_id)s
              AND bl.entity_type = 'app_credential'
              AND bl.first_run_at < bl.last_run_at
        ),
        new_cred AS (
            SELECT h.entity_key, h.entity_label, h.content,
                   CASE WHEN h.content->>'object_id' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                        THEN (h.content->>'object_id')::uuid END AS object_id,
                   CASE WHEN h.content->>'app_id' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                        THEN (h.content->>'app_id')::uuid END AS app_id
            FROM entra_change_history h
            JOIN b ON b.client_id = h.client_id
            WHERE h.entity_type = 'app_credential'
              AND h.valid_from = b.last_run_at
              AND h.valid_to IS NULL
              AND NOT EXISTS (SELECT 1 FROM entra_change_history e
                              WHERE e.client_id = h.client_id AND e.entity_type = h.entity_type
                                AND e.entity_key = h.entity_key AND e.valid_from < b.last_run_at)
        ),
        enriched AS (
            SELECT n.*, sp.entra_object_id AS sp_id, sp.display_name AS sp_name,
                   sp.app_owner_organization_id, sp.preferred_single_sign_on_mode,
                   sp.app_owner_organization_id IN ('f8cdef31-a31e-4b4a-93e4-5f571e91255a',
                                                    '72f988bf-86f1-41af-91ab-2d7cd011db47')
                       AS first_party,
                   (SELECT jsonb_agg(DISTINCT rm.role_display_name ORDER BY rm.role_display_name)
                    FROM entra_directory_role_member rm
                    WHERE rm.client_id = %(client_id)s AND rm.member_id = sp.entra_object_id
                      AND rm.role_template_id IN (
                          '62e90394-69f5-4237-9190-012177145e10', 'e8611ab8-c189-46e8-94e1-60213ab1f814',
                          '7be44c8a-adaf-4e2a-84d6-ab2649e08a13', '194ae4cb-b126-40b2-bd5b-6091b380977d',
                          '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2', '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3',
                          '158c047a-c907-4556-b7ef-446551a6b5f7', '29232cdf-9323-42fd-ade2-1d097af3e4de',
                          'f28a1f50-f6e7-4571-818b-6a12f2af6b6c', 'fe930be7-5e62-47db-91af-98c3a49a38b1',
                          'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', 'c4e39bd9-1100-46d3-8c65-fb160da0071f',
                          '3a2c62db-5318-420d-8d74-23affee5d9d5')) AS privileged_roles,
                   (SELECT jsonb_agg(DISTINCT p.perm ORDER BY p.perm)
                    FROM (SELECT g.permission_name AS perm FROM entra_app_role_grant g
                          WHERE g.client_id = %(client_id)s AND g.principal_id = sp.entra_object_id
                            AND g.permission_name IN (
                                'RoleManagement.ReadWrite.Directory', 'AppRoleAssignment.ReadWrite.All',
                                'Application.ReadWrite.All', 'Application.ReadWrite.OwnedBy',
                                'Directory.ReadWrite.All', 'Domain.ReadWrite.All',
                                'Group.ReadWrite.All', 'GroupMember.ReadWrite.All',
                                'User.ReadWrite.All', 'UserAuthenticationMethod.ReadWrite.All',
                                'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.AuthenticationMethod',
                                'PrivilegedAccess.ReadWrite.AzureAD', 'ServicePrincipalEndpoint.ReadWrite.All',
                                'Mail.ReadWrite', 'Mail.Send', 'Files.ReadWrite.All',
                                'Sites.FullControl.All', 'Sites.ReadWrite.All',
                                'full_access_as_app', 'Exchange.ManageAsApp',
                                'DeviceManagementRBAC.ReadWrite.All',
                                'DeviceManagementConfiguration.ReadWrite.All')
                          UNION
                          SELECT d.permission_name FROM entra_dangerous_permission_grant d
                          WHERE d.client_id = %(client_id)s AND d.principal_id = sp.entra_object_id) p
                   ) AS privileged_permissions
            FROM new_cred n
            LEFT JOIN LATERAL (
                SELECT s.* FROM entra_service_principal s
                WHERE s.client_id = %(client_id)s
                  AND ((n.content->>'object_type' = 'servicePrincipal' AND s.entra_object_id = n.object_id)
                       OR (n.content->>'object_type' = 'application' AND s.app_id = n.app_id))
                ORDER BY s.entra_object_id LIMIT 1
            ) sp ON TRUE
        ),
        sev AS (
            SELECT e.*,
                   CASE WHEN e.first_party IS TRUE OR e.privileged_roles IS NOT NULL
                             OR e.privileged_permissions IS NOT NULL THEN 'critical'
                        WHEN e.content->>'object_type' = 'servicePrincipal'
                             AND e.content->>'credential_type' = 'certificate'
                             AND lower(COALESCE(e.preferred_single_sign_on_mode, '')) = 'saml'
                            THEN 'medium'
                        ELSE 'high' END AS severity
            FROM enriched e
        )
        SELECT
            CASE WHEN s.severity = 'medium' THEN 'warn' ELSE 'fail' END AS status,
            md5('11023:' || %(client_id)s::text || ':' || s.entity_key)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            s.severity AS fd_severity,
            'New ' || CASE WHEN s.content->>'credential_type' = 'certificate' THEN 'certificate'
                           ELSE 'client secret' END
                || ' added to ' || CASE WHEN s.content->>'object_type' = 'servicePrincipal'
                                        THEN 'service principal' ELSE 'application' END
                || ' "' || COALESCE(s.content->>'display_name', s.entity_label, s.content->>'object_id', '?') || '"'
                || CASE WHEN s.first_party IS TRUE THEN ' (Microsoft first-party)' ELSE '' END
                || CASE WHEN s.privileged_roles IS NOT NULL OR s.privileged_permissions IS NOT NULL
                        THEN ' (privileged)' ELSE '' END
                || ' since the previous Entra collection' AS summary,
            jsonb_build_object(
                'object_type', s.content->>'object_type',
                'object_id', s.content->>'object_id',
                'app_id', s.content->>'app_id',
                'display_name', s.content->>'display_name',
                'credential_type', s.content->>'credential_type',
                'key_id', s.content->>'key_id',
                'credential_display_name', s.content->>'credential_display_name',
                'end_date_time', s.content->>'end_date_time',
                'service_principal_id', s.sp_id,
                'app_owner_organization_id', s.app_owner_organization_id,
                'microsoft_first_party', s.first_party,
                'preferred_single_sign_on_mode', s.preferred_single_sign_on_mode,
                'privileged_directory_roles', s.privileged_roles,
                'privileged_permissions', s.privileged_permissions,
                'detected_at', (SELECT last_run_at FROM b)
            ) AS detail
        FROM sev s
    """,
}
