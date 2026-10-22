"""
Plugin 11030: New Federated Identity Credential Since the Previous Run

Change Detection for Microsoft Entra ID. Reports federated identity
credentials (FICs) that appeared on an application registration in the
latest Entra collection.

Why: a FIC lets tokens from an outside identity provider (GitHub Actions,
a pipeline, a Kubernetes cluster, another tenant, or an issuer the
attacker runs) be exchanged for the application's own token. Adding one
to an existing application is credential-less persistence: no secret or
certificate appears, so plugin 11023 and credential reviews do not see it,
and it survives secret rotation. MITRE ATT&CK T1098.001.

Data: entra_change_history entity_type 'federated_identity_credential'
(key <application object id>:<credential id>; content {app_object_id,
app_id, app_display_name, name, issuer, subject, audiences}) and
entra_change_baseline, from entra_graph_collector 0.9.0 (source
federated_identity_credentials). Only NEW credentials are reported (no
earlier version of the key). Suppressed on the first collection of this
entity type; findings stay open until the next Entra collection.

Severity: critical when the application's service principal holds a
highly privileged directory role or a privileged application permission
(same enrichment as plugin 11023), high otherwise. One row per credential
(object_guid = md5('11030:' || client_id || ':' || key)).
"""

PLUGIN = {
    "plugin_id": 11030,
    "category": "Change Detection",
    "name": "New Federated Identity Credential Since the Previous Run",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "CHANGE-11030",
    "requires_sources": ["federated_identity_credentials", "service_principals"],
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-AC-2(4)",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16",
        "SOC2-CC7.2",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1098.001",
        
    ],
    "references": [
        {"title": "Microsoft: Workload identity federation",
         "url": "https://learn.microsoft.com/en-us/entra/workload-id/workload-identity-federation"},
        {"title": "Microsoft Graph: federatedIdentityCredential resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/federatedidentitycredential"},
        {"title": "MITRE ATT&CK T1098.001: Account Manipulation: Additional Cloud Credentials",
         "url": "https://attack.mitre.org/techniques/T1098/001/"},
    ],
    "description": (
        "Reports federated identity credentials added to application registrations since the "
        "previous Entra collection: trust in an outside identity provider's tokens that "
        "gives credential-less access as the application. Critical when the application "
        "holds a privileged directory role or application permission, high otherwise. "
        "Suppressed on the first collection."
    ),
    "remediation": (
        "Confirm the credential with the application owner: the Entra audit log activity "
        "'Update application' (target property FederatedIdentityCredentials) shows who added "
        "it. If unexpected, remove it (Remove-MgApplicationFederatedIdentityCredential), "
        "review the application's service principal sign-ins and actions, and restrict who "
        "can manage the application (owners, Application Administrator assignments)."
    ),
    "base_severity": "high",
    "query": """
        WITH b AS (
            SELECT bl.client_id, bl.last_run_at
            FROM entra_change_baseline bl
            WHERE bl.client_id = %(client_id)s
              AND bl.entity_type = 'federated_identity_credential'
              AND bl.first_run_at < bl.last_run_at
        ),
        new_cred AS (
            SELECT h.entity_key, h.entity_label, h.content,
                   CASE WHEN h.content->>'app_id' ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'
                        THEN (h.content->>'app_id')::uuid END AS app_id
            FROM entra_change_history h
            JOIN b ON b.client_id = h.client_id
            WHERE h.entity_type = 'federated_identity_credential'
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
                          'db506228-d27e-4b7d-95e5-295956d6615f',
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
                  AND s.app_id = n.app_id
                ORDER BY s.entra_object_id LIMIT 1
            ) sp ON TRUE
        ),
        sev AS (
            SELECT e.*,
                   CASE WHEN e.privileged_roles IS NOT NULL OR e.privileged_permissions IS NOT NULL
                        THEN 'critical' ELSE 'high' END AS severity
            FROM enriched e
        )
        SELECT
            'fail' AS status,
            md5('11030:' || %(client_id)s::text || ':' || s.entity_key)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            s.severity AS fd_severity,
            'New federated identity credential "' || COALESCE(s.content->>'name', '?') || '" on application "'
                || COALESCE(s.content->>'app_display_name', s.content->>'app_id', '?') || '"'
                || CASE WHEN s.severity = 'critical' THEN ' (privileged)' ELSE '' END
                || ' trusts ' || COALESCE(s.content->>'issuer', '?') || ' subject '
                || COALESCE(s.content->>'subject', '?') || ' since the previous Entra collection' AS summary,
            jsonb_build_object(
                'application', s.content->>'app_display_name',
                'app_object_id', s.content->>'app_object_id',
                'app_id', s.content->>'app_id',
                'credential_name', s.content->>'name',
                'issuer', s.content->>'issuer',
                'subject', s.content->>'subject',
                'audiences', s.content->'audiences',
                'service_principal_id', s.sp_id,
                'privileged_roles', s.privileged_roles,
                'privileged_permissions', s.privileged_permissions,
                'detected_at', (SELECT last_run_at FROM b)
            ) AS detail
        FROM sev s
    """,
}
