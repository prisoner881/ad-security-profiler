"""
Plugin 10087: Application Accepts Unverified E-mail Claims or Still Configured for Azure AD Graph

Reports application registrations with either legacy setting:

- nOAuth: authenticationBehaviors.removeUnverifiedEmailClaim explicitly
  false -> fail / medium. The application receives an e-mail claim whose
  domain the issuing tenant has not verified; an application that
  identifies users by e-mail can then be signed into as anyone whose
  address an attacker puts on an account in their own tenant (Microsoft
  security advisory, June 2023; Descope "nOAuth" 2023, Semperis 2025).
  An explicit false is a deliberate opt-out of Microsoft's protection.
  (Unset, Microsoft removes unverified e-mail claims except for
  single-tenant apps and multi-tenant apps already seen with unverified
  e-mails, which cannot be told from Graph; those are not reported.)
- Azure AD Graph: requiredResourceAccess still requests permissions on
  Azure AD Graph (resourceAppId 00000002-0000-0000-c000-000000000000), or
  authenticationBehaviors.blockAzureADGraphAccess is false (the extended
  access exception) -> warn / low. Azure AD Graph is fully retired and
  refuses every application, so this is no longer an access path but
  leftover configuration that hides which apps were never migrated and
  can break them (Microsoft Zero Trust assessment 21780).

Data: entra_application.required_resource_access and
authentication_behaviors (entra_graph_collector 0.9.0; NULL before, and
then not reported). One finding per application (object_guid
md5('10087:' || client_id || ':' || application object id)), every issue
listed.
"""

PLUGIN = {
    "plugin_id": 10087,
    "category": "Hybrid Identity",
    "name": "Application Accepts Unverified E-mail Claims or Still Configured for Azure AD Graph",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10087",
    "framework_tags": [
        "NIST-800-53-SA-22",
        "NIST-800-53-IA-2",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.PS-02",
        "NIST-CSF-2.0-PR.AA-03",
        "CIS-CSC-8-2.2",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1550.001",
    ],
    "references": [
        {"title": "Microsoft: Migrate your apps from Azure AD Graph to Microsoft Graph",
         "url": "https://learn.microsoft.com/en-us/graph/migrate-azure-ad-graph-overview"},
        {"title": "Microsoft: Manage application authenticationBehaviors (blockAzureADGraphAccess, removeUnverifiedEmailClaim)",
         "url": "https://learn.microsoft.com/en-us/graph/applications-authenticationbehaviors"},
        {"title": "Microsoft Security Response Center: Potential risk of privilege escalation in Azure AD applications (nOAuth)",
         "url": "https://msrc.microsoft.com/blog/2023/06/potential-risk-of-privilege-escalation-in-azure-ad-applications/"},
        {"title": "MITRE ATT&CK T1550.001: Use Alternate Authentication Material: Application Access Token",
         "url": "https://attack.mitre.org/techniques/T1550/001/"},
    ],
    "description": (
        "An application registration accepts e-mail claims from unverified domains "
        "(removeUnverifiedEmailClaim = false: nOAuth account takeover when the app identifies "
        "users by e-mail; medium), or is still configured for the retired Azure AD Graph API "
        "(requested permissions or the blockAzureADGraphAccess exception; low clean-up)."
    ),
    "remediation": (
        "Move the application to Microsoft Graph and remove the Azure AD Graph permissions "
        "from its API permissions; then remove the blockAzureADGraphAccess exception (Graph "
        "PATCH /applications/{id}/authenticationBehaviors {\"blockAzureADGraphAccess\": "
        "true}). Set removeUnverifiedEmailClaim to true, and identify users by the "
        "immutable object id (oid) and tenant id (tid) claims, never by e-mail."
    ),
    "base_severity": "medium",
    "query": """
        WITH app AS (
            SELECT a.*,
                   EXISTS (SELECT 1 FROM jsonb_array_elements(
                               CASE WHEN jsonb_typeof(a.required_resource_access) = 'array'
                                    THEN a.required_resource_access ELSE '[]'::jsonb END) r
                            WHERE lower(r->>'resourceAppId') = '00000002-0000-0000-c000-000000000000'
                              AND jsonb_array_length(COALESCE(r->'resourceAccess', '[]'::jsonb)) > 0)
                       AS requests_aad_graph,
                   a.authentication_behaviors->'blockAzureADGraphAccess' AS block_aad_graph,
                   a.authentication_behaviors->'removeUnverifiedEmailClaim' AS remove_unverified_email
              FROM entra_application a
             WHERE a.client_id = %(client_id)s
        ),
        issue AS (
            SELECT a.entra_object_id, 2 AS rank,
                   'accepts e-mail claims from unverified domains (removeUnverifiedEmailClaim = false, nOAuth)' AS issue
              FROM app a WHERE a.remove_unverified_email = 'false'::jsonb
            UNION ALL
            SELECT a.entra_object_id, 1, 'still requests permissions on the retired Azure AD Graph API'
              FROM app a WHERE a.requests_aad_graph
            UNION ALL
            SELECT a.entra_object_id, 1,
                   'still carries the Azure AD Graph extended-access exception (blockAzureADGraphAccess = false)'
              FROM app a WHERE a.block_aad_graph = 'false'::jsonb
        ),
        agg AS (
            SELECT i.entra_object_id, max(i.rank) AS rank,
                   string_agg(i.issue, '; ' ORDER BY i.rank DESC, i.issue) AS issue_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC, i.issue) AS issues
              FROM issue i GROUP BY i.entra_object_id
        )
        SELECT
            CASE WHEN g.rank >= 2 THEN 'fail' ELSE 'warn' END AS status,
            md5('10087:' || %(client_id)s::text || ':' || g.entra_object_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.rank >= 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Application ' || COALESCE(a.display_name, a.app_id::text) || ': ' || g.issue_text AS summary,
            jsonb_build_object(
                'application', a.display_name,
                'app_id', a.app_id,
                'sign_in_audience', a.sign_in_audience,
                'created_at', a.created_at,
                'issues', g.issues,
                'authentication_behaviors', a.authentication_behaviors,
                'azure_ad_graph_permissions', (SELECT r->'resourceAccess' FROM jsonb_array_elements(
                        CASE WHEN jsonb_typeof(a.required_resource_access) = 'array'
                             THEN a.required_resource_access ELSE '[]'::jsonb END) r
                     WHERE lower(r->>'resourceAppId') = '00000002-0000-0000-c000-000000000000' LIMIT 1)
            ) AS detail
        FROM agg g
        JOIN app a ON a.entra_object_id = g.entra_object_id
    """,
}
