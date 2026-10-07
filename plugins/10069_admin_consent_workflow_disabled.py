"""
Plugin 10069: Admin Consent Workflow Disabled While User Consent Is Blocked

Reports a tenant where users cannot consent to applications themselves but
the admin consent workflow (adminConsentRequestPolicy) is disabled. One
tenant-level finding, low, status 'warn'.

Why it matters: with user consent blocked (the right setting, SCuBA
MS.AAD.5.2 / plugin 10016) and no admin consent workflow, a user who needs
an application simply gets an error, with no sanctioned way to ask for it.
That pushes people to workarounds -- personal accounts, unmanaged tools,
shadow IT -- and leaves administrators unaware of the demand. CISA SCuBA
MS.AAD.5.3: "An admin consent workflow SHALL be configured" so requests
reach designated reviewers, who can grant consent after review.

Condition:
- entra_tenant_setting 'admin_consent_request_policy' content isEnabled is
  JSON false (source admin_consent_request_policy 'ok', required); and
- user consent is blocked: the authorization policy
  (entra_security_posture.authorization_policy, as plugin 10016 reads it)
  is readable and defaultUserRolePermissions.permissionGrantPoliciesAssigned
  is an array containing no Microsoft built-in user consent policy
  ('ManagePermissionGrantsForSelf.microsoft-*': default-legacy,
  default-low, and [v1.1] default-recommended and any newer built-in).
  v1.0 checked only legacy and low, so a tenant on Microsoft's managed
  (recommended) consent setting was wrongly reported as blocking user
  consent while 10016 reported it as allowing it.
When user consent is allowed, plugin 10016 reports that instead and this
plugin is silent. A custom ManagePermissionGrantsForSelf policy is treated
as "blocked" here (it usually covers only specific apps); the policy name
is listed in detail.

Data caveats: no row when either policy could not be read. Tenant-level
finding: object_guid = md5('10069:' || client_id), as in plugin 10004.
"""

PLUGIN = {
    "plugin_id": 10069,
    "category": "Hybrid Identity",
    "name": "Admin Consent Workflow Disabled While User Consent Is Blocked",
    "version": "1.1",
    "revision_date": "2026-10-07",
    "control_id": "HYBRID-10069",
    "requires_sources": ["admin_consent_request_policy"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.5.3",
        "NIST-800-53-CM-11",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "ISO-27001-2022-A.5.23",
        "SOC2-CC6.3",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.5.3)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Configure the admin consent workflow",
         "url": "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-admin-consent-workflow"},
        {"title": "Microsoft Graph: adminConsentRequestPolicy resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/adminconsentrequestpolicy"},
    ],
    "description": (
        "Users cannot consent to applications, but the admin consent "
        "workflow is disabled, so users have no sanctioned way to request "
        "an application and administrators never see the demand -- which "
        "pushes people to unmanaged workarounds. CISA SCuBA MS.AAD.5.3 "
        "requires an admin consent workflow. Low; silent when either "
        "policy could not be read or when user consent is allowed "
        "(plugin 10016)."
    ),
    "remediation": (
        "Entra admin center -> Enterprise applications -> Consent and "
        "permissions -> Admin consent settings: set 'Users can request "
        "admin consent to apps they are unable to consent to' to Yes, "
        "choose reviewers (users, groups or roles who can grant consent), "
        "enable email notifications and set the request expiry. Graph: "
        "PUT /policies/adminConsentRequestPolicy with isEnabled true and "
        "reviewers. Keep user consent blocked."
    ),
    "base_severity": "low",
    "query": """
        WITH acr AS (
            SELECT ts.client_id, ts.content
              FROM entra_tenant_setting ts
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'admin_consent_request_policy'
               AND jsonb_typeof(ts.content) = 'object'
               AND ts.content->'isEnabled' = 'false'::jsonb
               AND EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s
                              AND s.source = 'admin_consent_request_policy'
                              AND s.status = 'ok')
        ),
        consent AS (
            SELECT sp.client_id,
                   sp.authorization_policy->'defaultUserRolePermissions'->'permissionGrantPoliciesAssigned' AS pgpa
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
               AND jsonb_typeof(sp.authorization_policy) = 'object'
               AND jsonb_typeof(sp.authorization_policy->'defaultUserRolePermissions') = 'object'
               AND jsonb_typeof(sp.authorization_policy->'defaultUserRolePermissions'
                                ->'permissionGrantPoliciesAssigned') = 'array'
        )
        SELECT
            'warn' AS status,
            md5('10069:' || a.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Admin consent workflow is disabled while users cannot consent to applications' AS summary,
            jsonb_build_object(
                'admin_consent_request_policy_enabled', a.content->'isEnabled',
                'reviewer_count', CASE WHEN jsonb_typeof(a.content->'reviewers') = 'array'
                                       THEN jsonb_array_length(a.content->'reviewers') END,
                'permission_grant_policies_assigned', c.pgpa
            ) AS detail
        FROM acr a
        JOIN consent c ON c.client_id = a.client_id
        WHERE NOT EXISTS (SELECT 1 FROM jsonb_array_elements_text(c.pgpa) g
                           WHERE g LIKE 'ManagePermissionGrantsForSelf.microsoft-%%')
    """,
}
