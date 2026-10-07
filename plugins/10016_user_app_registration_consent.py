"""
Plugin 10016: Users Can Register Applications or Consent to Apps

Reads the tenant authorization policy (Graph /policies/authorizationPolicy,
entra_security_posture.authorization_policy, schema v38) and reports when
ordinary users can register applications or grant consent to applications
on their own behalf.

Why it matters: CISA SCuBA MS.AAD.5.1 ("Only administrators SHALL be
allowed to register applications") and MS.AAD.5.2 ("Only administrators
SHALL be allowed to consent to applications"). User consent is the basis
of illicit consent grant / consent phishing: a user is tricked into granting
a malicious multi-tenant app delegated access (mail, files) that survives
password resets and MFA (MITRE T1528). User app registration lets any
account create an identity (with its own credentials) that persists in the
tenant and can be used for the same purpose. NIST CM-11 (user-installed
software).

Checks, combined into one tenant-level finding (worst severity wins, every
issue listed in detail):
- defaultUserRolePermissions.allowedToCreateApps = true -> medium.
- permissionGrantPoliciesAssigned contains
  'ManagePermissionGrantsForSelf.microsoft-user-default-legacy' (users may
  consent to any app for any delegated permission not requiring admin
  consent) -> medium.
- 'ManagePermissionGrantsForSelf.microsoft-user-default-low' (users may
  consent only for apps from verified publishers / registered in this
  tenant, for permissions classified low-risk -- the "more flexible" option
  SCuBA accepts) -> low 'warn' so the setting stays visible.
- [v1.1] 'ManagePermissionGrantsForSelf.microsoft-user-default-recommended'
  ("Let Microsoft manage your consent settings": users may consent to
  what Microsoft's current recommendation allows, low-risk permissions)
  -> low 'warn'.
- [v1.1] any other Microsoft built-in policy
  ('ManagePermissionGrantsForSelf.microsoft-*', conditions not collected)
  -> low 'warn', named as a Microsoft built-in policy. v1.0 called these
  "custom".
- any other 'ManagePermissionGrantsForSelf.*' entry (a custom consent
  policy whose conditions are not collected) -> low 'warn', review.
'ManagePermissionGrantsForOwnedResource.*' entries (group/team owner
consent for resource-specific permissions) are out of scope. status is
'fail' when any medium issue exists, otherwise 'warn'.

Data caveats: authorization_policy NULL (the read failed -- see
authorization_policy_status -- or collector older than 0.7.0) -> no row.
A key Graph omitted is stored as JSON null and is treated as "unknown"
(that check is skipped). The admin consent workflow (MS.AAD.5.3) is a
separate setting and not checked.

Tenant-level finding: object_guid is md5('10016:' || client_id), as in
plugin 10004.
"""

PLUGIN = {
    "plugin_id": 10016,
    "category": "Hybrid Identity",
    "name": "Users Can Register Applications or Consent to Apps",
    "version": "1.1",
    "revision_date": "2026-10-07",
    "control_id": "HYBRID-10016",
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.5.1",
        "CISA-SCUBA-MS.AAD.5.2",
        "NIST-800-53-CM-11",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "ISO-27001-2022-A.5.23",
        "SOC2-CC6.3",
        "MITRE-ATTCK-T1528",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.5.1, 5.2)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Configure how users consent to applications",
         "url": "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent"},
        {"title": "Microsoft Graph: authorizationPolicy resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy"},
        {"title": "MITRE ATT&CK T1528: Steal Application Access Token",
         "url": "https://attack.mitre.org/techniques/T1528/"},
    ],
    "description": (
        "The tenant authorization policy lets ordinary users register "
        "applications (allowedToCreateApps, medium) or consent to any "
        "application's delegated permissions (legacy user consent "
        "policy, medium) -- the basis of illicit consent grant attacks "
        "that give an attacker's app lasting access to mail and files "
        "regardless of password resets and MFA (SCuBA MS.AAD.5.1/5.2). "
        "Consent limited to verified publishers and low-risk "
        "permissions, Microsoft's managed (recommended) consent policy, or "
        "another built-in or custom consent policy, is a low warning. One "
        "tenant-level finding listing every issue; silent when the "
        "authorization policy could not be read."
    ),
    "remediation": (
        "Entra admin center -> Identity -> Users -> User settings: set "
        "'Users can register applications' to No. Enterprise apps -> "
        "Consent and permissions -> User consent settings: choose 'Do not "
        "allow user consent' (or at most 'Allow user consent for apps "
        "from verified publishers, for selected permissions' with a "
        "reviewed low-risk permission classification), and enable the "
        "admin consent workflow so users can request apps. PowerShell: "
        "Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions "
        "@{AllowedToCreateApps=$false; PermissionGrantPoliciesAssigned=@()}. "
        "Then review existing user consents (Get-MgOauth2PermissionGrant) "
        "for unexpected apps."
    ),
    "base_severity": "medium",
    "query": """
        WITH ap AS (
            SELECT sp.client_id, sp.authorization_policy AS pol,
                   CASE WHEN jsonb_typeof(sp.authorization_policy->'defaultUserRolePermissions') = 'object'
                        THEN sp.authorization_policy->'defaultUserRolePermissions' END AS durp
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
               AND jsonb_typeof(sp.authorization_policy) = 'object'
        ),
        grants AS (
            SELECT a.client_id, g COLLATE "C" AS g
              FROM ap a
              CROSS JOIN LATERAL jsonb_array_elements_text(
                  CASE WHEN jsonb_typeof(a.durp->'permissionGrantPoliciesAssigned') = 'array'
                       THEN a.durp->'permissionGrantPoliciesAssigned' ELSE '[]'::jsonb END) g
             WHERE g LIKE 'ManagePermissionGrantsForSelf.%%'
        ),
        issues AS (
            SELECT a.client_id, 2 AS rank,
                   'users can register applications' AS issue
              FROM ap a
             WHERE a.durp->'allowedToCreateApps' = 'true'::jsonb
            UNION ALL
            SELECT g.client_id,
                   CASE WHEN g.g = 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy' THEN 2 ELSE 1 END,
                   CASE WHEN g.g = 'ManagePermissionGrantsForSelf.microsoft-user-default-legacy'
                        THEN 'users can consent to any application (legacy user consent policy)'
                        WHEN g.g = 'ManagePermissionGrantsForSelf.microsoft-user-default-low'
                        THEN 'users can consent to verified-publisher apps for low-risk permissions'
                        WHEN g.g = 'ManagePermissionGrantsForSelf.microsoft-user-default-recommended'
                        THEN 'users can consent under the Microsoft-managed (recommended) user consent policy'
                        WHEN g.g LIKE 'ManagePermissionGrantsForSelf.microsoft-%%'
                        THEN 'Microsoft built-in user consent policy assigned (' || substr(g.g, 31) || ')'
                        ELSE 'custom user consent policy assigned (' || substr(g.g, 31) || ')' END
              FROM grants g
        ),
        agg AS (
            SELECT i.client_id, max(i.rank) AS rank,
                   string_agg(i.issue COLLATE "C", '; ' ORDER BY i.rank DESC, i.issue COLLATE "C") AS summary_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC, i.issue COLLATE "C") AS issue_list
              FROM issues i
             GROUP BY i.client_id
        )
        SELECT
            CASE WHEN g.rank = 2 THEN 'fail' ELSE 'warn' END AS status,
            md5('10016:' || g.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.rank = 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Application registration / user consent not restricted to administrators: '
                || g.summary_text AS summary,
            jsonb_build_object(
                'issues', g.issue_list,
                'allowed_to_create_apps', a.durp->'allowedToCreateApps',
                'permission_grant_policies_assigned', a.durp->'permissionGrantPoliciesAssigned'
            ) AS detail
        FROM agg g
        JOIN ap a ON a.client_id = g.client_id
    """,
}
