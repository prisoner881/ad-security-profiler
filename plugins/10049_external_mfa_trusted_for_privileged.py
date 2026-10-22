"""
Plugin 10049: External (Third-Party) MFA Method Trusted for Privileged Users

Reports external authentication methods (third-party MFA providers
registered in the authentication methods policy, Graph
externalAuthenticationMethodConfiguration) that are enabled for users
holding highly privileged directory roles.

Why: Entra ID accepts the external provider's assertion that the user
completed MFA. The provider's own security -- its signing keys, its admin
console, its enrolment and recovery process, the app registration that
represents it (appId) -- becomes part of the trust path to the tenant's
administrators, and none of it is visible in Entra ID. A compromise of the
provider, or of whoever can change that registration, satisfies MFA for
every covered administrator. Administrators should use phishing-resistant
methods Entra ID verifies itself (FIDO2, Windows Hello, CBA with high
affinity); plugin 10041 checks they have one.

One finding per external method (object_guid md5('10049:' || client_id ||
':' || method id)):
- fail / medium: enabled and targeting all users, or a group that has a
  privileged role holder among its collected transitive members
  (entra_group_member covers sensitive groups only);
- warn / low: enabled for groups whose membership was not collected, so
  coverage of administrators could not be confirmed.
Privileged = an active or eligible holder of one of the roles below.
Excluded groups are listed in detail but not subtracted. External methods
are only seen when Graph returns the method configurations inline with
the policy (it does for current tenants).
"""

PLUGIN = {
    "plugin_id": 10049,
    "category": "Hybrid Identity",
    "name": "External (Third-Party) MFA Method Trusted for Privileged Users",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10049",
    "requires_sources": ["auth_methods_policy"],
    "framework_tags": [
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-AC-20",
        "NIST-CSF-2.0-PR.AA-03",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.5.19",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1556.006",
    ],
    "references": [
        {"title": "Microsoft: Manage an external authentication method in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-external-method-manage"},
        {"title": "Microsoft Graph: externalAuthenticationMethodConfiguration resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/externalauthenticationmethodconfiguration"},
        {"title": "MITRE ATT&CK T1556.006: Modify Authentication Process: Multi-Factor Authentication",
         "url": "https://attack.mitre.org/techniques/T1556/006/"},
    ],
    "description": (
        "A third-party MFA provider (external authentication method) is enabled for users "
        "who hold highly privileged roles, so Entra ID accepts that provider's MFA claim "
        "for administrators. The provider and its app registration become part of the path "
        "to Tier 0 without being visible in Entra ID. Low when coverage of administrators "
        "could not be confirmed."
    ),
    "remediation": (
        "Entra admin center > Protection > Authentication methods > Policies > the external "
        "method: exclude a group containing the privileged role holders, and require a "
        "phishing-resistant authentication strength (FIDO2, Windows Hello for Business, "
        "certificate-based authentication) for those roles in Conditional Access. Restrict "
        "who can change the external method's app registration and review the provider's "
        "own administrative access."
    ),
    "base_severity": "medium",
    "query": """
        WITH tier0(role_template_id) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid), ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid), ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid), ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid),
                   ('db506228-d27e-4b7d-95e5-295956d6615f'::uuid),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid), ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid), ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid), ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid)
        ),
        admins AS (
            SELECT DISTINCT rm.member_id, rm.member_upn
              FROM entra_directory_role_member rm
              JOIN tier0 t ON t.role_template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.user'
        ),
        ext AS (
            SELECT ts.client_id, c AS cfg,
                   ARRAY(SELECT lower(x->>'id') FROM jsonb_array_elements(
                             CASE WHEN jsonb_typeof(c->'includeTargets') = 'array'
                                  THEN c->'includeTargets' ELSE '[]'::jsonb END) x) AS targets
              FROM entra_tenant_setting ts
              CROSS JOIN LATERAL jsonb_array_elements(
                  CASE WHEN jsonb_typeof(ts.content->'authenticationMethodConfigurations') = 'array'
                       THEN ts.content->'authenticationMethodConfigurations' ELSE '[]'::jsonb END) c
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'auth_methods_policy'
               AND c->>'@odata.type' = '#microsoft.graph.externalAuthenticationMethodConfiguration'
               AND lower(COALESCE(c->>'state', '')) = 'enabled'
        ),
        cov AS (
            SELECT e.*,
                   'all_users' = ANY(e.targets) AS all_users,
                   (SELECT count(*) FROM admins) AS admin_total,
                   (SELECT jsonb_agg(DISTINCT a.member_upn) FROM admins a
                     WHERE EXISTS (SELECT 1 FROM entra_group_member gm
                                    WHERE gm.client_id = e.client_id AND gm.member_id = a.member_id
                                      AND lower(gm.group_id::text) = ANY(e.targets))) AS admins_in_groups
              FROM ext e
        )
        SELECT
            CASE WHEN c.all_users OR c.admins_in_groups IS NOT NULL THEN 'fail' ELSE 'warn' END AS status,
            md5('10049:' || c.client_id::text || ':' || lower(COALESCE(c.cfg->>'id', '')))::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.all_users OR c.admins_in_groups IS NOT NULL THEN 'medium' ELSE 'low' END AS fd_severity,
            'External MFA method "' || COALESCE(c.cfg->>'displayName', c.cfg->>'id') || '" is enabled '
                || CASE WHEN c.all_users THEN 'for all users, including ' || c.admin_total
                                              || ' privileged role holder(s)'
                        WHEN c.admins_in_groups IS NOT NULL
                        THEN 'for groups that include ' || jsonb_array_length(c.admins_in_groups)
                             || ' privileged role holder(s)'
                        ELSE 'for selected groups (whether they include privileged users was not determined)'
                   END AS summary,
            jsonb_build_object(
                'method_id', c.cfg->>'id',
                'display_name', c.cfg->>'displayName',
                'app_id', c.cfg->>'appId',
                'discovery_url', c.cfg->'openIdConnectSetting'->>'discoveryUrl',
                'include_targets', c.cfg->'includeTargets',
                'exclude_targets', c.cfg->'excludeTargets',
                'privileged_users_in_target_groups', c.admins_in_groups
            ) AS detail
        FROM cov c
    """,
}
