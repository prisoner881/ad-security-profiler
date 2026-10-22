"""
Plugin 10037: Token Protection Not Required for Privileged Role Sign-Ins

Reports a tenant where no enabled Conditional Access policy requires token
protection (session control secureSignInSession.isEnabled, "Require token
protection for sign-in sessions") for the highly privileged directory
roles.

Why: token protection binds the sign-in session's refresh token to the
device it was issued to, so a token stolen from that device (infostealer,
adversary-in-the-middle phishing) cannot be replayed from elsewhere.
Administrators are the accounts whose stolen sessions do the most damage
(CISA AA26-237A; the 2025 ConsentFix campaign). CIS M365 5.2.2.16 and
Microsoft's Zero Trust assessment (21941) recommend it for privileged
users. It applies only to supported clients (Windows desktop applications
for Exchange, SharePoint and Teams, and the Entra and Azure portals as
Microsoft extends it), so this is a hardening gap, not an exposure: warn /
low.

A policy counts when it is enabled, requires token protection, and
includes all users or one of the privileged roles below without
excluding it; detail lists the roles covered and not covered. Needs
'ca_policies_beta' (source ca_policies_beta, entra_graph_collector 0.9.0).
Not reported when the licence read shows no Entra ID P1 (Conditional
Access unavailable). One tenant-level row, object_guid md5('10037:' ||
client_id).
"""

PLUGIN = {
    "plugin_id": 10037,
    "category": "Hybrid Identity",
    "name": "Token Protection Not Required for Privileged Role Sign-Ins",
    "version": "1.0",
    "revision_date": "2026-10-22",
    "control_id": "HYBRID-10037",
    "requires_sources": ["ca_policies_beta"],
    "framework_tags": [
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-SC-23",
        "NIST-CSF-2.0-PR.AA-03",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1550.001",
        "MITRE-ATTCK-T1539",
    ],
    "references": [
        {"title": "Microsoft: Token protection in Conditional Access",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-token-protection"},
        {"title": "Microsoft Graph (beta): conditionalAccessSessionControls (secureSignInSession)",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/conditionalaccesssessioncontrols?view=graph-rest-beta"},
        {"title": "MITRE ATT&CK T1539: Steal Web Session Cookie",
         "url": "https://attack.mitre.org/techniques/T1539/"},
    ],
    "description": (
        "No enabled Conditional Access policy requires token protection for the highly "
        "privileged roles, so an administrator's stolen refresh token or session can be "
        "replayed from another device. Token protection binds the session to the device "
        "it was issued to (supported clients only)."
    ),
    "remediation": (
        "Create a Conditional Access policy: Users = the privileged directory roles "
        "(exclude emergency-access accounts); Target resources = Office 365 Exchange "
        "Online, Office 365 SharePoint Online, Microsoft Teams Services (and the other "
        "resources Microsoft lists as supported); Conditions > Device platforms = Windows; "
        "Client apps = Mobile apps and desktop clients; Session = Require token protection "
        "for sign-in sessions. Run it in report-only first and check the sign-in logs for "
        "unsupported clients, then switch it On."
    ),
    "base_severity": "low",
    "query": """
        WITH tier0(role_template_id, role_name) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10', 'Global Administrator'),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814', 'Privileged Role Administrator'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13', 'Privileged Authentication Administrator'),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d', 'Security Administrator'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2', 'Hybrid Identity Administrator'),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3', 'Application Administrator'),
                   ('db506228-d27e-4b7d-95e5-295956d6615f', 'Agent ID Administrator'),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7', 'Cloud Application Administrator'),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de', 'Exchange Administrator'),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c', 'SharePoint Administrator'),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1', 'User Administrator'),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9', 'Conditional Access Administrator'),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f', 'Authentication Administrator'),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5', 'Intune Administrator')
        ),
        ts AS (
            SELECT t.client_id, t.content
              FROM entra_tenant_setting t
             WHERE t.client_id = %(client_id)s
               AND t.setting_name = 'ca_policies_beta'
               AND jsonb_typeof(t.content) = 'array'
               AND NOT EXISTS (SELECT 1 FROM v_entra_tenant_capability c
                                WHERE c.client_id = t.client_id AND c.license_status = 'ok'
                                  AND NOT c.has_p1)
        ),
        tp AS (
            SELECT p->>'id' AS id, p->>'display_name' AS name,
                   COALESCE(p->'conditions'->'users'->'includeUsers', '[]'::jsonb) ? 'All' AS all_users,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'includeRoles') = 'array'
                        THEN p->'conditions'->'users'->'includeRoles' ELSE '[]'::jsonb END AS inc_roles,
                   CASE WHEN jsonb_typeof(p->'conditions'->'users'->'excludeRoles') = 'array'
                        THEN p->'conditions'->'users'->'excludeRoles' ELSE '[]'::jsonb END AS ex_roles
              FROM ts CROSS JOIN LATERAL jsonb_array_elements(ts.content) p
             WHERE p->>'state' = 'enabled'
               AND p->'session_controls'->'secureSignInSession'->'isEnabled' = 'true'::jsonb
        ),
        cov AS (
            SELECT r.role_template_id, r.role_name,
                   EXISTS (SELECT 1 FROM tp
                            WHERE (tp.all_users OR tp.inc_roles ? r.role_template_id)
                              AND NOT tp.ex_roles ? r.role_template_id) AS covered
              FROM tier0 r
        )
        SELECT
            'warn' AS status,
            md5('10037:' || ts.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            CASE WHEN NOT EXISTS (SELECT 1 FROM cov WHERE covered)
                 THEN 'No enabled Conditional Access policy requires token protection for privileged roles'
                 ELSE 'Token protection is required for only some privileged roles'
            END AS summary,
            jsonb_build_object(
                'roles_covered', (SELECT jsonb_agg(role_name ORDER BY role_name) FROM cov WHERE covered),
                'roles_not_covered', (SELECT jsonb_agg(role_name ORDER BY role_name) FROM cov WHERE NOT covered),
                'token_protection_policies', (SELECT jsonb_agg(jsonb_build_object('policy', name, 'id', id)
                                                               ORDER BY name, id) FROM tp),
                'note', 'Token protection only applies to supported clients and resources; check the '
                        || 'current list in Microsoft''s documentation.'
            ) AS detail
        FROM ts
        WHERE EXISTS (SELECT 1 FROM cov WHERE NOT covered)
    """,
}
