"""
Plugin 10041: Privileged User Without a Phishing-Resistant Method Registered

Detects enabled users holding a highly privileged Entra role (TIER0 set:
Global, Privileged Role, Privileged Authentication, Security, Hybrid
Identity, Application, Cloud Application, Exchange, SharePoint, User,
Conditional Access, Authentication and Intune Administrator; active or
PIM-eligible, directly or through a role-assignable group) whose registered
authentication methods include no phishing-resistant method.

Phishing-resistant = any methods_registered value (case-insensitive)
starting with 'fido2' (fido2SecurityKey), 'passKey' (passKeyDeviceBound,
passKeyDeviceBoundAuthenticator, and any newer passkey variant),
'windowsHello' (windowsHelloForBusiness), 'x509' (certificate-based
authentication variants), or equal to 'macOsSecureEnclaveKey' (Platform
Credential for macOS).

Why: plugin 10014 checks that Conditional Access *requires*
phishing-resistant MFA for administrators (CISA SCuBA MS.AAD.3.6); this
checks the administrators can actually *meet* it. An administrator with
only push, OTP or SMS is either blocked by such a policy -- and so usually
ends up excluded from it -- or is protected only by methods that
adversary-in-the-middle phishing kits defeat (Storm-1167 / EvilProxy token
theft; MITRE ATT&CK T1557, T1078.004).

Data: entra_user_registration (schema v42; AuditLog.Read.All + Entra ID P1)
and entra_directory_role_member. requires_sources ['registration_details'].
Privileged users without a registration row, and disabled accounts, are
not reported.

Severity: high (fail), one row per user (identity = the user's Entra object
id) listing all highly privileged roles held.
"""

PLUGIN = {
    "plugin_id": 10041,
    "category": "Hybrid Identity",
    "name": "Privileged User Without a Phishing-Resistant Method Registered",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10041",
    "requires_sources": ["registration_details"],
    "framework_tags": [
        "CISA-SCUBA-MS.AAD.3.6",
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-IA-2(8)",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.4.1",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "HIPAA-164.312(d)",
        "NIST-800-53-AC-6(5)",
        "CIS-CSC-8-5.4",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1566.002",
    ],
    "references": [
        {"title": "CISA SCuBA Microsoft Entra ID baseline (MS.AAD.3.6)",
         "url": "https://github.com/cisagov/ScubaGear/blob/main/PowerShell/ScubaGear/baselines/aad.md"},
        {"title": "Microsoft: Require phishing-resistant MFA for administrators",
         "url": "https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-admin-phish-resistant-mfa"},
        {"title": "Microsoft Graph: userRegistrationDetails resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails"},
    ],
    "description": (
        "A user holding a highly privileged Entra role (active or PIM-eligible) has no "
        "phishing-resistant method registered (FIDO2 security key, passkey, Windows "
        "Hello for Business, certificate-based authentication, macOS Platform "
        "Credential). The administrator either cannot satisfy a phishing-resistant "
        "Conditional Access requirement (and is likely excluded from it) or is protected "
        "only by phishable methods. SCuBA MS.AAD.3.6. High, one finding per user."
    ),
    "remediation": (
        "Register a phishing-resistant method for every listed administrator: a FIDO2 "
        "security key or device-bound passkey (Microsoft Authenticator), Windows Hello "
        "for Business, or certificate-based authentication. Issue a one-time Temporary "
        "Access Pass after verifying identity in person to bootstrap registration. Then "
        "enforce the 'Phishing-resistant MFA' authentication strength for all highly "
        "privileged roles in Conditional Access (plugin 10014) and remove any exclusions "
        "added as a workaround."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0 (template_id, role_name) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid, 'Global Administrator'),
                   ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid, 'Privileged Role Administrator'),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid, 'Privileged Authentication Administrator'),
                   ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid, 'Security Administrator'),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid, 'Hybrid Identity Administrator'),
                   ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid, 'Application Administrator'),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid, 'Cloud Application Administrator'),
                   ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid, 'Exchange Administrator'),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid, 'SharePoint Administrator'),
                   ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid, 'User Administrator'),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid, 'Conditional Access Administrator'),
                   ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid, 'Authentication Administrator'),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid, 'Intune Administrator')
        ),
        priv AS (
            SELECT rm.member_id,
                   array_agg(DISTINCT t.role_name || CASE WHEN rm.assignment_type = 'eligible'
                                                          THEN ' (eligible)' ELSE '' END
                             ORDER BY t.role_name || CASE WHEN rm.assignment_type = 'eligible'
                                                          THEN ' (eligible)' ELSE '' END) AS roles,
                   bool_or(rm.account_enabled IS FALSE) AS any_disabled
              FROM entra_directory_role_member rm
              JOIN tier0 t ON t.template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.user'
             GROUP BY rm.member_id
        ),
        src AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s
                              AND s.source = 'registration_details'
                              AND s.status = 'ok') AS ok
        ),
        cand AS (
            SELECT p.member_id, p.roles,
                   COALESCE(u.user_principal_name, r.user_principal_name) AS upn,
                   u.display_name, u.on_premises_sync_enabled,
                   r.methods_registered, r.default_mfa_method, r.is_mfa_registered
              FROM priv p
              JOIN entra_user_registration r
                ON r.client_id = %(client_id)s AND r.entra_object_id = p.member_id
              LEFT JOIN entra_user u
                ON u.client_id = %(client_id)s AND u.entra_object_id = p.member_id
              CROSS JOIN src
             WHERE src.ok
               AND COALESCE(u.account_enabled, NOT p.any_disabled) IS TRUE
               AND NOT EXISTS (
                   SELECT 1 FROM unnest(r.methods_registered) m(method)
                    WHERE lower(m.method) LIKE 'fido2%%'
                       OR lower(m.method) LIKE 'passkey%%'
                       OR lower(m.method) LIKE 'windowshello%%'
                       OR lower(m.method) LIKE 'x509%%'
                       OR lower(m.method) = 'macossecureenclavekey')
        )
        SELECT
            'fail' AS status,
            c.member_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Privileged user "' || COALESCE(c.upn, c.member_id::text)
                || '" has no phishing-resistant authentication method registered (holds '
                || array_to_string(c.roles, ', ') || ')' AS summary,
            jsonb_build_object(
                'user_principal_name', c.upn,
                'display_name', c.display_name,
                'on_premises_sync_enabled', c.on_premises_sync_enabled,
                'privileged_roles', to_jsonb(c.roles),
                'methods_registered', to_jsonb(c.methods_registered),
                'default_mfa_method', c.default_mfa_method,
                'is_mfa_registered', c.is_mfa_registered,
                'scuba_policy', 'MS.AAD.3.6'
            ) AS detail
        FROM cand c
    """,
}
