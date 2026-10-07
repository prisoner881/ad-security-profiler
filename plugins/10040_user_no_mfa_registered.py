"""
Plugin 10040: Enabled User Without Any MFA Method Registered

Detects enabled Entra ID users whose MFA registration report
(reports/authenticationMethods/userRegistrationDetails) says
isMfaRegistered = false.

Why: an account with a password and no registered MFA method can be
completed by whoever signs in first with that password -- in a password
spray the attacker registers their own authenticator and from then on
satisfies every MFA prompt (MITRE ATT&CK T1078.004, T1098.005; the most
common initial-access path in Entra password-spray incidents, e.g. CISA
AA24-057A). Even where Conditional Access requires MFA, an unregistered
user is asked to register at their next sign-in, which an attacker holding
the password can do.

Data: entra_user_registration (schema v42; AuditLog.Read.All + Entra ID
P1) joined to entra_user for account_enabled and user_type. requires_sources
['registration_details']: without it the plugin returns nothing (adaudit
reports NOT ASSESSED). Users with no registration row, or
isMfaRegistered NULL, are not reported. Disabled accounts are excluded
(they cannot sign in; plugin 10045 covers disabled accounts still holding
roles).

Severity, one row per user (identity = the user's Entra object id):
- privileged user (holds a highly privileged role, TIER0 set, active or
  PIM-eligible, directly or via a group): fail, high;
- other member users: warn, medium;
- guests: warn, low (their MFA may be satisfied in their home tenant when
  cross-tenant MFA trust is configured).
"""

PLUGIN = {
    "plugin_id": 10040,
    "category": "Hybrid Identity",
    "name": "Enabled User Without Any MFA Method Registered",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10040",
    "requires_sources": ["registration_details"],
    "framework_tags": [
        "NIST-800-53-IA-2(1)",
        "NIST-800-53-IA-2(2)",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-8.4.2",
        "PCI-DSS-4.0-8.4.3",
        "CIS-CSC-8-6.3",
        "CIS-CSC-8-6.4",
        "CIS-CSC-8-6.5",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "HIPAA-164.312(d)",
        "MITRE-ATTCK-T1078.004",
        "MITRE-ATTCK-T1110.003",
        "MITRE-ATTCK-T1098.005",
    ],
    "references": [
        {"title": "Microsoft Graph: userRegistrationDetails resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/userregistrationdetails"},
        {"title": "Microsoft: Authentication methods activity (registration report)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-methods-activity"},
        {"title": "Microsoft: Nudge users to set up Microsoft Authenticator (registration campaign)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-mfa-registration-campaign"},
    ],
    "description": (
        "An enabled user has no MFA method registered (userRegistrationDetails "
        "isMfaRegistered = false). Whoever next signs in with the password -- possibly "
        "an attacker after a password spray -- can register their own authenticator and "
        "satisfy MFA from then on. One finding per user: high for holders of a highly "
        "privileged role (active or eligible), medium for other members, low for guests. "
        "Disabled accounts are excluded."
    ),
    "remediation": (
        "Have each listed user register a strong method (Microsoft Authenticator, passkey "
        "/ FIDO2, Windows Hello for Business), starting with privileged users -- for "
        "administrators, issue a one-time Temporary Access Pass in person and register a "
        "phishing-resistant method. Enable the registration campaign (Authentication "
        "methods > Registration campaign) and protect registration itself with a "
        "Conditional Access policy on the 'Register security information' user action "
        "(trusted location or compliant device, SCuBA MS.AAD.3.8) so an attacker holding "
        "only the password cannot register. Disable or remove accounts that are no "
        "longer needed."
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
                                                          THEN ' (eligible)' ELSE '' END) AS roles
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
            SELECT r.entra_object_id,
                   COALESCE(u.user_principal_name, r.user_principal_name) AS upn,
                   u.display_name,
                   COALESCE(u.user_type, r.user_type) AS user_type,
                   u.on_premises_sync_enabled,
                   r.methods_registered, r.is_sspr_registered, r.is_admin, r.last_updated_at,
                   p.roles,
                   CASE WHEN p.member_id IS NOT NULL THEN 'privileged'
                        WHEN COALESCE(u.user_type, r.user_type) = 'Guest' THEN 'guest'
                        ELSE 'member' END AS kind
              FROM entra_user_registration r
              JOIN entra_user u ON u.client_id = r.client_id AND u.entra_object_id = r.entra_object_id
              LEFT JOIN priv p ON p.member_id = r.entra_object_id
              CROSS JOIN src
             WHERE r.client_id = %(client_id)s
               AND src.ok
               AND u.account_enabled IS TRUE
               AND r.is_mfa_registered IS FALSE
        )
        SELECT
            CASE WHEN c.kind = 'privileged' THEN 'fail' ELSE 'warn' END AS status,
            c.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE c.kind WHEN 'privileged' THEN 'high' WHEN 'member' THEN 'medium' ELSE 'low' END AS fd_severity,
            CASE c.kind WHEN 'privileged' THEN 'Privileged user "'
                        WHEN 'guest' THEN 'Enabled guest user "'
                        ELSE 'Enabled user "' END
                || COALESCE(c.upn, c.entra_object_id::text) || '" has no MFA method registered'
                || CASE WHEN c.kind = 'privileged'
                        THEN ' (holds ' || array_to_string(c.roles, ', ') || ')' ELSE '' END AS summary,
            jsonb_build_object(
                'user_principal_name', c.upn,
                'display_name', c.display_name,
                'user_type', c.user_type,
                'on_premises_sync_enabled', c.on_premises_sync_enabled,
                'privileged_roles', to_jsonb(c.roles),
                'methods_registered', to_jsonb(c.methods_registered),
                'is_sspr_registered', c.is_sspr_registered,
                'is_admin', c.is_admin,
                'registration_last_updated_at', c.last_updated_at
            ) AS detail
        FROM cand c
    """,
}
