"""
Plugin 10047: Entra User With Strong Password Requirement Disabled

Detects enabled users whose passwordPolicies property contains
'DisableStrongPassword'.

Why: that flag lets the account's cloud password ignore Entra ID's
complexity requirements, so an administrator, script or the user can set a
much weaker password than tenant policy allows, making it a prime
password-spraying target (MITRE ATT&CK T1110.003). It is typically
left behind by legacy provisioning scripts (Set-MsolUser
-StrongPasswordRequired $false).

'DisablePasswordExpiration' is deliberately NOT reported: CISA SCuBA
MS.AAD.6.1 says user passwords SHALL NOT expire and NIST SP 800-63B
recommends against periodic rotation. For synced users with password hash
sync the cloud password policy is not used for the synced hash, so the flag
matters mainly for cloud-only accounts and cloud password changes; the
detail shows on_premises_sync_enabled.

Data: entra_user.password_policies (schema v42; comma-separated Graph
passwordPolicies, NULL = none). Disabled accounts are excluded.

Severity: medium (warn), one row per user (identity = Entra object id);
high (fail) when the user holds a highly privileged role (TIER0 set,
active or PIM-eligible, directly or via a group).
"""

PLUGIN = {
    "plugin_id": 10047,
    "category": "Hybrid Identity",
    "name": "Entra User With Strong Password Requirement Disabled",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10047",
    "framework_tags": [
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-5(1)",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.6",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "HIPAA-164.308(a)(5)(ii)(D)",
        "MITRE-ATTCK-T1110.003",
    ],
    "references": [
        {"title": "Microsoft: Password policies and account restrictions in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/concept-sspr-policy"},
        {"title": "Microsoft Graph: user resource type (passwordPolicies)",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/user"},
        {"title": "MITRE ATT&CK T1110.003: Brute Force: Password Spraying",
         "url": "https://attack.mitre.org/techniques/T1110/003/"},
    ],
    "description": (
        "An enabled user has passwordPolicies 'DisableStrongPassword', so its cloud "
        "password is exempt from Entra ID complexity requirements and may be trivially "
        "weak -- an easy password-spraying target. Medium; high when the user holds a "
        "highly privileged role. 'DisablePasswordExpiration' is not reported (SCuBA "
        "MS.AAD.6.1: passwords shall not expire)."
    ),
    "remediation": (
        "Remove the flag and force a password change: Update-MgUser -UserId <id> "
        "-PasswordPolicies 'None' (or 'DisablePasswordExpiration' if that flag should "
        "stay), then require a reset at next sign-in (Update-MgUser -PasswordProfile "
        "@{ForceChangePasswordNextSignIn=$true}). Find and fix the provisioning script "
        "or process that sets it, and make sure the account is protected by MFA and "
        "Entra Password Protection."
    ),
    "base_severity": "medium",
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
        cand AS (
            SELECT u.entra_object_id, u.user_principal_name, u.display_name, u.user_type,
                   u.on_premises_sync_enabled, u.password_policies, u.last_password_change_at,
                   p.roles
              FROM entra_user u
              LEFT JOIN priv p ON p.member_id = u.entra_object_id
             WHERE u.client_id = %(client_id)s
               AND u.account_enabled IS TRUE
               AND EXISTS (SELECT 1
                             FROM unnest(string_to_array(u.password_policies, ',')) f(flag)
                            WHERE lower(btrim(f.flag)) = 'disablestrongpassword')
        )
        SELECT
            CASE WHEN c.roles IS NOT NULL THEN 'fail' ELSE 'warn' END AS status,
            c.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.roles IS NOT NULL THEN 'high' ELSE 'medium' END AS fd_severity,
            CASE WHEN c.roles IS NOT NULL THEN 'Privileged user "' ELSE 'User "' END
                || COALESCE(c.user_principal_name, c.entra_object_id::text)
                || '" has DisableStrongPassword set (password complexity not enforced)'
                || CASE WHEN c.roles IS NOT NULL
                        THEN ' (holds ' || array_to_string(c.roles, ', ') || ')' ELSE '' END AS summary,
            jsonb_build_object(
                'user_principal_name', c.user_principal_name,
                'display_name', c.display_name,
                'user_type', c.user_type,
                'on_premises_sync_enabled', c.on_premises_sync_enabled,
                'password_policies', c.password_policies,
                'last_password_change_at', c.last_password_change_at,
                'privileged_roles', to_jsonb(c.roles)
            ) AS detail
        FROM cand c
    """,
}
