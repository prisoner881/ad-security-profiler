"""
Plugin 10072: Email-Verified Self-Service Join or Email-Based Subscriptions Allowed

Reads the tenant authorization policy (entra_security_posture.
authorization_policy, Tier A -- already collected) and reports two
self-service settings that plugin 10017 does not read:

- allowEmailVerifiedUsersToJoinOrganization true -> medium. Anyone who can
  receive mail at one of the tenant's verified domains can create a user
  account in this directory through email verification ("viral" or
  unmanaged sign-up), outside the joiner process, without an
  administrator approving it.
- allowedToSignUpEmailBasedSubscriptions true -> low. Users can sign up
  for email-based (self-service / trial) subscriptions, which brings
  services and data outside IT control (shadow IT).

Each setting is its own finding: md5('10072:' || client_id ||
':email_verified_join') and md5('10072:' || client_id ||
':email_based_subscriptions'), so fixing one closes only that one.

Data caveats: authorization_policy NULL (the read failed -- see
authorization_policy_status -- or an older collector) -> no rows. A key
Graph omitted (JSON null) is skipped, not guessed. Both settings are
Microsoft's defaults for new tenants (true), so a fresh tenant is reported.
"""

PLUGIN = {
    "plugin_id": 10072,
    "category": "Hybrid Identity",
    "name": "Email-Verified Self-Service Join or Email-Based Subscriptions Allowed",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10072",
    "framework_tags": [
        "NIST-800-53-AC-2",
        "NIST-800-53-CM-11",
        "NIST-CSF-2.0-PR.AA-01",
        "CIS-CSC-8-5.3",
        "ISO-27001-2022-A.5.18",
        "SOC2-CC6.2",
        "MITRE-ATTCK-T1136.003",
    ],
    "references": [
        {"title": "Microsoft Graph: authorizationPolicy resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy"},
        {"title": "Microsoft: What is self-service sign-up for Microsoft Entra ID?",
         "url": "https://learn.microsoft.com/en-us/entra/identity/users/directory-self-service-signup"},
        {"title": "Microsoft: Manage self-service sign-up subscriptions",
         "url": "https://learn.microsoft.com/en-us/microsoft-365/commerce/subscriptions/manage-self-service-signup-subscriptions"},
    ],
    "description": (
        "The authorization policy lets anyone with a mailbox at a verified "
        "domain join the tenant by email verification "
        "(allowEmailVerifiedUsersToJoinOrganization, medium) and/or lets "
        "users sign up for email-based self-service subscriptions "
        "(allowedToSignUpEmailBasedSubscriptions, low). Accounts and "
        "services are then created outside the identity lifecycle "
        "process. One finding per setting; silent when the authorization "
        "policy could not be read."
    ),
    "remediation": (
        "Microsoft Graph PowerShell: Update-MgPolicyAuthorizationPolicy "
        "-AllowEmailVerifiedUsersToJoinOrganization:$false "
        "-AllowedToSignUpEmailBasedSubscriptions:$false. Also block "
        "self-service purchases per product "
        "(Update-MSCommerceProductPolicy -PolicyId AllowSelfServicePurchase "
        "-Enabled $false) where trials and purchases should go through IT."
    ),
    "base_severity": "medium",
    "query": """
        WITH ap AS (
            SELECT sp.client_id, sp.authorization_policy AS pol
              FROM entra_security_posture sp
             WHERE sp.client_id = %(client_id)s
               AND jsonb_typeof(sp.authorization_policy) = 'object'
        )
        SELECT
            'fail' AS status,
            md5('10072:' || a.client_id::text || ':email_verified_join')::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Users with an email address at a verified domain can join the tenant by email '
                || 'verification (allowEmailVerifiedUsersToJoinOrganization is true)' AS summary,
            jsonb_build_object(
                'setting', 'allowEmailVerifiedUsersToJoinOrganization',
                'value', a.pol -> 'allowEmailVerifiedUsersToJoinOrganization'
            ) AS detail
        FROM ap a
        WHERE a.pol ->> 'allowEmailVerifiedUsersToJoinOrganization' = 'true'
        UNION ALL
        SELECT
            'warn',
            md5('10072:' || a.client_id::text || ':email_based_subscriptions')::uuid,
            NULL, NULL, NULL, NULL,
            'low',
            'Users can sign up for email-based self-service subscriptions '
                || '(allowedToSignUpEmailBasedSubscriptions is true)',
            jsonb_build_object(
                'setting', 'allowedToSignUpEmailBasedSubscriptions',
                'value', a.pol -> 'allowedToSignUpEmailBasedSubscriptions'
            )
        FROM ap a
        WHERE a.pol ->> 'allowedToSignUpEmailBasedSubscriptions' = 'true'
    """,
}
