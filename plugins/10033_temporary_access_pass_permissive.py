"""
Plugin 10033: Temporary Access Pass Policy Too Permissive

Detects the Temporary Access Pass (TAP) method enabled in the authentication
methods policy with multi-use passes allowed (isUsableOnce false) or a
maximum lifetime over 8 hours (maximumLifetimeInMinutes > 480).

Why: a TAP is a time-limited passcode that fully satisfies MFA and can be
used to register new methods, including passkeys. Anyone holding
Authentication Administrator, Privileged Authentication Administrator or an
equivalent role (or an attacker who has compromised one) can issue a TAP
for a user and sign in as that user with a fully MFA-satisfied session,
then register their own persistent method. Multi-use and long-lived passes
widen the window in which a leaked or attacker-issued pass is usable
(MITRE ATT&CK T1098.005 / T1556-style persistence via new authenticators).

Data: entra_tenant_setting 'auth_methods_policy' (schema v42; TAP settings
isUsableOnce, maximumLifetimeInMinutes, defaultLifetimeInMinutes).
requires_sources ['auth_methods_policy']. A disabled TAP method, or one that
is single-use with a lifetime of 8 hours or less, is not reported.

Severity: medium (warn) when TAP targets all users (includeTargets id
'all_users'), low when it is scoped to groups. One tenant-level row
(identity md5 of plugin and client).
"""

PLUGIN = {
    "plugin_id": 10033,
    "category": "Hybrid Identity",
    "name": "Temporary Access Pass Policy Too Permissive",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10033",
    "requires_sources": ["auth_methods_policy"],
    "framework_tags": [
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-5(1)",
        "NIST-CSF-2.0-PR.AA-01",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1098.005",
    ],
    "references": [
        {"title": "Microsoft: Configure Temporary Access Pass to register passwordless authentication methods",
         "url": "https://learn.microsoft.com/en-us/entra/identity/authentication/howto-authentication-temporary-access-pass"},
        {"title": "MITRE ATT&CK T1098.005: Account Manipulation: Device Registration",
         "url": "https://attack.mitre.org/techniques/T1098/005/"},
    ],
    "description": (
        "Temporary Access Pass is enabled with multi-use passes allowed or a maximum "
        "lifetime over 8 hours. A TAP fully satisfies MFA and lets its holder register "
        "new authentication methods, so an administrator (or an attacker holding an "
        "authentication administrator role) can mint one for any targeted user and take "
        "over the account; multi-use and long-lived passes widen that window. Medium when "
        "TAP is enabled for all users, low when scoped to groups."
    ),
    "remediation": (
        "Entra admin center > Protection > Authentication methods > Temporary Access "
        "Pass: set 'One-time use' to Yes and the maximum lifetime to 8 hours or less "
        "(1 hour default is usually enough for onboarding and recovery), and target a "
        "dedicated onboarding/recovery group instead of All users. With Graph: "
        "Update-MgPolicyAuthenticationMethodPolicyAuthenticationMethodConfiguration "
        "-AuthenticationMethodConfigurationId TemporaryAccessPass with isUsableOnce=$true "
        "and maximumLifetimeInMinutes<=480. Restrict who holds Authentication "
        "Administrator / Privileged Authentication Administrator and alert on TAP "
        "creation in the audit log ('Admin registered security info', method TAP)."
    ),
    "base_severity": "medium",
    "query": """
        WITH pol AS (
            SELECT ts.client_id, ts.content
              FROM entra_tenant_setting ts
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'auth_methods_policy'
               AND jsonb_typeof(ts.content) = 'object'
        ),
        tap AS (
            SELECT pol.client_id, m,
                   m->'isUsableOnce' AS usable_once,
                   CASE WHEN jsonb_typeof(m->'maximumLifetimeInMinutes') = 'number'
                        THEN (m->>'maximumLifetimeInMinutes')::numeric END AS max_lifetime,
                   CASE WHEN jsonb_typeof(m->'includeTargets') = 'array'
                        THEN m->'includeTargets' ELSE '[]'::jsonb END AS include_targets
              FROM pol
             CROSS JOIN LATERAL jsonb_array_elements(
                   CASE WHEN jsonb_typeof(pol.content->'authenticationMethodConfigurations') = 'array'
                        THEN pol.content->'authenticationMethodConfigurations' ELSE '[]'::jsonb END) m
             WHERE m->>'id' = 'TemporaryAccessPass'
               AND lower(COALESCE(m->>'state', '')) = 'enabled'
        ),
        scored AS (
            SELECT t.*,
                   EXISTS (SELECT 1 FROM jsonb_array_elements(t.include_targets) x
                            WHERE x->>'id' = 'all_users') AS all_users,
                   array_remove(ARRAY[
                       CASE WHEN t.usable_once = 'false'::jsonb THEN 'multi-use passes allowed' END,
                       CASE WHEN t.max_lifetime > 480 THEN 'maximum lifetime over 8 hours' END
                   ], NULL) AS issues
              FROM tap t
        )
        SELECT
            'warn' AS status,
            md5('10033:' || s.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN s.all_users THEN 'medium' ELSE 'low' END AS fd_severity,
            'Temporary Access Pass is enabled for '
                || CASE WHEN s.all_users THEN 'all users' ELSE 'selected groups' END
                || ' with ' || array_to_string(s.issues, ' and ') AS summary,
            jsonb_build_object(
                'issues', to_jsonb(s.issues),
                'is_usable_once', s.usable_once,
                'maximum_lifetime_in_minutes', s.m->'maximumLifetimeInMinutes',
                'default_lifetime_in_minutes', s.m->'defaultLifetimeInMinutes',
                'targets_all_users', s.all_users,
                'include_targets', s.include_targets,
                'exclude_targets', s.m->'excludeTargets'
            ) AS detail
        FROM scored s
        WHERE cardinality(s.issues) > 0
    """,
}
