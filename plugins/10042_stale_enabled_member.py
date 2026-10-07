"""
Plugin 10042: Stale Enabled Entra ID Member Account

Detects enabled member (non-guest) users with no sign-in activity for 90
days or more: the latest of lastSuccessfulSignInDateTime,
lastSignInDateTime and lastNonInteractiveSignInDateTime is older than 90
days, or there is no sign-in recorded at all and the account was created
more than 90 days ago.

Why: dormant accounts keep valid credentials nobody watches; they are the
preferred targets of password spraying and account takeover because their
owner will not notice (CISA AA24-057A: SVR actors used dormant accounts;
MITRE ATT&CK T1078.004). This is the cloud counterpart of on-prem plugin
1007. For synced users the AD lastLogonTimestamp is shown in the detail
(an account active on-prem but unused in the cloud may only need its cloud
access reviewed).

Data: entra_user.last_successful_sign_in_at / last_sign_in_at /
last_non_interactive_sign_in_at (signInActivity, AuditLog.Read.All + Entra
ID P1) and created_at (schema v42). requires_sources ['sign_in_activity']:
the query also checks the source is 'ok' and returns nothing otherwise
(sign-in columns are NULL then). Microsoft only records sign-ins since April
2020, so "never" means "none recorded".

Excluded: guests (plugin 10044), disabled accounts, holders of a highly
privileged role (TIER0 set, active or eligible: plugin 10043 uses a 45-day
threshold for them), and break-glass accounts (plugin 10055 checks them;
declared in entra_breakglass_account, otherwise the heuristic: cloud-only
enabled member with direct active Global Administrator excluded by name from
an enabled Conditional Access policy that targets all users -- the mode
used is in the detail). Accounts without created_at and without activity are
not reported (age unknown).

Severity: low (warn), one row per user (identity = Entra object id). The
summary states the threshold, not the age; the exact age is in the detail.
"""

PLUGIN = {
    "plugin_id": 10042,
    "category": "Hybrid Identity",
    "name": "Stale Enabled Entra ID Member Account",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10042",
    "requires_sources": ["sign_in_activity"],
    "framework_tags": [
        "NIST-800-53-AC-2",
        "NIST-800-53-AC-2(3)",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.2.6",
        "CIS-CSC-8-5.3",
        "ISO-27001-2022-A.5.18",
        "SOC2-CC6.2",
        "HIPAA-164.308(a)(3)(ii)(C)",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: How to manage inactive user accounts",
         "url": "https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-manage-inactive-user-accounts"},
        {"title": "CISA AA24-057A: SVR Cyber Actors Adapt Tactics for Initial Cloud Access",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-057a"},
        {"title": "MITRE ATT&CK T1078.004: Valid Accounts: Cloud Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/004/"},
    ],
    "description": (
        "An enabled member account has not signed in (interactive, non-interactive or "
        "successful) for 90 days or more, or has never signed in and was created more "
        "than 90 days ago. Dormant accounts are favoured targets for password spraying "
        "and takeover because nobody notices their use. Guests, privileged role holders "
        "(plugin 10043) and break-glass accounts (plugin 10055) are excluded. Low, one "
        "finding per user."
    ),
    "remediation": (
        "Confirm with the owner or manager whether each account is still needed. Disable "
        "unneeded accounts (Update-MgUser -UserId <id> -AccountEnabled:$false; for synced "
        "users disable the AD account) and delete them after the retention period. "
        "Automate this with Entra ID Governance access reviews for inactive users or a "
        "lifecycle workflow, and revoke sessions (Revoke-MgUserSignInSession) when "
        "disabling."
    ),
    "base_severity": "low",
    "query": """
        WITH tier0 (template_id) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid), ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid), ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid), ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid), ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid), ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid), ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid)
        ),
        priv AS (
            SELECT DISTINCT rm.member_id
              FROM entra_directory_role_member rm
              JOIN tier0 t ON t.template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.user'
        ),
        bg_declared AS (
            SELECT lower(b.user_principal_name) AS upn
              FROM entra_breakglass_account b
             WHERE b.client_id = %(client_id)s
        ),
        bg_mode AS (
            SELECT CASE WHEN EXISTS (SELECT 1 FROM bg_declared) THEN 'declared' ELSE 'heuristic' END AS mode
        ),
        breakglass AS (
            SELECT u.entra_object_id
              FROM entra_user u CROSS JOIN bg_mode m
             WHERE u.client_id = %(client_id)s
               AND m.mode = 'declared'
               AND lower(u.user_principal_name) IN (SELECT upn FROM bg_declared)
            UNION
            SELECT u.entra_object_id
              FROM entra_user u CROSS JOIN bg_mode m
             WHERE u.client_id = %(client_id)s
               AND m.mode = 'heuristic'
               AND u.user_type = 'Member'
               AND u.account_enabled IS TRUE
               AND u.on_premises_sync_enabled IS NOT TRUE
               AND EXISTS (SELECT 1 FROM entra_directory_role_member rm
                            WHERE rm.client_id = u.client_id
                              AND rm.member_id = u.entra_object_id
                              AND rm.role_template_id = '62e90394-69f5-4237-9190-012177145e10'::uuid
                              AND rm.assignment_type = 'active'
                              AND rm.via_group_id IS NULL)
               AND EXISTS (SELECT 1
                             FROM entra_security_posture sp
                            CROSS JOIN LATERAL jsonb_array_elements(
                                  CASE WHEN jsonb_typeof(sp.ca_policies) = 'array'
                                       THEN sp.ca_policies ELSE '[]'::jsonb END) p
                            WHERE sp.client_id = u.client_id
                              AND p->>'state' = 'enabled'
                              AND jsonb_typeof(p->'conditions'->'users'->'includeUsers') = 'array'
                              AND p->'conditions'->'users'->'includeUsers' ? 'All'
                              AND jsonb_typeof(p->'conditions'->'users'->'excludeUsers') = 'array'
                              AND p->'conditions'->'users'->'excludeUsers' ? u.entra_object_id::text)
        ),
        src AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s
                              AND s.source = 'sign_in_activity'
                              AND s.status = 'ok') AS ok
        ),
        users AS (
            SELECT u.*,
                   greatest(u.last_successful_sign_in_at, u.last_sign_in_at,
                            u.last_non_interactive_sign_in_at) AS last_activity
              FROM entra_user u CROSS JOIN src
             WHERE u.client_id = %(client_id)s
               AND src.ok
               AND u.account_enabled IS TRUE
               AND u.user_type = 'Member'
               AND u.entra_object_id NOT IN (SELECT member_id FROM priv)
               AND u.entra_object_id NOT IN (SELECT entra_object_id FROM breakglass)
        ),
        stale AS (
            SELECT u.*
              FROM users u
             WHERE u.last_activity < now() - interval '90 days'
                OR (u.last_activity IS NULL AND u.created_at < now() - interval '90 days')
        )
        SELECT
            'warn' AS status,
            s.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Enabled user "' || COALESCE(s.user_principal_name, s.entra_object_id::text) || '" '
                || CASE WHEN s.last_activity IS NULL
                        THEN 'has never signed in and was created 90 days or more ago'
                        ELSE 'has not signed in for 90 days or more' END AS summary,
            jsonb_build_object(
                'user_principal_name', s.user_principal_name,
                'display_name', s.display_name,
                'created_at', s.created_at,
                'last_activity_at', s.last_activity,
                'days_since_last_activity', floor(extract(epoch FROM now() - s.last_activity) / 86400),
                'last_successful_sign_in_at', s.last_successful_sign_in_at,
                'last_sign_in_at', s.last_sign_in_at,
                'last_non_interactive_sign_in_at', s.last_non_interactive_sign_in_at,
                'on_premises_sync_enabled', s.on_premises_sync_enabled,
                'ad_last_logon_timestamp', (SELECT max(au.last_logon_timestamp)
                                              FROM ad_user au
                                             WHERE au.client_id = s.client_id
                                               AND au.object_guid = s.on_prem_object_guid
                                               AND au.valid_to IS NULL),
                'threshold_days', 90,
                'breakglass_mode', (SELECT mode FROM bg_mode)
            ) AS detail
        FROM stale s
    """,
}
