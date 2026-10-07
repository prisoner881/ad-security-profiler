"""
Plugin 11026: Tenant Authorization, Authentication-Methods or Cross-Tenant Policy Changed

Change Detection for Microsoft Entra ID. Reports changes, in the latest
Entra collection, to the tenant-wide policies that gate consent, guest
access, authentication methods and cross-tenant access: the authorization
policy, the authentication methods policy, the cross-tenant access default
policy and the admin consent request policy.

Why: these settings regress silently -- re-enabling SMS or voice, opening
user consent to applications, letting everyone invite guests, or switching
the authentication-methods migration back -- and each loosening widens the
attack surface the rest of the assessment measured (MITRE ATT&CK T1484.002
Domain or Tenant Policy Modification). Security Defaults is reported by
plugin 11025.

Data: entra_change_history entity_type 'tenant_policy', keys
'authorization_policy' (content = the authorization policy JSON),
'auth_methods_policy' (per-method {id: {state, includeTargets,
excludeTargets}} plus policyMigrationState), 'cross_tenant_default' and
'admin_consent_request_policy' (their Graph content), with
entra_change_baseline. A policy that first appears after the baseline (no
earlier version) is not reported -- there is nothing to compare it with.
Suppressed on the first collection; findings stay open until the next
Entra collection.

Severity high when a weak method was enabled or consent / access opened:
  * auth methods: Sms, Voice or Email changed to state 'enabled', or
    policyMigrationState changed away from 'migrationComplete';
  * authorization policy: a ManagePermissionGrantsForSelf.* policy added to
    permissionGrantPoliciesAssigned (user consent opened), allowedToCreateApps
    turned on, allowInvitesFrom changed to 'everyone', or guestUserRoleId
    changed to the member-equivalent role
    (a0b1b346-4d3e-4e8b-98f8-753987be4970);
otherwise medium (including a policy no longer present). One row per policy
(object_guid = md5('11026:' || client_id || ':' || key)).
"""

PLUGIN = {
    "plugin_id": 11026,
    "category": "Change Detection",
    "name": "Tenant Authorization, Authentication-Methods or Cross-Tenant Policy Changed",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "CHANGE-11026",
    "requires_sources": ["auth_methods_policy", "cross_tenant_policy", "admin_consent_request_policy"],
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-11.5.2",
        "CIS-CSC-8-8.11",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.8.32",
        "SOC2-CC7.2", "SOC2-CC8.1",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1484.002",
    ],
    "references": [
        {"title": "Microsoft Graph: authorizationPolicy resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/authorizationpolicy"},
        {"title": "Microsoft Graph: authenticationMethodsPolicy resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/authenticationmethodspolicy"},
        {"title": "Microsoft: Configure how users consent to applications",
         "url": "https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/configure-user-consent"},
        {"title": "MITRE ATT&CK T1484.002: Domain or Tenant Policy Modification: Trust Modification",
         "url": "https://attack.mitre.org/techniques/T1484/002/"},
    ],
    "description": (
        "Reports changes to the authorization policy, authentication methods policy, "
        "cross-tenant access default policy and admin consent request policy since the "
        "previous Entra collection. High when SMS, voice or email OTP was enabled, the "
        "authentication-methods migration was rolled back, user consent was opened, users "
        "were allowed to register apps, anyone may invite guests, or guests got member-level "
        "access; medium for other changes. Suppressed on the first Entra collection."
    ),
    "remediation": (
        "Confirm the change in the Entra audit log (category Policy: 'Update authorization "
        "policy', 'Authentication Methods Policy Update', 'Update cross tenant access "
        "settings', 'Update admin consent request policy'). Revert unapproved changes: "
        "disable SMS/Voice/Email OTP (SCuBA MS.AAD.3.5), set the migration to Migration "
        "Complete (MS.AAD.3.4), restrict user consent and app registration to administrators "
        "(MS.AAD.5.1 / 5.2), keep guest access restricted (MS.AAD.8.1) and guest invitation to "
        "Guest Inviters (MS.AAD.8.2)."
    ),
    "base_severity": "medium",
    "query": """
        WITH b AS (
            SELECT bl.client_id, bl.last_run_at
            FROM entra_change_baseline bl
            WHERE bl.client_id = %(client_id)s AND bl.entity_type = 'tenant_policy'
              AND bl.first_run_at < bl.last_run_at
        ),
        k AS (
            SELECT DISTINCT h.entity_key
            FROM entra_change_history h
            JOIN b ON b.client_id = h.client_id
            WHERE h.entity_type = 'tenant_policy'
              AND h.entity_key IN ('authorization_policy', 'auth_methods_policy',
                                   'cross_tenant_default', 'admin_consent_request_policy')
              AND (h.valid_from = b.last_run_at OR h.valid_to = b.last_run_at)
        ),
        chg AS (
            SELECT k.entity_key, nv.content AS new_c, ov.content AS old_c,
                   CASE WHEN nv.content IS NOT NULL AND ov.content IS NULL THEN 'new'
                        WHEN nv.content IS NOT NULL THEN 'modified'
                        ELSE 'removed' END AS kind
            FROM k
            CROSS JOIN b
            LEFT JOIN entra_change_history nv
              ON nv.client_id = b.client_id AND nv.entity_type = 'tenant_policy'
             AND nv.entity_key = k.entity_key AND nv.valid_from = b.last_run_at AND nv.valid_to IS NULL
            LEFT JOIN entra_change_history ov
              ON ov.client_id = b.client_id AND ov.entity_type = 'tenant_policy'
             AND ov.entity_key = k.entity_key AND ov.valid_to = b.last_run_at
        ),
        eval AS (
            SELECT c.*,
                   COALESCE((SELECT array_agg(x.key ORDER BY x.key)
                             FROM (SELECT key FROM jsonb_each(CASE WHEN jsonb_typeof(c.new_c) = 'object'
                                                                   THEN c.new_c ELSE '{}'::jsonb END)
                                   UNION
                                   SELECT key FROM jsonb_each(CASE WHEN jsonb_typeof(c.old_c) = 'object'
                                                                   THEN c.old_c ELSE '{}'::jsonb END)) x
                             WHERE (c.new_c -> x.key) IS DISTINCT FROM (c.old_c -> x.key)),
                            '{}'::text[]) AS changed_keys,
                   array_remove(ARRAY[
                       -- Authentication methods
                       CASE WHEN c.entity_key = 'auth_methods_policy' THEN
                           (SELECT string_agg(m.key || ' enabled', ', ' ORDER BY m.key)
                            FROM jsonb_each(CASE WHEN jsonb_typeof(c.new_c) = 'object'
                                                 THEN c.new_c ELSE '{}'::jsonb END) m
                            WHERE lower(m.key) IN ('sms', 'voice', 'email')
                              AND jsonb_typeof(m.value) = 'object'
                              AND lower(COALESCE(m.value->>'state', '')) = 'enabled'
                              AND lower(COALESCE(c.old_c #>> ARRAY[m.key, 'state'], '')) <> 'enabled')
                       END,
                       CASE WHEN c.entity_key = 'auth_methods_policy'
                                 AND c.old_c->>'policyMigrationState' = 'migrationComplete'
                                 AND (c.new_c->>'policyMigrationState') IS DISTINCT FROM 'migrationComplete'
                            THEN 'policyMigrationState rolled back to '
                                 || COALESCE(c.new_c->>'policyMigrationState', 'unset') END,
                       -- Authorization policy
                       CASE WHEN c.entity_key = 'authorization_policy'
                                 AND EXISTS (
                                     SELECT 1
                                     FROM jsonb_array_elements_text(
                                         CASE WHEN jsonb_typeof(c.new_c #> '{defaultUserRolePermissions,permissionGrantPoliciesAssigned}') = 'array'
                                              THEN c.new_c #> '{defaultUserRolePermissions,permissionGrantPoliciesAssigned}'
                                              ELSE '[]'::jsonb END) p
                                     WHERE p LIKE 'ManagePermissionGrantsForSelf.%%'
                                       AND NOT (CASE WHEN jsonb_typeof(c.old_c #> '{defaultUserRolePermissions,permissionGrantPoliciesAssigned}') = 'array'
                                                     THEN c.old_c #> '{defaultUserRolePermissions,permissionGrantPoliciesAssigned}'
                                                     ELSE '[]'::jsonb END) @> to_jsonb(p))
                            THEN 'user consent to applications opened' END,
                       CASE WHEN c.entity_key = 'authorization_policy'
                                 AND (c.new_c #>> '{defaultUserRolePermissions,allowedToCreateApps}') = 'true'
                                 AND (c.old_c #>> '{defaultUserRolePermissions,allowedToCreateApps}')
                                     IS DISTINCT FROM 'true'
                            THEN 'users allowed to register applications' END,
                       CASE WHEN c.entity_key = 'authorization_policy'
                                 AND c.new_c->>'allowInvitesFrom' = 'everyone'
                                 AND (c.old_c->>'allowInvitesFrom') IS DISTINCT FROM 'everyone'
                            THEN 'anyone may invite guests' END,
                       CASE WHEN c.entity_key = 'authorization_policy'
                                 AND lower(c.new_c->>'guestUserRoleId') = 'a0b1b346-4d3e-4e8b-98f8-753987be4970'
                                 AND lower(COALESCE(c.old_c->>'guestUserRoleId', ''))
                                     <> 'a0b1b346-4d3e-4e8b-98f8-753987be4970'
                            THEN 'guests given member-level directory access' END
                   ], NULL) AS loosened
            FROM chg c
            WHERE c.kind <> 'new'
        )
        SELECT
            CASE WHEN cardinality(e.loosened) > 0 THEN 'fail' ELSE 'warn' END AS status,
            md5('11026:' || %(client_id)s::text || ':' || e.entity_key)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN cardinality(e.loosened) > 0 THEN 'high' ELSE 'medium' END AS fd_severity,
            CASE e.entity_key
                 WHEN 'authorization_policy' THEN 'Authorization policy'
                 WHEN 'auth_methods_policy' THEN 'Authentication methods policy'
                 WHEN 'cross_tenant_default' THEN 'Cross-tenant access default policy'
                 ELSE 'Admin consent request policy' END
                || CASE WHEN e.kind = 'removed' THEN ' is no longer present'
                        WHEN cardinality(e.loosened) > 0
                            THEN ' loosened: ' || array_to_string(e.loosened, '; ')
                        ELSE ' changed (' || array_to_string(e.changed_keys, ', ') || ')' END
                || ' since the previous Entra collection' AS summary,
            jsonb_build_object(
                'policy', e.entity_key,
                'change', e.kind,
                'loosened', to_jsonb(e.loosened),
                'changed_keys', to_jsonb(e.changed_keys),
                'previous', e.old_c,
                'current', e.new_c,
                'detected_at', (SELECT last_run_at FROM b)
            ) AS detail
        FROM eval e
    """,
}
