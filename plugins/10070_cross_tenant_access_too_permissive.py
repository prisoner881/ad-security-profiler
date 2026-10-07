"""
Plugin 10070: Cross-Tenant Access Settings Too Permissive

Reads the cross-tenant access policy (source cross_tenant_policy):
entra_tenant_setting 'cross_tenant_default' (policies/crossTenantAccessPolicy/
default) and entra_cross_tenant_partner (one row per configured partner
tenant, with its identitySynchronization object).

Default policy (one tenant-level finding, every issue listed):
- inboundTrust.isMfaAccepted true -> medium. MFA performed in ANY external
  tenant satisfies this tenant's MFA requirement for B2B users, so the
  weakest MFA of any home tenant becomes good enough here.
- b2bDirectConnectInbound open to all users or all applications -> medium.
  B2B direct connect (Teams shared channels) gives external users access
  without a guest object in this directory, so they are invisible to
  guest reviews. Microsoft's default blocks it.
- b2bCollaborationOutbound open to all users or all applications -> low
  (Microsoft's default; reported so that outbound collaboration is an
  explicit decision).
A section counts as "open to all" when one of its two dimensions
(usersAndGroups / applications) is allowed for every target (accessType
'allowed' with target AllUsers / AllApplications, or 'blocked' with only
specific targets, i.e. allowed for everyone else) and the other dimension
is not blocked for everyone. A section or key Graph did not return (null)
is skipped, not guessed.

Each configured partner (one finding per partner):
- identitySynchronization.userSyncInbound.isSyncAllowed true -> high. The
  partner tenant may push (create and update) users into this tenant via
  cross-tenant synchronization; a compromised partner gains a persistent
  foothold here (Vectra, 2023: cross-tenant synchronization abuse for
  lateral movement and persistence).
- the partner's own inboundTrust.isMfaAccepted true -> low (a deliberate,
  scoped trust; still worth reviewing). A partner whose inboundTrust is
  null inherits the default and is covered by the default finding.

Identities: default finding md5('10070:' || client_id); partner finding
md5('10070:' || client_id || ':' || partner tenant id). status 'fail' at
medium or above, 'warn' at low. Requires source cross_tenant_policy: when
it is not 'ok' the plugin reports nothing (and adaudit shows NOT ASSESSED).
"""

PLUGIN = {
    "plugin_id": 10070,
    "category": "Hybrid Identity",
    "name": "Cross-Tenant Access Settings Too Permissive",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10070",
    "requires_sources": ["cross_tenant_policy"],
    "framework_tags": [
        "NIST-800-53-AC-20",
        "NIST-800-53-AC-4",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-8.2.7",
        "CIS-CSC-8-6.7",
        "ISO-27001-2022-A.5.19",
        "ISO-27001-2022-A.8.20",
        "SOC2-CC6.6",
        "MITRE-ATTCK-T1199",
        "MITRE-ATTCK-T1078.004",
    ],
    "references": [
        {"title": "Microsoft: Cross-tenant access overview",
         "url": "https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-overview"},
        {"title": "Microsoft: Configure cross-tenant access settings for B2B collaboration",
         "url": "https://learn.microsoft.com/en-us/entra/external-id/cross-tenant-access-settings-b2b-collaboration"},
        {"title": "Microsoft: Cross-tenant synchronization overview",
         "url": "https://learn.microsoft.com/en-us/entra/identity/multi-tenant-organizations/cross-tenant-synchronization-overview"},
        {"title": "Microsoft Graph: crossTenantAccessPolicyConfigurationDefault",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/crosstenantaccesspolicyconfigurationdefault"},
        {"title": "MITRE ATT&CK T1199 Trusted Relationship",
         "url": "https://attack.mitre.org/techniques/T1199/"},
    ],
    "description": (
        "Cross-tenant access settings trust or open this tenant to other "
        "tenants more than necessary. Default policy: MFA from every "
        "external tenant accepted (medium), B2B direct connect inbound open "
        "to all users or applications (medium), outbound B2B collaboration "
        "unrestricted (low) -- one tenant-level finding. Per partner: the "
        "partner may synchronize users into this tenant (cross-tenant "
        "sync inbound allowed, high -- a compromised partner can create "
        "and update users here) or the partner's MFA is trusted (low)."
    ),
    "remediation": (
        "Entra admin center -> External Identities -> Cross-tenant access "
        "settings. Default settings: Trust settings -> clear 'Trust "
        "multifactor authentication from Microsoft Entra tenants'; B2B "
        "direct connect -> Inbound -> block all users and applications; "
        "B2B collaboration -> Outbound -> restrict to the users/groups and "
        "applications that need it. Trust MFA only for named partner "
        "organizations that enforce it. For each partner with "
        "cross-tenant synchronization: Organizational settings -> partner "
        "-> Inbound access -> Cross-tenant sync -> clear 'Allow users sync "
        "into this tenant' unless a multi-tenant organization design "
        "requires it, and then scope the sync to specific users. Graph: "
        "Update-MgPolicyCrossTenantAccessPolicyDefault / "
        "Set-MgPolicyCrossTenantAccessPolicyPartnerIdentitySynchronization "
        "-UserSyncInbound @{IsSyncAllowed=$false}."
    ),
    "base_severity": "high",
    "query": """
        WITH src AS (
            SELECT EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s
                              AND s.source = 'cross_tenant_policy'
                              AND s.status = 'ok') AS ok
        ),
        dflt AS (
            SELECT ts.client_id, ts.content
              FROM entra_tenant_setting ts, src
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'cross_tenant_default'
               AND jsonb_typeof(ts.content) = 'object'
               AND src.ok
        ),
        dim AS (
            -- one row per (section, dimension) of the default policy
            SELECT d.client_id, sec.name AS section, dm.name AS dimension,
                   d.content -> sec.name -> dm.name ->> 'accessType' AS access_type,
                   CASE WHEN jsonb_typeof(d.content -> sec.name -> dm.name -> 'targets') = 'array'
                        THEN EXISTS (SELECT 1
                                       FROM jsonb_array_elements(d.content -> sec.name -> dm.name -> 'targets') t
                                      WHERE t ->> 'target' IN ('AllUsers', 'AllApplications'))
                        ELSE FALSE END AS has_all
              FROM dflt d
              CROSS JOIN (VALUES ('b2bDirectConnectInbound'), ('b2bCollaborationOutbound')) sec(name)
              CROSS JOIN (VALUES ('usersAndGroups'), ('applications')) dm(name)
             WHERE jsonb_typeof(d.content -> sec.name -> dm.name) = 'object'
        ),
        sect AS (
            SELECT client_id, section,
                   count(*) AS dims,
                   -- not blocked for everyone
                   bool_and(access_type = 'allowed' OR (access_type = 'blocked' AND NOT has_all)) AS all_open,
                   -- allowed for everyone (or everyone but a few)
                   bool_or((access_type = 'allowed' AND has_all) OR (access_type = 'blocked' AND NOT has_all)) AS any_broad,
                   jsonb_object_agg(dimension, jsonb_build_object('accessType', access_type, 'all_targets', has_all)) AS dims_detail
              FROM dim
             GROUP BY client_id, section
        ),
        default_issue AS (
            SELECT d.client_id, 3 AS rank,
                   'MFA performed in any external tenant is trusted (default inboundTrust.isMfaAccepted)' AS issue
              FROM dflt d
             WHERE d.content -> 'inboundTrust' ->> 'isMfaAccepted' = 'true'
            UNION ALL
            SELECT s.client_id,
                   CASE s.section WHEN 'b2bDirectConnectInbound' THEN 3 ELSE 2 END,
                   CASE s.section
                        WHEN 'b2bDirectConnectInbound'
                        THEN 'B2B direct connect inbound is open to all external users or applications by default'
                        ELSE 'outbound B2B collaboration is unrestricted by default (all users / all applications)' END
              FROM sect s
             WHERE s.dims = 2 AND s.all_open AND s.any_broad
        ),
        default_row AS (
            SELECT i.client_id, max(i.rank) AS rank,
                   string_agg(i.issue, '; ' ORDER BY i.rank DESC, i.issue COLLATE "C") AS summary_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC, i.issue COLLATE "C") AS issues
              FROM default_issue i
             GROUP BY i.client_id
        ),
        partner AS (
            SELECT p.client_id, p.partner_tenant_id, p.content,
                   COALESCE((p.content -> 'identitySynchronization' ->> 'displayName')
                            || ' (' || p.partner_tenant_id::text || ')',
                            p.partner_tenant_id::text) AS label
              FROM entra_cross_tenant_partner p, src
             WHERE p.client_id = %(client_id)s
               AND src.ok
               AND jsonb_typeof(p.content) = 'object'
        ),
        partner_issue AS (
            SELECT p.partner_tenant_id, 4 AS rank,
                   'may synchronize users into this tenant (cross-tenant sync inbound allowed)' AS issue
              FROM partner p
             WHERE p.content -> 'identitySynchronization' -> 'userSyncInbound' ->> 'isSyncAllowed' = 'true'
            UNION ALL
            SELECT p.partner_tenant_id, 2,
                   'MFA performed in the partner tenant is trusted'
              FROM partner p
             WHERE p.content -> 'inboundTrust' ->> 'isMfaAccepted' = 'true'
        ),
        partner_row AS (
            SELECT i.partner_tenant_id, max(i.rank) AS rank,
                   string_agg(i.issue, '; ' ORDER BY i.rank DESC, i.issue COLLATE "C") AS summary_text,
                   jsonb_agg(i.issue ORDER BY i.rank DESC, i.issue COLLATE "C") AS issues
              FROM partner_issue i
             GROUP BY i.partner_tenant_id
        )
        SELECT
            CASE WHEN r.rank >= 3 THEN 'fail' ELSE 'warn' END AS status,
            md5('10070:' || r.client_id::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE r.rank WHEN 3 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Default cross-tenant access settings too permissive: ' || r.summary_text AS summary,
            jsonb_build_object(
                'scope', 'default',
                'issues', r.issues,
                'inbound_trust', d.content -> 'inboundTrust',
                'automatic_user_consent_settings', d.content -> 'automaticUserConsentSettings',
                'b2b_direct_connect_inbound', d.content -> 'b2bDirectConnectInbound',
                'b2b_collaboration_outbound', d.content -> 'b2bCollaborationOutbound',
                'b2b_collaboration_inbound', d.content -> 'b2bCollaborationInbound'
            ) AS detail
        FROM default_row r
        JOIN dflt d ON d.client_id = r.client_id
        UNION ALL
        SELECT
            CASE WHEN r.rank >= 3 THEN 'fail' ELSE 'warn' END,
            md5('10070:' || p.client_id::text || ':' || p.partner_tenant_id::text)::uuid,
            NULL, NULL, NULL, NULL,
            CASE r.rank WHEN 4 THEN 'high' ELSE 'low' END,
            'Cross-tenant partner ' || p.label || ': ' || r.summary_text,
            jsonb_build_object(
                'scope', 'partner',
                'partner_tenant_id', p.partner_tenant_id,
                'issues', r.issues,
                'identity_synchronization', p.content -> 'identitySynchronization',
                'inbound_trust', p.content -> 'inboundTrust',
                'automatic_user_consent_settings', p.content -> 'automaticUserConsentSettings',
                'is_service_provider', p.content -> 'isServiceProvider',
                'is_in_multi_tenant_organization', p.content -> 'isInMultiTenantOrganization'
            )
        FROM partner_row r
        JOIN partner p ON p.partner_tenant_id = r.partner_tenant_id
    """,
}
