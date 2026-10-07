"""
Plugin 10092: Synced User Enabled in Entra but Disabled or Gone in AD

Joins Entra users to their on-premises AD account (entra_user.
on_prem_object_guid, resolved by SID; Tier A data) and reports cloud
accounts that outlive their on-premises account:

- (a) entra_user.on_premises_sync_enabled true and account_enabled true,
  while the current ad_user row of the linked AD account is disabled
  (ad_user.is_enabled false, or userAccountControl ACCOUNTDISABLE 0x2 when
  is_enabled is NULL) -> high. A disable made on-premises has not reached
  the cloud: sync is broken, the account was moved out of sync scope, or
  someone re-enabled it in the cloud.
- (b) an enabled Entra user still marked synced, or converted to
  cloud-managed (on_premises_sync_enabled not true but
  onPremisesSecurityIdentifier still set), whose AD account no longer
  exists -> medium: the linked directory_object is_deleted, or the SID
  resolved to no AD object at all while the SID's domain part (the SID
  without its final RID) is a domain this client collects (a
  directory_object of class 'domain', or client.domain_sid). Users from
  forests or domains we do not collect are never reported, because their
  AD objects cannot be seen. A SID that matches a live, non-deleted
  directory_object (a timing gap between the AD and Entra collections)
  is not reported.

Severity is raised one level (high -> critical, medium -> high) when the
Entra user holds a highly privileged (Tier 0) Entra role, active or
PIM-eligible, directly or through a group.

Why: leavers keep cloud access (mail, Teams, every SaaS app behind SSO)
when the on-premises disable does not propagate (NIST AC-2(3); the
joiner/mover/leaver control). Disabled Entra accounts are out of scope.

One finding per Entra user (object_guid = entra_object_id). Uses current
AD rows (valid_to IS NULL), independent of the AD run id.
"""

PLUGIN = {
    "plugin_id": 10092,
    "category": "Hybrid Identity",
    "name": "Synced User Enabled in Entra but Disabled or Gone in AD",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10092",
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
        {"title": "Microsoft: Troubleshoot object synchronization with Microsoft Entra Connect Sync",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/tshoot-connect-objectsync"},
        {"title": "Microsoft: Microsoft Entra Connect Sync: Configure filtering",
         "url": "https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-sync-configure-filtering"},
        {"title": "Microsoft Graph: user resource type (onPremisesSyncEnabled)",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/user"},
    ],
    "description": (
        "An enabled Entra user is synchronized from an AD account that is "
        "disabled on-premises (high), or is still marked synced (or was "
        "converted to cloud-managed) while its AD account was deleted or "
        "no longer exists in a collected domain (medium). The on-premises "
        "disable or deletion did not reach the cloud, so a leaver keeps "
        "cloud access. One level higher when the user holds a highly "
        "privileged Entra role. Users from un-collected domains are not "
        "reported."
    ),
    "remediation": (
        "Disable the cloud account now (Update-MgUser -UserId <id> "
        "-AccountEnabled:$false) and revoke its sessions "
        "(Revoke-MgUserSignInSession). Then find out why the change did "
        "not sync: check Entra Connect / Cloud Sync health and the last "
        "sync time (plugin 10093), sync-scope filtering (OU, group or "
        "attribute filters that dropped the object), export errors, and "
        "whether the account was re-enabled in the cloud. For converted "
        "or orphaned accounts, delete them or bring them under the "
        "leaver process; clear onPremisesImmutableId only on accounts "
        "that are meant to stay cloud-only."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0_role(role_template_id) AS (
            VALUES ('62e90394-69f5-4237-9190-012177145e10'::uuid), ('e8611ab8-c189-46e8-94e1-60213ab1f814'::uuid),
                   ('7be44c8a-adaf-4e2a-84d6-ab2649e08a13'::uuid), ('194ae4cb-b126-40b2-bd5b-6091b380977d'::uuid),
                   ('8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2'::uuid), ('9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3'::uuid),
                   ('158c047a-c907-4556-b7ef-446551a6b5f7'::uuid), ('29232cdf-9323-42fd-ade2-1d097af3e4de'::uuid),
                   ('f28a1f50-f6e7-4571-818b-6a12f2af6b6c'::uuid), ('fe930be7-5e62-47db-91af-98c3a49a38b1'::uuid),
                   ('b1be1c3e-b65d-4f19-8427-f6fa0d97feb9'::uuid), ('c4e39bd9-1100-46d3-8c65-fb160da0071f'::uuid),
                   ('3a2c62db-5318-420d-8d74-23affee5d9d5'::uuid)
        ),
        priv AS (
            SELECT rm.member_id,
                   string_agg(DISTINCT rm.role_display_name, ', ' ORDER BY rm.role_display_name) AS roles
              FROM entra_directory_role_member rm
              JOIN tier0_role t ON t.role_template_id = rm.role_template_id
             WHERE rm.client_id = %(client_id)s
               AND rm.member_type = '#microsoft.graph.user'
             GROUP BY rm.member_id
        ),
        domain_sid AS (
            SELECT o.object_sid::text AS sid
              FROM directory_object o
             WHERE o.client_id = %(client_id)s AND o.object_class = 'domain'
               AND NOT o.is_deleted AND o.object_sid IS NOT NULL
            UNION
            SELECT c.domain_sid::text FROM client c
             WHERE c.client_id = %(client_id)s AND c.domain_sid IS NOT NULL
        ),
        eu AS (
            SELECT e.*
              FROM entra_user e
             WHERE e.client_id = %(client_id)s
               AND e.account_enabled IS TRUE
               AND (e.on_premises_sync_enabled IS TRUE OR e.on_premises_security_identifier IS NOT NULL)
        ),
        finding AS (
            -- (a) AD account disabled
            SELECT e.entra_object_id, 3 AS rank, 'ad_disabled' AS kind,
                   o.object_guid AS ad_guid, o.dn_current, o.sam_account_name,
                   u.is_enabled AS ad_is_enabled, u.user_account_control, NULL::timestamptz AS deleted_detected_at
              FROM eu e
              JOIN directory_object o
                ON o.client_id = e.client_id AND o.object_guid = e.on_prem_object_guid AND NOT o.is_deleted
              JOIN ad_user u
                ON u.client_id = o.client_id AND u.object_guid = o.object_guid AND u.valid_to IS NULL
             WHERE e.on_premises_sync_enabled IS TRUE
               AND COALESCE(u.is_enabled = FALSE, (u.user_account_control & 2) <> 0, FALSE)
            UNION ALL
            -- (b1) linked AD object deleted
            SELECT e.entra_object_id, 2, 'ad_deleted',
                   o.object_guid, o.dn_current, o.sam_account_name, NULL, NULL, o.deleted_detected_at
              FROM eu e
              JOIN directory_object o
                ON o.client_id = e.client_id AND o.object_guid = e.on_prem_object_guid AND o.is_deleted
            UNION ALL
            -- (b2) SID in a collected domain, but no AD object has it
            SELECT e.entra_object_id, 2, 'ad_missing',
                   NULL, NULL, NULL, NULL, NULL, NULL
              FROM eu e
             WHERE e.on_prem_object_guid IS NULL
               AND e.on_premises_security_identifier IS NOT NULL
               AND regexp_replace(e.on_premises_security_identifier, '-[0-9]+$', '') IN (SELECT sid FROM domain_sid)
               AND NOT EXISTS (SELECT 1 FROM directory_object o
                                WHERE o.client_id = e.client_id
                                  AND o.object_sid::text = e.on_premises_security_identifier)
        ),
        one AS (
            -- one row per user: the strongest finding
            SELECT DISTINCT ON (f.entra_object_id) f.*
              FROM finding f
             ORDER BY f.entra_object_id, f.rank DESC, f.kind
        )
        SELECT
            'fail' AS status,
            f.entra_object_id AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE f.rank + CASE WHEN p.member_id IS NOT NULL THEN 1 ELSE 0 END
                 WHEN 4 THEN 'critical' WHEN 3 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Entra user ' || COALESCE(e.user_principal_name, e.display_name, e.entra_object_id::text)
                || CASE WHEN e.on_premises_sync_enabled IS TRUE THEN ' (synced)'
                        WHEN e.on_premises_sync_enabled IS FALSE THEN ' (converted to cloud-managed)'
                        ELSE '' END
                || ' is enabled, but its on-premises AD account '
                || CASE f.kind
                       WHEN 'ad_disabled' THEN COALESCE(f.sam_account_name, f.ad_guid::text) || ' is disabled'
                       WHEN 'ad_deleted' THEN COALESCE(f.sam_account_name, f.ad_guid::text) || ' has been deleted'
                       ELSE 'no longer exists in a collected domain' END
                || CASE WHEN p.member_id IS NOT NULL
                        THEN '; the user holds highly privileged Entra roles (' || p.roles || ')' ELSE '' END
                AS summary,
            jsonb_build_object(
                'entra_object_id', e.entra_object_id,
                'user_principal_name', e.user_principal_name,
                'user_type', e.user_type,
                'on_premises_sync_enabled', e.on_premises_sync_enabled,
                'on_premises_security_identifier', e.on_premises_security_identifier,
                'on_premises_last_sync_at', e.on_premises_last_sync_at,
                'finding', f.kind,
                'ad_object_guid', f.ad_guid,
                'ad_distinguished_name', f.dn_current,
                'ad_sam_account_name', f.sam_account_name,
                'ad_is_enabled', f.ad_is_enabled,
                'ad_user_account_control', f.user_account_control,
                'ad_deleted_detected_at', f.deleted_detected_at,
                'privileged_entra_roles', p.roles,
                'related_plugins', jsonb_build_array(10093)
            ) AS detail
        FROM one f
        JOIN eu e ON e.entra_object_id = f.entra_object_id
        LEFT JOIN priv p ON p.member_id = f.entra_object_id
    """,
}
