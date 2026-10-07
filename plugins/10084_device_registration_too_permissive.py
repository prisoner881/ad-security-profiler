"""
Plugin 10084: Device Join and Registration Policy Too Permissive

Reads the tenant device registration policy (entra_tenant_setting
'device_registration_policy', Graph policies/deviceRegistrationPolicy, schema
v42) and reports, in one tenant-level medium finding, the settings that let
any user bring an attacker-controlled device into the tenant or that weaken
local administration of joined devices:
- every user may Microsoft Entra join devices (azureADJoin.allowedToJoin is
  an allDeviceRegistrationMembership);
- MFA is not required to register or join devices
  (multiFactorAuthConfiguration 'notRequired') AND no enabled Conditional
  Access policy covers the 'Register or join devices' user action
  (includeUserActions 'urn:user:registerdevice') with MFA / an
  authentication strength (Microsoft recommends the CA user action instead
  of this switch, so the switch alone is not reported);
- the registering user becomes local administrator of every device they
  join (azureADJoin.localAdmins.registeringUsers is an
  allDeviceRegistrationMembership);
- Microsoft Entra LAPS is disabled (localAdminPassword.isEnabled false):
  local administrator passwords are not rotated and often repeat across
  devices;
- the per-user device quota (userDeviceQuota) is above 20 (default 50).
Why: an attacker with one user's password and an unprotected join/register
flow gets a device identity that satisfies device-based Conditional Access
and obtains a Primary Refresh Token (MITRE T1098.005 Device Registration;
Storm-2372 / device-code phishing campaigns register devices for
persistence).

Separately (its own identity, low 'warn'): the tenant authorization policy
lets users read the BitLocker recovery keys of the devices they own
(defaultUserRolePermissions.allowedToReadBitlockerKeysForOwnedDevice true,
the default). A stolen user session then also yields the disk recovery key
of the user's laptop. This row reads entra_security_posture.
authorization_policy (Tier A) and is produced whatever the device
registration source status; it is absent when authorization_policy could
not be read.

Data caveats: requires_sources ['device_registration_policy'] (beta API,
Policy.Read.DeviceConfiguration): when that source is not 'ok' the device
registration row is absent and a clean result is NOT ASSESSED (even if the
BitLocker row alone would pass). Membership objects (allowedToJoin,
registeringUsers) are typed only by their '@odata.type'; when that
annotation is missing from the stored JSON, "everyone" cannot be told apart
from "nobody", and the check is skipped for that setting and listed as
undetermined in detail -- an object with users/groups lists is a selected
set and is not reported.

object_guid: md5('10084:' || client_id) for the device registration row;
md5('10084:' || client_id || ':bitlocker') for the BitLocker row.
"""

PLUGIN = {
    "plugin_id": 10084,
    "category": "Hybrid Identity",
    "name": "Device Join and Registration Policy Too Permissive",
    "version": "1.0",
    "revision_date": "2026-10-05",
    "control_id": "HYBRID-10084",
    "requires_sources": ["device_registration_policy"],
    "framework_tags": [
        "NIST-800-53-CM-7",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1098.005",
    ],
    "references": [
        {"title": "Microsoft Graph: deviceRegistrationPolicy resource type",
         "url": "https://learn.microsoft.com/en-us/graph/api/resources/deviceregistrationpolicy"},
        {"title": "Microsoft: Manage device identities (device settings)",
         "url": "https://learn.microsoft.com/en-us/entra/identity/devices/manage-device-identities"},
        {"title": "Microsoft: Windows Local Administrator Password Solution in Microsoft Entra ID",
         "url": "https://learn.microsoft.com/en-us/entra/identity/devices/howto-manage-local-admin-passwords"},
        {"title": "MITRE ATT&CK T1098.005: Device Registration",
         "url": "https://attack.mitre.org/techniques/T1098/005/"},
    ],
    "description": (
        "The device registration policy lets every user Entra-join devices, "
        "does not require MFA to register/join (with no Conditional Access "
        "'register or join devices' policy instead), makes the registering "
        "user local administrator, leaves Entra LAPS disabled or allows more "
        "than 20 devices per user -- attacker-joined devices satisfy "
        "device-based Conditional Access and obtain PRTs (medium). "
        "Separately, users can read the BitLocker keys of devices they own "
        "(low)."
    ),
    "remediation": (
        "Entra admin center -> Identity -> Devices -> Device settings: "
        "'Users may join devices to Microsoft Entra' = Selected (a device "
        "enrolment group); 'Registering user is added as local "
        "administrator' = None (manage local admins with Intune / LAPS); "
        "'Enable Microsoft Entra Local Administrator Password Solution "
        "(LAPS)' = Yes; 'Maximum number of devices per user' = 20 or fewer; "
        "and either 'Require MFA to register or join devices' = Yes or "
        "(preferred) a Conditional Access policy on the user action "
        "'Register or join devices' requiring MFA. 'Restrict users from "
        "recovering the BitLocker key(s) for their owned devices' = Yes "
        "(Update-MgPolicyAuthorizationPolicy -DefaultUserRolePermissions "
        "@{AllowedToReadBitlockerKeysForOwnedDevice=$false})."
    ),
    "base_severity": "medium",
    "query": """
        WITH drp AS (
            SELECT ts.content AS c
              FROM entra_tenant_setting ts
             WHERE ts.client_id = %(client_id)s
               AND ts.setting_name = 'device_registration_policy'
               AND jsonb_typeof(ts.content) = 'object'
               AND EXISTS (SELECT 1 FROM entra_collection_status s
                            WHERE s.client_id = %(client_id)s AND s.source = 'device_registration_policy'
                              AND s.status = 'ok')
        ),
        membership AS (
            -- 'all' | 'none' | 'selected' | 'undetermined' (no @odata.type kept) | NULL (absent)
            SELECT d.c,
                   CASE WHEN COALESCE(jsonb_typeof(m.join_m), '') <> 'object' THEN NULL
                        WHEN m.join_m->>'@odata.type' ILIKE '%%allDeviceRegistrationMembership' THEN 'all'
                        WHEN m.join_m->>'@odata.type' ILIKE '%%noDeviceRegistrationMembership' THEN 'none'
                        WHEN m.join_m->>'@odata.type' IS NOT NULL OR m.join_m ?| ARRAY['users', 'groups'] THEN 'selected'
                        ELSE 'undetermined' END AS join_scope,
                   CASE WHEN COALESCE(jsonb_typeof(m.admin_m), '') <> 'object' THEN NULL
                        WHEN m.admin_m->>'@odata.type' ILIKE '%%allDeviceRegistrationMembership' THEN 'all'
                        WHEN m.admin_m->>'@odata.type' ILIKE '%%noDeviceRegistrationMembership' THEN 'none'
                        WHEN m.admin_m->>'@odata.type' IS NOT NULL OR m.admin_m ?| ARRAY['users', 'groups'] THEN 'selected'
                        ELSE 'undetermined' END AS local_admin_scope
              FROM drp d
              CROSS JOIN LATERAL (SELECT d.c->'azureADJoin'->'allowedToJoin' AS join_m,
                                         d.c->'azureADJoin'->'localAdmins'->'registeringUsers' AS admin_m) m
        ),
        ca_register AS (
            SELECT EXISTS (
                SELECT 1
                  FROM entra_security_posture sp
                  CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(sp.ca_policies) = 'array'
                                                               THEN sp.ca_policies ELSE '[]'::jsonb END) p
                 WHERE sp.client_id = %(client_id)s
                   AND p->>'state' = 'enabled'
                   AND jsonb_typeof(p->'conditions'->'applications'->'includeUserActions') = 'array'
                   AND p->'conditions'->'applications'->'includeUserActions' ? 'urn:user:registerdevice'
                   AND (COALESCE(p->'grant_controls'->'builtInControls', '[]'::jsonb) ? 'mfa'
                        OR jsonb_typeof(p->'grant_controls'->'authenticationStrength') = 'object')
            ) AS present
        ),
        quota AS (
            SELECT CASE WHEN jsonb_typeof(m.c->'userDeviceQuota') = 'number'
                        THEN (m.c->>'userDeviceQuota')::numeric END AS q
              FROM membership m
        ),
        issues AS (
            SELECT 'all users can join devices to Microsoft Entra' AS issue, 1 AS ord
              FROM membership WHERE join_scope = 'all'
            UNION ALL
            SELECT 'MFA is not required to register or join devices (no Conditional Access register-device policy)', 2
              FROM membership m CROSS JOIN ca_register r
             WHERE lower(m.c->>'multiFactorAuthConfiguration') = 'notrequired' AND NOT r.present
            UNION ALL
            SELECT 'the registering user becomes local administrator of joined devices', 3
              FROM membership WHERE local_admin_scope = 'all'
            UNION ALL
            SELECT 'Microsoft Entra LAPS is disabled', 4
              FROM membership m WHERE m.c->'localAdminPassword'->'isEnabled' = 'false'::jsonb
            UNION ALL
            SELECT 'device quota per user is ' || q.q || ' (above 20)', 5
              FROM quota q WHERE q.q > 20
        ),
        agg AS (
            SELECT string_agg(issue, '; ' ORDER BY ord) AS issue_text,
                   jsonb_agg(issue ORDER BY ord) AS issue_list
              FROM issues
            HAVING count(*) > 0
        )
        SELECT
            'fail' AS status,
            md5('10084:' || %(client_id)s::text)::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Device join / registration policy too permissive: ' || a.issue_text AS summary,
            jsonb_build_object(
                'issues', a.issue_list,
                'allowed_to_join', m.join_scope,
                'registering_user_local_admin', m.local_admin_scope,
                'multi_factor_auth_configuration', m.c->'multiFactorAuthConfiguration',
                'ca_register_device_policy_with_mfa', r.present,
                'local_admin_password_enabled', m.c->'localAdminPassword'->'isEnabled',
                'user_device_quota', m.c->'userDeviceQuota',
                'undetermined', NULLIF(concat_ws(', ',
                    CASE WHEN m.join_scope = 'undetermined' THEN 'allowedToJoin (membership type not stored)' END,
                    CASE WHEN m.local_admin_scope = 'undetermined' THEN 'localAdmins.registeringUsers (membership type not stored)' END), '')
            ) AS detail
        FROM agg a
        CROSS JOIN membership m
        CROSS JOIN ca_register r
        UNION ALL
        SELECT
            'warn',
            md5('10084:' || sp.client_id::text || ':bitlocker')::uuid,
            NULL, NULL, NULL, NULL,
            'low',
            'Users can read the BitLocker recovery keys of devices they own (allowedToReadBitlockerKeysForOwnedDevice is true)',
            jsonb_build_object(
                'allowed_to_read_bitlocker_keys_for_owned_device',
                    sp.authorization_policy->'defaultUserRolePermissions'->'allowedToReadBitlockerKeysForOwnedDevice'
            )
        FROM entra_security_posture sp
        WHERE sp.client_id = %(client_id)s
          AND jsonb_typeof(sp.authorization_policy) = 'object'
          AND sp.authorization_policy->'defaultUserRolePermissions'->'allowedToReadBitlockerKeysForOwnedDevice' = 'true'::jsonb
    """,
}
