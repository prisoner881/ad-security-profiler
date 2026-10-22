-- ============================================================================
-- schema_migration_v46.sql
--
-- Entra ID coverage, waves 1 and 2 (entra_graph_collector.py 0.9.0,
-- adaudit.py 0.10.6):
--
--   * ad_intel.is_entra_kerberos_server(): identifies the Microsoft Entra
--     Kerberos server object (CN=AzureADKerberos), which AD flags as a
--     read-only DC. v_gpo_dc_application (and so v_dc_effective_gpo_setting)
--     and the DC posture plugins leave it out. Uses columns adprofiler
--     already collects (sAMAccountName, msDS-KrbTgtLink): no rescan.
--   * entra_application.required_resource_access / authentication_behaviors,
--     entra_group.visibility.
--   * New tables entra_federated_identity_credential,
--     entra_administrative_unit, entra_administrative_unit_member,
--     entra_device.
--   * Comments for the new optional sources, tenant settings and change
--     history entity types.
--
-- Everything new stays empty until entra_graph_collector 0.9.0 runs; the
-- plugins that need it show NOT ASSESSED until then.
-- ============================================================================

BEGIN;

CREATE OR REPLACE FUNCTION ad_intel.is_entra_kerberos_server(sam_account_name text, krbtgt_link text)
RETURNS boolean
LANGUAGE sql IMMUTABLE PARALLEL SAFE
AS $fn$
    -- The computer object Set-AzureADKerberosServer creates
    -- (CN=AzureADKerberos,OU=Domain Controllers): RODC-like, linked to the
    -- krbtgt-AzureAD key account ('_' in LIKE also matches the '-' spelling).
    SELECT COALESCE(lower(sam_account_name) = 'azureadkerberos$', false)
        OR COALESCE(lower(krbtgt_link) LIKE 'cn=krbtgt_azuread,%', false);
$fn$;
COMMENT ON FUNCTION ad_intel.is_entra_kerberos_server(text, text) IS
    'TRUE for the Microsoft Entra Kerberos server object (CN=AzureADKerberos in the Domain '
    'Controllers OU, sAMAccountName AzureADKerberos$, msDS-KrbTgtLink to CN=krbtgt-AzureAD). '
    'Microsoft documents it as functioning like a read-only domain controller, so AD flags it as '
    'one, but it is not a server: DC posture plugins and v_gpo_dc_application leave it out. Pass '
    'ad_computer.sam_account_name and ad_computer.krbtgt_link. (schema v46)';

CREATE OR REPLACE VIEW ad_intel.v_gpo_dc_application AS
WITH dc AS (
    SELECT c.client_id, c.object_guid AS dc_guid, lower(d.dn_current) AS dc_dn, d.object_sid AS dc_sid
    FROM ad_intel.ad_computer c
    JOIN ad_intel.directory_object d
      ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
    WHERE c.valid_to IS NULL AND c.is_domain_controller
      -- [v46] not the Microsoft Entra Kerberos server object (no host, no Group Policy)
      AND NOT ad_intel.is_entra_kerberos_server(c.sam_account_name, c.krbtgt_link)
),
som AS (
    SELECT o.client_id, o.object_guid, lower(d.dn_current) AS dn,
           COALESCE(o.block_inheritance, false) AS block_inheritance, false AS is_domain
    FROM ad_intel.ad_ou o
    JOIN ad_intel.directory_object d
      ON d.object_guid = o.object_guid AND d.client_id = o.client_id AND NOT d.is_deleted
    WHERE o.valid_to IS NULL
    UNION ALL
    SELECT m.client_id, m.object_guid, lower(d.dn_current),
           COALESCE(m.block_inheritance, false), true
    FROM ad_intel.ad_domain m
    JOIN ad_intel.directory_object d
      ON d.object_guid = m.object_guid AND d.client_id = m.client_id AND NOT d.is_deleted
    WHERE m.valid_to IS NULL
),
chain AS (
    -- Domain root and every OU above the DC. depth = number of commas in the
    -- container's DN (the domain root is the shallowest).
    SELECT dc.client_id, dc.dc_guid, dc.dc_sid, s.object_guid AS container_guid, s.is_domain,
           s.block_inheritance,
           length(s.dn) - length(replace(s.dn, ',', '')) AS depth
    FROM dc
    JOIN som s ON s.client_id = dc.client_id AND dc.dc_dn LIKE '%,' || s.dn
),
blocked AS (
    -- Block inheritance on an OU stops non-enforced links from containers above it.
    SELECT client_id, dc_guid, max(depth) AS block_depth
    FROM chain WHERE block_inheritance AND NOT is_domain
    GROUP BY client_id, dc_guid
),
links AS (
    SELECT l.client_id, l.container_guid, l.gpo_guid, l.link_enforced, l.link_enabled,
           max(l.link_order) OVER (PARTITION BY l.client_id, l.container_guid) - l.link_order + 1
               AS gpmc_link_order
    FROM ad_intel.gpo_link_edge l
    WHERE l.valid_to IS NULL
),
dc_sids AS (
    SELECT dc.client_id, dc.dc_guid, dc.dc_sid::text AS sid FROM dc WHERE dc.dc_sid IS NOT NULL
    UNION
    SELECT dc.client_id, dc.dc_guid, w.sid
    FROM dc CROSS JOIN (VALUES ('S-1-1-0'), ('S-1-5-11'), ('S-1-5-9')) AS w(sid)
    UNION
    SELECT dc.client_id, dc.dc_guid, gd.object_sid::text
    FROM dc
    JOIN ad_intel.v_effective_group_membership m
      ON m.client_id = dc.client_id AND m.member_guid = dc.dc_guid
    JOIN ad_intel.directory_object gd
      ON gd.object_guid = m.group_guid AND gd.client_id = m.client_id
    WHERE gd.object_sid IS NOT NULL
),
candidate AS (
    SELECT ch.client_id, ch.dc_guid, lk.gpo_guid, ch.container_guid, ch.is_domain, ch.depth,
           lk.link_enforced, lk.gpmc_link_order,
           (g.gpo_flags IS NULL OR (g.gpo_flags & 2) = 0) AS computer_settings_enabled,
           (
             NOT EXISTS (
               SELECT 1 FROM ad_intel.acl_edge a
               JOIN dc_sids s ON s.client_id = a.client_id AND s.dc_guid = ch.dc_guid AND s.sid = a.trustee_sid::text
               WHERE a.client_id = ch.client_id AND a.object_guid = lk.gpo_guid AND a.valid_to IS NULL
                 AND a.ace_type = 'deny' AND a.inherit_only IS NOT TRUE
                 AND (a.access_mask & 256) <> 0
                 AND (a.object_type_guid IS NULL OR a.object_type_guid = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939')
             )
             AND (
               NOT EXISTS (SELECT 1 FROM ad_intel.acl_edge a
                           WHERE a.client_id = ch.client_id AND a.object_guid = lk.gpo_guid
                             AND a.valid_to IS NULL)
               OR EXISTS (
                 SELECT 1 FROM ad_intel.acl_edge a
                 JOIN dc_sids s ON s.client_id = a.client_id AND s.dc_guid = ch.dc_guid AND s.sid = a.trustee_sid::text
                 WHERE a.client_id = ch.client_id AND a.object_guid = lk.gpo_guid AND a.valid_to IS NULL
                   AND a.ace_type = 'allow' AND a.inherit_only IS NOT TRUE
                   AND ( ((a.access_mask & 256) <> 0
                          AND (a.object_type_guid IS NULL OR a.object_type_guid = 'edacfd8f-ffb3-11d1-b41d-00a0c968f939'))
                         OR (a.access_mask & 983551) = 983551
                         OR (a.access_mask & 268435456) <> 0 )
               )
             )
           ) AS security_filter_applies
    FROM chain ch
    JOIN links lk ON lk.client_id = ch.client_id AND lk.container_guid = ch.container_guid AND lk.link_enabled
    JOIN ad_intel.ad_gpo g ON g.object_guid = lk.gpo_guid AND g.client_id = lk.client_id AND g.valid_to IS NULL
    LEFT JOIN blocked b ON b.client_id = ch.client_id AND b.dc_guid = ch.dc_guid
    WHERE lk.link_enforced OR b.block_depth IS NULL OR ch.depth >= b.block_depth
)
SELECT c.client_id, c.dc_guid, c.gpo_guid, c.container_guid, c.is_domain AS linked_at_domain,
       c.depth, c.link_enforced, c.gpmc_link_order, c.computer_settings_enabled,
       c.security_filter_applies,
       CASE WHEN c.computer_settings_enabled AND c.security_filter_applies THEN
           row_number() OVER (
               PARTITION BY c.client_id, c.dc_guid
               ORDER BY (c.computer_settings_enabled AND c.security_filter_applies) DESC,
                        c.link_enforced DESC,
                        CASE WHEN c.link_enforced THEN c.depth END ASC,
                        CASE WHEN NOT c.link_enforced THEN c.depth END DESC,
                        c.gpmc_link_order ASC)
       END AS precedence
FROM candidate c;


-- ----------------------------------------------------------------------------
-- Entra ID: entra_graph_collector.py 0.9.0
-- ----------------------------------------------------------------------------
ALTER TABLE ad_intel.entra_application
    ADD COLUMN IF NOT EXISTS required_resource_access jsonb,
    ADD COLUMN IF NOT EXISTS authentication_behaviors jsonb;
COMMENT ON COLUMN ad_intel.entra_application.required_resource_access IS
    'requiredResourceAccess: the permissions the registration requests, [{resourceAppId, '
    'resourceAccess: [{id, type}]}] (ids lower-case; type ''Scope'' = delegated, ''Role'' = '
    'application). Azure AD Graph is resourceAppId 00000002-0000-0000-c000-000000000000. NULL = '
    'collected before entra_graph_collector 0.9.0. (schema v46)';
COMMENT ON COLUMN ad_intel.entra_application.authentication_behaviors IS
    'authenticationBehaviors: {blockAzureADGraphAccess, removeUnverifiedEmailClaim, '
    'requireClientServicePrincipal, ...}; each is null until set. removeUnverifiedEmailClaim false '
    'lets the app receive an email claim from an unverified domain (nOAuth). NULL = not returned or '
    'collected before entra_graph_collector 0.9.0. (schema v46)';

ALTER TABLE ad_intel.entra_group
    ADD COLUMN IF NOT EXISTS visibility text;
COMMENT ON COLUMN ad_intel.entra_group.visibility IS
    'Graph visibility: ''Public'' (any user can join a Microsoft 365 group and read its content), '
    '''Private'', ''HiddenMembership''; NULL = not set (security groups) or collected before '
    'entra_graph_collector 0.9.0. (schema v46)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_federated_identity_credential (
    client_id         UUID NOT NULL,
    app_object_id     UUID NOT NULL,
    credential_id     UUID NOT NULL,
    app_id            UUID,
    app_display_name  TEXT,
    name              TEXT,
    issuer            TEXT,
    subject           TEXT,
    audiences         TEXT[] NOT NULL DEFAULT '{}',
    description       TEXT,
    collected_at      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, app_object_id, credential_id)
);
COMMENT ON TABLE ad_intel.entra_federated_identity_credential IS
    'Federated identity credentials of application registrations '
    '(/applications/{id}/federatedIdentityCredentials, Application.Read.All; source '
    'federated_identity_credentials). Each lets a token from issuer whose subject matches be '
    'exchanged for the application''s own token, without a secret or certificate (e.g. GitHub '
    'Actions issuer https://token.actions.githubusercontent.com, subject repo:<org>/<repo>:...). '
    'Credentials on user-assigned managed identities are Azure resources and are not read. '
    '(schema v46)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_administrative_unit (
    client_id                         UUID NOT NULL,
    unit_id                           UUID NOT NULL,
    display_name                      TEXT,
    visibility                        TEXT,
    is_member_management_restricted   BOOLEAN,
    membership_type                   TEXT,
    membership_rule                   TEXT,
    membership_rule_processing_state  TEXT,
    collected_at                      TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, unit_id)
);
COMMENT ON TABLE ad_intel.entra_administrative_unit IS
    'Administrative units (/directory/administrativeUnits, Directory.Read.All; source '
    'administrative_units). is_member_management_restricted TRUE = restricted management AU: only '
    'roles scoped to the AU can change its members, tenant-wide administrators cannot. visibility '
    '''HiddenMembership'' = only members and AU-scoped administrators see the membership. '
    'membership_type ''Dynamic'' with membership_rule, or ''Assigned''/NULL. (schema v46)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_administrative_unit_member (
    client_id     UUID NOT NULL,
    unit_id       UUID NOT NULL,
    member_id     UUID NOT NULL,
    member_type   TEXT,
    collected_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, unit_id, member_id)
);
COMMENT ON TABLE ad_intel.entra_administrative_unit_member IS
    'Direct members of each administrative unit; member_type is Graph''s @odata.type '
    '(#microsoft.graph.user, .group, .device). (schema v46)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_device (
    client_id                    UUID NOT NULL,
    entra_object_id              UUID NOT NULL,
    device_id                    TEXT,
    display_name                 TEXT,
    account_enabled              BOOLEAN,
    approximate_last_sign_in_at  TIMESTAMPTZ,
    registered_at                TIMESTAMPTZ,
    trust_type                   TEXT,
    is_managed                   BOOLEAN,
    is_compliant                 BOOLEAN,
    operating_system             TEXT,
    operating_system_version     TEXT,
    registered_owner_count       INTEGER,
    collected_at                 TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, entra_object_id)
);
COMMENT ON TABLE ad_intel.entra_device IS
    'Devices (/devices, Directory.Read.All; source devices). trust_type ''Workplace'' (registered), '
    '''AzureAd'' (Entra joined), ''ServerAd'' (hybrid joined). registered_owner_count is capped at '
    '20 by Graph ($expand); 0 = no registered owner. approximate_last_sign_in_at is updated by '
    'Entra roughly every 14 days. (schema v46)';

COMMENT ON TABLE ad_intel.entra_custom_role_assignment IS
    'Assignments of CUSTOM role definitions (is_built_in = false), which /directoryRoles does not '
    'list: assignment_type ''active'' (roleManagement/directory/roleAssignments) or ''eligible'' '
    '(roleEligibilityScheduleInstances, P2). Since schema v46 (entra_graph_collector 0.9.0) also '
    'the ACTIVE assignments of the built-in Application Administrator and Cloud Application '
    'Administrator roles that are scoped to one application or service principal '
    '(directory_scope_id ''/<object id>'', role_definition_id = the role template id); their '
    'tenant-wide assignments are in entra_directory_role_member. (schema v42, v46)';

-- Comments that list sources, settings and entity types: the v46 additions
-- are appended once (the DO blocks are safe to run again).
DO $do$
DECLARE
    additions CONSTANT text[][] := ARRAY[
        ['ad_intel.entra_collection_status',
         ' Since schema v46 (entra_graph_collector 0.9.0) also: ca_policies_beta, '
         'app_management_policy, federated_token_validation_policy, federated_identity_credentials, '
         'administrative_units, devices. (schema v46)'],
        ['ad_intel.entra_tenant_setting',
         ' Since schema v46: ''ca_policies_beta'' (beta identity/conditionalAccess/policies, a JSON '
         'array in the ca_policies element shape; beta adds sessionControls.continuousAccessEvaluation '
         '{mode}, sessionControls.secureSignInSession {isEnabled} (token protection), '
         'conditions.agentIdRiskLevels and agent identity targets in conditions.clientApplications); '
         '''app_management_policy'' (policies/defaultAppManagementPolicy: isEnabled, '
         'applicationRestrictions and servicePrincipalRestrictions {passwordCredentials[], '
         'keyCredentials[]} each {restrictionType, state, maxLifetime, restrictForAppsCreatedAfterDateTime}); '
         '''federated_token_validation_policy'' (beta policies/federatedTokenValidationPolicy: '
         'validatingDomains {@odata.type, rootDomains, domainNames}); auth_methods_policy is read from '
         'beta when available (content.graph_version ''beta'' or ''v1.0''), which adds '
         'reportSuspiciousActivitySettings, Authenticator isSoftwareOathEnabled and '
         'featureSettings.companionAppAllowedState, and X509Certificate authenticationModeConfiguration '
         'and certificateUserBindings[].trustAffinityLevel. (schema v46)'],
        ['ad_intel.entra_change_history',
         ' Since schema v46: ''federated_identity_credential'' / <application object id>:<credential '
         'id> / {app_object_id, app_id, app_display_name, name, issuer, subject, audiences}; '
         '''pim_policy'' / role template id / {role_template_id, role_display_name, rules (the stored '
         'entra_role_management_policy rules, ordered by rule id)}. (schema v46)']
    ];
    i int;
    current_comment text;
BEGIN
    FOR i IN 1 .. array_length(additions, 1) LOOP
        current_comment := obj_description(additions[i][1]::regclass, 'pg_class');
        IF current_comment IS NULL OR position('(schema v46)' IN current_comment) = 0 THEN
            EXECUTE format('COMMENT ON TABLE %s IS %L', additions[i][1],
                           COALESCE(current_comment, '') || additions[i][2]);
        END IF;
    END LOOP;
END
$do$;

COMMENT ON COLUMN ad_intel.entra_security_posture.authorization_policy IS
    'Graph /policies/authorizationPolicy: {allowInvitesFrom, guestUserRoleId, '
    'allowedToSignUpEmailBasedSubscriptions, allowEmailVerifiedUsersToJoinOrganization, '
    'blockMsolPowerShell, allowedToUseSSPR, allowUserConsentForRiskyApps, '
    'defaultUserRolePermissions: {allowedToCreateApps, allowedToCreateSecurityGroups, '
    'allowedToCreateTenants, allowedToReadOtherUsers, permissionGrantPoliciesAssigned[], '
    'allowedToReadBitlockerKeysForOwnedDevice}}. allowedToUseSSPR and allowUserConsentForRiskyApps '
    'are absent when collected before entra_graph_collector 0.9.0. NULL = not read (see '
    'authorization_policy_status). (schema v38, v46)';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (46, 'Entra Kerberos server identification; Entra application, group, federated identity '
            'credential, administrative unit and device data (entra_graph_collector 0.9.0)')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;
