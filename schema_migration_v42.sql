-- ============================================================================
-- schema_migration_v42.sql
--
-- Entra ID coverage round (entra_graph_collector.py 0.8.0, plugins
-- 10020-10121 and 11022-11029).
--
--   * entra_collection_status: one row per (client, data source) saying
--     whether the latest Entra run could read it ('ok') or why not (missing
--     permission, missing licence, beta endpoint unavailable). adaudit.py
--     shows a plugin as NOT ASSESSED when a source it reads is not 'ok'.
--   * More user, application and service-principal fields; groups, owners,
--     role definitions, custom-role assignments, PIM role settings,
--     application and delegated permission grants, named locations,
--     domains and federation, licences, cross-tenant partners, partner
--     contracts, MFA registration details, Identity Protection risk.
--   * entra_tenant_setting: single-object tenant policies stored as JSON.
--   * entra_change_history: SCD2 versions of the Entra objects that change
--     detection reports on (the snapshot tables above are still replaced
--     wholesale each run, so existing plugins are unaffected).
--
-- Every table here is a current snapshot replaced per client on each Entra
-- run, except entra_change_history (versioned) and entra_collection_status
-- (upserted per source). A source whose read failed keeps no rows (its
-- table is emptied for the client) and has a non-'ok' status, so plugins
-- see "no data", and adaudit reports NOT ASSESSED rather than pass.
-- ============================================================================

BEGIN;

-- ----------------------------------------------------------------------------
-- Collection status per data source
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_collection_status (
    client_id     UUID NOT NULL,
    source        TEXT NOT NULL,
    status        TEXT NOT NULL,
    collected_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, source)
);
COMMENT ON TABLE ad_intel.entra_collection_status IS
    'Whether the latest entra_graph_collector.py run could read each optional data source. '
    'status is ''ok'' or the reason it could not (e.g. ''HTTP 403 Authorization_RequestDenied: ...'', '
    '''not licensed'', ''skipped: ...''). Sources: subscribed_skus, organization, domains, '
    'federation, groups, role_definitions, custom_role_assignments, pim_policies, '
    'service_principals, app_owners, app_role_grants, delegated_grants, named_locations, '
    'auth_methods_policy, cross_tenant_policy, admin_consent_request_policy, directory_settings, '
    'device_registration_policy, onprem_sync, pta_agents, partner_contracts, '
    'registration_details, sign_in_activity, sp_sign_in_activity, risky_users, risk_detections. '
    'adaudit.py OPTIONAL_DATA_SOURCES probes it. (schema v42)';

-- ----------------------------------------------------------------------------
-- Users: more fields
-- ----------------------------------------------------------------------------
ALTER TABLE ad_intel.entra_user
    ADD COLUMN IF NOT EXISTS display_name text,
    ADD COLUMN IF NOT EXISTS created_at timestamptz,
    ADD COLUMN IF NOT EXISTS password_policies text,
    ADD COLUMN IF NOT EXISTS last_password_change_at timestamptz,
    ADD COLUMN IF NOT EXISTS external_user_state text,
    ADD COLUMN IF NOT EXISTS external_user_state_changed_at timestamptz,
    ADD COLUMN IF NOT EXISTS on_premises_last_sync_at timestamptz,
    ADD COLUMN IF NOT EXISTS assigned_services text[],
    ADD COLUMN IF NOT EXISTS last_sign_in_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_non_interactive_sign_in_at timestamptz,
    ADD COLUMN IF NOT EXISTS last_successful_sign_in_at timestamptz;
COMMENT ON COLUMN ad_intel.entra_user.password_policies IS
    'Graph passwordPolicies, e.g. ''DisablePasswordExpiration'', ''DisableStrongPassword'' or both '
    'comma-separated; NULL = none set. (schema v42)';
COMMENT ON COLUMN ad_intel.entra_user.external_user_state IS
    'Graph externalUserState for B2B guests: ''PendingAcceptance'' or ''Accepted''; NULL for members. (schema v42)';
COMMENT ON COLUMN ad_intel.entra_user.assigned_services IS
    'Distinct assignedPlans[].service values whose capabilityStatus is ''Enabled'' (e.g. '
    '''exchange'', ''SharePoint'', ''MicrosoftCommunicationsOnline'', ''AADPremiumService''). '
    'Empty array = unlicensed. (schema v42)';
COMMENT ON COLUMN ad_intel.entra_user.last_successful_sign_in_at IS
    'signInActivity (needs AuditLog.Read.All and Entra ID P1): lastSignInDateTime -> last_sign_in_at, '
    'lastNonInteractiveSignInDateTime -> last_non_interactive_sign_in_at, '
    'lastSuccessfulSignInDateTime -> last_successful_sign_in_at. All three NULL when the source '
    'sign_in_activity is not ''ok'' (entra_collection_status) -- and also NULL for a user who has '
    'never signed in (or not since Microsoft began recording, April 2020), so only read them when '
    'that source is ''ok''. (schema v42)';

-- ----------------------------------------------------------------------------
-- Applications: more fields
-- ----------------------------------------------------------------------------
ALTER TABLE ad_intel.entra_application
    ADD COLUMN IF NOT EXISTS key_credentials jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS sign_in_audience text,
    ADD COLUMN IF NOT EXISTS publisher_domain text,
    ADD COLUMN IF NOT EXISTS verified_publisher_name text,
    ADD COLUMN IF NOT EXISTS web_redirect_uris text[],
    ADD COLUMN IF NOT EXISTS spa_redirect_uris text[],
    ADD COLUMN IF NOT EXISTS public_client_redirect_uris text[],
    ADD COLUMN IF NOT EXISTS implicit_access_token_issuance boolean,
    ADD COLUMN IF NOT EXISTS implicit_id_token_issuance boolean,
    ADD COLUMN IF NOT EXISTS is_fallback_public_client boolean,
    ADD COLUMN IF NOT EXISTS service_principal_lock_enabled boolean,
    ADD COLUMN IF NOT EXISTS created_at timestamptz;
COMMENT ON COLUMN ad_intel.entra_application.key_credentials IS
    'JSONB array, one per certificate: [{key_id, display_name, type, usage, start_date_time, '
    'end_date_time}]. (schema v42; key_credential_count kept for plugin 10005)';
COMMENT ON COLUMN ad_intel.entra_application.sign_in_audience IS
    'AzureADMyOrg (single tenant), AzureADMultipleOrgs, AzureADandPersonalMicrosoftAccount, '
    'PersonalMicrosoftAccount. (schema v42)';
COMMENT ON COLUMN ad_intel.entra_application.service_principal_lock_enabled IS
    'servicePrincipalLockConfiguration.isEnabled (app instance property lock). NULL = not returned. (schema v42)';

-- ----------------------------------------------------------------------------
-- Service principals
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_service_principal (
    client_id                      UUID NOT NULL,
    entra_object_id                UUID NOT NULL,
    app_id                         UUID,
    display_name                   TEXT,
    service_principal_type         TEXT,
    app_owner_organization_id      UUID,
    publisher_name                 TEXT,
    verified_publisher_name        TEXT,
    sign_in_audience               TEXT,
    account_enabled                BOOLEAN,
    app_role_assignment_required   BOOLEAN,
    preferred_single_sign_on_mode  TEXT,
    password_credentials           JSONB NOT NULL DEFAULT '[]'::jsonb,
    key_credentials                JSONB NOT NULL DEFAULT '[]'::jsonb,
    tags                           TEXT[],
    last_sign_in_activity_at       TIMESTAMPTZ,
    collected_at                   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, entra_object_id)
);
COMMENT ON TABLE ad_intel.entra_service_principal IS
    'Every service principal (enterprise application) in the tenant (Application.Read.All). '
    'app_owner_organization_id: the tenant that owns the application -- this tenant for its own apps, '
    'f8cdef31-a31e-4b4a-93e4-5f571e91255a (or 72f988bf-86f1-41af-91ab-2d7cd011db47) for Microsoft '
    'first-party apps, anything else = a third-party multi-tenant app. password_credentials / '
    'key_credentials: credentials set on the SERVICE PRINCIPAL object itself (not the app '
    'registration), same element shape as entra_application.key_credentials plus hint for secrets. '
    'SAML SSO apps (preferred_single_sign_on_mode = ''saml'') legitimately carry their token-signing '
    'certificate here (key usage Sign/Verify, plus a password credential with the same '
    'customKeyIdentifier). last_sign_in_activity_at: servicePrincipalSignInActivities lastSignInActivity '
    '(beta, AuditLog.Read.All + P1); NULL unless source sp_sign_in_activity is ''ok''. (schema v42)';

-- ----------------------------------------------------------------------------
-- Owners of applications and service principals
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_app_owner (
    client_id                      UUID NOT NULL,
    owned_object_id                UUID NOT NULL,
    owned_object_type              TEXT NOT NULL,
    owned_app_id                   UUID,
    owned_display_name             TEXT,
    owner_id                       UUID NOT NULL,
    owner_type                     TEXT,
    owner_display_name             TEXT,
    owner_upn                      TEXT,
    owner_user_type                TEXT,
    owner_on_premises_sync_enabled BOOLEAN,
    owner_account_enabled          BOOLEAN,
    collected_at                   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, owned_object_id, owner_id)
);
COMMENT ON TABLE ad_intel.entra_app_owner IS
    'Owners of every application registration and of every service principal not owned by Microsoft '
    '(owned_object_type ''application'' or ''servicePrincipal''; owner_type is the Graph @odata.type, '
    'e.g. ''#microsoft.graph.user'', ''#microsoft.graph.servicePrincipal''). An owner can add '
    'credentials to what it owns and so act as that application. (schema v42)';

-- ----------------------------------------------------------------------------
-- Application permission (app role) grants, all resources of interest
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_app_role_grant (
    client_id               UUID NOT NULL,
    assignment_id           TEXT NOT NULL,
    principal_id            UUID NOT NULL,
    principal_display_name  TEXT,
    principal_type          TEXT,
    resource_id             UUID NOT NULL,
    resource_app_id         UUID,
    resource_display_name   TEXT,
    permission_id           UUID,
    permission_name         TEXT,
    collected_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, assignment_id)
);
COMMENT ON TABLE ad_intel.entra_app_role_grant IS
    'Every application permission (appRoleAssignedTo) granted on these resource APIs: Microsoft Graph '
    '(00000003-0000-0000-c000-000000000000), Office 365 Exchange Online '
    '(00000002-0000-0ff1-ce00-000000000000), Office 365 SharePoint Online '
    '(00000003-0000-0ff1-ce00-000000000000), Azure Key Vault (cfa8b339-82a2-471a-a3c9-0fc0be7a4093), '
    'Windows Azure Active Directory / AAD Graph (00000002-0000-0000-c000-000000000000), Microsoft '
    'Teams Services / Skype for Business Online (00000004-0000-0ff1-ce00-000000000000), Office 365 '
    'Management APIs (c5393580-f805-4401-95e8-94b7a6ef2fc2), Dynamics CRM '
    '(00000007-0000-0000-c000-000000000000) and Microsoft Intune API '
    '(c161e42e-d4df-4a3d-9b42-e7a3c31f59d4). resource_app_id is the resource''s appId (fixed across '
    'tenants); permission_name is the app role''s value (e.g. ''full_access_as_app'', '
    '''Mail.ReadWrite''), NULL when the role id is unknown to the resource. principal_type is Graph''s '
    'principalType (''ServicePrincipal'', ''User'', ''Group''). Unfiltered -- plugins classify. '
    'entra_dangerous_permission_grant (the 11-permission Graph subset used by plugin 10007) is kept. '
    '(schema v42)';

-- ----------------------------------------------------------------------------
-- Delegated permission grants (oauth2PermissionGrants)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_delegated_grant (
    client_id              UUID NOT NULL,
    grant_id               TEXT NOT NULL,
    client_sp_id           UUID NOT NULL,
    client_display_name    TEXT,
    consent_type           TEXT,
    principal_id           UUID,
    principal_upn          TEXT,
    resource_sp_id         UUID NOT NULL,
    resource_app_id        UUID,
    resource_display_name  TEXT,
    scopes                 TEXT[] NOT NULL DEFAULT '{}',
    collected_at           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, grant_id)
);
COMMENT ON TABLE ad_intel.entra_delegated_grant IS
    'Every oauth2PermissionGrant (Directory.Read.All). consent_type ''AllPrincipals'' = admin consent '
    'for every user in the tenant; ''Principal'' = one user''s consent (principal_id, principal_upn '
    'resolved from entra_user when possible). scopes = the space-separated scope string split. '
    'client_sp_id joins entra_service_principal.entra_object_id. (schema v42)';

-- ----------------------------------------------------------------------------
-- Groups, owners and members (for the groups that matter)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_group (
    client_id                        UUID NOT NULL,
    entra_object_id                  UUID NOT NULL,
    display_name                     TEXT,
    is_assignable_to_role            BOOLEAN,
    security_enabled                 BOOLEAN,
    mail_enabled                     BOOLEAN,
    group_types                      TEXT[],
    membership_rule                  TEXT,
    membership_rule_processing_state TEXT,
    on_premises_sync_enabled         BOOLEAN,
    on_premises_security_identifier  TEXT,
    on_prem_object_guid              UUID,
    is_sensitive                     BOOLEAN NOT NULL DEFAULT FALSE,
    sensitive_reasons                TEXT[] NOT NULL DEFAULT '{}',
    collected_at                     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, entra_object_id)
);
COMMENT ON TABLE ad_intel.entra_group IS
    'Every group in the tenant (Directory.Read.All). on_prem_object_guid resolved like '
    'entra_user.on_prem_object_guid (SID match to directory_object). is_sensitive marks the groups '
    'whose owners and transitive members are also collected (entra_group_owner / entra_group_member); '
    'sensitive_reasons lists why: ''role_assignable'' (isAssignableToRole), ''holds_role'' (member of '
    'a directory role, active or eligible), ''ca_include'' / ''ca_exclude'' (named in an include or '
    'exclude list of a Conditional Access policy that is not disabled), ''app_role'' (assigned an app '
    'role on a service principal that holds a privileged permission or directory role). (schema v42)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_group_owner (
    client_id                      UUID NOT NULL,
    group_id                       UUID NOT NULL,
    owner_id                       UUID NOT NULL,
    owner_type                     TEXT,
    owner_display_name             TEXT,
    owner_upn                      TEXT,
    owner_user_type                TEXT,
    owner_on_premises_sync_enabled BOOLEAN,
    owner_account_enabled          BOOLEAN,
    collected_at                   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, group_id, owner_id)
);
COMMENT ON TABLE ad_intel.entra_group_owner IS
    'Owners of the sensitive groups (entra_group.is_sensitive). An owner can change membership. (schema v42)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_group_member (
    client_id                UUID NOT NULL,
    group_id                 UUID NOT NULL,
    member_id                UUID NOT NULL,
    member_type              TEXT,
    member_display_name      TEXT,
    member_upn               TEXT,
    member_user_type         TEXT,
    on_premises_sync_enabled BOOLEAN,
    account_enabled          BOOLEAN,
    collected_at             TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, group_id, member_id)
);
COMMENT ON TABLE ad_intel.entra_group_member IS
    'Transitive members (transitiveMembers) of the sensitive groups (entra_group.is_sensitive), '
    'including nested groups themselves. (schema v42)';

-- ----------------------------------------------------------------------------
-- Role definitions, custom-role assignments, PIM role settings
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_role_definition (
    client_id           UUID NOT NULL,
    role_definition_id  UUID NOT NULL,
    template_id         UUID,
    display_name        TEXT,
    is_built_in         BOOLEAN,
    is_enabled          BOOLEAN,
    allowed_actions     TEXT[] NOT NULL DEFAULT '{}',
    collected_at        TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, role_definition_id)
);
COMMENT ON TABLE ad_intel.entra_role_definition IS
    'Every directory role definition, built-in and custom (RoleManagement.Read.Directory). '
    'allowed_actions = union of rolePermissions[].allowedResourceActions, e.g. '
    '''microsoft.directory/applications/credentials/update''. (schema v42)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_custom_role_assignment (
    client_id               UUID NOT NULL,
    role_definition_id      UUID NOT NULL,
    principal_id            UUID NOT NULL,
    principal_type          TEXT,
    principal_display_name  TEXT,
    principal_upn           TEXT,
    directory_scope_id      TEXT NOT NULL DEFAULT '/',
    assignment_type         TEXT NOT NULL,
    collected_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, role_definition_id, principal_id, directory_scope_id, assignment_type)
);
COMMENT ON TABLE ad_intel.entra_custom_role_assignment IS
    'Assignments of CUSTOM role definitions (is_built_in = false), which /directoryRoles does not '
    'list: assignment_type ''active'' (roleManagement/directory/roleAssignments) or ''eligible'' '
    '(roleEligibilityScheduleInstances, P2). (schema v42)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_role_management_policy (
    client_id          UUID NOT NULL,
    role_template_id   UUID NOT NULL,
    role_display_name  TEXT,
    policy_id          TEXT,
    rules              JSONB NOT NULL DEFAULT '[]'::jsonb,
    collected_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, role_template_id)
);
COMMENT ON TABLE ad_intel.entra_role_management_policy IS
    'PIM role settings per directory role (policies/roleManagementPolicyAssignments with '
    'scopeId ''/'' scopeType ''DirectoryRole'', expanded policy rules; Entra ID P2). rules = the '
    'policy''s rules array as Graph returns it (each element has id and @odata.type kept as '
    '"rule_type", e.g. id ''Enablement_EndUser_Assignment'' with enabledRules [''MultiFactorAuthentication'', '
    '''Justification'', ''Ticketing''], ''Approval_EndUser_Assignment'' with setting.isApprovalRequired, '
    '''Expiration_EndUser_Assignment'' with maximumDuration (ISO 8601, e.g. ''PT8H''), '
    '''Expiration_Admin_Eligibility'' / ''Expiration_Admin_Assignment'' with isExpirationRequired and '
    'maximumDuration, ''AuthenticationContext_EndUser_Assignment'' with isEnabled/claimValue, '
    '''Notification_Admin_Admin_Assignment'' / ''Notification_Admin_Admin_Eligibility'' / '
    '''Notification_Admin_EndUser_Assignment'' with notificationRecipients[], isDefaultRecipientsEnabled, '
    'notificationLevel). (schema v42)';

-- ----------------------------------------------------------------------------
-- Named locations
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_named_location (
    client_id        UUID NOT NULL,
    location_id      UUID NOT NULL,
    display_name     TEXT,
    location_type    TEXT NOT NULL,
    is_trusted       BOOLEAN,
    ip_ranges        TEXT[] NOT NULL DEFAULT '{}',
    countries        TEXT[] NOT NULL DEFAULT '{}',
    include_unknown_countries BOOLEAN,
    collected_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, location_id)
);
COMMENT ON TABLE ad_intel.entra_named_location IS
    'Conditional Access named locations (Policy.Read.All). location_type ''ip'' (ip_ranges as CIDR '
    'strings, IPv4 and IPv6; is_trusted = isTrusted) or ''country'' (countries = ISO codes; '
    'is_trusted NULL). (schema v42)';

-- ----------------------------------------------------------------------------
-- Single-object tenant settings
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_tenant_setting (
    client_id     UUID NOT NULL,
    setting_name  TEXT NOT NULL,
    content       JSONB NOT NULL,
    collected_at  TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, setting_name)
);
COMMENT ON TABLE ad_intel.entra_tenant_setting IS
    'Single-object tenant policies, JSON as Graph returns them minus @odata annotations other than '
    '"@odata.type" (kept at every level: polymorphic values such as deviceRegistrationPolicy '
    'azureADJoin.allowedToJoin are only distinguishable by it). A row exists '
    'only when the read succeeded (entra_collection_status source of the same name is ''ok''). '
    'setting_name / source / content: '
    '''auth_methods_policy'' (policies/authenticationMethodsPolicy: policyMigrationState, '
    'registrationEnforcement, systemCredentialPreferences, authenticationMethodConfigurations[] each '
    'with id (''Sms'', ''Voice'', ''Email'', ''Fido2'', ''MicrosoftAuthenticator'', ''TemporaryAccessPass'', '
    '''SoftwareOath'', ''X509Certificate'', ...), state, includeTargets[], excludeTargets[] and the '
    'method''s own settings, e.g. featureSettings for Authenticator, isAttestationEnforced and '
    'keyRestrictions for Fido2, isUsableOnce/maximumLifetimeInMinutes/defaultLifetimeInMinutes for '
    'TemporaryAccessPass, isUsableForSignIn in Sms includeTargets); '
    '''cross_tenant_default'' (policies/crossTenantAccessPolicy/default); '
    '''admin_consent_request_policy'' (policies/adminConsentRequestPolicy); '
    '''password_rule_settings'' and ''group_unified_settings'' (/groupSettings objects with '
    'displayName ''Password Rule Settings'' / ''Group.Unified'', stored as {name: value} from values[]: '
    'e.g. BannedPasswordCheckOnPremisesMode, EnableBannedPasswordCheckOnPremises, '
    'EnableBannedPasswordCheck, LockoutDurationInSeconds, LockoutThreshold, BannedPasswordList / '
    'EnableGroupCreation, GroupCreationAllowedGroupId, AllowGuestsToBeGroupOwner). source '
    'directory_settings is ''ok'' when /groupSettings was read; a setting object that does not exist '
    '(defaults in force) gives no row even then; '
    '''device_registration_policy'' (policies/deviceRegistrationPolicy, beta); '
    '''onprem_sync'' (directory/onPremisesSynchronization, beta: the first element, {features: '
    '{blockCloudObjectTakeoverThroughHardMatchEnabled, blockSoftMatchEnabled, passwordSyncEnabled, '
    '...}, configuration: {...}}); '
    '''organization'' (/organization: {id, displayName, onPremisesSyncEnabled, '
    'onPremisesLastSyncDateTime, verifiedDomains, createdDateTime}). (schema v42)';

-- ----------------------------------------------------------------------------
-- Licences
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_tenant_license (
    client_id          UUID NOT NULL,
    sku_id             UUID NOT NULL,
    sku_part_number    TEXT,
    capability_status  TEXT,
    enabled_units      INTEGER,
    consumed_units     INTEGER,
    service_plans      TEXT[] NOT NULL DEFAULT '{}',
    collected_at       TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, sku_id)
);
COMMENT ON TABLE ad_intel.entra_tenant_license IS
    'Tenant subscriptions (/subscribedSkus, Directory.Read.All). service_plans = servicePlanName of '
    'each servicePlans[] element whose provisioningStatus is ''Success''. Entra ID P1 = plan '
    '''AAD_PREMIUM'', P2 = ''AAD_PREMIUM_P2'', Workload ID = ''AAD_WRKLDID_P1'' / ''AAD_WRKLDID_P2''. '
    'See v_entra_tenant_capability. (schema v42)';

CREATE OR REPLACE VIEW ad_intel.v_entra_tenant_capability AS
SELECT s.client_id,
       s.status AS license_status,
       COALESCE(bool_or(l.capability_status = 'Enabled'
                        AND l.service_plans && ARRAY['AAD_PREMIUM', 'AAD_PREMIUM_P2']), FALSE) AS has_p1,
       COALESCE(bool_or(l.capability_status = 'Enabled'
                        AND l.service_plans && ARRAY['AAD_PREMIUM_P2']), FALSE) AS has_p2,
       COALESCE(bool_or(l.capability_status = 'Enabled'
                        AND l.service_plans && ARRAY['AAD_WRKLDID_P1', 'AAD_WRKLDID_P2']), FALSE)
           AS has_workload_id
FROM ad_intel.entra_collection_status s
LEFT JOIN ad_intel.entra_tenant_license l ON l.client_id = s.client_id
WHERE s.source = 'subscribed_skus'
GROUP BY s.client_id, s.status;
COMMENT ON VIEW ad_intel.v_entra_tenant_capability IS
    'One row per client whose Entra collection tried /subscribedSkus. has_p1 / has_p2 / '
    'has_workload_id are only meaningful when license_status = ''ok''. (schema v42)';

-- ----------------------------------------------------------------------------
-- Domains and federation
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_domain (
    client_id                      UUID NOT NULL,
    domain_name                    TEXT NOT NULL,
    authentication_type            TEXT,
    is_verified                    BOOLEAN,
    is_default                     BOOLEAN,
    is_initial                     BOOLEAN,
    is_root                        BOOLEAN,
    password_validity_period_days  INTEGER,
    supported_services             TEXT[] NOT NULL DEFAULT '{}',
    collected_at                   TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, domain_name)
);
COMMENT ON TABLE ad_intel.entra_domain IS
    'Tenant domains (/domains, Directory.Read.All). authentication_type ''Managed'' or ''Federated''. '
    'password_validity_period_days: Graph passwordValidityPeriodInDays (2147483647 = never expires). '
    '(schema v42)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_domain_federation (
    client_id                              UUID NOT NULL,
    domain_name                            TEXT NOT NULL,
    federation_id                          TEXT NOT NULL,
    display_name                           TEXT,
    issuer_uri                             TEXT,
    passive_sign_in_uri                    TEXT,
    active_sign_in_uri                     TEXT,
    sign_out_uri                           TEXT,
    metadata_exchange_uri                  TEXT,
    preferred_authentication_protocol      TEXT,
    federated_idp_mfa_behavior             TEXT,
    prompt_login_behavior                  TEXT,
    is_signed_authentication_request_required BOOLEAN,
    signing_certificate_thumbprint         TEXT,
    signing_certificate_subject            TEXT,
    signing_certificate_not_before         TIMESTAMPTZ,
    signing_certificate_not_after          TIMESTAMPTZ,
    next_signing_certificate_thumbprint    TEXT,
    next_signing_certificate_not_after     TIMESTAMPTZ,
    collected_at                           TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, domain_name, federation_id)
);
COMMENT ON TABLE ad_intel.entra_domain_federation IS
    'internalDomainFederation for each Federated domain (/domains/{id}/federationConfiguration, '
    'Domain.Read.All). federated_idp_mfa_behavior: ''acceptIfMfaDoneByFederatedIdp'', '
    '''enforceMfaByFederatedIdp'', ''rejectMfaByFederatedIdp'' (NULL = not set: the legacy '
    'SupportsMfa behaviour). Certificates are parsed from the base64 signingCertificate / '
    'nextSigningCertificate: thumbprint = upper-case hex SHA-1 of the DER; validity dates NULL when '
    'the collector could not parse the certificate. (schema v42)';

-- ----------------------------------------------------------------------------
-- Cross-tenant partners and partner contracts
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_cross_tenant_partner (
    client_id        UUID NOT NULL,
    partner_tenant_id UUID NOT NULL,
    content          JSONB NOT NULL,
    collected_at     TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, partner_tenant_id)
);
COMMENT ON TABLE ad_intel.entra_cross_tenant_partner IS
    'policies/crossTenantAccessPolicy/partners (Policy.Read.All), one row per configured partner '
    'tenant; content = the partner configuration minus @odata annotations other than "@odata.type", plus key '
    '"identitySynchronization" = /partners/{id}/identitySynchronization (its userSyncInbound.isSyncAllowed '
    'says whether that tenant may sync users into this one; null when none is configured). '
    'Read under source cross_tenant_policy together with entra_tenant_setting ''cross_tenant_default''. '
    '(schema v42)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_partner_contract (
    client_id            UUID NOT NULL,
    contract_object_id   UUID NOT NULL,
    contract_type        TEXT,
    customer_id          UUID,
    default_domain_name  TEXT,
    display_name         TEXT,
    collected_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, contract_object_id)
);
COMMENT ON TABLE ad_intel.entra_partner_contract IS
    '/contracts (Directory.Read.All): partner (CSP / reseller) relationships recorded in the '
    'directory. (schema v42)';

-- ----------------------------------------------------------------------------
-- Pass-through authentication agents
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_pta_agent (
    client_id            UUID NOT NULL,
    agent_id             TEXT NOT NULL,
    machine_name         TEXT,
    external_ip          TEXT,
    status               TEXT,
    collected_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, agent_id)
);
COMMENT ON TABLE ad_intel.entra_pta_agent IS
    'Pass-through authentication agents (beta onPremisesPublishingProfiles/authentication/agents). '
    'Microsoft only offers OnPremisesPublishingProfiles.ReadWrite.All for this read, so it is opt-in '
    '(source pta_agents ''skipped: ...'' unless enabled). machine_name is the agent host FQDN. '
    '(schema v42)';

-- ----------------------------------------------------------------------------
-- MFA registration details
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_user_registration (
    client_id                 UUID NOT NULL,
    entra_object_id           UUID NOT NULL,
    user_principal_name       TEXT,
    user_type                 TEXT,
    is_admin                  BOOLEAN,
    is_mfa_registered         BOOLEAN,
    is_mfa_capable            BOOLEAN,
    is_passwordless_capable   BOOLEAN,
    is_sspr_registered        BOOLEAN,
    methods_registered        TEXT[] NOT NULL DEFAULT '{}',
    default_mfa_method        TEXT,
    is_system_preferred_enabled BOOLEAN,
    last_updated_at           TIMESTAMPTZ,
    collected_at              TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, entra_object_id)
);
COMMENT ON TABLE ad_intel.entra_user_registration IS
    'reports/authenticationMethods/userRegistrationDetails (AuditLog.Read.All + Entra ID P1). '
    'methods_registered values as Graph returns them, e.g. ''microsoftAuthenticatorPush'', '
    '''softwareOneTimePasscode'', ''mobilePhone'', ''alternateMobilePhone'', ''officePhone'', ''email'', '
    '''fido2SecurityKey'', ''passKeyDeviceBound'', ''passKeyDeviceBoundAuthenticator'', '
    '''windowsHelloForBusiness'', ''macOsSecureEnclaveKey'', ''microsoftAuthenticatorPasswordless'', '
    '''temporaryAccessPass''. (schema v42)';

-- ----------------------------------------------------------------------------
-- Identity Protection
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_risky_user (
    client_id               UUID NOT NULL,
    entra_object_id         UUID NOT NULL,
    user_principal_name     TEXT,
    risk_level              TEXT,
    risk_state              TEXT,
    risk_detail             TEXT,
    risk_last_updated_at    TIMESTAMPTZ,
    collected_at            TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, entra_object_id)
);
COMMENT ON TABLE ad_intel.entra_risky_user IS
    'identityProtection/riskyUsers with riskState ''atRisk'' or ''confirmedCompromised'' '
    '(IdentityRiskyUser.Read.All + Entra ID P2). (schema v42)';

CREATE TABLE IF NOT EXISTS ad_intel.entra_risk_detection (
    client_id            UUID NOT NULL,
    detection_id         TEXT NOT NULL,
    entra_object_id      UUID,
    user_principal_name  TEXT,
    risk_event_type      TEXT,
    risk_level           TEXT,
    risk_state           TEXT,
    detection_timing_type TEXT,
    source               TEXT,
    detected_at          TIMESTAMPTZ,
    collected_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, detection_id)
);
COMMENT ON TABLE ad_intel.entra_risk_detection IS
    'identityProtection/riskDetections detected in the last 90 days whose riskState is ''atRisk'' or '
    '''confirmedCompromised'' (IdentityRiskEvent.Read.All + Entra ID P2). risk_event_type e.g. '
    '''leakedCredentials'', ''passwordSpray'', ''anomalousToken'', ''unfamiliarFeatures''. (schema v42)';

-- ----------------------------------------------------------------------------
-- Authorization policy: one more field
-- ----------------------------------------------------------------------------
COMMENT ON COLUMN ad_intel.entra_security_posture.authorization_policy IS
    'Graph /policies/authorizationPolicy: {allowInvitesFrom, guestUserRoleId, '
    'allowedToSignUpEmailBasedSubscriptions, allowEmailVerifiedUsersToJoinOrganization, '
    'blockMsolPowerShell, defaultUserRolePermissions: {allowedToCreateApps, '
    'allowedToCreateSecurityGroups, allowedToCreateTenants, allowedToReadOtherUsers, '
    'allowedToReadBitlockerKeysForOwnedDevice (schema v42), permissionGrantPoliciesAssigned[]}}. '
    'NULL = not read (see authorization_policy_status). (schema v38)';

-- ----------------------------------------------------------------------------
-- Declared emergency-access (break-glass) accounts
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_breakglass_account (
    client_id            UUID NOT NULL,
    user_principal_name  TEXT NOT NULL,
    note                 TEXT,
    added_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (client_id, user_principal_name)
);
COMMENT ON TABLE ad_intel.entra_breakglass_account IS
    'Optional, maintained by hand (never by a collector): the client''s declared emergency-access '
    'accounts, by UPN (compared case-insensitively). When a client has any row here, plugins treat '
    'exactly these accounts as break-glass; otherwise they use a heuristic (cloud-only enabled member '
    'holding Global Administrator that is excluded from an enabled Conditional Access policy '
    'targeting all users). (schema v42)';

-- ----------------------------------------------------------------------------
-- Change history (SCD2) for Entra change detection
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ad_intel.entra_change_history (
    client_id      UUID NOT NULL,
    entity_type    TEXT NOT NULL,
    entity_key     TEXT NOT NULL,
    entity_label   TEXT,
    content        JSONB NOT NULL,
    content_hash   TEXT NOT NULL,
    valid_from     TIMESTAMPTZ NOT NULL,
    valid_to       TIMESTAMPTZ,
    PRIMARY KEY (client_id, entity_type, entity_key, valid_from)
);
CREATE UNIQUE INDEX IF NOT EXISTS entra_change_history_open_uidx
    ON ad_intel.entra_change_history (client_id, entity_type, entity_key) WHERE valid_to IS NULL;
CREATE TABLE IF NOT EXISTS ad_intel.entra_change_baseline (
    client_id      UUID NOT NULL,
    entity_type    TEXT NOT NULL,
    first_run_at   TIMESTAMPTZ NOT NULL,
    last_run_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (client_id, entity_type)
);
COMMENT ON TABLE ad_intel.entra_change_history IS
    'SCD2 versions of the Entra objects change detection reports on. After each entity type''s '
    'source is read successfully, the collector compares each entity''s content (canonical JSON, '
    'md5 in content_hash) with the open version: unchanged -> nothing; changed -> the open row gets '
    'valid_to = this run''s time and a new open row is inserted with valid_from = the same time; '
    'new -> open row inserted; gone -> open row closed (valid_to set), no new row. A failed read '
    'leaves that entity type untouched. entity_type / entity_key / content: '
    '''federation'' / domain name / {authentication_type, issuer_uri, passive_sign_in_uri, '
    'active_sign_in_uri, federated_idp_mfa_behavior, prompt_login_behavior, '
    'signing_certificate_thumbprint, next_signing_certificate_thumbprint} -- one per domain, '
    'Managed domains too (federation fields null), from entra_domain + entra_domain_federation; '
    '''app_credential'' / <owner object id>:<keyId> / {object_type (''application''|''servicePrincipal''), '
    'object_id, app_id, display_name, credential_type (''password''|''certificate''), key_id, '
    'credential_display_name, end_date_time}; '
    '''app_permission'' / <principal id>:<resource app id>:<permission id> for application '
    'permissions (from entra_app_role_grant) and <client sp id>:<resource app id>:AllPrincipals:<scope> '
    'for tenant-wide delegated scopes (from entra_delegated_grant consent_type AllPrincipals) / '
    '{grant_kind (''application''|''delegated''), principal_id, principal_display_name, '
    'resource_app_id, resource_display_name, permission_name}; '
    '''ca_policy'' / policy id / the stored ca_policies element; '
    '''tenant_policy'' / ''security_defaults'' -> {enabled}, ''authorization_policy'' -> '
    'authorization_policy, ''auth_methods_policy'' -> per-method {id: {state, includeTargets, '
    'excludeTargets}} plus policyMigrationState, ''cross_tenant_default'' -> its content, '
    '''admin_consent_request_policy'' -> its content; '
    '''owner'' / <owned object id>:<owner id> / {owned_object_type (''application''|'
    '''servicePrincipal''|''group''), owned_object_id, owned_display_name, owner_id, owner_type, '
    'owner_display_name, owner_upn} for entra_app_owner and entra_group_owner rows; '
    '''partner'' / ''contract:''||contract_object_id or ''cross_tenant:''||partner tenant id / the '
    'entra_partner_contract row or partner content; '
    '''group_member'' / <group id>:<member id> / {group_id, group_display_name, '
    'group_sensitive_reasons, member_id, member_type, member_display_name, member_upn, '
    'member_user_type, on_premises_sync_enabled} for entra_group_member rows. '
    'entity_label = a human-readable name for summaries. (schema v42)';
COMMENT ON TABLE ad_intel.entra_change_baseline IS
    'Per (client, entity_type): first_run_at = the first successful history update (everything is '
    '"new" then, so change plugins suppress findings when first_run_at = last_run_at) and '
    'last_run_at = the latest successful history update; a version with valid_from = last_run_at, or '
    'closed with valid_to = last_run_at, changed in the latest Entra collection. (schema v42)';

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (42, 'Entra ID coverage round: collection status, groups/owners/members, service principals, '
            'permission grants, policies, domains/federation, licences, registration, risk, change history')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;
