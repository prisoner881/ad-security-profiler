#!/usr/bin/env python3
"""
entra_graph_collector.py -- Microsoft Entra ID / Graph API Email Collector

VERSION: 0.8.1

CHANGELOG:
    0.8.1 - Run Summary: a source name too long for the label column
            (admin_consent_request_policy, custom_role_assignments,
            device_registration_policy) ran into its status with no space
            ("...policy:ok"); the column now widens for it. Output only.

    0.8.0 - Requires schema v42. Collects much more of the tenant, each
            new data source optional: a 400/403/404 (permission not
            granted, licence missing, beta endpoint unavailable) no longer
            aborts anything -- the source's rows are removed for the
            client and the reason is stored in entra_collection_status
            (one row per source per run, 'ok' when read), so adaudit.py
            shows the plugins that need it as NOT ASSESSED. New sources:
            licences (subscribedSkus), organization, domains and
            federation configuration (signing certificates parsed),
            groups with owners and transitive members of the sensitive
            ones, role definitions, custom-role assignments, PIM role
            settings, service principals (own credentials, owner tenant,
            publisher) and their sign-in activity, application and
            service-principal owners, application permissions on nine
            resource APIs, delegated (oauth2PermissionGrants) grants,
            named locations, the authentication methods, cross-tenant
            access, admin consent request, directory (password
            protection / group) and device registration policies,
            on-prem sync feature flags, partner contracts, MFA
            registration details, risky users and risk detections, and
            (opt-in, --include-pta-agents) pass-through authentication
            agents. Users gain createdDateTime, passwordPolicies, password
            change time, guest invitation state, last sync time, licensed
            services and (optional pass) sign-in activity; applications
            gain certificate details, audience, publisher, redirect URIs,
            implicit grant and instance-lock settings; the authorization
            policy gains allowedToReadBitlockerKeysForOwnedDevice. After
            all sources run, entra_change_history (SCD2) and
            entra_change_baseline are updated for every entity type whose
            input sources were all read. Per-object owner/member/app-role
            reads go through Graph JSON batching ($batch, 20 per request,
            429 sub-responses retried honouring Retry-After). Existing
            core steps and tables are unchanged. New optional permissions
            are listed under CREDENTIAL SETUP; none is required.
    0.7.0 - Requires schema v38. Active directory role rows now say how
            the role is held (assignment_kind 'permanent', 'time_bound'
            or 'activated', with assignment_start/assignment_end), from
            roleAssignmentScheduleInstances; like eligibility this needs
            Entra ID P2, and when Graph refuses it the kind stays NULL and
            the reason goes to entra_security_posture.role_schedule_status.
            The tenant authorization policy (user app registration and
            consent, guest invitation/access settings, MSOnline PowerShell
            block) is stored in entra_security_posture.authorization_policy
            (status in authorization_policy_status; NULL when unreadable).
            ca_policies now also keeps each policy's conditions and
            session_controls (existing keys unchanged; grant_controls keeps
            authenticationStrength trimmed to id/displayName/
            allowedCombinations). Every (role, member, assignment type)
            seen is upserted into entra_role_assignment_history
            (first_seen_at kept, last_seen_at advanced, never deleted), so
            newly granted privileged roles can be reported (plugin 11020).
            No new Graph permissions: RoleManagement.Read.Directory and
            Policy.Read.All already cover the new reads.
    0.6.0 - Requires schema v37. Directory role membership now includes
            PIM-eligible assignments (roleEligibilityScheduleInstances;
            assignment_type 'eligible') and the transitive members of
            groups that hold a role (via_group_id). Before, only active
            direct members were seen, so someone who could activate Global
            Administrator through PIM, or held it through a role-assignable
            group, was invisible to plugins 10002/10003/10006. Eligibility
            needs Entra ID P2; when Graph refuses it (or group expansion),
            the reason is recorded in entra_security_posture and the run
            continues.
    0.5.1 - DANGEROUS_GRAPH_PERMISSIONS extended with six more Graph
            application permissions that lead directly to tenant takeover
            (Policy.ReadWrite.PermissionGrant,
            UserAuthenticationMethod.ReadWrite.All,
            RoleAssignmentSchedule/RoleEligibilitySchedule.ReadWrite.Directory,
            Group.ReadWrite.All, GroupMember.ReadWrite.All).
    0.5.0 - Every Graph and token request now retries 429 (honouring
            Retry-After), transient 5xx, and network errors/timeouts with
            exponential backoff, and refreshes the access token once on
            HTTP 401 (long runs can outlive the token). Exhausted retries
            abort the run with a message naming the request and last
            error. Fetching a directory role's members no longer logs a
            warning and skips that role on failure -- skipping silently
            erased the role's rows (Global Administrator included), since
            the sync step replaces the whole table; it now retries and
            then aborts, leaving the previous role data in place. Role
            member lists now follow @odata.nextLink. An aborted run now
            logs which tables were already refreshed this run and which
            still hold data from an earlier run, since each step commits
            on its own.
    0.4.2 - Every 403 error message now explicitly explains the Delegated-
            vs-Application permission-type distinction, not just consent
            status -- a real case showed Entra's admin-consent checkmark
            can be genuinely green while the permission is still useless
            for this script's client_credentials (no signed-in user) auth
            flow, because it was granted under the wrong permission type.
    0.4.1 - resolve_client_id()'s --domain-fqdn lookup is now case-insensitive
            (was an exact-case match, which caused a real "No client found"
            failure from a one-character casing difference). Added --client-id
            as a direct alternative that bypasses the domain-name lookup
            entirely.

WHAT THIS IS
    Harvests user email data (mail, proxyAddresses, and related fields)
    from Microsoft Graph for a client whose email is hosted in Exchange
    Online -- fully cloud-only, or hybrid with identity synced from
    on-prem AD but mailboxes living entirely in the cloud. Overwhelmingly
    the common case today: on-prem mail/proxyAddresses is only populated
    when something local (classic Exchange Hybrid, or the newer Exchange
    attribute writeback feature) actively writes it there, and most
    environments no longer have that.

WHY THIS IS A SEPARATE SCRIPT, NOT A MODE ON adprofiler.py
    adprofiler.py is, and should stay, a single-purpose LDAP collector:
    one transport (LDAP/LDAPS), one credential type (a domain bind
    account), one trust boundary (a domain controller). This script's
    entire mechanism is different in every one of those dimensions:
    OAuth2 client-credentials against Entra ID over HTTPS, a credential
    that lives in an Entra App Registration and has zero on-prem
    representation, and a trust boundary that's Microsoft's cloud, not
    the client's own network. Folding this into adprofiler.py would blur
    a boundary that's worth keeping sharp: LDAP-collected facts and
    cloud-collected facts have different provenance, different
    credential requirements, and different failure modes, and a report
    reader (or an auditor of THIS tool's own access) should be able to
    tell at a glance which is which. Two scripts, one shared database.

CREDENTIAL SETUP (done once, by the client, in their own Entra tenant)
    1. Register an application in the Entra admin center (Entra ID ->
       App registrations -> New registration). Any name/redirect URI is
       fine -- this app is never used interactively.
    2. Under API permissions, add five Microsoft Graph APPLICATION
       permissions (not delegated): User.Read.All, RoleManagement.Read.Directory
       (directory role membership -- who's a Global Administrator),
       Policy.Read.All (Security Defaults status and Conditional
       Access policies), Application.Read.All (app registration client
       secret expiry), and, as of v0.4.0, Directory.Read.All (needed
       specifically to read appRoleAssignedTo -- which applications
       have been granted a highly privileged Microsoft Graph
       permission; confirmed against Microsoft's own documentation
       that this specific read is not covered by Application.Read.All
       alone). Application permissions require a tenant admin to grant
       consent (API permissions -> Grant admin consent) -- if this app
       was set up before v0.4.0, the newer permissions need adding and
       consenting to separately; existing consent for the earlier ones
       doesn't cover them.
    3. Under Certificates & secrets, create a client secret (or,
       preferably for anything long-lived, a certificate instead --
       this script currently only supports a client secret; certificate
       auth is a reasonable follow-on if this becomes a standing tool
       rather than a one-off).
    4. You now have three values this script needs: the tenant ID, the
       application (client) ID, and the client secret.
    5. [v0.8.0] OPTIONAL application permissions. The five above are the
       only REQUIRED ones (they also cover licences, organization,
       domains, groups and owners, role definitions and custom-role
       assignments, service principals and owners, application and
       delegated grants, named locations, the authentication methods /
       cross-tenant / admin consent request / directory settings
       policies, and partner contracts). Each optional permission below
       unlocks one or more sources; without it (or without the licence)
       the collector records why in entra_collection_status and the
       plugins that need it show as NOT ASSESSED:
         AuditLog.Read.All (Entra ID P1) -- user sign-in activity,
             service-principal sign-in activity (beta), MFA registration
             details.
         Domain.Read.All -- federation configuration of Federated
             domains (signing certificates, MFA behaviour).
         RoleManagementPolicy.Read.Directory (Entra ID P2) -- PIM role
             settings (activation MFA/approval/duration/notifications).
             This is the precise permission; RoleManagement.Read.Directory
             (already required) is also documented as sufficient.
         Policy.Read.DeviceConfiguration -- device registration policy
             (beta).
         OnPremDirectorySynchronization.Read.All -- on-prem sync feature
             flags (password hash sync, soft/hard-match blocking).
         IdentityRiskyUser.Read.All (Entra ID P2) -- risky users.
         IdentityRiskEvent.Read.All (Entra ID P2) -- risk detections.
         OnPremisesPublishingProfiles.ReadWrite.All -- pass-through
             authentication agents. Microsoft offers no read-only
             permission for this read, so it is opt-in: only used with
             --include-pta-agents, and only grant it if you accept a
             write-capable permission on this app.

WHAT THIS DOES NOT DO
    Does not create, modify, or delete anything in Entra ID -- every
    request is a GET (the [v0.8.0] JSON batch POST to /$batch only
    carries GETs), and every permission above is read-only except the
    explicit opt-in OnPremisesPublishingProfiles.ReadWrite.All for
    --include-pta-agents, which is write-capable even though this
    collector only reads with it. Does not touch on-prem AD, any domain controller, or
    any client machine at all -- purely an outbound HTTPS call from
    wherever this script runs to Microsoft's cloud API. Does not require
    --domain-fqdn's on-prem AD to have ever been collected by
    adprofiler.py, though most of what makes the resulting data useful
    (correlating cloud users back to on-prem accounts) depends on it
    having been.

SCOPE, HONESTLY
    User.Read.All returns every user Graph exposes, cloud-only and
    synced alike. Correlation back to an on-prem AD account uses Graph's
    own onPremisesSecurityIdentifier field, matched against
    directory_object.object_sid for the same client -- exact SID
    comparison, no fuzzy matching on name or UPN (both can legitimately
    differ between the two systems, as this project has already found
    in real client data). A user with no on-prem match is not an error;
    it just means Graph doesn't consider that account synced from AD --
    a genuinely cloud-only or guest account.
"""

import argparse
import atexit
import base64
import hashlib
import getpass
import email.utils
import json
import random
import re
import sys
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import requests
import psycopg2
import psycopg2.extras

# [test-candidate-branch] Always overwritten by main() from
# --pg-host/--pg-port/--pg-dbname/--pg-user/--pg-password before
# connect_postgres() is ever called -- placeholders, not a real
# client's connection details.
PG_HOST = None
PG_PORT = 5432
PG_DBNAME = "adprofiler"
PG_USER = None
PG_PASSWORD = None

VERSION = "0.8.1"

# [v0.5.0] Retry policy shared by every Graph/token request (see
# _send_with_retry()). 429 and transient 5xx responses, plus network
# errors/timeouts, are retried with exponential backoff (2s, 4s, 8s, 16s,
# 32s, plus up to 1s jitter), or for exactly as long as a Retry-After
# header asks when Graph supplies one (capped, so a pathological value
# can't hang the run). Worst case is roughly a minute of backoff per
# request before the run aborts -- long enough to ride out ordinary
# throttling, short enough that a genuinely down or saturated tenant
# fails promptly with a clear message instead of appearing hung.
GRAPH_MAX_ATTEMPTS = 6
GRAPH_BACKOFF_BASE_SECONDS = 2
GRAPH_BACKOFF_MAX_SECONDS = 60
GRAPH_RETRY_AFTER_MAX_SECONDS = 300
GRAPH_RETRYABLE_STATUSES = {429, 500, 502, 503, 504}

GRAPH_TOKEN_URL_TMPL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
GRAPH_USERS_URL = "https://graph.microsoft.com/v1.0/users"
GRAPH_USER_SELECT = (
    "id,userPrincipalName,mail,proxyAddresses,accountEnabled,"
    "onPremisesSecurityIdentifier,onPremisesSyncEnabled,userType,"
    # [v0.8.0] More user fields, all User.Read.All. signInActivity is
    # deliberately NOT here: without AuditLog.Read.All (and P1) it fails
    # the whole /users call, so it is read in a separate optional pass
    # (fetch_sign_in_activity()).
    "displayName,createdDateTime,passwordPolicies,lastPasswordChangeDateTime,"
    "externalUserState,externalUserStateChangeDateTime,onPremisesLastSyncDateTime,"
    "assignedPlans"
)
GRAPH_PAGE_SIZE = 999  # Graph's own maximum for $top on /users, not a choice made here

# [v0.2.0] Directory role membership -- only roles that have ever been
# activated in the tenant are returned by GET /directoryRoles at all
# (confirmed against Microsoft's own documentation: "Only the Company
# Administrators [Global Administrator] directory role is activated by
# default"; every other built-in role only appears here once someone
# has actually been assigned to it at least once). That's exactly the
# right behavior for this project's purposes -- an inactive role has
# never had a member, so there's nothing to cross-reference regardless.
GRAPH_DIRECTORY_ROLES_URL = "https://graph.microsoft.com/v1.0/directoryRoles"
# [v0.6.0] PIM-eligible role assignments (not visible in /directoryRoles,
# which lists only active members) and the members of groups that hold a
# role (role-assignable groups). Eligibility needs Entra ID P2 / Governance
# licensing; without it Graph answers 400/403 and the collector records
# that it couldn't check rather than failing the run. Permissions:
# RoleManagement.Read.Directory (eligibility) and Directory.Read.All or
# GroupMember.Read.All (group members) -- both already in SETUP.md's list.
GRAPH_ROLE_ELIGIBILITY_URL = (
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleEligibilityScheduleInstances"
    "?$expand=principal,roleDefinition"
)
GRAPH_GROUPS_URL = "https://graph.microsoft.com/v1.0/groups"
# [v0.7.0] Active role assignment schedule instances -- one per active
# assignment, with assignmentType 'Assigned' (a standing assignment, with or
# without an end date) or 'Activated' (a PIM-eligible principal's current
# activation). Used only to classify the active rows already read from
# /directoryRoles (assignment_kind). Same permission and licensing as
# eligibility: RoleManagement.Read.Directory, Entra ID P2 / ID Governance.
GRAPH_ROLE_ASSIGNMENT_SCHEDULE_URL = (
    "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignmentScheduleInstances"
)
# Fixed, immutable across every tenant -- confirmed against Microsoft's
# own documentation and cross-checked against multiple independent
# sources, not tenant-specific the way a role's own "id" is.
GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

# [v0.3.0] Security Defaults + Conditional Access -- both read via
# Policy.Read.All, a new permission alongside RoleManagement.Read.Directory.
GRAPH_SECURITY_DEFAULTS_URL = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
GRAPH_CA_POLICIES_URL = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"
# [v0.7.0] Tenant-wide authorization policy (who may register apps, consent
# to apps, create tenants/groups, invite guests; guest user role; MSOnline
# PowerShell block). Also Policy.Read.All. A single object in v1.0.
GRAPH_AUTHORIZATION_POLICY_URL = "https://graph.microsoft.com/v1.0/policies/authorizationPolicy"
# The fields stored in entra_security_posture.authorization_policy (the v38
# column comment is the contract); anything Graph omits is stored as null.
AUTHORIZATION_POLICY_FIELDS = (
    "allowInvitesFrom", "guestUserRoleId", "allowedToSignUpEmailBasedSubscriptions",
    "allowEmailVerifiedUsersToJoinOrganization", "blockMsolPowerShell",
)
AUTHORIZATION_POLICY_DEFAULT_USER_FIELDS = (
    "allowedToCreateApps", "allowedToCreateSecurityGroups", "allowedToCreateTenants",
    "allowedToReadOtherUsers", "permissionGrantPoliciesAssigned",
    # [v0.8.0] schema v42 column comment.
    "allowedToReadBitlockerKeysForOwnedDevice",
)

# [v0.3.0] Application registrations -- read via Application.Read.All, a
# new permission. Scoped deliberately to client secret expiry only, not
# full Graph API permission-grant parsing (which would need resolving
# each servicePrincipal's oauth2PermissionGrants/appRoleAssignments
# against Microsoft Graph's own well-known permission GUIDs -- a
# separate, larger piece of work than this pass covers).
GRAPH_APPLICATIONS_URL = "https://graph.microsoft.com/v1.0/applications"

# [v0.4.0] Dangerous Graph API permission grants. Microsoft Graph
# itself is always the "resource" here -- confirmed against multiple
# independent sources that its service principal has a fixed,
# well-known appId identical across every tenant, unlike an
# individual app's own service principal id, which is tenant-specific.
GRAPH_MSGRAPH_SP_APPID = "00000003-0000-0000-c000-000000000000"
GRAPH_SERVICE_PRINCIPALS_URL = "https://graph.microsoft.com/v1.0/servicePrincipals"

# Sourced directly from Microsoft's own Graph permissions reference
# documentation's explicit "Use caution when granting any of these
# permissions" warnings -- not this project's own judgment call. Two
# categories Microsoft itself calls out: permissions that "allow an
# application to grant additional privileges to itself, other
# applications, or any user" (privilege-escalation capable), and
# permissions that "allow an application to act as other entities, and
# use the privileges they were granted" (impersonation capable).
DANGEROUS_GRAPH_PERMISSIONS = {
    "Application.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Directory.ReadWrite.All",
    "EntitlementManagement.ReadWrite.All",
    # [v0.5.1] Further application permissions that are each a direct path to
    # Global Administrator or to taking over privileged accounts (consent
    # grants, MFA method resets, PIM role assignment/eligibility, membership
    # of role-assignable groups). Raised by the per-plugin review of 10007.
    "Policy.ReadWrite.PermissionGrant",
    "UserAuthenticationMethod.ReadWrite.All",
    "RoleAssignmentSchedule.ReadWrite.Directory",
    "RoleEligibilitySchedule.ReadWrite.Directory",
    "Group.ReadWrite.All",
    "GroupMember.ReadWrite.All",
}

# ----------------------------------------------------------------------------
# [v0.8.0] Optional data sources (schema v42). Every source below is read
# with graph_get_optional(): a 400/403/404 is recorded in
# entra_collection_status and that source's rows are removed for the
# client; anything else is retried and then aborts, as for the core steps.
# ----------------------------------------------------------------------------
GRAPH_V1 = "https://graph.microsoft.com/v1.0"
# [v0.8.0] Beta endpoints are used only where v1.0 has no equivalent (or as a
# fallback when the v1.0 read fails with 400/404). Microsoft can change or
# remove beta APIs without notice, so these reads may start failing; the
# failure is then recorded per source like any other.
GRAPH_BETA = "https://graph.microsoft.com/beta"
# [v0.8.0] JSON batching: up to 20 GETs per POST (Graph's documented limit).
# The POST itself carries only GET sub-requests -- nothing is written.
GRAPH_BATCH_URL = GRAPH_V1 + "/$batch"
GRAPH_BATCH_MAX_REQUESTS = 20
# entra_collection_status.status reasons are Graph's own error code and
# message, trimmed to this length.
STATUS_REASON_MAX = 300

GRAPH_SUBSCRIBED_SKUS_URL = GRAPH_V1 + "/subscribedSkus"
GRAPH_ORGANIZATION_URL = GRAPH_V1 + "/organization"
GRAPH_DOMAINS_URL = GRAPH_V1 + "/domains"
GRAPH_ROLE_DEFINITIONS_URL = GRAPH_V1 + "/roleManagement/directory/roleDefinitions"
GRAPH_ROLE_ASSIGNMENTS_URL = GRAPH_V1 + "/roleManagement/directory/roleAssignments"
GRAPH_PIM_POLICY_ASSIGNMENTS_URL = (
    GRAPH_V1 + "/policies/roleManagementPolicyAssignments"
    "?$filter=scopeId eq '/' and scopeType eq 'DirectoryRole'&$expand=policy($expand=rules)"
)
GRAPH_SP_SIGN_IN_ACTIVITY_URL = GRAPH_BETA + "/reports/servicePrincipalSignInActivities"
GRAPH_OAUTH2_GRANTS_URL = GRAPH_V1 + "/oauth2PermissionGrants"
GRAPH_NAMED_LOCATIONS_URL = GRAPH_V1 + "/identity/conditionalAccess/namedLocations"
GRAPH_AUTH_METHODS_POLICY_URL = GRAPH_V1 + "/policies/authenticationMethodsPolicy"
GRAPH_CROSS_TENANT_DEFAULT_URL = GRAPH_V1 + "/policies/crossTenantAccessPolicy/default"
GRAPH_CROSS_TENANT_PARTNERS_URL = GRAPH_V1 + "/policies/crossTenantAccessPolicy/partners"
GRAPH_ADMIN_CONSENT_POLICY_URL = GRAPH_V1 + "/policies/adminConsentRequestPolicy"
GRAPH_GROUP_SETTINGS_URL = GRAPH_V1 + "/groupSettings"
GRAPH_DEVICE_REGISTRATION_POLICY_PATH = "/policies/deviceRegistrationPolicy"
GRAPH_ONPREM_SYNC_PATH = "/directory/onPremisesSynchronization"
GRAPH_CONTRACTS_URL = GRAPH_V1 + "/contracts"
GRAPH_REGISTRATION_DETAILS_URL = GRAPH_V1 + "/reports/authenticationMethods/userRegistrationDetails"
GRAPH_RISKY_USERS_URL = (
    GRAPH_V1 + "/identityProtection/riskyUsers"
    "?$filter=riskState eq 'atRisk' or riskState eq 'confirmedCompromised'"
)
GRAPH_RISK_DETECTIONS_URL = GRAPH_V1 + "/identityProtection/riskDetections"
RISK_DETECTION_LOOKBACK_DAYS = 90
RISK_STATES_KEPT = {"atRisk", "confirmedCompromised"}
# [v0.8.0] Pass-through authentication agents: onPremisesAgent list under
# the 'authentication' publishing type (beta only). Path written from
# Microsoft's onPremisesPublishingProfiles documentation
# (GET /onPremisesPublishingProfiles/{publishingType}/agents); kept as a
# named constant in case Microsoft moves it. Needs
# OnPremisesPublishingProfiles.ReadWrite.All -- there is no read-only
# permission -- so it is only read with --include-pta-agents.
GRAPH_PTA_AGENTS_URL = GRAPH_BETA + "/onPremisesPublishingProfiles/authentication/agents"
PTA_SKIPPED_STATUS = ("skipped: requires OnPremisesPublishingProfiles.ReadWrite.All; "
                      "enable with --include-pta-agents")

# [v0.8.0] Tenants that own Microsoft's first-party applications (v42
# entra_service_principal comment). Owners are not read for their service
# principals.
MICROSOFT_TENANT_IDS = {"f8cdef31-a31e-4b4a-93e4-5f571e91255a", "72f988bf-86f1-41af-91ab-2d7cd011db47"}

# [v0.8.0] Resource APIs whose application permissions (appRoleAssignedTo)
# go to entra_app_role_grant -- appIds are fixed across tenants (v42
# entra_app_role_grant comment).
APP_ROLE_GRANT_RESOURCE_APP_IDS = (
    "00000003-0000-0000-c000-000000000000",  # Microsoft Graph
    "00000002-0000-0ff1-ce00-000000000000",  # Office 365 Exchange Online
    "00000003-0000-0ff1-ce00-000000000000",  # Office 365 SharePoint Online
    "cfa8b339-82a2-471a-a3c9-0fc0be7a4093",  # Azure Key Vault
    "00000002-0000-0000-c000-000000000000",  # Windows Azure Active Directory (AAD Graph)
    "00000004-0000-0ff1-ce00-000000000000",  # Microsoft Teams Services / Skype for Business Online
    "c5393580-f805-4401-95e8-94b7a6ef2fc2",  # Office 365 Management APIs
    "00000007-0000-0000-c000-000000000000",  # Dynamics CRM
    "c161e42e-d4df-4a3d-9b42-e7a3c31f59d4",  # Microsoft Intune API
)
# An app role assignment with this appRoleId is "default access" (no
# specific permission) -- stored with permission_name NULL.
DEFAULT_ACCESS_APP_ROLE_ID = "00000000-0000-0000-0000-000000000000"

# [v0.8.0] Built-in directory roles treated as privileged when deciding
# whether a group's app role assignment on a service principal makes the
# group sensitive ('app_role'): a service principal holding one of these
# (or a DANGEROUS_GRAPH_PERMISSIONS grant) can take over the tenant or its
# privileged accounts. Template ids are fixed across tenants.
PRIVILEGED_ROLE_TEMPLATE_IDS = {
    "62e90394-69f5-4237-9190-012177145e10",  # Global Administrator
    "e8611ab8-c189-46e8-94e1-60213ab1f814",  # Privileged Role Administrator
    "7be44c8a-adaf-4e2a-84d6-ab2649e08a13",  # Privileged Authentication Administrator
    "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3",  # Application Administrator
    "158c047a-c907-4556-b7ef-446551a6b5f7",  # Cloud Application Administrator
    "194ae4cb-b126-40b2-bd5b-6091b380977d",  # Security Administrator
    "fe930be7-5e62-47db-91af-98c3a49a38b1",  # User Administrator
    "c4e39bd9-1100-46d3-8c65-fb160da0071f",  # Authentication Administrator
    "729827e3-9c14-49f7-bb1b-9608f156bbb8",  # Helpdesk Administrator
    "29232cdf-9323-42fd-ade2-1d097af3e4de",  # Exchange Administrator
    "f28a1f50-f6e7-4571-818b-6a12f2af6b6c",  # SharePoint Administrator
    "3a2c62db-5318-420d-8d74-23affee5d9d5",  # Intune Administrator
    "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9",  # Conditional Access Administrator
    "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2",  # Hybrid Identity Administrator
    "fdd7a751-b60b-444a-984c-02652fe8fa1c",  # Groups Administrator
    "9360feb5-f418-4baa-8175-e2a00bac4301",  # Directory Writers
    "e00e864a-17c5-4a4b-9c06-f5b95a8d5bd8",  # Partner Tier2 Support
    "8329153b-31d0-4727-b945-745eb3bc5f31",  # Domain Name Administrator
    "be2f45a1-457d-42af-a067-6ec1fa63bc45",  # External Identity Provider Administrator
    "d29b2b05-8046-44ba-8758-1e26182fcf32",  # Directory Synchronization Accounts
}

# [v0.8.0] Authentication method configurations fetched one by one when
# Graph does not return them inline with authenticationMethodsPolicy.
AUTH_METHOD_CONFIG_IDS = (
    "Sms", "Voice", "Email", "Fido2", "MicrosoftAuthenticator", "TemporaryAccessPass",
    "SoftwareOath", "X509Certificate",
)

# [v0.8.0] User fields read through the /microsoft.graph.user cast segment
# of owner / member collections. Selecting them on a plain directoryObject
# collection can return 400, and full objects without $select omit them
# (users only return a default property set), so each owner/member list is
# read twice: once as full objects (every type -- users, groups, service
# principals, devices) and once cast to users with these fields; merged by id.
DIRECTORY_USER_EXTRA_SELECT = "id,userType,onPremisesSyncEnabled,accountEnabled"

# [v0.8.0] Every optional source, in run order. Names are exactly those in
# the entra_collection_status table comment (schema v42).
OPTIONAL_SOURCES = (
    "sign_in_activity", "subscribed_skus", "organization", "domains", "federation",
    "service_principals", "sp_sign_in_activity", "app_role_grants", "delegated_grants",
    "app_owners", "groups", "role_definitions", "custom_role_assignments", "pim_policies",
    "named_locations", "auth_methods_policy", "cross_tenant_policy",
    "admin_consent_request_policy", "directory_settings", "device_registration_policy",
    "onprem_sync", "pta_agents", "partner_contracts", "registration_details",
    "risky_users", "risk_detections",
)


# ============================================================================
# Logging -- deliberately duplicated from adprofiler.py's helpers rather
# than imported, so this script stays independently runnable without
# adprofiler_v002.py needing to be present/importable alongside it. Same
# visual language on purpose, so console output reads consistently
# across both tools even though they're intentionally separate.
# ============================================================================

_USE_COLOR = sys.stdout.isatty()

class _C:
    RESET = "\033[0m" if _USE_COLOR else ""
    RED = "\033[91m" if _USE_COLOR else ""
    GREEN = "\033[92m" if _USE_COLOR else ""
    YELLOW = "\033[93m" if _USE_COLOR else ""
    CYAN = "\033[96m" if _USE_COLOR else ""
    WHITE = "\033[97m" if _USE_COLOR else ""
    BOLD = "\033[1m" if _USE_COLOR else ""
    DIM = "\033[2m" if _USE_COLOR else ""


class _TeeStream:
    """[test-candidate-branch] Same class, same reasoning, as
    adprofiler.py's own _TeeStream -- see that docstring. Duplicated
    here rather than imported from adprofiler.py since these two
    scripts have always been fully independent (see this script's own
    module docstring on why entra_graph_collector.py is separate from
    adprofiler.py at all), and this project's plugins are the only
    thing genuinely meant to be shared between files."""
    _ANSI_RE = re.compile(r"\033\[[0-9;]*m")

    def __init__(self, console_stream, log_fh):
        self._console = console_stream
        self._log_fh = log_fh

    def write(self, data):
        self._console.write(data)
        self._log_fh.write(self._ANSI_RE.sub("", data).replace("\r", "\n"))

    def flush(self):
        self._console.flush()
        self._log_fh.flush()

    def isatty(self):
        return self._console.isatty()


def _ts():
    return datetime.now().strftime("%H:%M:%S")


def log_info(msg):
    print(f"{_C.DIM}[{_ts()}]{_C.RESET} {_C.WHITE}[INFO]{_C.RESET}    {msg}")


def log_success(msg):
    print(f"{_C.DIM}[{_ts()}]{_C.RESET} {_C.GREEN}[ OK ]{_C.RESET}    {msg}")


def log_warn(msg):
    print(f"{_C.DIM}[{_ts()}]{_C.RESET} {_C.YELLOW}[WARN]{_C.RESET}    {msg}")


def log_error(msg):
    print(f"{_C.DIM}[{_ts()}]{_C.RESET} {_C.RED}[FAIL]{_C.RESET}    {msg}")


def log_header(msg):
    bar = "=" * max(60, len(msg) + 4)
    print(f"\n{_C.BOLD}{_C.CYAN}{bar}\n  {msg}\n{bar}{_C.RESET}")


class CollectorAbort(Exception):
    pass


# ============================================================================
# Microsoft Graph
# ============================================================================

def _retry_delay(resp, attempt):
    """Seconds to wait before the next attempt: the server's own
    Retry-After when it sent one (delta-seconds or HTTP-date form, both
    allowed by RFC 9110), otherwise exponential backoff with jitter."""
    retry_after = resp.headers.get("Retry-After") if resp is not None else None
    if retry_after:
        try:
            seconds = float(retry_after)
        except ValueError:
            try:
                when = email.utils.parsedate_to_datetime(retry_after)
                seconds = (when - datetime.now(timezone.utc)).total_seconds()
            except (TypeError, ValueError):
                seconds = None
        if seconds is not None:
            return min(max(seconds, 1.0), GRAPH_RETRY_AFTER_MAX_SECONDS)
    backoff = GRAPH_BACKOFF_BASE_SECONDS * (2 ** (attempt - 1))
    return min(backoff, GRAPH_BACKOFF_MAX_SECONDS) + random.uniform(0, 1)


def _send_with_retry(send, what, on_unauthorized=None):
    """Calls send() (which returns a requests.Response) until it gets a
    response that isn't worth retrying, and returns that response for
    the caller to interpret. Retries network errors/timeouts and
    GRAPH_RETRYABLE_STATUSES up to GRAPH_MAX_ATTEMPTS times in total.
    On the first HTTP 401, calls on_unauthorized() (token refresh) and
    retries once without counting it as an attempt. Raises
    CollectorAbort once retries are exhausted -- never returns a
    partial or failed result as if it were data."""
    attempt = 0
    refreshed = False
    while True:
        attempt += 1
        resp = None
        try:
            resp = send()
        except requests.exceptions.RequestException as exc:
            problem = f"network error: {exc}"
        else:
            if resp.status_code == 401 and on_unauthorized is not None and not refreshed:
                log_warn(f"  {what} returned HTTP 401 -- access token likely "
                          f"expired mid-run; requesting a new one and retrying.")
                on_unauthorized()
                refreshed = True
                attempt -= 1
                continue
            if resp.status_code not in GRAPH_RETRYABLE_STATUSES:
                return resp
            problem = f"HTTP {resp.status_code}"

        if attempt >= GRAPH_MAX_ATTEMPTS:
            throttle_hint = (
                " Microsoft is throttling this tenant/application -- re-run later, "
                "or space collection runs further apart if this recurs."
                if resp is not None and resp.status_code == 429 else
                " Re-run once Microsoft Graph / network connectivity is healthy."
            )
            raise CollectorAbort(
                f"{what}: still failing after {GRAPH_MAX_ATTEMPTS} attempts "
                f"(last error: {problem}). Aborting rather than recording incomplete "
                f"data.{throttle_hint}"
            )
        delay = _retry_delay(resp, attempt)
        log_warn(f"  {what} failed ({problem}); retrying in {delay:.0f}s "
                  f"(attempt {attempt + 1} of {GRAPH_MAX_ATTEMPTS})...")
        time.sleep(delay)


def get_graph_token(tenant_id, app_id, app_secret):
    """OAuth2 client-credentials (app-only) flow. No signed-in user, no
    interactive consent at runtime -- consent was already granted once,
    ahead of time, when a tenant admin approved the application
    permission in the Entra admin center."""
    resp = _send_with_retry(
        lambda: requests.post(
            GRAPH_TOKEN_URL_TMPL.format(tenant_id=tenant_id),
            data={
                "client_id": app_id,
                "client_secret": app_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=30,
        ),
        "Token request to Microsoft's token endpoint",
    )

    if resp.status_code != 200:
        try:
            detail = resp.json().get("error_description", resp.text)
        except ValueError:
            detail = resp.text or resp.reason
        raise CollectorAbort(
            f"Token request failed (HTTP {resp.status_code}): {detail}\n"
            "Common causes: wrong tenant ID, wrong app ID/secret, secret "
            "expired, or an application permission was never admin-consented. "
            "If a downstream Graph call fails with 403 despite Entra showing "
            "the permission as granted, see that error for a more specific "
            "explanation -- it's very often a Delegated-vs-Application "
            "permission-type mix-up, not a consent problem at all."
        )
    return resp.json()["access_token"]


class GraphClient:
    """Holds the app credentials and current access token so a token
    that expires partway through a long collection (tokens last roughly
    60-90 minutes) can be replaced transparently, and routes every GET
    through _send_with_retry()."""

    def __init__(self, tenant_id, app_id, app_secret):
        self._tenant_id = tenant_id
        self._app_id = app_id
        self._app_secret = app_secret
        self._token = get_graph_token(tenant_id, app_id, app_secret)

    def _refresh_token(self):
        self._token = get_graph_token(self._tenant_id, self._app_id, self._app_secret)

    def get(self, url, what, forbidden_message=None):
        """GETs url and returns the parsed JSON body. Raises
        CollectorAbort on 403 (with forbidden_message when given -- the
        permission-specific explanation), on any other non-200, or once
        retries are exhausted."""
        resp = _send_with_retry(
            lambda: requests.get(url, headers={"Authorization": f"Bearer {self._token}"}, timeout=60),
            f"Graph request for {what}",
            on_unauthorized=self._refresh_token,
        )
        if resp.status_code == 403 and forbidden_message:
            raise CollectorAbort(forbidden_message)
        if resp.status_code != 200:
            raise CollectorAbort(f"Graph request for {what} failed (HTTP {resp.status_code}): {resp.text}")
        try:
            return resp.json()
        except ValueError:
            raise CollectorAbort(f"Graph request for {what} returned HTTP 200 with a non-JSON body.")

    def post_batch(self, payload, what):
        """[v0.8.0] POSTs a JSON batch (GET sub-requests only -- nothing is
        written) to GRAPH_BATCH_URL and returns the raw response for
        graph_batch_get_all() to interpret. Whole-request 429/5xx/network
        errors are retried like every GET; 401 refreshes the token once."""
        return _send_with_retry(
            lambda: requests.post(
                GRAPH_BATCH_URL, json=payload,
                headers={"Authorization": f"Bearer {self._token}", "Content-Type": "application/json"},
                timeout=120,
            ),
            f"Graph request for {what}",
            on_unauthorized=self._refresh_token,
        )


def _graph_error_reason(status_code, body=None, text=""):
    """[v0.8.0] "HTTP <status> <code>: <message>" from a Graph error body
    (dict) -- the same wording graph_get_optional() has used since v0.6.0,
    shared with JSON batch sub-responses."""
    detail = ""
    if isinstance(body, dict):
        err = body.get("error") or {}
        if isinstance(err, dict):
            detail = f"{err.get('code', '')}: {err.get('message', '')}".strip(": ")
    elif text:
        detail = text[:200]
    return f"HTTP {status_code} {detail}".strip()


def _status_text(status):
    """[v0.8.0] A collection status as stored: 'ok', or the reason trimmed
    to STATUS_REASON_MAX characters."""
    status = (status or "unknown").strip()
    if len(status) > STATUS_REASON_MAX:
        status = status[:STATUS_REASON_MAX - 3] + "..."
    return status


def graph_get_optional(graph, url, what):
    """[v0.6.0] Like graph.get(), but a 400/403/404 (feature not licensed,
    permission not granted, object gone) returns (None, "<reason>") instead
    of aborting the run. Throttling and transient errors are still retried
    by _send_with_retry(), and still abort once retries run out."""
    resp = _send_with_retry(
        lambda: requests.get(url, headers={"Authorization": f"Bearer {graph._token}"}, timeout=60),
        f"Graph request for {what}",
        on_unauthorized=graph._refresh_token,
    )
    if resp.status_code == 200:
        try:
            return resp.json(), "ok"
        except ValueError:
            raise CollectorAbort(f"Graph request for {what} returned HTTP 200 with a non-JSON body.")
    if resp.status_code in (400, 403, 404):
        try:
            return None, _graph_error_reason(resp.status_code, resp.json())
        except ValueError:
            return None, _graph_error_reason(resp.status_code, text=resp.text)
    raise CollectorAbort(f"Graph request for {what} failed (HTTP {resp.status_code}): {resp.text}")


def graph_get_all_optional(graph, url, what):
    """[v0.8.0] graph_get_optional() over every @odata.nextLink page.
    Returns (items, "ok"), or (None, "<reason>") if any page was refused --
    never a partial list presented as complete."""
    items = []
    page = 0
    while url:
        page += 1
        body, status = graph_get_optional(graph, url, what if page == 1 else f"{what} (page {page})")
        if body is None:
            return None, status
        items.extend(body.get("value", []))
        url = body.get("@odata.nextLink")
    return items, "ok"


def graph_get_single_optional(graph, url, what):
    """[v0.8.0] One object (no collection). Accepts a one-element "value"
    wrapper too. Returns (dict, "ok") or (None, "<reason>")."""
    body, status = graph_get_optional(graph, url, what)
    if body is None:
        return None, status
    if isinstance(body.get("value"), list):
        body = body["value"][0] if body["value"] else {}
    return body, "ok"


def _graph_get_with_beta_fallback(graph, path, what, single=True):
    """[v0.8.0] Reads path from v1.0, and from beta when v1.0 answers 400 or
    404 (endpoint not available in v1.0). A 403 is a permission problem
    that beta shares, so it is returned as is. Beta can change without
    notice."""
    reader = graph_get_single_optional if single else graph_get_all_optional
    body, status = reader(graph, GRAPH_V1 + path, what)
    if body is None and (status.startswith("HTTP 400") or status.startswith("HTTP 404")):
        log_info(f"  {what}: v1.0 unavailable ({status[:80]}); trying the beta endpoint")
        body, status = reader(graph, GRAPH_BETA + path, f"{what} (beta)")
    return body, status


def graph_batch_get_all(graph, requests_list, what):
    """[v0.8.0] Runs many GETs through Graph JSON batching
    (GRAPH_BATCH_MAX_REQUESTS per POST). requests_list is [(key,
    relative_url)], relative to v1.0 (e.g. "/groups/{id}/owners").
    Returns {key: (items, "ok") | (None, "<reason>")}: every page of each
    collection (an @odata.nextLink in a sub-response is followed with
    ordinary GETs), or the reason for a 400/403/404 sub-response (the
    caller decides whether one object's failure matters). 429 and 5xx
    sub-responses are retried, honouring their Retry-After, up to
    GRAPH_MAX_ATTEMPTS; still failing after that aborts like any other
    exhausted retry. If Graph refuses the batch request itself (non-200),
    the chunk is read with ordinary sequential GETs instead."""
    results = {}
    for start in range(0, len(requests_list), GRAPH_BATCH_MAX_REQUESTS):
        chunk = requests_list[start:start + GRAPH_BATCH_MAX_REQUESTS]
        pending = {str(i): item for i, item in enumerate(chunk)}
        attempt = 0
        while pending:
            attempt += 1
            payload = {"requests": [{"id": rid, "method": "GET", "url": rel}
                                    for rid, (_key, rel) in pending.items()]}
            resp = graph.post_batch(payload, f"{what} (JSON batch of {len(pending)})")
            body = None
            if resp.status_code == 200:
                try:
                    body = resp.json()
                except ValueError:
                    body = None
            if not isinstance(body, dict) or not isinstance(body.get("responses"), list):
                log_warn(f"  JSON batch for {what} refused (HTTP {resp.status_code}); "
                         f"reading these {len(pending)} request(s) one by one instead.")
                for _rid, (key, rel) in pending.items():
                    results[key] = graph_get_all_optional(graph, GRAPH_V1 + rel, f"{what} ({rel})")
                pending = {}
                break
            retry, delay = {}, 0.0
            for sub in body["responses"]:
                rid = str(sub.get("id"))
                if rid not in pending:
                    continue
                key, rel = pending[rid]
                code = int(sub.get("status") or 0)
                sub_body = sub.get("body")
                if code == 200:
                    sub_body = sub_body if isinstance(sub_body, dict) else {}
                    items = list(sub_body.get("value", []))
                    status = "ok"
                    next_url = sub_body.get("@odata.nextLink")
                    while next_url:
                        page, status = graph_get_optional(graph, next_url, f"{what} ({rel}, next page)")
                        if page is None:
                            items = None
                            break
                        items.extend(page.get("value", []))
                        next_url = page.get("@odata.nextLink")
                    results[key] = (items, status)
                elif code in GRAPH_RETRYABLE_STATUSES:
                    retry[rid] = pending[rid]
                    headers = requests.structures.CaseInsensitiveDict(sub.get("headers") or {})
                    delay = max(delay, _retry_delay(SimpleNamespace(headers=headers), attempt))
                elif code in (400, 403, 404):
                    results[key] = (None, _graph_error_reason(code, sub_body))
                else:
                    raise CollectorAbort(
                        f"Graph request for {what} ({rel}) failed in a JSON batch "
                        f"(HTTP {code}): {json.dumps(sub_body)[:500]}")
            # A sub-request Graph did not answer at all is retried too.
            for rid, item in pending.items():
                if rid not in retry and item[0] not in results:
                    retry[rid] = item
            pending = retry
            if pending:
                if attempt >= GRAPH_MAX_ATTEMPTS:
                    raise CollectorAbort(
                        f"Graph request for {what}: {len(pending)} JSON batch sub-request(s) still "
                        f"throttled/failing after {GRAPH_MAX_ATTEMPTS} attempts. Aborting rather "
                        f"than recording incomplete data. Re-run later.")
                if not delay:
                    delay = _retry_delay(None, attempt)
                log_warn(f"  {len(pending)} JSON batch sub-request(s) for {what} throttled or "
                         f"failed; retrying in {delay:.0f}s (attempt {attempt + 1} of "
                         f"{GRAPH_MAX_ATTEMPTS})...")
                time.sleep(delay)
    return results


def graph_batch_directory_objects(graph, objects, what):
    """[v0.8.0] For each (key, relative collection url) -- e.g. a group's
    owners -- reads the collection twice in one JSON batch run: as full
    objects (all types) and through the /microsoft.graph.user cast with
    DIRECTORY_USER_EXTRA_SELECT, then merges the user fields into the full
    objects by id (see DIRECTORY_USER_EXTRA_SELECT for why). Returns
    {key: (objects, "ok") | (None, "<reason>")}."""
    reqs = []
    for key, rel in objects:
        reqs.append(((key, "all"), rel))
        base, _, query = rel.partition("?")
        cast = f"{base}/microsoft.graph.user?$select={DIRECTORY_USER_EXTRA_SELECT}"
        if query:
            cast += "&" + query
        reqs.append(((key, "users"), cast))
    raw = graph_batch_get_all(graph, reqs, what)
    merged = {}
    for key, _rel in objects:
        everything, status = raw[(key, "all")]
        users, user_status = raw[(key, "users")]
        if everything is None:
            merged[key] = (None, status)
            continue
        if users is None:
            merged[key] = (None, user_status)
            continue
        extra = {u.get("id"): u for u in users if u.get("id")}
        out = []
        for obj in everything:
            obj = dict(obj)
            for field in ("userType", "onPremisesSyncEnabled", "accountEnabled"):
                if obj.get("id") in extra and field in extra[obj["id"]]:
                    obj[field] = extra[obj["id"]][field]
            out.append(obj)
        merged[key] = (out, "ok")
    return merged


def fetch_all_users(graph):
    """Paginated via @odata.nextLink -- Graph enforces its own page-size
    ceiling regardless of $top, so this always follows nextLink rather
    than assume one request is enough."""
    users = []
    url = f"{GRAPH_USERS_URL}?$select={GRAPH_USER_SELECT}&$top={GRAPH_PAGE_SIZE}"
    page = 0
    while url:
        page += 1
        body = graph.get(
            url, f"users (page {page})",
            forbidden_message=(
                "Graph returned HTTP 403 (Forbidden). The application permission "
                "(User.Read.All) is likely either not admin-consented, or -- just "
                "as commonly -- consented under the wrong permission TYPE. Entra "
                "lists 'Delegated permissions' and 'Application permissions' as "
                "two entirely separate sections that can both contain a "
                "permission with this exact same name; only the Application-type "
                "grant works for this script, since it authenticates unattended "
                "(client_credentials) with no signed-in user. In the App "
                "Registration's API permissions blade, confirm User.Read.All is "
                "listed under 'Application permissions' specifically (not "
                "'Delegated permissions'), showing 'Granted for <tenant>'."
            ),
        )
        page_users = body.get("value", [])
        users.extend(page_users)
        log_info(f"  page {page}: {len(page_users)} user(s) ({len(users)} total so far)")
        url = body.get("@odata.nextLink")

    return users


def fetch_directory_roles_with_members(graph):
    """Two-step fetch: list every activated role, then one members call
    per role. /directoryRoles/{id}/members doesn't support $top, but
    @odata.nextLink is still followed if Graph returns one ([v0.5.0];
    previously assumed never to happen) -- following it costs nothing
    when absent and avoids silently truncating a large role.

    A role member can be a user, a group, or a service principal
    (Graph distinguishes these via @odata.type on each returned
    object) -- all three are kept here rather than filtered down to
    users only, since a service principal or group holding Global
    Administrator is a genuinely different, separately worth-knowing
    fact from a human account holding it, not something to silently
    drop.
    """
    body = graph.get(
        GRAPH_DIRECTORY_ROLES_URL, "directory roles",
        forbidden_message=(
            "Graph returned HTTP 403 (Forbidden) fetching directory roles. The "
            "application permission (RoleManagement.Read.Directory) is likely "
            "either not admin-consented, or -- just as commonly -- consented "
            "under the wrong permission TYPE. Entra lists 'Delegated "
            "permissions' and 'Application permissions' as two entirely "
            "separate sections that can both contain a permission with this "
            "exact same name; only the Application-type grant works for this "
            "script, since it authenticates unattended (client_credentials) "
            "with no signed-in user. In the App Registration's API permissions "
            "blade, confirm RoleManagement.Read.Directory is listed under "
            "'Application permissions' specifically (not 'Delegated "
            "permissions'), showing 'Granted for <tenant>'."
        ),
    )
    roles = body.get("value", [])
    log_info(f"  {len(roles)} activated directory role(s) found")

    role_members = []
    member_select = "id,displayName,userPrincipalName,onPremisesSecurityIdentifier,accountEnabled"
    for role in roles:
        # [v0.5.0] A failure here used to log a warning and skip the role.
        # sync_directory_role_members() replaces the whole table, so a
        # skipped role (one throttled call on Global Administrator, say)
        # silently erased that role's rows and every Entra plugin then
        # reported it clean. Now retried by graph.get(), and an exhausted
        # retry aborts the run before anything is written, leaving the
        # previous run's role data in place.
        url = f"{GRAPH_DIRECTORY_ROLES_URL}/{role['id']}/members?$select={member_select}"
        members = []
        while url:
            body = graph.get(url, f"members of directory role '{role.get('displayName')}'")
            members.extend(body.get("value", []))
            url = body.get("@odata.nextLink")
        log_info(f"  role '{role.get('displayName')}': {len(members)} member(s)")
        for member in members:
            role_members.append({"role": role, "member": member, "assignment_type": "active",
                                 "via_group": None, "directory_scope_id": "/"})

    return role_members


def fetch_role_eligibility(graph):
    """[v0.6.0] PIM-eligible directory role assignments. An eligible
    principal holds no permissions until it activates the role, but can do
    so on demand -- so for exposure purposes (who can become Global
    Administrator) it counts like an active member. Returns
    (role_member_entries, status); status is "ok" or why eligibility
    couldn't be read (typically no Entra ID P2 licence)."""
    entries = []
    url = GRAPH_ROLE_ELIGIBILITY_URL
    while url:
        body, status = graph_get_optional(graph, url, "PIM-eligible role assignments")
        if body is None:
            log_warn(f"  PIM-eligible role assignments could not be read ({status}); "
                     f"eligible-only role holders will not be reported.")
            return [], status
        for inst in body.get("value", []):
            principal = inst.get("principal") or {}
            definition = inst.get("roleDefinition") or {}
            if not principal.get("id"):
                continue
            role = {
                "id": inst.get("roleDefinitionId") or definition.get("id"),
                "roleTemplateId": definition.get("templateId") or inst.get("roleDefinitionId"),
                "displayName": definition.get("displayName"),
            }
            entries.append({"role": role, "member": principal, "assignment_type": "eligible",
                            "via_group": None,
                            "directory_scope_id": inst.get("directoryScopeId") or "/"})
        url = body.get("@odata.nextLink")
    log_info(f"  {len(entries)} PIM-eligible role assignment(s) found")
    return entries, "ok"


def expand_group_role_members(graph, role_members):
    """[v0.6.0] A role held by a (role-assignable) group is held by every
    member of that group. Adds one entry per transitive member, tagged
    with the group it comes through (via_group), for every group found
    among active and eligible role members. Returns (entries, status)."""
    member_select = "id,displayName,userPrincipalName,onPremisesSecurityIdentifier,accountEnabled"
    cache = {}
    expanded = []
    status = "ok"
    for rm in role_members:
        group = rm["member"]
        if group.get("@odata.type") != "#microsoft.graph.group":
            continue
        gid = group["id"]
        if gid not in cache:
            members = []
            url = f"{GRAPH_GROUPS_URL}/{gid}/transitiveMembers?$select={member_select}"
            while url:
                body, result = graph_get_optional(
                    graph, url, f"members of role-holding group '{group.get('displayName')}'")
                if body is None:
                    log_warn(f"  Could not expand group '{group.get('displayName')}' ({result}).")
                    status = result
                    members = []
                    break
                members.extend(m for m in body.get("value", [])
                               if m.get("@odata.type") != "#microsoft.graph.group")
                url = body.get("@odata.nextLink")
            cache[gid] = members
        for member in cache[gid]:
            expanded.append({"role": rm["role"], "member": member,
                             "assignment_type": rm["assignment_type"],
                             "via_group": group,
                             "directory_scope_id": rm["directory_scope_id"]})
    if expanded:
        log_info(f"  {len(expanded)} role membership(s) held through role-assignable groups")
    return expanded, status


def fetch_role_assignment_schedules(graph):
    """[v0.7.0] Active role assignment schedule instances, as a list of
    {principal_id, role_definition_id, directory_scope_id, assignment_type,
    start, end, member_type}. Returns (instances, status); instances is None
    (not []) when they couldn't be read -- typically no Entra ID P2 --
    so the caller leaves assignment_kind NULL rather than treating every
    active row as unmatched."""
    instances = []
    url = GRAPH_ROLE_ASSIGNMENT_SCHEDULE_URL
    while url:
        body, status = graph_get_optional(graph, url, "active role assignment schedules")
        if body is None:
            log_warn(f"  Active role assignment schedules could not be read ({status}); "
                     f"whether active role holders are permanent, time-bound or PIM "
                     f"activations will not be recorded.")
            return None, status
        for inst in body.get("value", []):
            if not inst.get("principalId") or not inst.get("roleDefinitionId"):
                continue
            instances.append({
                "principal_id": inst["principalId"].lower(),
                "role_definition_id": inst["roleDefinitionId"].lower(),
                "directory_scope_id": inst.get("directoryScopeId") or "/",
                "assignment_type": inst.get("assignmentType"),
                "start": inst.get("startDateTime"),
                "end": inst.get("endDateTime"),
                "member_type": inst.get("memberType"),
            })
        url = body.get("@odata.nextLink")
    log_info(f"  {len(instances)} active role assignment schedule instance(s) found")
    return instances, "ok"


# [v0.7.0] When one principal has more than one instance for the same role
# and scope, the most durable kind wins (a standing assignment outlives a
# temporary activation).
_ASSIGNMENT_KIND_RANK = {"permanent": 0, "time_bound": 1, "activated": 2}


def _assignment_kind(inst):
    if (inst.get("assignment_type") or "").lower() == "activated":
        return "activated"
    return "permanent" if not inst.get("end") else "time_bound"


def apply_assignment_kinds(role_members, instances):
    """[v0.7.0] Sets assignment_kind/assignment_start/assignment_end on
    every active entry from the schedule instance matching (principal,
    role template, directory scope). Entries held through a group take the
    kind of the group's own instance. Eligible entries, and active ones with
    no matching instance, are left without a kind (stored as NULL). Returns
    the number of active entries classified."""
    best = {}
    for inst in instances or []:
        key = (inst["principal_id"], inst["role_definition_id"], inst["directory_scope_id"])
        kind = _assignment_kind(inst)
        current = best.get(key)
        if current is None or _ASSIGNMENT_KIND_RANK[kind] < _ASSIGNMENT_KIND_RANK[current[0]]:
            best[key] = (kind, inst.get("start"), inst.get("end"))
    classified = 0
    for rm in role_members:
        if rm.get("assignment_type", "active") != "active":
            continue
        holder = (rm.get("via_group") or rm["member"]).get("id") or ""
        template = rm["role"].get("roleTemplateId") or ""
        key = (holder.lower(), template.lower(), rm.get("directory_scope_id", "/"))
        match = best.get(key)
        if match:
            rm["assignment_kind"], rm["assignment_start"], rm["assignment_end"] = match
            classified += 1
    return classified


def fetch_security_defaults(graph):
    """A single object, no pagination -- confirmed against Microsoft's
    own documentation, {"isEnabled": bool, "displayName": ..., "id": ...}."""
    body = graph.get(
        GRAPH_SECURITY_DEFAULTS_URL, "Security Defaults status",
        forbidden_message=(
            "Graph returned HTTP 403 (Forbidden) fetching Security Defaults "
            "status. The application permission (Policy.Read.All) is likely "
            "either not admin-consented, or -- just as commonly -- consented "
            "under the wrong permission TYPE. Entra lists 'Delegated "
            "permissions' and 'Application permissions' as two entirely "
            "separate sections that can both contain a permission with this "
            "exact same name; only the Application-type grant works for this "
            "script, since it authenticates unattended (client_credentials) "
            "with no signed-in user, and admin consent on the Delegated "
            "version won't apply here even though Entra will still show it as "
            "granted. In the App Registration's API permissions blade, confirm "
            "Policy.Read.All is listed under 'Application permissions' "
            "specifically (not 'Delegated permissions'), showing 'Granted for "
            "<tenant>'."
        ),
    )
    return body.get("isEnabled")


def fetch_conditional_access_policies(graph):
    """No documented pagination on this endpoint -- tenants don't
    typically have more than a few dozen CA policies, well under any
    page-size ceiling Graph would otherwise enforce."""
    body = graph.get(
        GRAPH_CA_POLICIES_URL, "Conditional Access policies",
        forbidden_message=(
            "Graph returned HTTP 403 (Forbidden) fetching Conditional Access "
            "policies. The application permission (Policy.Read.All) is likely "
            "either not admin-consented, or -- just as commonly -- consented "
            "under the wrong permission TYPE. Entra lists 'Delegated "
            "permissions' and 'Application permissions' as two entirely "
            "separate sections that can both contain a permission with this "
            "exact same name; only the Application-type grant works for this "
            "script, since it authenticates unattended (client_credentials) "
            "with no signed-in user, and admin consent on the Delegated "
            "version won't apply here even though Entra will still show it as "
            "granted. In the App Registration's API permissions blade, confirm "
            "Policy.Read.All is listed under 'Application permissions' "
            "specifically (not 'Delegated permissions'), showing 'Granted for "
            "<tenant>'."
        ),
    )
    policies = body.get("value", [])
    # [v0.7.0] Follow @odata.nextLink if Graph ever sends one -- costs
    # nothing when absent, and a truncated list would hide policies.
    url = body.get("@odata.nextLink")
    while url:
        body = graph.get(url, "Conditional Access policies (next page)")
        policies.extend(body.get("value", []))
        url = body.get("@odata.nextLink")
    return policies


def fetch_authorization_policy(graph):
    """[v0.7.0] GET /policies/authorizationPolicy (Policy.Read.All).
    Returns (policy_dict, status): the fields named in
    AUTHORIZATION_POLICY_FIELDS / AUTHORIZATION_POLICY_DEFAULT_USER_FIELDS
    (missing ones as None), or (None, "<reason>") when Graph refused --
    the run carries on either way."""
    body, status = graph_get_optional(graph, GRAPH_AUTHORIZATION_POLICY_URL, "authorization policy")
    if body is None:
        log_warn(f"  Authorization policy could not be read ({status}); user consent / "
                 f"app registration / guest settings will not be reported.")
        return None, status
    # v1.0 returns the single policy object; older responses wrapped it in a
    # one-element "value" collection -- accept either.
    if isinstance(body.get("value"), list):
        body = body["value"][0] if body["value"] else {}
    policy = {field: body.get(field) for field in AUTHORIZATION_POLICY_FIELDS}
    defaults = body.get("defaultUserRolePermissions") or {}
    policy["defaultUserRolePermissions"] = {
        field: defaults.get(field) for field in AUTHORIZATION_POLICY_DEFAULT_USER_FIELDS
    }
    return policy, "ok"


def fetch_applications(graph):
    """Paginated the same way fetch_all_users is -- follows @odata.nextLink
    rather than assume one page covers every registration.

    Deliberately does NOT also fetch servicePrincipals or
    oauth2PermissionGrants/appRoleAssignments -- this collector's scope
    for applications is client secret expiry only (see
    GRAPH_APPLICATIONS_URL's own comment for why full permission-grant
    parsing is out of scope for this pass)."""
    apps = []
    # [v0.8.0] More fields, same permission (Application.Read.All).
    select = ("id,appId,displayName,passwordCredentials,keyCredentials,signInAudience,"
              "publisherDomain,verifiedPublisher,web,spa,publicClient,isFallbackPublicClient,"
              "servicePrincipalLockConfiguration,createdDateTime")
    url = f"{GRAPH_APPLICATIONS_URL}?$select={select}&$top=999"
    page = 0
    while url:
        page += 1
        body = graph.get(
            url, f"applications (page {page})",
            forbidden_message=(
                "Graph returned HTTP 403 (Forbidden) fetching applications. The "
                "application permission (Application.Read.All) is likely "
                "either not admin-consented, or -- just as commonly -- "
                "consented under the wrong permission TYPE. Entra lists "
                "'Delegated permissions' and 'Application permissions' as two "
                "entirely separate sections that can both contain a permission "
                "with this exact same name; only the Application-type grant "
                "works for this script, since it authenticates unattended "
                "(client_credentials) with no signed-in user. In the App "
                "Registration's API permissions blade, confirm "
                "Application.Read.All is listed under 'Application "
                "permissions' specifically (not 'Delegated permissions'), "
                "showing 'Granted for <tenant>'."
            ),
        )
        page_apps = body.get("value", [])
        apps.extend(page_apps)
        log_info(f"  page {page}: {len(page_apps)} application(s) ({len(apps)} total so far)")
        url = body.get("@odata.nextLink")
    return apps


def fetch_dangerous_permission_grants(graph):
    """Two Graph calls, not N+1 across every application: (1) fetch
    Microsoft Graph's own service principal, selecting just its id and
    appRoles -- the appRoles collection is Microsoft Graph's complete
    catalog of every application permission that exists for it, each
    with its own appRoleId and human-readable value (e.g.
    "Application.ReadWrite.All") -- giving a GUID-to-name lookup table
    in one response. (2) fetch that service principal's appRoleAssignedTo,
    which returns EVERY grant of ANY Microsoft Graph application
    permission to ANY principal, tenant-wide, already including
    principalDisplayName -- no separate per-application service
    principal lookup needed at all.

    Only returns grants whose resolved permission name is in
    DANGEROUS_GRAPH_PERMISSIONS -- this collector has no interest in
    (and doesn't store) the full, usually much longer list of routine
    permission grants like User.Read.All itself.
    """
    sp_url = f"{GRAPH_SERVICE_PRINCIPALS_URL}?$filter=appId eq '{GRAPH_MSGRAPH_SP_APPID}'&$select=id,appRoles"
    body = graph.get(
        sp_url, "the Microsoft Graph service principal",
        forbidden_message=(
            "Graph returned HTTP 403 (Forbidden) fetching the Microsoft Graph "
            "service principal. The application permission (Directory.Read.All) "
            "is likely either not admin-consented, or -- just as commonly -- "
            "consented under the wrong permission TYPE. Entra lists 'Delegated "
            "permissions' and 'Application permissions' as two entirely "
            "separate sections that can both contain a permission with this "
            "exact same name; only the Application-type grant works for this "
            "script, since it authenticates unattended (client_credentials) "
            "with no signed-in user. In the App Registration's API "
            "permissions blade, confirm Directory.Read.All is listed under "
            "'Application permissions' specifically (not 'Delegated "
            "permissions'), showing 'Granted for <tenant>'."
        ),
    )
    sp_results = body.get("value", [])
    if not sp_results:
        raise CollectorAbort(
            "Could not find Microsoft Graph's own service principal in this "
            "tenant by its well-known appId -- unexpected for any tenant with "
            "at least one app registration ever consented to use Graph."
        )
    graph_sp_id = sp_results[0]["id"]
    role_id_to_name = {
        role["id"]: role.get("value") for role in sp_results[0].get("appRoles", [])
    }

    grants = []
    url = f"{GRAPH_SERVICE_PRINCIPALS_URL}/{graph_sp_id}/appRoleAssignedTo?$top=999"
    while url:
        body = graph.get(url, "Microsoft Graph application permission grants")
        for assignment in body.get("value", []):
            permission_name = role_id_to_name.get(assignment.get("appRoleId"))
            if permission_name in DANGEROUS_GRAPH_PERMISSIONS:
                grants.append({
                    "principal_id": assignment.get("principalId"),
                    "principal_display_name": assignment.get("principalDisplayName"),
                    "principal_type": assignment.get("principalType"),
                    "permission_name": permission_name,
                })
        url = body.get("@odata.nextLink")
    return grants


# ============================================================================
# PostgreSQL
# ============================================================================

def connect_postgres():
    try:
        conn = psycopg2.connect(
            host=PG_HOST, port=PG_PORT, dbname=PG_DBNAME,
            user=PG_USER, password=PG_PASSWORD,
        )
    except psycopg2.OperationalError as exc:
        raise CollectorAbort(f"Could not connect to PostgreSQL: {exc}")
    with conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
    return conn


def resolve_client_id(pg_conn, domain_fqdn=None, client_id_override=None):
    """Looks up the EXISTING client row created by adprofiler.py's own
    LDAP collection -- deliberately does not create a new client row
    here. A Graph-only client with no prior LDAP baseline is a real,
    supportable scenario in principle, but this script's whole value is
    correlating cloud users back to on-prem accounts, which needs that
    baseline to already exist -- so absence is treated as a setup
    error to fix, not silently worked around.

    [v0.4.1] Two changes, both prompted by a real case: an operator
    typed --domain-fqdn PCC-domain.pima.edu (lowercase 'd') when the
    value adprofiler.py actually stored was PCC-Domain.pima.edu
    (capital 'D') -- a one-character casing mismatch against what used
    to be a case-sensitive exact match, producing a "No client found"
    error that looked like a deeper domain-mismatch problem but wasn't.
    First, the domain_fqdn lookup is now case-insensitive (LOWER() on
    both sides) -- AD domain names are not case-sensitive in any
    practical sense, so an exact-case match was never actually
    protecting against anything real, only creating a footgun. Second,
    --client-id is now available as a direct alternative: skips the
    domain_fqdn lookup (and its casing question) entirely for anyone
    who'd rather just supply the GUID from the client table directly."""
    if client_id_override:
        with pg_conn.cursor() as cur:
            cur.execute("SET search_path TO ad_intel, public;")
            cur.execute("SELECT client_id FROM client WHERE client_id = %s;", (client_id_override,))
            row = cur.fetchone()
        if row is None:
            raise CollectorAbort(
                f"No client found for client_id='{client_id_override}'. Double-check "
                "this GUID against the client table's own client_id column."
            )
        return row[0]

    with pg_conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
        cur.execute("SELECT client_id FROM client WHERE lower(domain_fqdn) = lower(%s);", (domain_fqdn,))
        row = cur.fetchone()
    if row is None:
        raise CollectorAbort(
            f"No client found for domain_fqdn='{domain_fqdn}' (case-insensitive "
            "match attempted). This script enriches an existing client record "
            "with cloud email data -- run adprofiler.py against this domain's "
            "on-prem AD at least once first, so there's a client row (and "
            "object_sid values) to correlate Graph users against. If "
            "adprofiler.py has already been run, double-check this value "
            "against the domain name shown at the top of its own output, or "
            "use --client-id instead to bypass this lookup entirely."
        )
    return row[0]


def _assigned_services(user):
    """[v0.8.0] Distinct assignedPlans[].service whose capabilityStatus is
    'Enabled', sorted; [] = unlicensed (v42 entra_user.assigned_services)."""
    return sorted({p.get("service") for p in (user.get("assignedPlans") or [])
                   if p.get("capabilityStatus") == "Enabled" and p.get("service")})


def sync_entra_users(pg_conn, client_id, users):
    """Whole-snapshot replace for this client: delete, then bulk-insert
    fresh rows, both inside one transaction. A partial failure rolls
    back to the PRIOR snapshot rather than leaving a half-updated one --
    stale-but-consistent is a better failure mode here than fresh-but-
    incomplete, given this table has no versioning to fall back on to
    tell the two apart later."""
    now = datetime.now(timezone.utc)
    rows = []
    matched = 0

    with pg_conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")

        # Resolve every user's on-prem match in one query rather than one
        # round-trip per user -- meaningful at scale (thousands of users).
        sids = [u.get("onPremisesSecurityIdentifier") for u in users if u.get("onPremisesSecurityIdentifier")]
        sid_to_guid = {}
        if sids:
            cur.execute(
                "SELECT object_sid, object_guid FROM directory_object "
                "WHERE client_id = %s AND object_sid = ANY(%s);",
                (client_id, sids),
            )
            sid_to_guid = dict(cur.fetchall())

        for u in users:
            on_prem_sid = u.get("onPremisesSecurityIdentifier")
            on_prem_guid = sid_to_guid.get(on_prem_sid)
            if on_prem_guid:
                matched += 1
            rows.append((
                client_id, u["id"], on_prem_guid, u.get("userPrincipalName"),
                u.get("mail"), u.get("proxyAddresses") or None, u.get("accountEnabled"),
                u.get("onPremisesSyncEnabled"), on_prem_sid, u.get("userType"), now,
                # [v0.8.0] schema v42 columns. The three sign-in columns are
                # left NULL here and filled by the optional sign_in_activity
                # pass (sync_sign_in_activity()).
                u.get("displayName"), u.get("createdDateTime"), u.get("passwordPolicies"),
                u.get("lastPasswordChangeDateTime"), u.get("externalUserState"),
                u.get("externalUserStateChangeDateTime"), u.get("onPremisesLastSyncDateTime"),
                _assigned_services(u),
            ))

        cur.execute("DELETE FROM entra_user WHERE client_id = %s;", (client_id,))
        if rows:
            psycopg2.extras.execute_values(
                cur,
                """
                INSERT INTO entra_user
                    (client_id, entra_object_id, on_prem_object_guid, user_principal_name,
                     mail, proxy_addresses, account_enabled, on_premises_sync_enabled,
                     on_premises_security_identifier, user_type, collected_at,
                     display_name, created_at, password_policies, last_password_change_at,
                     external_user_state, external_user_state_changed_at,
                     on_premises_last_sync_at, assigned_services)
                VALUES %s
                """,
                rows,
            )
    pg_conn.commit()
    return len(users), matched


def sync_directory_role_members(pg_conn, client_id, role_members, collected_at=None):
    """Same whole-snapshot-replace pattern as sync_entra_users, same
    reasoning. A member can be a user, group, or service principal --
    @odata.type distinguishes them; only users carry
    onPremisesSecurityIdentifier at all, so on-prem correlation is
    naturally None for the other two rather than needing special-cased
    logic to skip them. [v0.7.0] Also writes assignment_kind/start/end
    (set by apply_assignment_kinds(); NULL when not determined)."""
    now = collected_at or datetime.now(timezone.utc)
    rows = []

    with pg_conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")

        sids = [rm["member"].get("onPremisesSecurityIdentifier") for rm in role_members
                if rm["member"].get("onPremisesSecurityIdentifier")]
        sid_to_guid = {}
        if sids:
            cur.execute(
                "SELECT object_sid, object_guid FROM directory_object "
                "WHERE client_id = %s AND object_sid = ANY(%s);",
                (client_id, sids),
            )
            sid_to_guid = dict(cur.fetchall())

        seen = set()
        for rm in role_members:
            role, member = rm["role"], rm["member"]
            via = rm.get("via_group") or {}
            key = (role["id"], member["id"], rm.get("assignment_type", "active"),
                   via.get("id"), rm.get("directory_scope_id", "/"))
            if key in seen:
                continue
            seen.add(key)
            on_prem_sid = member.get("onPremisesSecurityIdentifier")
            rows.append((
                client_id, role["id"], role.get("roleTemplateId"), role.get("displayName"),
                member["id"], member.get("@odata.type"), member.get("displayName"),
                member.get("userPrincipalName"), sid_to_guid.get(on_prem_sid),
                on_prem_sid, member.get("accountEnabled"), now,
                rm.get("assignment_type", "active"), via.get("id"), via.get("displayName"),
                rm.get("directory_scope_id", "/"),
                rm.get("assignment_kind"), rm.get("assignment_start"), rm.get("assignment_end"),
            ))

        cur.execute("DELETE FROM entra_directory_role_member WHERE client_id = %s;", (client_id,))
        if rows:
            psycopg2.extras.execute_values(
                cur,
                """
                INSERT INTO entra_directory_role_member
                    (client_id, role_id, role_template_id, role_display_name,
                     member_id, member_type, member_display_name, member_upn,
                     on_prem_object_guid, on_premises_security_identifier,
                     account_enabled, collected_at,
                     assignment_type, via_group_id, via_group_display_name, directory_scope_id,
                     assignment_kind, assignment_start, assignment_end)
                VALUES %s
                """,
                rows,
            )
    pg_conn.commit()
    return len(rows)


def sync_role_assignment_history(pg_conn, client_id, role_members, collected_at):
    """[v0.7.0] Upserts one entra_role_assignment_history row per distinct
    (role template, member, assignment type) in this run's role-member data
    -- direct members, groups that hold a role, and the groups' members
    alike. first_seen_at is set only when the row is new; last_seen_at and
    the display fields are refreshed every run. Rows are never deleted, so
    "first seen recently" means a newly granted assignment (plugin 11020).
    Only called after role membership was read and stored successfully: an
    aborted read never reaches here, so it can't make every assignment look
    new (or old) on the next run."""
    distinct = {}
    for rm in role_members:
        role, member = rm["role"], rm["member"]
        if not role.get("roleTemplateId") or not member.get("id"):
            continue
        key = (role["roleTemplateId"].lower(), member["id"].lower(),
               rm.get("assignment_type", "active"))
        if key not in distinct:
            distinct[key] = (client_id, key[0], role.get("displayName"), key[1],
                             member.get("displayName"), member.get("userPrincipalName"),
                             member.get("@odata.type"), key[2], collected_at, collected_at)
    with pg_conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
        if distinct:
            psycopg2.extras.execute_values(
                cur,
                """
                INSERT INTO entra_role_assignment_history
                    (client_id, role_template_id, role_display_name, member_id,
                     member_display_name, member_upn, member_type, assignment_type,
                     first_seen_at, last_seen_at)
                VALUES %s
                ON CONFLICT (client_id, role_template_id, member_id, assignment_type) DO UPDATE SET
                    last_seen_at = EXCLUDED.last_seen_at,
                    role_display_name = COALESCE(EXCLUDED.role_display_name,
                                                 entra_role_assignment_history.role_display_name),
                    member_display_name = COALESCE(EXCLUDED.member_display_name,
                                                   entra_role_assignment_history.member_display_name),
                    member_upn = COALESCE(EXCLUDED.member_upn,
                                          entra_role_assignment_history.member_upn),
                    member_type = COALESCE(EXCLUDED.member_type,
                                           entra_role_assignment_history.member_type)
                """,
                list(distinct.values()),
            )
    pg_conn.commit()
    return len(distinct)


def _strip_odata_annotations(value):
    """[v0.7.0] Drops Graph's "@odata.*" / "x@odata.context" annotation keys
    (response metadata, not policy content) from nested dicts/lists."""
    if isinstance(value, dict):
        return {k: _strip_odata_annotations(v) for k, v in value.items() if "@odata." not in k}
    if isinstance(value, list):
        return [_strip_odata_annotations(v) for v in value]
    return value


def _strip_odata_keep_type(value):
    """[v0.8.0] Like _strip_odata_annotations() but keeps every "@odata.type"
    key: entra_tenant_setting / entra_cross_tenant_partner content (schema
    v42) holds polymorphic objects whose type is the meaning -- e.g.
    deviceRegistrationPolicy azureADJoin.allowedToJoin is
    allDeviceRegistrationMembership ("everyone") or
    noDeviceRegistrationMembership ("nobody"), both otherwise {}."""
    if isinstance(value, dict):
        return {k: _strip_odata_keep_type(v) for k, v in value.items()
                if k == "@odata.type" or "@odata." not in k}
    if isinstance(value, list):
        return [_strip_odata_keep_type(v) for v in value]
    return value


def _slim_ca_policy(p):
    """[v0.7.0] One stored ca_policies element: id, display_name, state,
    grant_controls (unchanged shape -- plugin 10004 reads builtInControls,
    operator, authenticationStrength, customAuthenticationFactors), plus
    conditions and session_controls as Graph returns them. Graph's own
    timestamps (createdDateTime/modifiedDateTime) are left out so an
    unchanged policy stores identically run to run."""
    grant = _strip_odata_annotations(p.get("grantControls"))
    if isinstance(grant, dict) and isinstance(grant.get("authenticationStrength"), dict):
        strength = grant["authenticationStrength"]
        grant["authenticationStrength"] = {
            "id": strength.get("id"), "displayName": strength.get("displayName"),
            "allowedCombinations": strength.get("allowedCombinations"),
        }
    return {
        "id": p.get("id"), "display_name": p.get("displayName"), "state": p.get("state"),
        "grant_controls": grant,
        "conditions": _strip_odata_annotations(p.get("conditions")),
        "session_controls": _strip_odata_annotations(p.get("sessionControls")),
    }


def sync_security_posture(pg_conn, client_id, security_defaults_enabled, ca_policies,
                          role_eligibility_status=None, group_expansion_status=None,
                          authorization_policy=None, authorization_policy_status=None,
                          role_schedule_status=None):
    """Combines both into one row per client, same snapshot-replace
    philosophy as entra_user -- these two facts are only ever meaningful
    together (see plugin 10004's own docstring for why), so storing them
    jointly avoids a join for what's fundamentally one finding's worth
    of input. ca_policies stored as a JSONB array of the fields plugins
    use (see _slim_ca_policy()) rather than the full Graph response.
    [v0.7.0] Each policy now also keeps its conditions (users,
    applications, client app types, platforms, locations, risk levels...)
    and session controls, so plugins can tell who and what a policy
    actually covers. Also stores the authorization policy (NULL when it
    couldn't be read) and the read status of it and of the active role
    assignment schedules."""
    now = datetime.now(timezone.utc)
    slim_policies = [_slim_ca_policy(p) for p in ca_policies]
    with pg_conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
        cur.execute("DELETE FROM entra_security_posture WHERE client_id = %s;", (client_id,))
        cur.execute(
            """
            INSERT INTO entra_security_posture
                (client_id, security_defaults_enabled, ca_policies, collected_at,
                 role_eligibility_status, group_expansion_status,
                 authorization_policy, authorization_policy_status, role_schedule_status)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
            """,
            (client_id, security_defaults_enabled, json.dumps(slim_policies), now,
             role_eligibility_status, group_expansion_status,
             json.dumps(authorization_policy) if authorization_policy is not None else None,
             authorization_policy_status, role_schedule_status),
        )
    pg_conn.commit()
    return len(slim_policies)


def _key_credential(c):
    """[v0.8.0] One certificate credential as stored (v42
    entra_application.key_credentials element shape, plus
    custom_key_identifier)."""
    return {
        "key_id": c.get("keyId"), "display_name": c.get("displayName"), "type": c.get("type"),
        "usage": c.get("usage"), "start_date_time": c.get("startDateTime"),
        "end_date_time": c.get("endDateTime"),
        # [v0.8.0] Graph customKeyIdentifier (base64 as returned, or null):
        # a SAML SSO app's signing certificate and its password credential
        # share it, so plugins can recognise that pair (plugin 10060).
        "custom_key_identifier": c.get("customKeyIdentifier"),
    }


def _sp_password_credential(c):
    """[v0.8.0] One secret on a service principal: the key_credentials
    element shape (type/usage null for secrets) plus hint (v42
    entra_service_principal comment)."""
    return {
        "key_id": c.get("keyId"), "display_name": c.get("displayName"), "type": None,
        "usage": None, "start_date_time": c.get("startDateTime"),
        "end_date_time": c.get("endDateTime"), "hint": c.get("hint"),
        "custom_key_identifier": c.get("customKeyIdentifier"),
    }


def sync_applications(pg_conn, client_id, applications):
    """Same whole-snapshot-replace pattern as sync_entra_users. Password
    credentials kept as a JSONB array per application (endDateTime is
    the field plugin 10005 actually needs; the rest -- displayName,
    hint, keyId -- kept for evidence display, matching the same
    "keep enough for a human to act on the finding" reasoning as
    ad_ntauth_store's certificate parsing)."""
    now = datetime.now(timezone.utc)
    rows = []
    for app in applications:
        creds = [
            {
                "display_name": c.get("displayName"), "key_id": c.get("keyId"),
                "hint": c.get("hint"), "end_date_time": c.get("endDateTime"),
                "start_date_time": c.get("startDateTime"),
                # [v0.8.0] see _key_credential().
                "custom_key_identifier": c.get("customKeyIdentifier"),
            }
            for c in (app.get("passwordCredentials") or [])
        ]
        # [v0.8.0] schema v42 columns.
        web = app.get("web") or {}
        implicit = web.get("implicitGrantSettings") or {}
        lock = app.get("servicePrincipalLockConfiguration")
        rows.append((
            client_id, app["id"], app.get("appId"), app.get("displayName"),
            json.dumps(creds), len(app.get("keyCredentials") or []), now,
            json.dumps([_key_credential(c) for c in (app.get("keyCredentials") or [])]),
            app.get("signInAudience"), app.get("publisherDomain"),
            (app.get("verifiedPublisher") or {}).get("displayName"),
            web.get("redirectUris") if app.get("web") is not None else None,
            (app.get("spa") or {}).get("redirectUris") if app.get("spa") is not None else None,
            ((app.get("publicClient") or {}).get("redirectUris")
             if app.get("publicClient") is not None else None),
            implicit.get("enableAccessTokenIssuance"), implicit.get("enableIdTokenIssuance"),
            app.get("isFallbackPublicClient"),
            lock.get("isEnabled") if isinstance(lock, dict) else None,
            app.get("createdDateTime"),
        ))

    with pg_conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
        cur.execute("DELETE FROM entra_application WHERE client_id = %s;", (client_id,))
        if rows:
            psycopg2.extras.execute_values(
                cur,
                """
                INSERT INTO entra_application
                    (client_id, entra_object_id, app_id, display_name,
                     password_credentials, key_credential_count, collected_at,
                     key_credentials, sign_in_audience, publisher_domain,
                     verified_publisher_name, web_redirect_uris, spa_redirect_uris,
                     public_client_redirect_uris, implicit_access_token_issuance,
                     implicit_id_token_issuance, is_fallback_public_client,
                     service_principal_lock_enabled, created_at)
                VALUES %s
                """,
                rows,
            )
    pg_conn.commit()
    return len(rows)


def sync_dangerous_permission_grants(pg_conn, client_id, grants):
    """Same snapshot-replace pattern as everything else in this
    collector. principal_id here is a service principal's object id
    (the grantee, i.e. the app that HAS the dangerous permission) --
    not directly comparable to entra_application.entra_object_id
    (an application object's id, a different object from its own
    service principal) or on-prem data at all. No cross-referencing
    attempted here beyond principalDisplayName, already included in
    Graph's own response -- resolving principal_id to a specific
    application registration would need a further servicePrincipal-to-
    application join this pass doesn't build."""
    now = datetime.now(timezone.utc)
    rows = [
        (client_id, g["principal_id"], g["principal_display_name"],
         g["principal_type"], g["permission_name"], now)
        for g in grants
    ]
    with pg_conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
        cur.execute("DELETE FROM entra_dangerous_permission_grant WHERE client_id = %s;", (client_id,))
        if rows:
            psycopg2.extras.execute_values(
                cur,
                """
                INSERT INTO entra_dangerous_permission_grant
                    (client_id, principal_id, principal_display_name,
                     principal_type, permission_name, collected_at)
                VALUES %s
                """,
                rows,
            )
    pg_conn.commit()
    return len(rows)


# ============================================================================
# [v0.8.0] Optional data sources (schema v42)
#
# Each source is a collect_<source>(graph, ctx) -> (data, status) and a
# write_<source>(cur, client_id, now, data). run_optional_sources() runs them
# in OPTIONAL_SOURCES order; per source, in one transaction, it removes the
# source's rows for the client (SOURCE_CLEAR_SQL), writes the new rows when
# the read was 'ok', upserts entra_collection_status, and commits. A
# non-'ok' read therefore leaves no stale rows that could pass for current
# data. Failures other than 400/403/404 abort the run, as in the core steps.
# ============================================================================

def _setting_clear(*names):
    quoted = ", ".join(f"'{n}'" for n in names)
    return [f"DELETE FROM entra_tenant_setting WHERE client_id = %s AND setting_name IN ({quoted});"]


SOURCE_CLEAR_SQL = {
    "sign_in_activity": [
        "UPDATE entra_user SET last_sign_in_at = NULL, last_non_interactive_sign_in_at = NULL, "
        "last_successful_sign_in_at = NULL WHERE client_id = %s;"],
    "subscribed_skus": ["DELETE FROM entra_tenant_license WHERE client_id = %s;"],
    "organization": _setting_clear("organization"),
    "domains": ["DELETE FROM entra_domain WHERE client_id = %s;"],
    "federation": ["DELETE FROM entra_domain_federation WHERE client_id = %s;"],
    "service_principals": ["DELETE FROM entra_service_principal WHERE client_id = %s;"],
    "sp_sign_in_activity": [
        "UPDATE entra_service_principal SET last_sign_in_activity_at = NULL WHERE client_id = %s;"],
    "app_role_grants": ["DELETE FROM entra_app_role_grant WHERE client_id = %s;"],
    "delegated_grants": ["DELETE FROM entra_delegated_grant WHERE client_id = %s;"],
    "app_owners": ["DELETE FROM entra_app_owner WHERE client_id = %s;"],
    "groups": ["DELETE FROM entra_group_member WHERE client_id = %s;",
               "DELETE FROM entra_group_owner WHERE client_id = %s;",
               "DELETE FROM entra_group WHERE client_id = %s;"],
    "role_definitions": ["DELETE FROM entra_role_definition WHERE client_id = %s;"],
    "custom_role_assignments": ["DELETE FROM entra_custom_role_assignment WHERE client_id = %s;"],
    "pim_policies": ["DELETE FROM entra_role_management_policy WHERE client_id = %s;"],
    "named_locations": ["DELETE FROM entra_named_location WHERE client_id = %s;"],
    "auth_methods_policy": _setting_clear("auth_methods_policy"),
    "cross_tenant_policy": _setting_clear("cross_tenant_default") + [
        "DELETE FROM entra_cross_tenant_partner WHERE client_id = %s;"],
    "admin_consent_request_policy": _setting_clear("admin_consent_request_policy"),
    "directory_settings": _setting_clear("password_rule_settings", "group_unified_settings"),
    "device_registration_policy": _setting_clear("device_registration_policy"),
    "onprem_sync": _setting_clear("onprem_sync"),
    "pta_agents": ["DELETE FROM entra_pta_agent WHERE client_id = %s;"],
    "partner_contracts": ["DELETE FROM entra_partner_contract WHERE client_id = %s;"],
    "registration_details": ["DELETE FROM entra_user_registration WHERE client_id = %s;"],
    "risky_users": ["DELETE FROM entra_risky_user WHERE client_id = %s;"],
    "risk_detections": ["DELETE FROM entra_risk_detection WHERE client_id = %s;"],
}


def _lower(value):
    return value.lower() if isinstance(value, str) else value


def _insert_dicts(cur, table, client_id, now, rows, jsonb=()):
    """[v0.8.0] Bulk-inserts row dicts (all with the same keys) plus
    client_id and collected_at. Keys named in jsonb are sent as JSON."""
    if not rows:
        return 0
    columns = list(rows[0].keys())
    values = [
        tuple([client_id] + [psycopg2.extras.Json(r[c]) if c in jsonb else r[c] for c in columns] + [now])
        for r in rows
    ]
    psycopg2.extras.execute_values(
        cur,
        f"INSERT INTO {table} (client_id, {', '.join(columns)}, collected_at) VALUES %s",
        values,
    )
    return len(rows)


def _update_from_values(cur, sql_template, client_id, rows):
    """[v0.8.0] execute_values() for an UPDATE ... FROM (VALUES %%s) whose
    WHERE also needs client_id: client_id is bound first via mogrify."""
    if not rows:
        return
    sql = cur.mogrify(sql_template, (client_id,)).decode()
    psycopg2.extras.execute_values(cur, sql, rows)


def _put_setting(cur, client_id, now, name, content):
    """content is already free of @odata annotations except nested
    "@odata.type" (_strip_odata_keep_type())."""
    cur.execute(
        "INSERT INTO entra_tenant_setting (client_id, setting_name, content, collected_at) "
        "VALUES (%s, %s, %s, %s);",
        (client_id, name, json.dumps(content, default=str), now),
    )


def _dedupe(rows, key_fields):
    """Keeps the first row per primary key (Graph can list one object twice
    across pages or through several paths)."""
    seen, out = set(), []
    for r in rows:
        key = tuple(_lower(r[k]) if isinstance(r[k], str) else r[k] for k in key_fields)
        if key in seen:
            continue
        seen.add(key)
        out.append(r)
    return out


def _skipped(source, status):
    return f"skipped: {source} not read ({status})"


# ---- users: sign-in activity (separate optional pass) ----------------------

def collect_sign_in_activity(graph, ctx):
    """[v0.8.0] /users?$select=id,signInActivity (AuditLog.Read.All +
    Entra ID P1). Kept out of the core /users select: without the
    permission or licence Graph fails the whole call. $top=120 is the page
    ceiling Graph has documented for signInActivity reads (nextLink is
    followed either way)."""
    users, status = graph_get_all_optional(
        graph, f"{GRAPH_USERS_URL}?$select=id,signInActivity&$top=120", "user sign-in activity")
    if users is None:
        return None, status
    activity = {}
    for u in users:
        a = u.get("signInActivity") or {}
        if u.get("id"):
            activity[u["id"]] = (a.get("lastSignInDateTime"), a.get("lastNonInteractiveSignInDateTime"),
                                 a.get("lastSuccessfulSignInDateTime"))
    return activity, "ok"


def write_sign_in_activity(cur, client_id, now, data):
    rows = [(uid, a, b, c) for uid, (a, b, c) in data.items() if a or b or c]
    _update_from_values(
        cur,
        "UPDATE entra_user u SET last_sign_in_at = v.a::timestamptz, "
        "last_non_interactive_sign_in_at = v.b::timestamptz, "
        "last_successful_sign_in_at = v.c::timestamptz "
        "FROM (VALUES %%s) AS v(id, a, b, c) "
        "WHERE u.client_id = %s AND u.entra_object_id = v.id::uuid",
        client_id, rows,
    )
    return len(rows)


# ---- licences, organization, domains, federation ---------------------------

def collect_subscribed_skus(graph, ctx):
    skus, status = graph_get_all_optional(graph, GRAPH_SUBSCRIBED_SKUS_URL, "subscribed SKUs (licences)")
    if skus is None:
        return None, status
    rows = [{
        "sku_id": s.get("skuId"), "sku_part_number": s.get("skuPartNumber"),
        "capability_status": s.get("capabilityStatus"),
        "enabled_units": (s.get("prepaidUnits") or {}).get("enabled"),
        "consumed_units": s.get("consumedUnits"),
        "service_plans": sorted({p.get("servicePlanName") for p in (s.get("servicePlans") or [])
                                 if p.get("provisioningStatus") == "Success" and p.get("servicePlanName")}),
    } for s in skus if s.get("skuId")]
    return _dedupe(rows, ["sku_id"]), "ok"


def write_subscribed_skus(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_tenant_license", client_id, now, data)


ORGANIZATION_FIELDS = ("id", "displayName", "onPremisesSyncEnabled", "onPremisesLastSyncDateTime",
                       "verifiedDomains", "createdDateTime")


def collect_organization(graph, ctx):
    orgs, status = graph_get_all_optional(graph, GRAPH_ORGANIZATION_URL, "organization")
    if orgs is None:
        return None, status
    if not orgs:
        return None, "ok"
    return {f: _strip_odata_keep_type(orgs[0].get(f)) for f in ORGANIZATION_FIELDS}, "ok"


def write_organization(cur, client_id, now, data):
    if data is None:
        return 0
    _put_setting(cur, client_id, now, "organization", data)
    return 1


def collect_domains(graph, ctx):
    domains, status = graph_get_all_optional(graph, GRAPH_DOMAINS_URL, "domains")
    if domains is None:
        return None, status
    rows = [{
        "domain_name": d.get("id"), "authentication_type": d.get("authenticationType"),
        "is_verified": d.get("isVerified"), "is_default": d.get("isDefault"),
        "is_initial": d.get("isInitial"), "is_root": d.get("isRoot"),
        "password_validity_period_days": d.get("passwordValidityPeriodInDays"),
        "supported_services": d.get("supportedServices") or [],
    } for d in domains if d.get("id")]
    return _dedupe(rows, ["domain_name"]), "ok"


def write_domains(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_domain", client_id, now, data)


def _parse_certificate(b64):
    """[v0.8.0] (thumbprint, subject, not_before, not_after) of a base64 DER
    certificate as Graph returns it in signingCertificate /
    nextSigningCertificate: thumbprint is the upper-case hex SHA-1 of the
    DER, subject in RFC 4514 form. The thumbprint needs only the DER; the
    other fields need the cryptography package and stay None (no abort)
    when it is missing or the certificate does not parse."""
    if not b64:
        return None, None, None, None
    try:
        der = base64.b64decode("".join(str(b64).split()), validate=True)
    except (ValueError, TypeError):
        return None, None, None, None
    thumbprint = hashlib.sha1(der).hexdigest().upper()
    try:
        from cryptography import x509
        cert = x509.load_der_x509_certificate(der)
        not_before = getattr(cert, "not_valid_before_utc", None) or \
            cert.not_valid_before.replace(tzinfo=timezone.utc)
        not_after = getattr(cert, "not_valid_after_utc", None) or \
            cert.not_valid_after.replace(tzinfo=timezone.utc)
        return thumbprint, cert.subject.rfc4514_string(), not_before, not_after
    except Exception as exc:  # any parse problem leaves the parsed fields NULL
        log_warn(f"  Could not parse a federation signing certificate ({type(exc).__name__}); "
                 f"its subject and validity dates are left empty.")
        return None, None, None, None


def collect_federation(graph, ctx):
    """[v0.8.0] internalDomainFederation of each Federated domain
    (/domains/{id}/federationConfiguration, Domain.Read.All). A 404 for one
    domain (no configuration object) gives no row for it; any other refusal
    fails the source. No federated domains: 'ok' with no rows."""
    if ctx["statuses"].get("domains") != "ok":
        return None, _skipped("domains", ctx["statuses"].get("domains"))
    rows = []
    for d in ctx["data"]["domains"]:
        if (d.get("authentication_type") or "").lower() != "federated":
            continue
        name = d["domain_name"]
        configs, status = graph_get_all_optional(
            graph, f"{GRAPH_DOMAINS_URL}/{name}/federationConfiguration",
            f"federation configuration of {name}")
        if configs is None:
            if status.startswith("HTTP 404"):
                log_warn(f"  No federation configuration returned for federated domain {name} ({status}).")
                continue
            return None, status
        for fc in configs:
            thumb, subject, not_before, not_after = _parse_certificate(fc.get("signingCertificate"))
            next_thumb, _subj, _nb, next_not_after = _parse_certificate(fc.get("nextSigningCertificate"))
            rows.append({
                "domain_name": name, "federation_id": fc.get("id") or name,
                "display_name": fc.get("displayName"), "issuer_uri": fc.get("issuerUri"),
                "passive_sign_in_uri": fc.get("passiveSignInUri"),
                "active_sign_in_uri": fc.get("activeSignInUri"),
                "sign_out_uri": fc.get("signOutUri"),
                "metadata_exchange_uri": fc.get("metadataExchangeUri"),
                "preferred_authentication_protocol": fc.get("preferredAuthenticationProtocol"),
                "federated_idp_mfa_behavior": fc.get("federatedIdpMfaBehavior"),
                "prompt_login_behavior": fc.get("promptLoginBehavior"),
                "is_signed_authentication_request_required": fc.get("isSignedAuthenticationRequestRequired"),
                "signing_certificate_thumbprint": thumb, "signing_certificate_subject": subject,
                "signing_certificate_not_before": not_before, "signing_certificate_not_after": not_after,
                "next_signing_certificate_thumbprint": next_thumb,
                "next_signing_certificate_not_after": next_not_after,
            })
    return _dedupe(rows, ["domain_name", "federation_id"]), "ok"


def write_federation(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_domain_federation", client_id, now, data)


# ---- service principals, sign-in activity, grants, owners ------------------

GRAPH_SP_SELECT = (
    "id,appId,displayName,servicePrincipalType,appOwnerOrganizationId,publisherName,"
    "verifiedPublisher,signInAudience,accountEnabled,appRoleAssignmentRequired,"
    "preferredSingleSignOnMode,passwordCredentials,keyCredentials,tags"
)


def collect_service_principals(graph, ctx):
    sps, status = graph_get_all_optional(
        graph, f"{GRAPH_SERVICE_PRINCIPALS_URL}?$select={GRAPH_SP_SELECT}&$top=999", "service principals")
    if sps is None:
        return None, status
    rows = [{
        "entra_object_id": sp.get("id"), "app_id": sp.get("appId"),
        "display_name": sp.get("displayName"),
        "service_principal_type": sp.get("servicePrincipalType"),
        "app_owner_organization_id": sp.get("appOwnerOrganizationId"),
        "publisher_name": sp.get("publisherName"),
        "verified_publisher_name": (sp.get("verifiedPublisher") or {}).get("displayName"),
        "sign_in_audience": sp.get("signInAudience"), "account_enabled": sp.get("accountEnabled"),
        "app_role_assignment_required": sp.get("appRoleAssignmentRequired"),
        "preferred_single_sign_on_mode": sp.get("preferredSingleSignOnMode"),
        "password_credentials": [_sp_password_credential(c) for c in (sp.get("passwordCredentials") or [])],
        "key_credentials": [_key_credential(c) for c in (sp.get("keyCredentials") or [])],
        "tags": sp.get("tags") or [],
    } for sp in sps if sp.get("id")]
    return _dedupe(rows, ["entra_object_id"]), "ok"


def write_service_principals(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_service_principal", client_id, now, data,
                         jsonb=("password_credentials", "key_credentials"))


def collect_sp_sign_in_activity(graph, ctx):
    """[v0.8.0] beta /reports/servicePrincipalSignInActivities
    (AuditLog.Read.All + P1), matched to service principals by appId.
    Beta: may change without notice."""
    if ctx["statuses"].get("service_principals") != "ok":
        return None, _skipped("service_principals", ctx["statuses"].get("service_principals"))
    items, status = graph_get_all_optional(graph, GRAPH_SP_SIGN_IN_ACTIVITY_URL,
                                           "service principal sign-in activity (beta)")
    if items is None:
        return None, status
    latest = {}
    for item in items:
        app_id = _lower(item.get("appId"))
        when = (item.get("lastSignInActivity") or {}).get("lastSignInDateTime")
        if app_id and when and (app_id not in latest or when > latest[app_id]):
            latest[app_id] = when
    return latest, "ok"


def write_sp_sign_in_activity(cur, client_id, now, data):
    rows = list(data.items())
    _update_from_values(
        cur,
        "UPDATE entra_service_principal s SET last_sign_in_activity_at = v.ts::timestamptz "
        "FROM (VALUES %%s) AS v(app_id, ts) "
        "WHERE s.client_id = %s AND s.app_id = v.app_id::uuid",
        client_id, rows,
    )
    return len(rows)


def collect_app_role_grants(graph, ctx):
    """[v0.8.0] Every appRoleAssignedTo on each resource API in
    APP_ROLE_GRANT_RESOURCE_APP_IDS present in the tenant (Directory.Read.All,
    as for the dangerous-grant step, which is kept unchanged)."""
    rows = []
    for resource_app_id in APP_ROLE_GRANT_RESOURCE_APP_IDS:
        sps, status = graph_get_all_optional(
            graph, f"{GRAPH_SERVICE_PRINCIPALS_URL}?$filter=appId eq '{resource_app_id}'"
                   f"&$select=id,appId,displayName,appRoles",
            f"resource service principal {resource_app_id}")
        if sps is None:
            return None, status
        if not sps:
            continue
        resource = sps[0]
        role_names = {_lower(r.get("id")): r.get("value") for r in (resource.get("appRoles") or [])}
        assignments, status = graph_get_all_optional(
            graph, f"{GRAPH_SERVICE_PRINCIPALS_URL}/{resource['id']}/appRoleAssignedTo?$top=999",
            f"application permissions granted on {resource.get('displayName') or resource_app_id}")
        if assignments is None:
            return None, status
        for a in assignments:
            role_id = _lower(a.get("appRoleId"))
            rows.append({
                "assignment_id": a.get("id"), "principal_id": a.get("principalId"),
                "principal_display_name": a.get("principalDisplayName"),
                "principal_type": a.get("principalType"),
                "resource_id": resource["id"], "resource_app_id": resource.get("appId") or resource_app_id,
                "resource_display_name": resource.get("displayName"),
                "permission_id": role_id,
                "permission_name": None if role_id == DEFAULT_ACCESS_APP_ROLE_ID else role_names.get(role_id),
            })
    return _dedupe([r for r in rows if r["assignment_id"] and r["principal_id"]], ["assignment_id"]), "ok"


def write_app_role_grants(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_app_role_grant", client_id, now, data)


def collect_delegated_grants(graph, ctx):
    """[v0.8.0] /oauth2PermissionGrants (Directory.Read.All). Client and
    resource service principals resolved from this run's service principal
    inventory, or -- when that source was not read -- by looking each
    distinct one up (left NULL if that fails too). principal_upn from the
    users read this run."""
    grants, status = graph_get_all_optional(graph, GRAPH_OAUTH2_GRANTS_URL, "delegated permission grants")
    if grants is None:
        return None, status
    sp_index = {}
    if ctx["statuses"].get("service_principals") == "ok":
        sp_index = {_lower(sp["entra_object_id"]): (sp["app_id"], sp["display_name"])
                    for sp in ctx["data"]["service_principals"]}
    for sp_id in sorted({_lower(g.get(k)) for g in grants for k in ("clientId", "resourceId") if g.get(k)}):
        if sp_id in sp_index:
            continue
        body, _st = graph_get_optional(
            graph, f"{GRAPH_SERVICE_PRINCIPALS_URL}/{sp_id}?$select=id,appId,displayName",
            f"service principal {sp_id}")
        sp_index[sp_id] = (body.get("appId"), body.get("displayName")) if body else (None, None)
    upns = {_lower(u.get("id")): u.get("userPrincipalName") for u in ctx["users"]}
    rows = []
    for g in grants:
        if not g.get("id") or not g.get("clientId") or not g.get("resourceId"):
            continue
        client = sp_index.get(_lower(g["clientId"]), (None, None))
        resource = sp_index.get(_lower(g["resourceId"]), (None, None))
        rows.append({
            "grant_id": g["id"], "client_sp_id": g["clientId"], "client_display_name": client[1],
            "consent_type": g.get("consentType"), "principal_id": g.get("principalId"),
            "principal_upn": upns.get(_lower(g.get("principalId"))) if g.get("principalId") else None,
            "resource_sp_id": g["resourceId"], "resource_app_id": resource[0],
            "resource_display_name": resource[1],
            "scopes": [s for s in (g.get("scope") or "").split(" ") if s],
        })
    return _dedupe(rows, ["grant_id"]), "ok"


def write_delegated_grants(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_delegated_grant", client_id, now, data)


def _owner_fields(owner, prefix="owner"):
    return {
        f"{prefix}_id": owner.get("id"), f"{prefix}_type": owner.get("@odata.type"),
        f"{prefix}_display_name": owner.get("displayName"),
        f"{prefix}_upn": owner.get("userPrincipalName"),
        f"{prefix}_user_type": owner.get("userType"),
        f"{prefix}_on_premises_sync_enabled": owner.get("onPremisesSyncEnabled"),
        f"{prefix}_account_enabled": owner.get("accountEnabled"),
    }


def collect_app_owners(graph, ctx):
    """[v0.8.0] Owners of every application registration and of every
    service principal not owned by a Microsoft tenant, via JSON batching.
    One object's 403/404 is skipped with a warning (and its owners are not
    closed in change history); if every object fails, the source fails."""
    if ctx["statuses"].get("service_principals") != "ok":
        return None, _skipped("service_principals", ctx["statuses"].get("service_principals"))
    owned = {}
    for app in ctx["applications"]:
        if app.get("id"):
            owned[app["id"]] = ("application", app.get("appId"), app.get("displayName"),
                                f"/applications/{app['id']}/owners")
    for sp in ctx["data"]["service_principals"]:
        if _lower(sp.get("app_owner_organization_id")) in MICROSOFT_TENANT_IDS:
            continue
        owned[sp["entra_object_id"]] = ("servicePrincipal", sp.get("app_id"), sp.get("display_name"),
                                        f"/servicePrincipals/{sp['entra_object_id']}/owners")
    results = graph_batch_directory_objects(
        graph, [(oid, info[3]) for oid, info in owned.items()], "application / service principal owners")
    rows, failed, first_failure = [], set(), None
    for oid, (otype, app_id, name, _rel) in owned.items():
        owners, status = results[oid]
        if owners is None:
            log_warn(f"  Owners of {otype} '{name}' could not be read ({status}); skipped.")
            failed.add(_lower(oid))
            first_failure = first_failure or status
            continue
        for o in owners:
            if not o.get("id"):
                continue
            rows.append(dict({"owned_object_id": oid, "owned_object_type": otype, "owned_app_id": app_id,
                              "owned_display_name": name}, **_owner_fields(o)))
    if owned and len(failed) == len(owned):
        return None, first_failure
    return {"rows": _dedupe(rows, ["owned_object_id", "owner_id"]), "failed": failed}, "ok"


def write_app_owners(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_app_owner", client_id, now, data["rows"])


# ---- groups ----------------------------------------------------------------

GRAPH_GROUP_SELECT = (
    "id,displayName,isAssignableToRole,securityEnabled,mailEnabled,groupTypes,membershipRule,"
    "membershipRuleProcessingState,onPremisesSyncEnabled,onPremisesSecurityIdentifier"
)
SENSITIVE_REASON_ORDER = ("role_assignable", "holds_role", "ca_include", "ca_exclude", "app_role")


def collect_groups(graph, ctx):
    """[v0.8.0] Every group, with is_sensitive / sensitive_reasons (v42
    entra_group comment), plus owners and transitive members of the
    sensitive ones. Reasons: role_assignable (isAssignableToRole);
    holds_role (a role member this run, active or eligible); ca_include /
    ca_exclude (in includeGroups / excludeGroups of a CA policy whose state
    is not 'disabled'); app_role (assigned an app role on a service
    principal that holds a PRIVILEGED_ROLE_TEMPLATE_IDS role or a
    DANGEROUS_GRAPH_PERMISSIONS grant). A single group's 403/404 is skipped
    with a warning; if every sensitive group fails, the source fails."""
    groups, status = graph_get_all_optional(
        graph, f"{GRAPH_GROUPS_URL}?$select={GRAPH_GROUP_SELECT}&$top=999", "groups")
    if groups is None:
        return None, status
    reasons = {}

    def add(gid, reason):
        if gid:
            reasons.setdefault(_lower(gid), set()).add(reason)

    for g in groups:
        if g.get("isAssignableToRole"):
            add(g.get("id"), "role_assignable")
    privileged_sps = set()
    for rm in ctx["role_members"]:
        member = rm["member"]
        if rm.get("via_group"):
            continue
        if member.get("@odata.type") == "#microsoft.graph.group":
            add(member.get("id"), "holds_role")
        if (member.get("@odata.type") == "#microsoft.graph.servicePrincipal"
                and _lower(rm["role"].get("roleTemplateId")) in PRIVILEGED_ROLE_TEMPLATE_IDS):
            privileged_sps.add(_lower(member.get("id")))
    for p in ctx["ca_policies"]:
        if (p.get("state") or "").lower() == "disabled":
            continue
        users = ((p.get("conditions") or {}).get("users") or {})
        for gid in users.get("includeGroups") or []:
            add(gid, "ca_include")
        for gid in users.get("excludeGroups") or []:
            add(gid, "ca_exclude")
    for grant in ctx["dangerous_grants"]:
        if (grant.get("principal_type") or "") == "ServicePrincipal" and grant.get("principal_id"):
            privileged_sps.add(_lower(grant["principal_id"]))
    if privileged_sps:
        assigned = graph_batch_get_all(
            graph, [(sp, f"/servicePrincipals/{sp}/appRoleAssignedTo") for sp in sorted(privileged_sps)],
            "app role assignments on privileged service principals")
        for sp, (items, st) in assigned.items():
            if items is None:
                log_warn(f"  App role assignments on service principal {sp} could not be read ({st}); "
                         f"groups assigned to it may not be marked sensitive.")
                continue
            for a in items:
                if a.get("principalType") == "Group":
                    add(a.get("principalId"), "app_role")

    rows = []
    for g in groups:
        if not g.get("id"):
            continue
        why = [r for r in SENSITIVE_REASON_ORDER if r in reasons.get(_lower(g["id"]), set())]
        rows.append({
            "entra_object_id": g["id"], "display_name": g.get("displayName"),
            "is_assignable_to_role": g.get("isAssignableToRole"),
            "security_enabled": g.get("securityEnabled"), "mail_enabled": g.get("mailEnabled"),
            "group_types": g.get("groupTypes") or [], "membership_rule": g.get("membershipRule"),
            "membership_rule_processing_state": g.get("membershipRuleProcessingState"),
            "on_premises_sync_enabled": g.get("onPremisesSyncEnabled"),
            "on_premises_security_identifier": g.get("onPremisesSecurityIdentifier"),
            "is_sensitive": bool(why), "sensitive_reasons": why,
        })
    rows = _dedupe(rows, ["entra_object_id"])
    sensitive = [r for r in rows if r["is_sensitive"]]
    requests_list = []
    for r in sensitive:
        requests_list.append(((r["entra_object_id"], "owners"), f"/groups/{r['entra_object_id']}/owners"))
        requests_list.append(((r["entra_object_id"], "members"),
                              f"/groups/{r['entra_object_id']}/transitiveMembers"))
    results = graph_batch_directory_objects(graph, requests_list, "sensitive group owners / members")
    owners, members, failed, first_failure = [], [], set(), None
    for r in sensitive:
        gid = r["entra_object_id"]
        got_owners, st_o = results[(gid, "owners")]
        got_members, st_m = results[(gid, "members")]
        if got_owners is None or got_members is None:
            st = st_o if got_owners is None else st_m
            log_warn(f"  Owners/members of group '{r['display_name']}' could not be read ({st}); skipped.")
            failed.add(_lower(gid))
            first_failure = first_failure or st
            continue
        for o in got_owners:
            if o.get("id"):
                owners.append(dict({"group_id": gid}, **_owner_fields(o)))
        for m in got_members:
            if m.get("id"):
                members.append({
                    "group_id": gid, "member_id": m["id"], "member_type": m.get("@odata.type"),
                    "member_display_name": m.get("displayName"),
                    "member_upn": m.get("userPrincipalName"), "member_user_type": m.get("userType"),
                    "on_premises_sync_enabled": m.get("onPremisesSyncEnabled"),
                    "account_enabled": m.get("accountEnabled"),
                })
    if sensitive and len(failed) == len(sensitive):
        return None, first_failure
    log_info(f"  {len(rows)} group(s), {len(sensitive)} sensitive; {len(owners)} owner and "
             f"{len(members)} transitive member row(s) of sensitive groups")
    return {"groups": rows, "owners": _dedupe(owners, ["group_id", "owner_id"]),
            "members": _dedupe(members, ["group_id", "member_id"]), "failed": failed}, "ok"


def write_groups(cur, client_id, now, data):
    """[v0.8.0] on_prem_object_guid resolved like entra_user's (SID match to
    directory_object)."""
    sids = [g["on_premises_security_identifier"] for g in data["groups"]
            if g["on_premises_security_identifier"]]
    sid_to_guid = {}
    if sids:
        cur.execute("SELECT object_sid, object_guid FROM directory_object "
                    "WHERE client_id = %s AND object_sid = ANY(%s);", (client_id, sids))
        sid_to_guid = dict(cur.fetchall())
    rows = [dict(g, on_prem_object_guid=sid_to_guid.get(g["on_premises_security_identifier"]))
            for g in data["groups"]]
    n = _insert_dicts(cur, "entra_group", client_id, now, rows)
    _insert_dicts(cur, "entra_group_owner", client_id, now, data["owners"])
    _insert_dicts(cur, "entra_group_member", client_id, now, data["members"])
    return n


# ---- role definitions, custom-role assignments, PIM settings ---------------

def collect_role_definitions(graph, ctx):
    defs, status = graph_get_all_optional(graph, GRAPH_ROLE_DEFINITIONS_URL, "directory role definitions")
    if defs is None:
        return None, status
    rows = [{
        "role_definition_id": d.get("id"), "template_id": d.get("templateId"),
        "display_name": d.get("displayName"), "is_built_in": d.get("isBuiltIn"),
        "is_enabled": d.get("isEnabled"),
        "allowed_actions": sorted({a for p in (d.get("rolePermissions") or [])
                                   for a in (p.get("allowedResourceActions") or [])}),
    } for d in defs if d.get("id")]
    return _dedupe(rows, ["role_definition_id"]), "ok"


def write_role_definitions(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_role_definition", client_id, now, data)


def collect_custom_role_assignments(graph, ctx):
    """[v0.8.0] Assignments of custom role definitions, which
    /directoryRoles does not list. Active: roleAssignments filtered per
    custom definition. Eligible: taken from this run's
    roleEligibilityScheduleInstances (which list custom roles too); when
    those could not be read (no P2 -- see
    entra_security_posture.role_eligibility_status) only active
    assignments are stored."""
    if ctx["statuses"].get("role_definitions") != "ok":
        return None, _skipped("role_definitions", ctx["statuses"].get("role_definitions"))
    custom = {_lower(d["role_definition_id"]): d for d in ctx["data"]["role_definitions"]
              if d.get("is_built_in") is False}
    rows = []
    for def_id, d in custom.items():
        items, status = graph_get_all_optional(
            graph, f"{GRAPH_ROLE_ASSIGNMENTS_URL}?$filter=roleDefinitionId eq '{d['role_definition_id']}'"
                   f"&$expand=principal",
            f"assignments of custom role '{d.get('display_name')}'")
        if items is None:
            return None, status
        for a in items:
            principal = a.get("principal") or {}
            pid = a.get("principalId") or principal.get("id")
            if pid:
                rows.append({
                    "role_definition_id": d["role_definition_id"], "principal_id": pid,
                    "principal_type": principal.get("@odata.type"),
                    "principal_display_name": principal.get("displayName"),
                    "principal_upn": principal.get("userPrincipalName"),
                    "directory_scope_id": a.get("directoryScopeId") or "/", "assignment_type": "active",
                })
    for rm in ctx["role_members"]:
        if rm.get("assignment_type") != "eligible" or rm.get("via_group"):
            continue
        if _lower(rm["role"].get("id")) not in custom or not rm["member"].get("id"):
            continue
        member = rm["member"]
        rows.append({
            "role_definition_id": custom[_lower(rm["role"]["id"])]["role_definition_id"],
            "principal_id": member["id"], "principal_type": member.get("@odata.type"),
            "principal_display_name": member.get("displayName"),
            "principal_upn": member.get("userPrincipalName"),
            "directory_scope_id": rm.get("directory_scope_id") or "/", "assignment_type": "eligible",
        })
    return _dedupe(rows, ["role_definition_id", "principal_id", "directory_scope_id", "assignment_type"]), "ok"


def write_custom_role_assignments(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_custom_role_assignment", client_id, now, data)


def _pim_rule(rule):
    """[v0.8.0] One PIM policy rule as stored: '@odata.type' kept as
    'rule_type', every other @odata annotation dropped."""
    out = {}
    for key, value in (rule or {}).items():
        if key == "@odata.type":
            out["rule_type"] = value
        elif "@odata." not in key:
            out[key] = _strip_odata_annotations(value)
    return out


def collect_pim_policies(graph, ctx):
    """[v0.8.0] PIM role settings per directory role (Entra ID P2;
    RoleManagementPolicy.Read.Directory, or RoleManagement.Read.Directory)."""
    items, status = graph_get_all_optional(graph, GRAPH_PIM_POLICY_ASSIGNMENTS_URL, "PIM role settings")
    if items is None:
        return None, status
    names = {}
    for rm in ctx["role_members"]:
        if rm["role"].get("roleTemplateId"):
            names.setdefault(_lower(rm["role"]["roleTemplateId"]), rm["role"].get("displayName"))
    if ctx["statuses"].get("role_definitions") == "ok":
        for d in ctx["data"]["role_definitions"]:
            for key in (d.get("template_id"), d.get("role_definition_id")):
                if key:
                    names[_lower(key)] = d.get("display_name")
    rows = []
    for a in items:
        template = a.get("roleDefinitionId")
        if not template:
            continue
        policy = a.get("policy") or {}
        rows.append({
            "role_template_id": template, "role_display_name": names.get(_lower(template)),
            "policy_id": a.get("policyId") or policy.get("id"),
            "rules": [_pim_rule(r) for r in (policy.get("rules") or [])],
        })
    return _dedupe(rows, ["role_template_id"]), "ok"


def write_pim_policies(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_role_management_policy", client_id, now, data, jsonb=("rules",))


# ---- policies and settings -------------------------------------------------

def collect_named_locations(graph, ctx):
    items, status = graph_get_all_optional(graph, GRAPH_NAMED_LOCATIONS_URL, "named locations")
    if items is None:
        return None, status
    rows = []
    for loc in items:
        kind = loc.get("@odata.type")
        base = {"location_id": loc.get("id"), "display_name": loc.get("displayName")}
        if kind == "#microsoft.graph.ipNamedLocation":
            rows.append(dict(base, location_type="ip", is_trusted=loc.get("isTrusted"),
                             ip_ranges=[r.get("cidrAddress") for r in (loc.get("ipRanges") or [])
                                        if r.get("cidrAddress")],
                             countries=[], include_unknown_countries=None))
        elif kind == "#microsoft.graph.countryNamedLocation":
            rows.append(dict(base, location_type="country", is_trusted=None, ip_ranges=[],
                             countries=loc.get("countriesAndRegions") or [],
                             include_unknown_countries=loc.get("includeUnknownCountriesAndRegions")))
        else:
            log_warn(f"  Named location '{loc.get('displayName')}' has unsupported type {kind}; skipped.")
    return _dedupe([r for r in rows if r["location_id"]], ["location_id"]), "ok"


def write_named_locations(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_named_location", client_id, now, data)


def collect_auth_methods_policy(graph, ctx):
    """[v0.8.0] policies/authenticationMethodsPolicy (Policy.Read.All) with
    its authenticationMethodConfigurations; when Graph does not return them
    inline, each of AUTH_METHOD_CONFIG_IDS is read on its own (404 = that
    method not present)."""
    policy, status = graph_get_single_optional(graph, GRAPH_AUTH_METHODS_POLICY_URL,
                                               "authentication methods policy")
    if policy is None:
        return None, status
    configs = policy.get("authenticationMethodConfigurations")
    if not configs:
        configs = []
        for method_id in AUTH_METHOD_CONFIG_IDS:
            body, st = graph_get_single_optional(
                graph, f"{GRAPH_AUTH_METHODS_POLICY_URL}/authenticationMethodConfigurations/{method_id}",
                f"authentication method configuration {method_id}")
            if body is None:
                if st.startswith("HTTP 404"):
                    continue
                return None, st
            configs.append(body)
    content = _strip_odata_keep_type(dict(policy, authenticationMethodConfigurations=configs))
    return content, "ok"


def write_auth_methods_policy(cur, client_id, now, data):
    _put_setting(cur, client_id, now, "auth_methods_policy", data)
    return 1


def collect_cross_tenant_policy(graph, ctx):
    """[v0.8.0] crossTenantAccessPolicy default and partners
    (Policy.Read.All), each partner with its identitySynchronization (404 =
    none configured -> null)."""
    default, status = graph_get_single_optional(graph, GRAPH_CROSS_TENANT_DEFAULT_URL,
                                                "cross-tenant access default")
    if default is None:
        return None, status
    partners, status = graph_get_all_optional(graph, GRAPH_CROSS_TENANT_PARTNERS_URL,
                                              "cross-tenant access partners")
    if partners is None:
        return None, status
    rows = []
    for p in partners:
        tid = p.get("tenantId")
        if not tid:
            continue
        sync, st = graph_get_single_optional(
            graph, f"{GRAPH_CROSS_TENANT_PARTNERS_URL}/{tid}/identitySynchronization",
            f"cross-tenant identity synchronization for {tid}")
        if sync is None and not st.startswith("HTTP 404"):
            return None, st
        content = _strip_odata_keep_type(p)
        content["identitySynchronization"] = _strip_odata_keep_type(sync) if sync is not None else None
        rows.append({"partner_tenant_id": tid, "content": content})
    return {"default": _strip_odata_keep_type(default),
            "partners": _dedupe(rows, ["partner_tenant_id"])}, "ok"


def write_cross_tenant_policy(cur, client_id, now, data):
    _put_setting(cur, client_id, now, "cross_tenant_default", data["default"])
    _insert_dicts(cur, "entra_cross_tenant_partner", client_id, now, data["partners"], jsonb=("content",))
    return 1 + len(data["partners"])


def collect_admin_consent_request_policy(graph, ctx):
    policy, status = graph_get_single_optional(graph, GRAPH_ADMIN_CONSENT_POLICY_URL,
                                               "admin consent request policy")
    return (_strip_odata_keep_type(policy), "ok") if policy is not None else (None, status)


def write_admin_consent_request_policy(cur, client_id, now, data):
    _put_setting(cur, client_id, now, "admin_consent_request_policy", data)
    return 1


DIRECTORY_SETTING_NAMES = {"password rule settings": "password_rule_settings",
                           "group.unified": "group_unified_settings"}


def collect_directory_settings(graph, ctx):
    """[v0.8.0] /groupSettings (Directory.Read.All): 'Password Rule
    Settings' and 'Group.Unified' as {name: value}. A setting object that
    does not exist (tenant defaults in force) gives no row."""
    items, status = graph_get_all_optional(graph, GRAPH_GROUP_SETTINGS_URL, "directory settings")
    if items is None:
        return None, status
    settings = {}
    for item in items:
        name = DIRECTORY_SETTING_NAMES.get((item.get("displayName") or "").lower())
        if name and name not in settings:
            settings[name] = {v.get("name"): v.get("value") for v in (item.get("values") or []) if v.get("name")}
    return settings, "ok"


def write_directory_settings(cur, client_id, now, data):
    for name, content in data.items():
        _put_setting(cur, client_id, now, name, content)
    return len(data)


def collect_device_registration_policy(graph, ctx):
    """[v0.8.0] deviceRegistrationPolicy (Policy.Read.DeviceConfiguration):
    v1.0 first, beta when v1.0 does not offer it."""
    policy, status = _graph_get_with_beta_fallback(
        graph, GRAPH_DEVICE_REGISTRATION_POLICY_PATH, "device registration policy")
    return (_strip_odata_keep_type(policy), "ok") if policy is not None else (None, status)


def write_device_registration_policy(cur, client_id, now, data):
    _put_setting(cur, client_id, now, "device_registration_policy", data)
    return 1


def collect_onprem_sync(graph, ctx):
    """[v0.8.0] directory/onPremisesSynchronization
    (OnPremDirectorySynchronization.Read.All): the first element (features +
    configuration). v1.0 first, beta when v1.0 does not offer it."""
    items, status = _graph_get_with_beta_fallback(
        graph, GRAPH_ONPREM_SYNC_PATH, "on-premises synchronization settings", single=False)
    if items is None:
        return None, status
    return (_strip_odata_keep_type(items[0]) if items else None), "ok"


def write_onprem_sync(cur, client_id, now, data):
    if data is None:
        return 0
    _put_setting(cur, client_id, now, "onprem_sync", data)
    return 1


def collect_pta_agents(graph, ctx):
    """[v0.8.0] Pass-through authentication agents (beta, opt-in: needs the
    write-capable OnPremisesPublishingProfiles.ReadWrite.All)."""
    if not ctx["include_pta_agents"]:
        return None, PTA_SKIPPED_STATUS
    items, status = graph_get_all_optional(graph, GRAPH_PTA_AGENTS_URL,
                                           "pass-through authentication agents (beta)")
    if items is None:
        return None, status
    rows = [{"agent_id": a.get("id"), "machine_name": a.get("machineName"),
             "external_ip": a.get("externalIp"), "status": a.get("status")}
            for a in items if a.get("id")]
    return _dedupe(rows, ["agent_id"]), "ok"


def write_pta_agents(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_pta_agent", client_id, now, data)


def collect_partner_contracts(graph, ctx):
    items, status = graph_get_all_optional(graph, GRAPH_CONTRACTS_URL, "partner contracts")
    if items is None:
        return None, status
    rows = [{"contract_object_id": c.get("id"), "contract_type": c.get("contractType"),
             "customer_id": c.get("customerId"), "default_domain_name": c.get("defaultDomainName"),
             "display_name": c.get("displayName")} for c in items if c.get("id")]
    return _dedupe(rows, ["contract_object_id"]), "ok"


def write_partner_contracts(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_partner_contract", client_id, now, data)


# ---- registration details and Identity Protection --------------------------

def collect_registration_details(graph, ctx):
    items, status = graph_get_all_optional(graph, GRAPH_REGISTRATION_DETAILS_URL,
                                           "user MFA registration details")
    if items is None:
        return None, status
    rows = [{
        "entra_object_id": r.get("id"), "user_principal_name": r.get("userPrincipalName"),
        "user_type": r.get("userType"), "is_admin": r.get("isAdmin"),
        "is_mfa_registered": r.get("isMfaRegistered"), "is_mfa_capable": r.get("isMfaCapable"),
        "is_passwordless_capable": r.get("isPasswordlessCapable"),
        "is_sspr_registered": r.get("isSsprRegistered"),
        "methods_registered": r.get("methodsRegistered") or [],
        "default_mfa_method": r.get("defaultMfaMethod"),
        "is_system_preferred_enabled": r.get("isSystemPreferredAuthenticationMethodEnabled"),
        "last_updated_at": r.get("lastUpdatedDateTime"),
    } for r in items if r.get("id")]
    return _dedupe(rows, ["entra_object_id"]), "ok"


def write_registration_details(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_user_registration", client_id, now, data)


def collect_risky_users(graph, ctx):
    items, status = graph_get_all_optional(graph, GRAPH_RISKY_USERS_URL, "risky users")
    if items is None:
        return None, status
    rows = [{
        "entra_object_id": r.get("id"), "user_principal_name": r.get("userPrincipalName"),
        "risk_level": r.get("riskLevel"), "risk_state": r.get("riskState"),
        "risk_detail": r.get("riskDetail"), "risk_last_updated_at": r.get("riskLastUpdatedDateTime"),
    } for r in items if r.get("id") and r.get("riskState") in RISK_STATES_KEPT]
    return _dedupe(rows, ["entra_object_id"]), "ok"


def write_risky_users(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_risky_user", client_id, now, data)


def collect_risk_detections(graph, ctx):
    """[v0.8.0] Risk detections of the last RISK_DETECTION_LOOKBACK_DAYS
    days, filtered to atRisk / confirmedCompromised here (riskState is not
    reliably filterable server-side together with detectedDateTime)."""
    since = (datetime.now(timezone.utc) - timedelta(days=RISK_DETECTION_LOOKBACK_DAYS))
    url = f"{GRAPH_RISK_DETECTIONS_URL}?$filter=detectedDateTime ge {since.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    items, status = graph_get_all_optional(graph, url, "risk detections")
    if items is None:
        return None, status
    rows = [{
        "detection_id": r.get("id"), "entra_object_id": r.get("userId"),
        "user_principal_name": r.get("userPrincipalName"), "risk_event_type": r.get("riskEventType"),
        "risk_level": r.get("riskLevel"), "risk_state": r.get("riskState"),
        "detection_timing_type": r.get("detectionTimingType"), "source": r.get("source"),
        "detected_at": r.get("detectedDateTime"),
    } for r in items if r.get("id") and r.get("riskState") in RISK_STATES_KEPT]
    return _dedupe(rows, ["detection_id"]), "ok"


def write_risk_detections(cur, client_id, now, data):
    return _insert_dicts(cur, "entra_risk_detection", client_id, now, data)


# ---- runner ----------------------------------------------------------------

def record_source(pg_conn, client_id, source, status, data=None):
    """[v0.8.0] One transaction per source: clear the source's rows for the
    client, write the new ones when status is 'ok', upsert
    entra_collection_status, commit."""
    status = _status_text(status)
    now = datetime.now(timezone.utc)
    written = 0
    with pg_conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
        for sql in SOURCE_CLEAR_SQL[source]:
            cur.execute(sql, (client_id,))
        if status == "ok":
            written = globals()[f"write_{source}"](cur, client_id, now, data)
        cur.execute(
            """
            INSERT INTO entra_collection_status (client_id, source, status, collected_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (client_id, source) DO UPDATE SET
                status = EXCLUDED.status, collected_at = EXCLUDED.collected_at;
            """,
            (client_id, source, status, now),
        )
    pg_conn.commit()
    return status, written


def run_optional_sources(graph, pg_conn, client_id, ctx, completed_steps):
    """[v0.8.0] Runs every OPTIONAL_SOURCES entry; fills ctx["statuses"]
    and ctx["data"] (used by later sources and by change history)."""
    for source in OPTIONAL_SOURCES:
        log_info(f"Source {source}...")
        data, status = globals()[f"collect_{source}"](graph, ctx)
        status, written = record_source(pg_conn, client_id, source, status, data)
        ctx["statuses"][source] = status
        ctx["data"][source] = data if status == "ok" else None
        completed_steps.append(source)
        if status == "ok":
            log_success(f"  {source}: ok ({written} row(s) written)")
        elif status.startswith("skipped"):
            log_info(f"  {source}: {status}")
        else:
            log_warn(f"  {source}: not read -- {status}")
    return ctx["statuses"]


# ============================================================================
# [v0.8.0] Change history (entra_change_history SCD2 + entra_change_baseline)
# ============================================================================

def _canonical(content):
    return json.dumps(content, sort_keys=True, separators=(",", ":"), default=str)


def update_change_history(pg_conn, client_id, entity_type, entities, run_time,
                          scope_keys=None, protected_prefixes=()):
    """[v0.8.0] SCD2 diff of one entity type, in one transaction.
    entities = {entity_key: (entity_label, content)}. Open versions whose
    key is outside scope_keys (when given), or starts with one of
    protected_prefixes (objects whose read failed this run), are left
    alone. Returns (new, changed, closed)."""
    new = changed = closed = 0
    with pg_conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
        cur.execute(
            "SELECT entity_key, content_hash FROM entra_change_history "
            "WHERE client_id = %s AND entity_type = %s AND valid_to IS NULL;",
            (client_id, entity_type),
        )
        open_versions = dict(cur.fetchall())
        close_keys, insert_rows = [], []
        for key, old_hash in open_versions.items():
            if scope_keys is not None and key not in scope_keys:
                continue
            if key not in entities:
                if any(key.startswith(p) for p in protected_prefixes):
                    continue
                close_keys.append(key)
                closed += 1
        for key, (label, content) in entities.items():
            canonical = _canonical(content)
            digest = hashlib.md5(canonical.encode("utf-8")).hexdigest()
            if key in open_versions:
                if open_versions[key] == digest:
                    continue
                close_keys.append(key)
                changed += 1
            else:
                new += 1
            insert_rows.append((client_id, entity_type, key, label, canonical, digest, run_time))
        if close_keys:
            cur.execute(
                "UPDATE entra_change_history SET valid_to = %s WHERE client_id = %s AND entity_type = %s "
                "AND valid_to IS NULL AND entity_key = ANY(%s);",
                (run_time, client_id, entity_type, close_keys),
            )
        if insert_rows:
            psycopg2.extras.execute_values(
                cur,
                "INSERT INTO entra_change_history (client_id, entity_type, entity_key, entity_label, "
                "content, content_hash, valid_from) VALUES %s",
                insert_rows,
                template="(%s, %s, %s, %s, %s::jsonb, %s, %s)",
            )
        cur.execute(
            """
            INSERT INTO entra_change_baseline (client_id, entity_type, first_run_at, last_run_at)
            VALUES (%s, %s, %s, %s)
            ON CONFLICT (client_id, entity_type) DO UPDATE SET last_run_at = EXCLUDED.last_run_at;
            """,
            (client_id, entity_type, run_time, run_time),
        )
    pg_conn.commit()
    return new, changed, closed


def _history_federation(ctx):
    feds = {}
    for f in sorted(ctx["data"]["federation"], key=lambda r: str(r["federation_id"])):
        feds.setdefault(_lower(f["domain_name"]), f)
    entities = {}
    for d in ctx["data"]["domains"]:
        f = feds.get(_lower(d["domain_name"]), {})
        entities[_lower(d["domain_name"])] = (d["domain_name"], {
            "authentication_type": d.get("authentication_type"),
            "issuer_uri": f.get("issuer_uri"), "passive_sign_in_uri": f.get("passive_sign_in_uri"),
            "active_sign_in_uri": f.get("active_sign_in_uri"),
            "federated_idp_mfa_behavior": f.get("federated_idp_mfa_behavior"),
            "prompt_login_behavior": f.get("prompt_login_behavior"),
            "signing_certificate_thumbprint": f.get("signing_certificate_thumbprint"),
            "next_signing_certificate_thumbprint": f.get("next_signing_certificate_thumbprint"),
        })
    return entities


def _history_app_credential(ctx):
    entities = {}

    def add(object_type, object_id, app_id, name, cred_type, cred):
        key_id = cred.get("key_id")
        if not object_id or not key_id:
            return
        entities[f"{_lower(object_id)}:{_lower(key_id)}"] = (
            f"{name} ({object_type}): {cred.get('display_name') or key_id}",
            {"object_type": object_type, "object_id": _lower(object_id), "app_id": _lower(app_id),
             "display_name": name, "credential_type": cred_type, "key_id": _lower(key_id),
             "credential_display_name": cred.get("display_name"),
             "end_date_time": cred.get("end_date_time")})

    for app in ctx["applications"]:
        for c in app.get("passwordCredentials") or []:
            add("application", app.get("id"), app.get("appId"), app.get("displayName"), "password",
                {"key_id": c.get("keyId"), "display_name": c.get("displayName"),
                 "end_date_time": c.get("endDateTime")})
        for c in app.get("keyCredentials") or []:
            add("application", app.get("id"), app.get("appId"), app.get("displayName"), "certificate",
                _key_credential(c))
    for sp in ctx["data"]["service_principals"]:
        for c in sp["password_credentials"]:
            add("servicePrincipal", sp["entra_object_id"], sp["app_id"], sp["display_name"], "password", c)
        for c in sp["key_credentials"]:
            add("servicePrincipal", sp["entra_object_id"], sp["app_id"], sp["display_name"], "certificate", c)
    return entities


def _history_app_permission(ctx):
    entities = {}
    for g in ctx["data"]["app_role_grants"]:
        key = f"{_lower(g['principal_id'])}:{_lower(g['resource_app_id'])}:{_lower(g['permission_id'])}"
        entities[key] = (
            f"{g['principal_display_name']} -> {g['resource_display_name']}: "
            f"{g['permission_name'] or g['permission_id']}",
            {"grant_kind": "application", "principal_id": _lower(g["principal_id"]),
             "principal_display_name": g["principal_display_name"],
             "resource_app_id": _lower(g["resource_app_id"]),
             "resource_display_name": g["resource_display_name"],
             "permission_name": g["permission_name"]})
    for g in ctx["data"]["delegated_grants"]:
        if g["consent_type"] != "AllPrincipals":
            continue
        for scope in g["scopes"]:
            key = f"{_lower(g['client_sp_id'])}:{_lower(g['resource_app_id'])}:AllPrincipals:{scope}"
            entities[key] = (
                f"{g['client_display_name']} -> {g['resource_display_name']}: {scope} (admin consent)",
                {"grant_kind": "delegated", "principal_id": _lower(g["client_sp_id"]),
                 "principal_display_name": g["client_display_name"],
                 "resource_app_id": _lower(g["resource_app_id"]),
                 "resource_display_name": g["resource_display_name"], "permission_name": scope})
    return entities


def _history_ca_policy(ctx):
    return {_lower(p["id"]): (p.get("display_name"), p)
            for p in (_slim_ca_policy(x) for x in ctx["ca_policies"]) if p.get("id")}


def _history_tenant_policy(ctx):
    """Returns (entities, scope_keys): only keys whose own source was read."""
    entities, scope = {}, set()
    scope.add("security_defaults")
    entities["security_defaults"] = ("Security defaults", {"enabled": ctx["security_defaults_enabled"]})
    if ctx["authorization_policy_status"] == "ok" and ctx["authorization_policy"] is not None:
        scope.add("authorization_policy")
        entities["authorization_policy"] = ("Authorization policy", ctx["authorization_policy"])
    if ctx["statuses"].get("auth_methods_policy") == "ok":
        policy = ctx["data"]["auth_methods_policy"]
        content = {"policyMigrationState": policy.get("policyMigrationState")}
        for m in policy.get("authenticationMethodConfigurations") or []:
            if m.get("id"):
                content[m["id"]] = {"state": m.get("state"), "includeTargets": m.get("includeTargets"),
                                    "excludeTargets": m.get("excludeTargets")}
        scope.add("auth_methods_policy")
        entities["auth_methods_policy"] = ("Authentication methods policy", content)
    if ctx["statuses"].get("cross_tenant_policy") == "ok":
        scope.add("cross_tenant_default")
        entities["cross_tenant_default"] = ("Cross-tenant access default",
                                            ctx["data"]["cross_tenant_policy"]["default"])
    if ctx["statuses"].get("admin_consent_request_policy") == "ok":
        scope.add("admin_consent_request_policy")
        entities["admin_consent_request_policy"] = ("Admin consent request policy",
                                                    ctx["data"]["admin_consent_request_policy"])
    return entities, scope


def _history_owner(ctx):
    entities = {}

    def add(owned_type, owned_id, owned_name, o):
        key = f"{_lower(owned_id)}:{_lower(o['owner_id'])}"
        entities[key] = (f"{owned_name} ({owned_type}) owned by {o['owner_upn'] or o['owner_display_name']}", {
            "owned_object_type": owned_type, "owned_object_id": _lower(owned_id),
            "owned_display_name": owned_name, "owner_id": _lower(o["owner_id"]),
            "owner_type": o["owner_type"], "owner_display_name": o["owner_display_name"],
            "owner_upn": o["owner_upn"]})

    for o in ctx["data"]["app_owners"]["rows"]:
        add(o["owned_object_type"], o["owned_object_id"], o["owned_display_name"], o)
    names = {_lower(g["entra_object_id"]): g["display_name"] for g in ctx["data"]["groups"]["groups"]}
    for o in ctx["data"]["groups"]["owners"]:
        add("group", o["group_id"], names.get(_lower(o["group_id"])), o)
    protected = tuple(f"{oid}:" for oid in ctx["data"]["app_owners"]["failed"] | ctx["data"]["groups"]["failed"])
    return entities, protected


def _history_partner(ctx):
    entities = {}
    for c in ctx["data"]["partner_contracts"]:
        entities[f"contract:{_lower(c['contract_object_id'])}"] = (
            c.get("display_name") or c.get("default_domain_name"), dict(c))
    for p in ctx["data"]["cross_tenant_policy"]["partners"]:
        entities[f"cross_tenant:{_lower(p['partner_tenant_id'])}"] = (
            f"Cross-tenant partner {p['partner_tenant_id']}", p["content"])
    return entities


def _history_group_member(ctx):
    groups = {_lower(g["entra_object_id"]): g for g in ctx["data"]["groups"]["groups"]}
    entities = {}
    for m in ctx["data"]["groups"]["members"]:
        g = groups.get(_lower(m["group_id"]), {})
        entities[f"{_lower(m['group_id'])}:{_lower(m['member_id'])}"] = (
            f"{m['member_upn'] or m['member_display_name']} in {g.get('display_name')}", {
                "group_id": _lower(m["group_id"]), "group_display_name": g.get("display_name"),
                "group_sensitive_reasons": g.get("sensitive_reasons"), "member_id": _lower(m["member_id"]),
                "member_type": m["member_type"], "member_display_name": m["member_display_name"],
                "member_upn": m["member_upn"], "member_user_type": m["member_user_type"],
                "on_premises_sync_enabled": m["on_premises_sync_enabled"]})
    protected = tuple(f"{gid}:" for gid in ctx["data"]["groups"]["failed"])
    return entities, protected


# entity_type -> the optional sources it is built from (core steps always
# succeeded by the time history runs). tenant_policy is handled per key.
CHANGE_HISTORY_INPUTS = (
    ("federation", ("domains", "federation")),
    ("app_credential", ("service_principals",)),
    ("app_permission", ("app_role_grants", "delegated_grants")),
    ("ca_policy", ()),
    ("tenant_policy", ()),
    ("owner", ("app_owners", "groups")),
    ("partner", ("partner_contracts", "cross_tenant_policy")),
    ("group_member", ("groups",)),
)


def update_entra_change_history(pg_conn, client_id, ctx):
    """[v0.8.0] After every source ran: updates history for each entity
    type whose input sources were all 'ok' this run; a type with any failed
    input is skipped entirely (left untouched), so a failed read is never
    recorded as everything having been removed. Returns {entity_type:
    (new, changed, closed) or "skipped: ..."}."""
    run_time = datetime.now(timezone.utc)
    results = {}
    for entity_type, inputs in CHANGE_HISTORY_INPUTS:
        failed = [s for s in inputs if ctx["statuses"].get(s) != "ok"]
        if failed:
            results[entity_type] = "skipped (not read: " + ", ".join(failed) + ")"
            log_info(f"  change history {entity_type}: {results[entity_type]}")
            continue
        scope, protected = None, ()
        if entity_type == "tenant_policy":
            entities, scope = _history_tenant_policy(ctx)
        elif entity_type in ("owner", "group_member"):
            entities, protected = globals()[f"_history_{entity_type}"](ctx)
        else:
            entities = globals()[f"_history_{entity_type}"](ctx)
        results[entity_type] = update_change_history(pg_conn, client_id, entity_type, entities, run_time,
                                                      scope_keys=scope, protected_prefixes=protected)
        new, changed, closed = results[entity_type]
        log_info(f"  change history {entity_type}: {len(entities)} current, {new} new, "
                 f"{changed} changed, {closed} gone")
    return results


# ============================================================================
# Main
# ============================================================================

def parse_args():
    """
    [test-candidate-branch] --tenant-id/--app-id/--domain-fqdn were
    argparse required=True, which meant --version failed with a usage
    error before main() ever got a chance to check it -- the exact bug
    adprofiler.py's own parse_args() already documents fixing in its
    v0.0.3 changelog entry. Never fixed here until now; caught while
    touching this function for an unrelated reason (adding the PG
    connection flags below) and fixed the same way: no longer required
    at the argparse level, validated manually after --version is
    checked.
    """
    parser = argparse.ArgumentParser(
        description="entra_graph_collector.py -- Microsoft Graph email collector, v" + VERSION,
    )
    parser.add_argument("--tenant-id", default=None,
                         help="Entra ID tenant ID (GUID) or verified domain name. "
                              "Required unless --version is given.")
    parser.add_argument("--app-id", default=None,
                         help="Entra App Registration's Application (client) ID. "
                              "Required unless --version is given.")
    parser.add_argument("--app-secret", default=None,
                         help="App Registration client secret. If omitted, you "
                              "will be prompted securely (recommended).")
    parser.add_argument("--domain-fqdn", default=None,
                         help="The on-prem AD domain FQDN already collected by "
                              "adprofiler.py (e.g. contoso.local) -- used to find "
                              "the existing client record to enrich. Matched "
                              "case-insensitively. Required unless --client-id "
                              "is given instead, or unless --version is given.")
    parser.add_argument("--client-id", default=None,
                         help="Alternative to --domain-fqdn: the client_id GUID "
                              "directly from the client table, bypassing the "
                              "domain-name lookup entirely. Useful if "
                              "--domain-fqdn keeps reporting 'No client found' "
                              "and you'd rather not troubleshoot the exact "
                              "domain string -- look the GUID up once with "
                              "`SELECT client_id, domain_fqdn FROM client;` and "
                              "use it directly from then on.")
    parser.add_argument("--include-pta-agents", action="store_true",
                         help="[v0.8.0] Also read pass-through authentication agents (beta). "
                              "Needs OnPremisesPublishingProfiles.ReadWrite.All -- Microsoft "
                              "offers no read-only permission for this read, so it is off by "
                              "default; this collector still only reads with it.")
    parser.add_argument("--version", action="store_true", help="Print version and exit.")
    parser.add_argument("--pg-host", default=None,
                         help="PostgreSQL server hostname or IP. Required unless --version is given.")
    parser.add_argument("--pg-port", type=int, default=5432,
                         help="PostgreSQL server port. Default: 5432.")
    parser.add_argument("--pg-dbname", default="adprofiler",
                         help="PostgreSQL database name. Default: adprofiler.")
    parser.add_argument("--pg-user", default=None,
                         help="PostgreSQL username. Required unless --version is given.")
    parser.add_argument("--pg-password", default=None,
                         help="PostgreSQL password. If omitted, you will be prompted "
                              "securely (recommended).")
    args = parser.parse_args()

    if not args.version and (not args.tenant_id or not args.app_id):
        parser.error("the following arguments are required: --tenant-id, --app-id")
    if not args.version and not args.domain_fqdn and not args.client_id:
        parser.error("one of the following arguments is required: --domain-fqdn, --client-id")
    if not args.version and (not args.pg_host or not args.pg_user):
        parser.error("the following arguments are required: --pg-host, --pg-user")

    return args


# [v0.5.0] Each step below commits on its own (whole-snapshot replace per
# table), so a run that aborts partway leaves earlier steps' tables
# refreshed and later ones still holding a previous run's data. Listed
# here, in run order, so an abort can say exactly which is which.
COLLECTION_STEPS = [
    ("users", ["entra_user"]),
    ("directory role membership", ["entra_directory_role_member"]),
    # [v0.7.0] Upserted, never replaced: a step that didn't run just leaves
    # last_seen_at at the previous run's time.
    ("role assignment history", ["entra_role_assignment_history"]),
    ("security posture", ["entra_security_posture"]),
    ("application registrations", ["entra_application"]),
    ("dangerous Graph permission grants", ["entra_dangerous_permission_grant"]),
    # [v0.8.0] Optional sources (step name = entra_collection_status source;
    # each also upserts its entra_collection_status row), then history.
    ("sign_in_activity", ["entra_user (sign-in columns)"]),
    ("subscribed_skus", ["entra_tenant_license"]),
    ("organization", ["entra_tenant_setting 'organization'"]),
    ("domains", ["entra_domain"]),
    ("federation", ["entra_domain_federation"]),
    ("service_principals", ["entra_service_principal"]),
    ("sp_sign_in_activity", ["entra_service_principal (last_sign_in_activity_at)"]),
    ("app_role_grants", ["entra_app_role_grant"]),
    ("delegated_grants", ["entra_delegated_grant"]),
    ("app_owners", ["entra_app_owner"]),
    ("groups", ["entra_group", "entra_group_owner", "entra_group_member"]),
    ("role_definitions", ["entra_role_definition"]),
    ("custom_role_assignments", ["entra_custom_role_assignment"]),
    ("pim_policies", ["entra_role_management_policy"]),
    ("named_locations", ["entra_named_location"]),
    ("auth_methods_policy", ["entra_tenant_setting 'auth_methods_policy'"]),
    ("cross_tenant_policy", ["entra_tenant_setting 'cross_tenant_default'", "entra_cross_tenant_partner"]),
    ("admin_consent_request_policy", ["entra_tenant_setting 'admin_consent_request_policy'"]),
    ("directory_settings", ["entra_tenant_setting 'password_rule_settings'/'group_unified_settings'"]),
    ("device_registration_policy", ["entra_tenant_setting 'device_registration_policy'"]),
    ("onprem_sync", ["entra_tenant_setting 'onprem_sync'"]),
    ("pta_agents", ["entra_pta_agent"]),
    ("partner_contracts", ["entra_partner_contract"]),
    ("registration_details", ["entra_user_registration"]),
    ("risky_users", ["entra_risky_user"]),
    ("risk_detections", ["entra_risk_detection"]),
    ("change history", ["entra_change_history", "entra_change_baseline"]),
]


def log_partial_run(completed_steps):
    """Called on any abort. If at least one step already committed, flags
    the database as holding a mix of this run's and an earlier run's
    Entra data -- adaudit.py has no way to tell the two apart, so its
    Entra findings shouldn't be trusted until a full run succeeds."""
    if not completed_steps:
        log_warn("No Entra tables were modified by this run -- any Entra data already in "
                  "the database is from an earlier run and was left unchanged.")
        return
    refreshed = [t for name, tables in COLLECTION_STEPS if name in completed_steps for t in tables]
    stale = [t for name, tables in COLLECTION_STEPS if name not in completed_steps for t in tables]
    log_error("PARTIAL RUN: this run aborted after some Entra tables were already "
              "committed. The database now holds a MIX of fresh and older Entra data:")
    log_error(f"    refreshed by this run:          {', '.join(refreshed)}")
    log_error(f"    NOT refreshed (earlier data):   {', '.join(stale)}")
    log_error("Entra findings from adaudit.py may be inconsistent until this collector "
              "completes a full successful run -- fix the error above and re-run.")


def main():
    args = parse_args()
    if args.version:
        print(f"entra_graph_collector.py version {VERSION}")
        return

    # [test-candidate-branch] Same reasoning as adprofiler.py's identical
    # addition -- see that script's main() for the full comment.
    log_filename = f"entra-graph-collector-results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
    log_fh = open(log_filename, "w")
    real_stdout = sys.stdout
    sys.stdout = _TeeStream(real_stdout, log_fh)

    def _restore_stdout():
        sys.stdout = real_stdout
        log_fh.close()
    atexit.register(_restore_stdout)

    log_header(f"entra_graph_collector.py v{VERSION} -- Microsoft Graph Email Collector")
    log_info(f"Mirroring console output to {log_filename}")

    global PG_HOST, PG_PORT, PG_DBNAME, PG_USER, PG_PASSWORD
    PG_HOST = args.pg_host
    PG_PORT = args.pg_port
    PG_DBNAME = args.pg_dbname
    PG_USER = args.pg_user
    if args.pg_password:
        log_warn("PostgreSQL password supplied via --pg-password is visible in shell "
                  "history and process listings. Prefer omitting it and entering it "
                  "at the secure prompt.")
        PG_PASSWORD = args.pg_password
    else:
        PG_PASSWORD = getpass.getpass(f"PostgreSQL password for {args.pg_user}@{args.pg_host}: ")

    if args.app_secret:
        log_warn("App secret supplied via --app-secret is visible in shell history "
                  "and process listings. Prefer omitting it and entering it at the "
                  "secure prompt.")
        app_secret = args.app_secret
    else:
        app_secret = getpass.getpass("Entra App Registration client secret: ")

    start_time = datetime.now(timezone.utc)
    completed_steps = []
    try:
        log_info(f"Requesting a Graph token for tenant {args.tenant_id}...")
        graph = GraphClient(args.tenant_id, args.app_id, app_secret)
        log_success("Token acquired.")

        log_info("Connecting to PostgreSQL...")
        pg_conn = connect_postgres()
        log_success("Connected to PostgreSQL.")

        client_id = resolve_client_id(pg_conn, domain_fqdn=args.domain_fqdn, client_id_override=args.client_id)
        log_success(f"Resolved client record for "
                    f"{'client_id=' + args.client_id if args.client_id else args.domain_fqdn}.")

        log_header("Collecting Users from Microsoft Graph")
        users = fetch_all_users(graph)
        log_success(f"Fetched {len(users)} user(s) from Graph.")

        total, matched = sync_entra_users(pg_conn, client_id, users)
        completed_steps.append("users")

        log_header("Collecting Directory Role Membership from Microsoft Graph")
        role_members = fetch_directory_roles_with_members(graph)
        eligible_members, role_eligibility_status = fetch_role_eligibility(graph)
        role_members += eligible_members
        group_members, group_expansion_status = expand_group_role_members(graph, role_members)
        role_members += group_members
        # [v0.7.0] Classify active rows (permanent / time-bound / PIM
        # activation). Optional: without P2 the kinds stay NULL.
        schedule_instances, role_schedule_status = fetch_role_assignment_schedules(graph)
        if schedule_instances is not None:
            classified = apply_assignment_kinds(role_members, schedule_instances)
            log_info(f"  {classified} active role membership(s) matched to an assignment schedule")
        role_collected_at = datetime.now(timezone.utc)
        role_member_count = sync_directory_role_members(pg_conn, client_id, role_members,
                                                        collected_at=role_collected_at)
        completed_steps.append("directory role membership")
        # [v0.7.0] Only reached when the role read above succeeded (any
        # failure there aborts first), so history never sees a failed read.
        history_count = sync_role_assignment_history(pg_conn, client_id, role_members,
                                                     role_collected_at)
        completed_steps.append("role assignment history")
        log_info(f"  {history_count} distinct role assignment(s) recorded in assignment history")
        global_admin_count = len({
            rm["member"]["id"] for rm in role_members
            if rm["role"].get("roleTemplateId") == GLOBAL_ADMIN_ROLE_TEMPLATE_ID
        })
        log_success(f"Recorded {role_member_count} role membership(s), "
                    f"including {global_admin_count} Global Administrator member(s).")

        log_header("Collecting Security Posture (Security Defaults, Conditional Access, Authorization Policy)")
        security_defaults_enabled = fetch_security_defaults(graph)
        ca_policies = fetch_conditional_access_policies(graph)
        authorization_policy, authorization_policy_status = fetch_authorization_policy(graph)
        ca_policy_count = sync_security_posture(pg_conn, client_id, security_defaults_enabled, ca_policies,
                                                role_eligibility_status, group_expansion_status,
                                                authorization_policy, authorization_policy_status,
                                                role_schedule_status)
        completed_steps.append("security posture")
        log_success(f"Security Defaults enabled: {security_defaults_enabled}. "
                    f"{ca_policy_count} Conditional Access polic{'y' if ca_policy_count == 1 else 'ies'} recorded.")

        log_header("Collecting Application Registrations from Microsoft Graph")
        applications = fetch_applications(graph)
        app_count = sync_applications(pg_conn, client_id, applications)
        completed_steps.append("application registrations")
        log_success(f"Recorded {app_count} application registration(s).")

        log_header("Checking for Highly Privileged Microsoft Graph API Permission Grants")
        dangerous_grants = fetch_dangerous_permission_grants(graph)
        grant_count = sync_dangerous_permission_grants(pg_conn, client_id, dangerous_grants)
        completed_steps.append("dangerous Graph permission grants")
        log_success(f"{grant_count} highly privileged Graph permission grant(s) found "
                    f"(out of Microsoft's own documented 'use caution' set).")

        # [v0.8.0] Optional sources: a refused read (400/403/404) is recorded
        # in entra_collection_status and the run carries on.
        log_header("Collecting Optional Entra Data Sources (schema v42)")
        ctx = {
            "users": users, "role_members": role_members, "ca_policies": ca_policies,
            "dangerous_grants": dangerous_grants, "applications": applications,
            "security_defaults_enabled": security_defaults_enabled,
            "authorization_policy": authorization_policy,
            "authorization_policy_status": authorization_policy_status,
            "include_pta_agents": args.include_pta_agents,
            "statuses": {}, "data": {},
        }
        source_statuses = run_optional_sources(graph, pg_conn, client_id, ctx, completed_steps)

        log_header("Updating Entra Change History")
        history_results = update_entra_change_history(pg_conn, client_id, ctx)
        completed_steps.append("change history")

        log_header("Run Summary")
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        print(f"  {_C.WHITE}Duration:{_C.RESET}                     {duration:.1f}s")
        print(f"  {_C.WHITE}Users fetched from Graph:{_C.RESET}      {total}")
        print(f"  {_C.GREEN}Matched to on-prem AD:{_C.RESET}         {matched}")
        print(f"  {_C.YELLOW}Cloud-only/unmatched:{_C.RESET}          {total - matched}")
        print(f"  {_C.WHITE}Directory role memberships:{_C.RESET}    {role_member_count}")
        print(f"  {_C.WHITE}Security Defaults enabled:{_C.RESET}     {security_defaults_enabled}")
        print(f"  {_C.WHITE}Conditional Access policies:{_C.RESET}   {ca_policy_count}")
        print(f"  {_C.WHITE}Role assignment schedules:{_C.RESET}     {role_schedule_status}")
        print(f"  {_C.WHITE}Authorization policy:{_C.RESET}          {authorization_policy_status}")
        print(f"  {_C.WHITE}Application registrations:{_C.RESET}     {app_count}")
        print(f"  {_C.WHITE}Dangerous permission grants:{_C.RESET}   {grant_count}")
        # [v0.8.0] One line per optional source.
        for source in OPTIONAL_SOURCES:
            status = source_statuses.get(source, "not run")
            colour = _C.GREEN if status == "ok" else _C.YELLOW
            label = f"Source {source}:"
            # [v0.8.1] at least one space after a label longer than the column
            print(f"  {_C.WHITE}{label:<{max(31, len(label) + 1)}}{_C.RESET}{colour}{status}{_C.RESET}")
        updated = sum(1 for r in history_results.values() if not isinstance(r, str))
        print(f"  {_C.WHITE}Change history:{_C.RESET}                {updated} of "
              f"{len(history_results)} entity type(s) updated")
        print(f"  {_C.WHITE}Result:{_C.RESET}                        SUCCESS")

    except CollectorAbort as exc:
        log_error(str(exc))
        log_partial_run(completed_steps)
        sys.exit(1)
    except KeyboardInterrupt:
        log_warn("Aborting due to Ctrl-C...")
        log_partial_run(completed_steps)
        sys.exit(130)
    except Exception:
        log_error("Unexpected error -- full traceback follows.")
        log_partial_run(completed_steps)
        raise


if __name__ == "__main__":
    main()
