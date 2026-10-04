#!/usr/bin/env python3
"""
entra_graph_collector.py -- Microsoft Entra ID / Graph API Email Collector

VERSION: 0.5.1

CHANGELOG:
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

WHAT THIS DOES NOT DO
    Does not create, modify, or delete anything in Entra ID -- both
    permissions above are read-only. Does not touch on-prem AD, any domain controller, or
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
import getpass
import email.utils
import json
import random
import re
import sys
import time
from datetime import datetime, timezone

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

VERSION = "0.5.1"

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
    "onPremisesSecurityIdentifier,onPremisesSyncEnabled,userType"
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
# Fixed, immutable across every tenant -- confirmed against Microsoft's
# own documentation and cross-checked against multiple independent
# sources, not tenant-specific the way a role's own "id" is.
GLOBAL_ADMIN_ROLE_TEMPLATE_ID = "62e90394-69f5-4237-9190-012177145e10"

# [v0.3.0] Security Defaults + Conditional Access -- both read via
# Policy.Read.All, a new permission alongside RoleManagement.Read.Directory.
GRAPH_SECURITY_DEFAULTS_URL = "https://graph.microsoft.com/v1.0/policies/identitySecurityDefaultsEnforcementPolicy"
GRAPH_CA_POLICIES_URL = "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies"

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
            role_members.append({"role": role, "member": member})

    return role_members


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
    return body.get("value", [])


def fetch_applications(graph):
    """Paginated the same way fetch_all_users is -- follows @odata.nextLink
    rather than assume one page covers every registration.

    Deliberately does NOT also fetch servicePrincipals or
    oauth2PermissionGrants/appRoleAssignments -- this collector's scope
    for applications is client secret expiry only (see
    GRAPH_APPLICATIONS_URL's own comment for why full permission-grant
    parsing is out of scope for this pass)."""
    apps = []
    select = "id,appId,displayName,passwordCredentials,keyCredentials"
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
            ))

        cur.execute("DELETE FROM entra_user WHERE client_id = %s;", (client_id,))
        psycopg2.extras.execute_values(
            cur,
            """
            INSERT INTO entra_user
                (client_id, entra_object_id, on_prem_object_guid, user_principal_name,
                 mail, proxy_addresses, account_enabled, on_premises_sync_enabled,
                 on_premises_security_identifier, user_type, collected_at)
            VALUES %s
            """,
            rows,
        )
    pg_conn.commit()
    return len(users), matched


def sync_directory_role_members(pg_conn, client_id, role_members):
    """Same whole-snapshot-replace pattern as sync_entra_users, same
    reasoning. A member can be a user, group, or service principal --
    @odata.type distinguishes them; only users carry
    onPremisesSecurityIdentifier at all, so on-prem correlation is
    naturally None for the other two rather than needing special-cased
    logic to skip them."""
    now = datetime.now(timezone.utc)
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

        for rm in role_members:
            role, member = rm["role"], rm["member"]
            on_prem_sid = member.get("onPremisesSecurityIdentifier")
            rows.append((
                client_id, role["id"], role.get("roleTemplateId"), role.get("displayName"),
                member["id"], member.get("@odata.type"), member.get("displayName"),
                member.get("userPrincipalName"), sid_to_guid.get(on_prem_sid),
                on_prem_sid, member.get("accountEnabled"), now,
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
                     account_enabled, collected_at)
                VALUES %s
                """,
                rows,
            )
    pg_conn.commit()
    return len(rows)


def sync_security_posture(pg_conn, client_id, security_defaults_enabled, ca_policies):
    """Combines both into one row per client, same snapshot-replace
    philosophy as entra_user -- these two facts are only ever meaningful
    together (see plugin 10004's own docstring for why), so storing them
    jointly avoids a join for what's fundamentally one finding's worth
    of input. ca_policies stored as a JSONB array of the fields actually
    needed (id, displayName, state, grantControls) rather than the full
    Graph response -- full condition/application/location targeting is
    out of scope for this pass (see GRAPH_CA_POLICIES_URL's own
    reasoning); storing more than what's used risks implying a precision
    this collector doesn't actually have."""
    now = datetime.now(timezone.utc)
    slim_policies = [
        {
            "id": p.get("id"), "display_name": p.get("displayName"), "state": p.get("state"),
            "grant_controls": p.get("grantControls"),
        }
        for p in ca_policies
    ]
    with pg_conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
        cur.execute("DELETE FROM entra_security_posture WHERE client_id = %s;", (client_id,))
        cur.execute(
            """
            INSERT INTO entra_security_posture
                (client_id, security_defaults_enabled, ca_policies, collected_at)
            VALUES (%s, %s, %s, %s);
            """,
            (client_id, security_defaults_enabled, json.dumps(slim_policies), now),
        )
    pg_conn.commit()
    return len(slim_policies)


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
            }
            for c in (app.get("passwordCredentials") or [])
        ]
        rows.append((
            client_id, app["id"], app.get("appId"), app.get("displayName"),
            json.dumps(creds), len(app.get("keyCredentials") or []), now,
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
                     password_credentials, key_credential_count, collected_at)
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
    ("security posture", ["entra_security_posture"]),
    ("application registrations", ["entra_application"]),
    ("dangerous Graph permission grants", ["entra_dangerous_permission_grant"]),
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
        role_member_count = sync_directory_role_members(pg_conn, client_id, role_members)
        completed_steps.append("directory role membership")
        global_admin_count = sum(
            1 for rm in role_members if rm["role"].get("roleTemplateId") == GLOBAL_ADMIN_ROLE_TEMPLATE_ID
        )
        log_success(f"Recorded {role_member_count} role membership(s), "
                    f"including {global_admin_count} Global Administrator member(s).")

        log_header("Collecting Security Posture (Security Defaults + Conditional Access)")
        security_defaults_enabled = fetch_security_defaults(graph)
        ca_policies = fetch_conditional_access_policies(graph)
        ca_policy_count = sync_security_posture(pg_conn, client_id, security_defaults_enabled, ca_policies)
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

        log_header("Run Summary")
        duration = (datetime.now(timezone.utc) - start_time).total_seconds()
        print(f"  {_C.WHITE}Duration:{_C.RESET}                     {duration:.1f}s")
        print(f"  {_C.WHITE}Users fetched from Graph:{_C.RESET}      {total}")
        print(f"  {_C.GREEN}Matched to on-prem AD:{_C.RESET}         {matched}")
        print(f"  {_C.YELLOW}Cloud-only/unmatched:{_C.RESET}          {total - matched}")
        print(f"  {_C.WHITE}Directory role memberships:{_C.RESET}    {role_member_count}")
        print(f"  {_C.WHITE}Security Defaults enabled:{_C.RESET}     {security_defaults_enabled}")
        print(f"  {_C.WHITE}Conditional Access policies:{_C.RESET}   {ca_policy_count}")
        print(f"  {_C.WHITE}Application registrations:{_C.RESET}     {app_count}")
        print(f"  {_C.WHITE}Dangerous permission grants:{_C.RESET}   {grant_count}")
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
