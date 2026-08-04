#!/usr/bin/env python3
"""
entra_graph_collector.py -- Microsoft Entra ID / Graph API Email Collector

VERSION: 0.4.0

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
import json
import re
import sys
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

VERSION = "0.4.0"

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

def get_graph_token(tenant_id, app_id, app_secret):
    """OAuth2 client-credentials (app-only) flow. No signed-in user, no
    interactive consent at runtime -- consent was already granted once,
    ahead of time, when a tenant admin approved the application
    permission in the Entra admin center."""
    try:
        resp = requests.post(
            GRAPH_TOKEN_URL_TMPL.format(tenant_id=tenant_id),
            data={
                "client_id": app_id,
                "client_secret": app_secret,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
            },
            timeout=30,
        )
    except requests.exceptions.RequestException as exc:
        raise CollectorAbort(f"Could not reach Microsoft's token endpoint: {exc}")

    if resp.status_code != 200:
        detail = resp.json().get("error_description", resp.text) if resp.content else resp.reason
        raise CollectorAbort(
            f"Token request failed (HTTP {resp.status_code}): {detail}\n"
            "Common causes: wrong tenant ID, wrong app ID/secret, secret "
            "expired, or the application permission was never admin-consented."
        )
    return resp.json()["access_token"]


def fetch_all_users(token):
    """Paginated via @odata.nextLink -- Graph enforces its own page-size
    ceiling regardless of $top, so this always follows nextLink rather
    than assume one request is enough."""
    users = []
    url = f"{GRAPH_USERS_URL}?$select={GRAPH_USER_SELECT}&$top={GRAPH_PAGE_SIZE}"
    headers = {"Authorization": f"Bearer {token}"}
    page = 0
    while url:
        page += 1
        try:
            resp = requests.get(url, headers=headers, timeout=60)
        except requests.exceptions.RequestException as exc:
            raise CollectorAbort(f"Could not reach Microsoft Graph: {exc}")

        if resp.status_code == 429:
            retry_after = resp.headers.get("Retry-After", "an unspecified time")
            raise CollectorAbort(
                f"Graph throttled this request (HTTP 429); Retry-After: {retry_after}. "
                "Re-run later, or reduce collection frequency if this recurs."
            )
        if resp.status_code == 403:
            raise CollectorAbort(
                "Graph returned HTTP 403 (Forbidden). The application permission "
                "(User.Read.All) likely was never admin-consented in the Entra "
                "admin center -- API permissions must show 'Granted for <tenant>', "
                "not just 'Not granted'."
            )
        if resp.status_code != 200:
            raise CollectorAbort(f"Graph request failed (HTTP {resp.status_code}): {resp.text}")

        body = resp.json()
        page_users = body.get("value", [])
        users.extend(page_users)
        log_info(f"  page {page}: {len(page_users)} user(s) ({len(users)} total so far)")
        url = body.get("@odata.nextLink")

    return users


def fetch_directory_roles_with_members(token):
    """Two-step fetch: list every activated role, then one members call
    per role -- /directoryRoles/{id}/members has no pagination of its
    own (confirmed against Microsoft's own documentation: returns up to
    1,000 objects, no $top-based paging), so no nextLink-following
    needed there, unlike fetch_all_users above.

    A role member can be a user, a group, or a service principal
    (Graph distinguishes these via @odata.type on each returned
    object) -- all three are kept here rather than filtered down to
    users only, since a service principal or group holding Global
    Administrator is a genuinely different, separately worth-knowing
    fact from a human account holding it, not something to silently
    drop.
    """
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(GRAPH_DIRECTORY_ROLES_URL, headers=headers, timeout=60)
    except requests.exceptions.RequestException as exc:
        raise CollectorAbort(f"Could not reach Microsoft Graph: {exc}")
    if resp.status_code == 403:
        raise CollectorAbort(
            "Graph returned HTTP 403 (Forbidden) fetching directory roles. The "
            "application permission (RoleManagement.Read.Directory) likely was "
            "never granted or admin-consented -- API permissions must show "
            "'Granted for <tenant>', not just 'Not granted'."
        )
    if resp.status_code != 200:
        raise CollectorAbort(f"Graph request failed (HTTP {resp.status_code}): {resp.text}")
    roles = resp.json().get("value", [])
    log_info(f"  {len(roles)} activated directory role(s) found")

    role_members = []
    member_select = "id,displayName,userPrincipalName,onPremisesSecurityIdentifier,accountEnabled"
    for role in roles:
        members_url = f"{GRAPH_DIRECTORY_ROLES_URL}/{role['id']}/members?$select={member_select}"
        try:
            resp = requests.get(members_url, headers=headers, timeout=60)
        except requests.exceptions.RequestException as exc:
            raise CollectorAbort(f"Could not reach Microsoft Graph: {exc}")
        if resp.status_code != 200:
            log_warn(f"  Could not fetch members of role '{role.get('displayName')}' "
                      f"(HTTP {resp.status_code}) -- skipping this role, continuing with others.")
            continue
        members = resp.json().get("value", [])
        log_info(f"  role '{role.get('displayName')}': {len(members)} member(s)")
        for member in members:
            role_members.append({"role": role, "member": member})

    return role_members


def fetch_security_defaults(token):
    """A single object, no pagination -- confirmed against Microsoft's
    own documentation, {"isEnabled": bool, "displayName": ..., "id": ...}."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(GRAPH_SECURITY_DEFAULTS_URL, headers=headers, timeout=60)
    except requests.exceptions.RequestException as exc:
        raise CollectorAbort(f"Could not reach Microsoft Graph: {exc}")
    if resp.status_code == 403:
        raise CollectorAbort(
            "Graph returned HTTP 403 (Forbidden) fetching Security Defaults status. "
            "The application permission (Policy.Read.All) likely was never granted "
            "or admin-consented."
        )
    if resp.status_code != 200:
        raise CollectorAbort(f"Graph request failed (HTTP {resp.status_code}): {resp.text}")
    return resp.json().get("isEnabled")


def fetch_conditional_access_policies(token):
    """No documented pagination on this endpoint -- tenants don't
    typically have more than a few dozen CA policies, well under any
    page-size ceiling Graph would otherwise enforce."""
    headers = {"Authorization": f"Bearer {token}"}
    try:
        resp = requests.get(GRAPH_CA_POLICIES_URL, headers=headers, timeout=60)
    except requests.exceptions.RequestException as exc:
        raise CollectorAbort(f"Could not reach Microsoft Graph: {exc}")
    if resp.status_code == 403:
        raise CollectorAbort(
            "Graph returned HTTP 403 (Forbidden) fetching Conditional Access "
            "policies. The application permission (Policy.Read.All) likely was "
            "never granted or admin-consented."
        )
    if resp.status_code != 200:
        raise CollectorAbort(f"Graph request failed (HTTP {resp.status_code}): {resp.text}")
    return resp.json().get("value", [])


def fetch_applications(token):
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
    headers = {"Authorization": f"Bearer {token}"}
    page = 0
    while url:
        page += 1
        try:
            resp = requests.get(url, headers=headers, timeout=60)
        except requests.exceptions.RequestException as exc:
            raise CollectorAbort(f"Could not reach Microsoft Graph: {exc}")
        if resp.status_code == 403:
            raise CollectorAbort(
                "Graph returned HTTP 403 (Forbidden) fetching applications. The "
                "application permission (Application.Read.All) likely was never "
                "granted or admin-consented."
            )
        if resp.status_code != 200:
            raise CollectorAbort(f"Graph request failed (HTTP {resp.status_code}): {resp.text}")
        body = resp.json()
        page_apps = body.get("value", [])
        apps.extend(page_apps)
        log_info(f"  page {page}: {len(page_apps)} application(s) ({len(apps)} total so far)")
        url = body.get("@odata.nextLink")
    return apps


def fetch_dangerous_permission_grants(token):
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
    headers = {"Authorization": f"Bearer {token}"}
    sp_url = f"{GRAPH_SERVICE_PRINCIPALS_URL}?$filter=appId eq '{GRAPH_MSGRAPH_SP_APPID}'&$select=id,appRoles"
    try:
        resp = requests.get(sp_url, headers=headers, timeout=60)
    except requests.exceptions.RequestException as exc:
        raise CollectorAbort(f"Could not reach Microsoft Graph: {exc}")
    if resp.status_code == 403:
        raise CollectorAbort(
            "Graph returned HTTP 403 (Forbidden) fetching the Microsoft Graph "
            "service principal. The application permission (Directory.Read.All) "
            "likely was never granted or admin-consented."
        )
    if resp.status_code != 200:
        raise CollectorAbort(f"Graph request failed (HTTP {resp.status_code}): {resp.text}")
    sp_results = resp.json().get("value", [])
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
        try:
            resp = requests.get(url, headers=headers, timeout=60)
        except requests.exceptions.RequestException as exc:
            raise CollectorAbort(f"Could not reach Microsoft Graph: {exc}")
        if resp.status_code != 200:
            raise CollectorAbort(f"Graph request failed (HTTP {resp.status_code}): {resp.text}")
        body = resp.json()
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


def resolve_client_id(pg_conn, domain_fqdn):
    """Looks up the EXISTING client row created by adprofiler.py's own
    LDAP collection -- deliberately does not create a new client row
    here. A Graph-only client with no prior LDAP baseline is a real,
    supportable scenario in principle, but this script's whole value is
    correlating cloud users back to on-prem accounts, which needs that
    baseline to already exist -- so absence is treated as a setup
    error to fix, not silently worked around."""
    with pg_conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
        cur.execute("SELECT client_id FROM client WHERE domain_fqdn = %s;", (domain_fqdn,))
        row = cur.fetchone()
    if row is None:
        raise CollectorAbort(
            f"No client found for domain_fqdn='{domain_fqdn}'. This script "
            "enriches an existing client record with cloud email data -- run "
            "adprofiler.py against this domain's on-prem AD at least once "
            "first, so there's a client row (and object_sid values) to "
            "correlate Graph users against."
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
                              "the existing client record to enrich. Required "
                              "unless --version is given.")
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

    if not args.version and (not args.tenant_id or not args.app_id or not args.domain_fqdn):
        parser.error("the following arguments are required: --tenant-id, --app-id, --domain-fqdn")
    if not args.version and (not args.pg_host or not args.pg_user):
        parser.error("the following arguments are required: --pg-host, --pg-user")

    return args


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
    try:
        log_info(f"Requesting a Graph token for tenant {args.tenant_id}...")
        token = get_graph_token(args.tenant_id, args.app_id, app_secret)
        log_success("Token acquired.")

        log_info("Connecting to PostgreSQL...")
        pg_conn = connect_postgres()
        log_success("Connected to PostgreSQL.")

        client_id = resolve_client_id(pg_conn, args.domain_fqdn)
        log_success(f"Resolved client record for {args.domain_fqdn}.")

        log_header("Collecting Users from Microsoft Graph")
        users = fetch_all_users(token)
        log_success(f"Fetched {len(users)} user(s) from Graph.")

        total, matched = sync_entra_users(pg_conn, client_id, users)

        log_header("Collecting Directory Role Membership from Microsoft Graph")
        role_members = fetch_directory_roles_with_members(token)
        role_member_count = sync_directory_role_members(pg_conn, client_id, role_members)
        global_admin_count = sum(
            1 for rm in role_members if rm["role"].get("roleTemplateId") == GLOBAL_ADMIN_ROLE_TEMPLATE_ID
        )
        log_success(f"Recorded {role_member_count} role membership(s), "
                    f"including {global_admin_count} Global Administrator member(s).")

        log_header("Collecting Security Posture (Security Defaults + Conditional Access)")
        security_defaults_enabled = fetch_security_defaults(token)
        ca_policies = fetch_conditional_access_policies(token)
        ca_policy_count = sync_security_posture(pg_conn, client_id, security_defaults_enabled, ca_policies)
        log_success(f"Security Defaults enabled: {security_defaults_enabled}. "
                    f"{ca_policy_count} Conditional Access polic{'y' if ca_policy_count == 1 else 'ies'} recorded.")

        log_header("Collecting Application Registrations from Microsoft Graph")
        applications = fetch_applications(token)
        app_count = sync_applications(pg_conn, client_id, applications)
        log_success(f"Recorded {app_count} application registration(s).")

        log_header("Checking for Highly Privileged Microsoft Graph API Permission Grants")
        dangerous_grants = fetch_dangerous_permission_grants(token)
        grant_count = sync_dangerous_permission_grants(pg_conn, client_id, dangerous_grants)
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
        sys.exit(1)
    except KeyboardInterrupt:
        log_warn("Aborting due to Ctrl-C...")
        sys.exit(130)


if __name__ == "__main__":
    main()
