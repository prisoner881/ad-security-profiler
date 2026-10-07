# Setup Guide -- Fresh Ubuntu 26 LTS

These steps take a brand-new Ubuntu 26 LTS machine to a working state
where the three scripts can be run interactively, in sequence, against
your live Active Directory and Entra ID environment.

## 1. Install Python and the venv module

Ubuntu 26 LTS ships Python 3 by default, but the `venv` module is a
separate package:

```
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
```

## 2. Create a working directory and place the files

```
mkdir ~/adprofiler
cd ~/adprofiler
```

Copy the following into this directory (however you received them --
USB drive, secure file transfer, etc.):

- `adprofiler.py`
- `sysvol_collector.py` (used by `adprofiler.py --sysvol`)
- `entra_graph_collector.py`
- `adaudit.py`
- `adaudit_push.py` (used by `adaudit.py --push`)
- `requirements.txt`
- `schema_init.sql`
- Every `schema_migration_vNN.sql` file (only needed to upgrade an
  existing database -- see Troubleshooting)
- A `plugins/` subdirectory containing every plugin `.py` file

When done, `~/adprofiler` should look like:

```
adprofiler/
    adprofiler.py
    sysvol_collector.py
    entra_graph_collector.py
    adaudit.py
    adaudit_push.py
    requirements.txt
    schema_init.sql
    plugins/
        1001_....py
        1002_....py
        ... (one file per plugin)
```

## 3. Create and activate a Python virtual environment

From inside `~/adprofiler`:

```
python3 -m venv venv
source venv/bin/activate
```

Your shell prompt should now start with `(venv)`. This needs to be
done once per terminal session -- if you close the terminal and open a
new one later, run `source venv/bin/activate` again before running any
of the scripts (you'll be back in the `~/adprofiler` directory, or
just `cd` there again first).

## 4. Install the required Python packages

With the venv active:

```
pip install -r requirements.txt
```

This installs everything all three scripts need, including `openpyxl`
(for `adaudit.py`'s Excel output), `ldap3` and `impacket` (for AD
collection), `requests` (for Entra ID collection), and `cryptography`
(for certificate parsing).

## 5. Initialize the database schema

Before running any of the scripts, the empty PostgreSQL database
mentioned above needs its schema created. From a machine that can
reach your PostgreSQL server (this one, or wherever you normally run
`psql` from):

```
psql -h <your-postgres-host> -p <port> -U <your-postgres-user> -d <your-database-name> -f schema_init.sql
```

This is a one-time step per database -- it creates every table,
function, and index all three scripts need. You'll be prompted for the
PostgreSQL password unless it's already set via `PGPASSWORD` or a
`.pgpass` file.

## 6. What you'll need before running anything

- **A PostgreSQL 17 server** you control, reachable from this machine,
  with an empty database already created for this project, plus the
  hostname/IP, port, database name, username, and password to connect
  to it.
- **A domain controller hostname or IP**, and a service/bind account
  with read access to Active Directory (a low-privileged domain user
  account is sufficient -- nothing administrative is required).
- **Optional, for Group Policy content (`--sysvol`)**: TCP 445 (SMB)
  from this machine to the same domain controller, in addition to
  LDAP/LDAPS. No extra account or permission is needed -- the same
  bind account reads the SYSVOL and NETLOGON shares, which every domain
  user can read by default. See "Collecting Group Policy content" below.
- **If Entra ID collection is also wanted**: an App Registration's
  tenant ID, application (client) ID, and client secret, with the
  Graph API permissions already granted and admin-consented
  (`User.Read.All`, `RoleManagement.Read.Directory`, `Policy.Read.All`,
  `Application.Read.All`, `Directory.Read.All`). **These must be
  granted as "Application permissions," not "Delegated permissions"**
  -- Entra's API permissions blade lists both as separate sections,
  and a permission with the same name can exist in both, but only the
  Application-type grant works for this script's unattended
  (client_credentials) authentication, which has no signed-in user.
  Granting the Delegated version by mistake still shows a green
  "Granted" checkmark in the portal, but produces a 403 error here --
  a real client hit exactly this before catching it.
  `RoleManagement.Read.Directory` also covers PIM-eligible role
  assignments, which are read when the tenant has Entra ID P2 (or ID
  Governance); without that licence the collector records that
  eligibility couldn't be checked and carries on. `Directory.Read.All`
  covers expanding the members of groups that hold a directory role.
  As of entra_graph_collector.py 0.7.0 no new permissions are needed:
  `Policy.Read.All` also covers the tenant authorization policy (user
  app registration/consent and guest settings), and
  `RoleManagement.Read.Directory` also covers the active role
  assignment schedules that say whether a role is held permanently,
  time-bound or through a PIM activation -- these schedules need Entra
  ID P2 (or ID Governance) like eligibility does, and without it the
  collector records why and carries on.
- **Optional Entra ID permissions (entra_graph_collector.py 0.8.0)**:
  the five permissions above are the only required ones. They also
  cover licences, organization, domains, groups (with owners and
  members of the sensitive ones), role definitions and custom-role
  assignments, service principals and their owners, application and
  delegated permission grants, named locations, and the authentication
  methods, cross-tenant access, admin consent request and directory
  (password protection / group) settings. Each optional permission
  below unlocks more checks; grant only the ones you want, all as
  **Application** permissions with admin consent. When a permission or
  its licence is missing, the collector records why for that data
  source (table `entra_collection_status`) and carries on, and
  `adaudit.py` shows the plugins that need it as **NOT ASSESSED**
  rather than passing them.

  | Permission | Type | Required / optional | Unlocks (plugins) | Licence |
  |---|---|---|---|---|
  | `User.Read.All` | Application | Required | Users (all Entra plugins) | – |
  | `RoleManagement.Read.Directory` | Application | Required | Directory roles, PIM eligibility/schedules, role definitions, custom-role assignments | P2 for PIM data |
  | `Policy.Read.All` | Application | Required | Security Defaults, Conditional Access, authorization, authentication methods, cross-tenant, admin consent request policies, named locations | P1 for Conditional Access |
  | `Application.Read.All` | Application | Required | App registrations, service principals, owners | – |
  | `Directory.Read.All` | Application | Required | Permission grants, groups, domains, licences, directory settings, partner contracts | – |
  | `AuditLog.Read.All` | Application | Optional | User sign-in activity, service-principal sign-in activity, MFA registration details: 10040–10044, 10055, 10066 | P1 |
  | `Domain.Read.All` | Application | Optional | Federation configuration of federated domains: 10090, 11022 | – |
  | `RoleManagementPolicy.Read.Directory` | Application | Optional | PIM role settings (activation MFA, approval, duration, notifications): 10050, 10051. The precise permission; `RoleManagement.Read.Directory` (required above) is also documented by Microsoft as sufficient | P2 |
  | `Policy.Read.DeviceConfiguration` | Application | Optional | Device registration policy (beta API): 10084 | – |
  | `OnPremDirectorySynchronization.Read.All` | Application | Optional | On-prem sync feature flags (password hash sync, soft/hard-match blocking): 10094 | – |
  | `IdentityRiskyUser.Read.All` | Application | Optional | Risky users: 10100 | P2 |
  | `IdentityRiskEvent.Read.All` | Application | Optional | Risk detections (e.g. leaked credentials): 10101 | P2 |
  | `OnPremisesPublishingProfiles.ReadWrite.All` | Application | Optional, opt-in, **write-capable** | Pass-through authentication agents (beta API): 10095. Microsoft offers no read-only permission for this read, so the collector only uses it when run with `--include-pta-agents`; it still only reads, but the permission itself allows changes, so grant it only if that is acceptable | – |

  Every permission in this table is read-only except
  `OnPremisesPublishingProfiles.ReadWrite.All`. Without
  `--include-pta-agents` the PTA agent source is recorded as skipped.
- **Emergency-access (break-glass) accounts (optional)**: plugins
  10026, 10042, 10043 and 10055 exempt or check break-glass accounts.
  By default they recognise them heuristically (cloud-only enabled
  Global Administrator excluded directly from an all-users Conditional
  Access policy). To name them explicitly, insert their UPNs once:
  `INSERT INTO ad_intel.entra_breakglass_account (client_id, user_principal_name, note) VALUES ('<client_id>', 'bg1@contoso.onmicrosoft.com', 'emergency access');`
  When a client has any row there, exactly those accounts are used.

None of these need to be typed on the command line if you'd rather
not -- every password/secret prompts securely (hidden input) if you
simply omit the corresponding flag.

## 7. Running the scripts, in sequence

All three scripts share the same PostgreSQL connection flags:
`--pg-host`, `--pg-port` (default 5432), `--pg-dbname` (default
`adprofiler`), `--pg-user`, and `--pg-password` (omit to be prompted
securely).

**Step 1 -- collect on-prem Active Directory data:**

```
python3 adprofiler.py \
  --dc-host <your-dc-hostname-or-ip> \
  --username <bind-account-upn> \
  --ssl \
  --pg-host <your-postgres-host> \
  --pg-user <your-postgres-user> \
  --pg-dbname <your-database-name>
```

You'll be prompted for the AD bind password and the PostgreSQL
password if you didn't pass `--password`/`--pg-password`. Drop `--ssl`
if your domain controller doesn't have LDAPS configured.

This creates a timestamped log file in the current directory:
`adprofiler-results_<timestamp>.log`, mirroring everything shown on
screen.

**Collecting Group Policy content (optional, recommended):** add
`--sysvol` to the Step 1 command. Group Policy settings are stored as
files on the domain controllers' SYSVOL share, not in LDAP; with
`--sysvol` the collector also reads, over SMB and read-only, each GPO's
security template, administrative-template settings, audit policy and
Group Policy Preferences, and scans logon/startup scripts (GPO script
folders and the NETLOGON share) for embedded credentials. This is what
lets the report check things like LDAP and SMB signing, NTLMv1, Kerberos
policy, user rights and audit policy on the domain controllers, and find
Group Policy Preferences passwords (MS14-025).

- Needs TCP 445 to the domain controller. If the DCs refuse NTLM, add
  `--sysvol-kerberos` and pass the DC's FQDN as `--dc-host` (or
  `--smb-host`); this machine must then resolve the DC by name in DNS
  and have its clock within 5 minutes of the DC's.
- Passwords found in Group Policy Preferences or scripts are never
  stored: only the fact that one is present, the account it is for, and
  for scripts the pattern name and line number.
- If an administrator removed "Authenticated Users" read access from a
  GPO (security filtering), the bind account can't read that GPO's
  folder; the report lists such GPOs (plugin 9021) and evaluates the
  rest. Grant the bind account read on them if you want them covered.
- Reading every GPO folder and searching scripts for passwords looks
  like an attacker's reconnaissance, so endpoint or identity monitoring
  tools may raise an alert. Tell the security team before the run, or
  have them allowlist this machine.
- If SMB is unreachable the run still succeeds; the SYSVOL-based checks
  are then shown as NOT ASSESSED in the report.

**Step 2 -- collect Entra ID data (skip this step entirely if there's
no Entra ID tenant to collect from):**

```
python3 entra_graph_collector.py \
  --tenant-id <tenant-id> \
  --app-id <app-id> \
  --domain-fqdn <the AD domain FQDN, e.g. contoso.local> \
  --pg-host <your-postgres-host> \
  --pg-user <your-postgres-user> \
  --pg-dbname <your-database-name>
```

You'll be prompted for the App Registration client secret and the
PostgreSQL password if omitted.

`--tenant-id` and `--domain-fqdn` are unrelated to each other --
easy to mix up, so worth being explicit: `--tenant-id` identifies your
Entra ID tenant for authentication (a GUID, or any domain Entra
considers verified for that tenant, which is very often *not* the
same string as your internal AD domain). `--domain-fqdn` is
purely a local lookup key, matched case-insensitively against
whatever `adprofiler.py` already collected in Step 1 -- it must match
that domain, not anything about Entra ID.

If `--domain-fqdn` keeps producing "No client found" and you're
confident `adprofiler.py` was already run successfully against this
domain, skip the domain-name lookup entirely: run
`SELECT client_id, domain_fqdn FROM client;` against the database once
to see the exact stored value, then either pass that exact
`domain_fqdn` string, or pass the `client_id` GUID directly instead:

```
python3 entra_graph_collector.py \
  --tenant-id <tenant-id> \
  --app-id <app-id> \
  --client-id <client_id GUID from the client table> \
  --pg-host <your-postgres-host> \
  --pg-user <your-postgres-user> \
  --pg-dbname <your-database-name>
```

This creates its own timestamped log:
`entra-graph-collector-results_<timestamp>.log`.

**Step 3 -- run the findings analysis:**

```
python3 adaudit.py \
  --pg-host <your-postgres-host> \
  --pg-user <your-postgres-user> \
  --pg-dbname <your-database-name>
```

This prints the full findings report to the screen (unchanged from
before), and additionally writes a timestamped Excel workbook:
`adaudit-findings_<timestamp>.xlsx`, with:

- A **Summary** tab listing FAIL/WARN/PASS counts per category.
- One tab per finding category (ACLs, Computer Accounts, User
  Accounts, etc.), listing only FAIL and WARN findings -- full
  PASS/FAIL/WARN detail for every plugin is still in the console
  output and its own timestamped log, unchanged.
- A **Compliance Summary** tab (right after Summary) showing, per
  framework (NIST SP 800-53, NIST CSF 2.0, PCI DSS 4.0, CIS Controls v8,
  ISO 27001, SOC 2, HIPAA, CISA SCuBA, DISA STIG, MITRE ATT&CK, and
  advisories/CVEs), how many controls the checks cover and how many of
  them are failing, warning or passing.
- One tab per framework listing each control, the checks mapped to it
  and their result (FAIL/WARN/PASS/ERROR, or NOT ASSESSED when the
  data it needs -- e.g. Entra ID -- wasn't collected) with open finding
  counts. Which controls each check maps to is listed in
  `COMPLIANCE_TAGS.md`.
- Separate inventory tabs (User Inventory, Computer Inventory, Group
  Inventory) with the full, unfiltered data those plugins produce.

To check only what a given framework covers, add `--framework` with its
name or tag prefix (for example `--framework PCI-DSS-4.0 "SOC 2"`).

`adaudit.py`'s exit status says whether the run is complete: `0` means
every plugin ran; `3` means it finished but at least one plugin failed
to load or errored (the end of the output lists which -- the rest of
the results are still valid); `1` means a fatal error such as no
database connection. Add `--fail-on fail` (or `--fail-on warn`) to
also get exit status `4` when there are open findings at that level.

**Optional -- push the results to FortifyData:**

`adaudit.py` can send each run to the FortifyData platform instead of
(or as well as) handing over the workbook. Add `--push`:

```
export FD_API_URL=us                 # or eu, test, or a full https:// URL
export FD_COMPANY_ID=<company id from FortifyData>
python3 adaudit.py --pg-host <host> --pg-user <user> --pg-dbname <db> \
  --push --api-key-file ~/adprofiler/fd_api_key.txt
```

- **Credentials are given at run time**, never stored in the database:
  `--api-url` / `--api-company-id` / `--api-key`, or the environment
  variables `FD_API_URL` / `FD_COMPANY_ID` / `FD_API_KEY`, or for the key
  a file (`--api-key-file`, first line; `chmod 600` it). With none of
  those, an interactive run prompts for the key. `--api-key` on the
  command line works but is visible in shell history and process
  listings.
- **What is sent:** the run's findings (with their evidence), the
  result of every check, the newest run's user / computer / group /
  subnet inventory, and the list of checks. No passwords or other
  secrets are ever collected, so none can be sent.
- **The first push from a new installation is refused** until
  FortifyData approves it. That is expected: `adaudit.py` says so,
  exits normally, and keeps the runs queued; the next push after
  approval sends them all.
- **Nothing is lost when the network is down.** Every complete run is
  queued in the database and pushed, oldest first, by the next
  `--push` (or `--push-only`, which pushes without evaluating -- useful
  in a daily job after a failed collection). Exit status `5` means the
  push did not finish; the results are still recorded locally.
- `--push-dry-run <dir>` writes exactly what would be sent to `<dir>`
  as JSON files and sends nothing (no credentials needed) -- a good way
  to review what leaves the network.
- Runs limited with `--plugin-id`, `--category` or `--framework` are
  diagnostic: they are never pushed and no longer change the findings
  history.
- If the platform keeps rejecting one run, `--push-skip <run id>` (the
  id is in the error message) lets the later runs go.

## 8. Reviewing results together

Once all three steps are complete, you'll have (in `~/adprofiler`):

- `adprofiler-results_<timestamp>.log`
- `entra-graph-collector-results_<timestamp>.log` (if Step 2 was run)
- `adaudit-findings_<timestamp>.xlsx`

Send these back for review -- the Excel workbook is the main thing
worth going through together; the two log files are there mainly for
troubleshooting if anything looked wrong during collection.

## Troubleshooting

- **`ModuleNotFoundError` when running any script**: the venv likely
  isn't active. Run `source venv/bin/activate` from inside
  `~/adprofiler` and try again.
- **A script can't connect to PostgreSQL**: double-check
  `--pg-host`/`--pg-port` are reachable from this machine (e.g.
  `nc -zv <host> <port>`), and that the database/user actually exist
  on that server.
- **`adprofiler.py` fails to bind to the domain controller**: confirm
  the bind account's password is correct, and try without `--ssl`
  first if LDAPS isn't confirmed to be configured on that DC.
- **`adprofiler.py` reports "Database schema is behind" (or "ahead,"
  or "predates schema version tracking")**: this means the database's
  schema doesn't match what this version of the script expects --
  normal after updating `adprofiler.py` without also updating the
  database. The message itself tells you exactly which
  `schema_migration_vNN.sql` file(s) to apply, by number, against your
  *existing* database. Never re-run `schema_init.sql` against a
  database that already has data in it -- that file is for a
  brand-new, empty database only, and can fail or leave things in a
  mixed state against one that isn't.
  After applying a migration, run `adprofiler.py` once with
  `--full-rescan` so objects that haven't changed in AD still get the
  columns the new version collects (otherwise some checks see them as
  "not collected" until each object next changes).
- **`adprofiler.py` stops with "The current month has no partition for
  ... table(s)"**: the collector creates the monthly storage partitions it
  needs at the start of every run (schema v41 and later). This message
  means it wasn't allowed to: apply `schema_migration_v41.sql` (or
  re-apply it) as the PostgreSQL user that owns the schema -- the
  maintenance functions then run with that user's rights even when the
  collector connects as a different user. Running
  `SELECT ad_intel.run_partition_maintenance();` once as that owner also
  fixes it.
- **Disk use / data retention**: superseded history (old versions of
  objects, removed memberships and permissions) is kept for
  `retention_months` (12 by default, per client in the `client` table)
  and then purged automatically, about once a month. Current state is
  never purged, however long it has been unchanged.
