# Setup Guide -- Fresh Ubuntu 26 LTS

These steps take a brand-new Ubuntu 26 LTS machine to a working state
where the three scripts can be run interactively, in sequence, against
your live Active Directory and Entra ID environment.

This guide covers release 1.0 and its 1.0.x updates (schema v49).
`RELEASE_NOTES.md` lists the current version of each script, what changed
and how to upgrade.

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
- `run_lock.py` (used by all three scripts: one run at a time)
- `secret_input.py` (used by all three scripts: passwords and secrets
  from the environment, a file or a prompt)
- `schema_setup.py` (optional: creates or upgrades the database schema
  without `psql`, see section 5)
- `requirements.txt`
- `schema_init.sql`
- The `migrations/` folder (schema changes after v50; may be empty)
- The `docs/` folder (this guide, `RELEASE_NOTES.md` and the other
  documents)
- A `plugins/` subdirectory containing every plugin `.py` file

When done, `~/adprofiler` should look like:

```
adprofiler/
    adprofiler.py
    sysvol_collector.py
    entra_graph_collector.py
    adaudit.py
    run_lock.py
    secret_input.py
    schema_setup.py
    requirements.txt
    schema_init.sql
    migrations/
    docs/
        SETUP.md, RELEASE_NOTES.md, ...
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

**Alternatively, without `psql`**, run `schema_setup.py` from the same
directory as the schema files:

```
python3 schema_setup.py --pg-host <your-postgres-host> --pg-user <your-postgres-user> \
    --pg-dbname <your-database-name>
```

The schema is the v50 baseline (`schema_init.sql`, never edited) plus one
migration per later version in the `migrations/` folder
(`schema_migration_v51.sql`, `v52`, ...).
- **Empty database:** it applies the baseline, then every migration in
  order.
- **Existing database (v50 or later):** it applies every migration above
  the database's version, in order. A database several versions behind is
  brought up in one run.
- **Current database:** it does nothing.

Each file is applied completely or not at all, and the script checks that
it recorded its version.

It refuses:
- PostgreSQL older than 17;
- a database older than v50 (create a new, empty one);
- a database newer than the files;
- a gap in the migration chain.
Run it as the role that owns the schema. `--check` reports what it would do
and changes nothing (exit status `3` when something needs doing). It takes
the run lock, so no collection runs while the schema changes. Exit status:
`0` current, `1` failed (the message says why and which version the database
is at), `3` (with `--check`) setup needed, `75` run lock held, `130`
interrupted. The PostgreSQL password comes from the same places as for the
other scripts (section 7, "Passwords and secrets").

**Backing up before an upgrade.** When new scripts bring schema migrations,
add `--backup-dir <dir>` (needs `pg_dump` from the PostgreSQL 17 client
tools). Before it migrates an existing database, `schema_setup.py` saves it
to `<dir>/adprofiler-v<from>-before-v<to>-<UTC time>.dump` and keeps the
newest 3 (`--backup-keep`). If the backup fails, nothing is migrated. To go
back to a backup, restore it together with the scripts it belongs to:

```
psql -h <host> -U <user> -d <database> -c "DROP SCHEMA ad_intel CASCADE"
pg_restore -h <host> -U <user> -d <database> --no-owner --exit-on-error <dir>/<file>.dump
```

Data collected since the backup is lost; the next run collects it again.

## 6. What you'll need before running anything

- **A PostgreSQL 17 server** you control, reachable from this machine,
  with an empty database already created for this project, plus the
  hostname/IP, port, database name, username, and password to connect
  to it.
- **A domain controller hostname or IP**, and a service/bind account:
  an ordinary domain user (nothing administrative), **plus two read
  delegations a Domain Admin grants once** -- on `CN=Deleted Objects`
  and on the Password Settings Container. Without them a run still
  succeeds, but deleted accounts are never recorded as deleted and
  fine-grained password policies are invisible. `PERMISSIONS.md`
  (section 2) gives the exact steps, what not to grant, and how to
  check the account; hand it to the client's AD administrator.
- **Optional, for Group Policy content (`--sysvol`)**: TCP 445 (SMB)
  from this machine to the same domain controller, in addition to
  LDAP/LDAPS. The same bind account reads the SYSVOL and NETLOGON
  shares, which every domain user can read by default; GPOs with
  security filtering need the account added with Read
  (`PERMISSIONS.md`, section 2.4). See "Collecting Group Policy content"
  below.
- **If Entra ID collection is also wanted**: an App Registration's
  tenant ID, application (client) ID, and client secret (step-by-step
  setup for the client's Entra administrator: `PERMISSIONS.md`, section
  3), with the
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
  its licence is missing, or Microsoft is still throttling the source
  (HTTP 429) after the collector's retries, the collector records why for
  that data source (table `entra_collection_status`) and carries on, and
  `adaudit.py` shows the plugins that need it as **NOT ASSESSED**
  rather than passing them.

  | Permission | Type | Required / optional | Unlocks (plugins) | Licence |
  |---|---|---|---|---|
  | `User.Read.All` | Application | Required | Users (all Entra plugins) | – |
  | `RoleManagement.Read.Directory` | Application | Required | Directory roles, PIM eligibility/schedules, role definitions, custom-role assignments | P2 for PIM data |
  | `Policy.Read.All` | Application | Required | Security Defaults, Conditional Access, authorization, authentication methods, cross-tenant, admin consent request, app management and federated token validation policies, named locations | P1 for Conditional Access |
  | `Application.Read.All` | Application | Required | App registrations, service principals, owners, federated identity credentials | – |
  | `Directory.Read.All` | Application | Required | Permission grants, groups, domains, licences, directory settings, partner contracts, administrative units, devices | – |
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
simply omit the corresponding flag, or can come from an environment
variable or a file (see "Passwords and secrets without a terminal" in
section 7).

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
password if you didn't pass `--password`/`--pg-password`. Keep `--ssl`:
without it the bind password crosses the network unencrypted, and a
domain controller that requires LDAP signing refuses the connection
(this collector binds with a password, so LDAPS is its only way in).
Use plain LDAP only on a lab domain controller that has no LDAPS
certificate.

With `--ssl` the connection is encrypted, but the domain controller's
certificate is not checked unless you add `--ca-cert <file.pem>`: a PEM file
with the certificate of the CA that issued the DC's certificate (for an
enterprise CA, export its certificate as Base-64). The certificate must also
name the host given in `--dc-host`, so use the DC's FQDN there.

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
  GPO (security filtering), the bind account usually can't read that
  GPO at all (neither its AD object nor its folder): it is left out,
  and the collector's log counts its links as unresolved. Plugin 9021
  lists only GPOs whose folder is unreadable while their AD object is
  readable. Grant the bind account Read on them in GPMC (Delegation
  tab) if you want them covered (`PERMISSIONS.md`, section 2.4).
- Reading every GPO folder and searching scripts for passwords looks
  like an attacker's reconnaissance, so endpoint or identity monitoring
  tools may raise an alert. Tell the security team before the run, or
  have them allowlist this machine.
- If SMB is unreachable, or a run is made without `--sysvol`, the run
  still succeeds; the SYSVOL-based checks are then shown as NOT ASSESSED
  for that run (their open findings stay open). Group Policy data from an
  earlier `--sysvol` run is kept in the database but not evaluated, so
  for current Group Policy results use `--sysvol` on every run.

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
  Inventory, AD Subnet Inventory) with the full, unfiltered data those
  plugins produce.

To check only what a given framework covers, add `--framework` with its
name or tag prefix (for example `--framework PCI-DSS-4.0 "SOC 2"`).

`adaudit.py`'s exit status says whether the run is complete: `0` means
every plugin ran; `3` means it finished but at least one plugin failed
to load or errored (the end of the output lists which -- the rest of
the results are still valid); `1` means a fatal error such as no
database connection; `75` means it did not start because another run
holds the run lock (see Troubleshooting). Add `--fail-on fail` (or
`--fail-on warn`) to also get exit status `4` when there are open
findings at that level.

**Running all three in one go** (for example from a shell script): run them
one after another -- `adprofiler.py`, then
`entra_graph_collector.py`, then `adaudit.py` -- and only start the next
one when the previous one exited with status `0`. Any other exit status
means that step did not complete, and its log file says why:

| Script | 0 | 1 | 75 | 130 |
|---|---|---|---|---|
| `adprofiler.py` | collected | failed; nothing committed | not started: run lock held | interrupted; rolled back |
| `entra_graph_collector.py` | collected | failed (the log says whether any Entra table was already refreshed) | not started: run lock held | interrupted |

Running `adaudit.py` after a failed collection would evaluate the previous
collection's data again. A collector that exits `0` may still have skipped
optional data (SYSVOL not readable, an unlicensed or throttled Entra
source); `adaudit.py` reports the affected checks as NOT ASSESSED. The
scripts set no overall time limit, because a large directory can take a
long time; every network request has its own timeout and retries, so a
dead domain controller or Graph endpoint ends in a non-zero exit rather
than a hang.

Stopping, logs and output (adprofiler.py 1.0.8, entra_graph_collector.py
1.0.6, adaudit.py 1.0.7):

- **Stopping a run:** Ctrl-C (or SIGTERM, what `kill` sends) rolls the run
  back or marks it aborted, and the script exits `130`. A signal that
  arrives while a database statement or a network call is running takes
  effect when it returns, so give it a moment; a process killed outright
  (`kill -9`) leaves its run marked as running.
- **Logs:** `--log-dir DIR` puts each run's log file in `DIR` (created if
  missing). `adprofiler.py` and `entra_graph_collector.py` always write one
  (default: the current directory); `adaudit.py` writes
  `adaudit-results_<timestamp>.log` only with `--log-dir`. The log files are
  never deleted by the scripts.
- **Workbook:** `adaudit.py` always writes the Excel workbook;
  `--report-dir DIR` says where it goes (default: the current directory).
- **Schema:** `schema_setup.py` (section 5) brings the database to the
  scripts' schema version before a run.

**Passwords and secrets** (adprofiler.py 1.0.7, entra_graph_collector.py
1.0.5, adaudit.py 1.0.6): by default each script asks for its passwords at
a hidden prompt. Command-line options such as `--password` also work but are
visible to anyone who can list processes. Each secret is taken from the
first of these that is set:

1. its command-line option (works, with a warning);
2. its environment variable;
3. the file named by the same variable with `_FILE` appended -- the first
   line of the file is used;
4. a hidden prompt, when the script is run from a terminal.

| Secret | Option | Variable | File variable | Used by |
|---|---|---|---|---|
| AD bind password (LDAP and SYSVOL) | `--password` | `AD_BIND_PASSWORD` | `AD_BIND_PASSWORD_FILE` | `adprofiler.py` |
| Entra App Registration client secret | `--app-secret` | `ENTRA_APP_SECRET` | `ENTRA_APP_SECRET_FILE` | `entra_graph_collector.py` |
| PostgreSQL password | `--pg-password` | `PGPASSWORD` | `PGPASSWORD_FILE` | all three |

- Set either the variable or its `_FILE` variant, not both (the script
  refuses to start).
- Without a terminal and without any of these, `adprofiler.py` and
  `entra_graph_collector.py` stop with exit status `1` and a message
  naming the variables. A missing PostgreSQL password is not an error:
  the PostgreSQL client library then uses `~/.pgpass` (or the file named by
  `PGPASSFILE`, which is that library's own variable for a `.pgpass`-format
  file, not the same as `PGPASSWORD_FILE`) or a password-less method, and
  reports its own error if none works.
- The logs say where each secret came from (for example "from the file
  named by AD_BIND_PASSWORD_FILE"), never the secret itself.
- Keep secret files readable only by the account that runs the scripts
  (`chmod 600`). An environment variable is visible to that account and to
  root (`/proc/<pid>/environ`) and is inherited by anything the script
  starts; a file is the better choice where it can be used.

Example, from a shell script:

```
export PGPASSWORD_FILE=~/adprofiler/secrets/pg_password
export AD_BIND_PASSWORD_FILE=~/adprofiler/secrets/ad_bind_password
export ENTRA_APP_SECRET_FILE=~/adprofiler/secrets/entra_app_secret
python3 adprofiler.py --dc-host dc01.corp.local --username svc_audit@corp.local --ssl \
    --pg-host db --pg-user adprofiler --pg-dbname adprofiler && \
python3 entra_graph_collector.py --tenant-id <tenant> --app-id <app-id> \
    --domain-fqdn corp.local --pg-host db --pg-user adprofiler --pg-dbname adprofiler && \
python3 adaudit.py --pg-host db --pg-user adprofiler --pg-dbname adprofiler
```

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
- **A script stops with "Cannot start ...: another adprofiler.py,
  entra_graph_collector.py or adaudit.py run is in progress" (exit status
  75)**: the three scripts run one at a time against a database, and
  another run holds the run lock. Nothing was done; run it again once the
  other run finishes. The message names the holder (script, `pid=`,
  `host=`, start time and PostgreSQL session). PostgreSQL releases the
  lock as soon as that process exits, so a lock never outlives its run.
  If the run is hung, stop it on that host with `kill -INT <pid>`; only if
  the process no longer exists, end its leftover database session with
  the `pg_terminate_backend(...)` command the message prints.
- **A script can't connect to PostgreSQL**: double-check
  `--pg-host`/`--pg-port` are reachable from this machine (e.g.
  `nc -zv <host> <port>`), and that the database/user actually exist
  on that server.
- **`adprofiler.py` fails to bind to the domain controller**: the
  message after "LDAP bind failed:" says why.
  - `invalid server address`: the `--dc-host` name does not resolve in
    DNS from this machine (`getent hosts <dc-host>` returns nothing);
    the password was never tried. Fix DNS or use the DC's IP address
    (not with `--sysvol-kerberos`, which needs the DC's FQDN).
  - `invalidCredentials` with `data 52e`: wrong password; `775`: account
    locked out; `532`: password expired; `533`: account disabled.
  - `strongerAuthRequired`: the DC requires LDAP signing; use `--ssl`
    (LDAPS on 636). The DC needs a server-authentication certificate.
  - A TLS or connection error with `--ssl`: LDAPS is not set up on that
    DC (no certificate). Ask for one rather than dropping `--ssl`: plain
    LDAP sends the password unencrypted (`PERMISSIONS.md`, section 2.7).
- **`adprofiler.py` reports "Database schema is behind" (or "ahead,"
  or "predates schema version tracking")**: this means the database's
  schema doesn't match what this version of the script expects --
  normal after updating `adprofiler.py` without also updating the
  database. Run `schema_setup.py`: it applies the migrations in
  `migrations/` above the database's version, in order. A database
  older than v50 cannot be upgraded: create a new, empty database and
  run `schema_setup.py` against it. When a migration needs one
  `adprofiler.py --full-rescan`, `schema_setup.py` says so. Never
  re-run `schema_init.sql` against a database that already has data in
  it -- that file is for a brand-new, empty database only, and can fail
  or leave things in a mixed state against one that isn't.
- **`adprofiler.py` stops with "The current month has no partition for
  ... table(s)"**: the collector creates the monthly storage partitions it
  needs at the start of every run (schema v41 and later). This message
  means it wasn't allowed to: run
  `SELECT ad_intel.run_partition_maintenance();` once as the PostgreSQL
  user that owns the schema (the one `schema_setup.py` or
  `schema_init.sql` created it with). The maintenance functions run with
  the owner's rights even when the collector connects as a different
  user.
- **Disk use / data retention**: superseded history (old versions of
  objects, removed memberships and permissions) is kept for
  `retention_months` (12 by default, per client in the `client` table)
  and then purged automatically, about once a month. Current state is
  never purged, however long it has been unchanged.
