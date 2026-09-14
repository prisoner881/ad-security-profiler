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
- `entra_graph_collector.py`
- `adaudit.py`
- `requirements.txt`
- `schema_init.sql`
- A `plugins/` subdirectory containing every plugin `.py` file

When done, `~/adprofiler` should look like:

```
adprofiler/
    adprofiler.py
    entra_graph_collector.py
    adaudit.py
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
- Separate inventory tabs (User Inventory, Computer Inventory, Group
  Inventory) with the full, unfiltered data those plugins produce.

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
