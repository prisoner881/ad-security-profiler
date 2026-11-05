# Release Notes

## Development branch (not yet released)

Changes on the `development` branch, which collects the work towards
running the scripts unattended under a supervising process (scheduled runs
in a container). They are not in `release` yet.

### Image pipeline: name, version, both architectures, backups (2026-11-05)

collector_daemon.py 1.2.0, schema_setup.py 1.3, image 1.2.0. Schema
unchanged (v50).

- **The image is `fortifydata/collector-ad`** on Docker Hub, for
  `linux/amd64` and `linux/arm64`:
  - releases `vX.Y.Z` and `latest`;
  - development builds `vX.Y.Z-dev.N` and `develop`.
  `docker/compose.yaml` and `install.sh` default to `v1.2.0`.
- **The image reports the version it was built as.**
  - CI passes `COLLECTOR_VERSION` (`1.2.0`, or `1.2.0-dev.17`).
  - The daemon reports it as the health report's `version`, in the
    User-Agent and in `--version`. Outside an image it reports its own
    `VERSION`.
  - A `v` in `targetVersion` is ignored when comparing.
- **CI** (`.github/workflows/collector-image.yml`, for FortifyData's
  repository):
  - runs the tests;
  - builds both architectures and smoke-tests each one;
  - pushes development builds from `development` and releases from a
    `vX.Y.Z` tag, which must match `VERSION`.
  The release process is in `MAINTAINERS.md`.
- **A backup before every schema migration.**
  - `schema_setup.py --backup-dir` dumps the database with `pg_dump`
    before migrating it, to `<state_dir>/backups/` (mode `0600`). The
    newest 3 are kept.
  - If the backup fails, nothing is migrated.
  - The image now includes the PostgreSQL 17 client tools.
  - The restore steps are in `CONTAINER.md`, section 5.
- **Tests** (`tests/`):
  - activation keys;
  - the schedule across daylight-saving changes;
  - the health-check configuration mapping;
  - the image version;
  - every plugin loading;
  - with a PostgreSQL 17 server, the schema chain: fresh, upgrade with
    skipped versions, the refusals, the backup and its restore, and an
    upgraded schema compared with a fresh one.

### The platform's real collector API (2026-11-05)

collector_daemon.py 1.1.0, platform_client.py 2.0, adaudit.py 1.0.11
(adaudit_push.py), image 1.1.0. Schema unchanged (v50). This follows the
platform developer's documents 04 (answers) and 05 (configuration
contract), and their follow-up answers.

- **Activation key environments.**
  - `e` is the platform's environment. Only `prod` (US production; `us` is
    never issued), `eu` and `test` have an API server a collector can use.
    **Before this change a real production key would have failed.**
  - A key without `e` is refused. Any other environment, or a bare license
    key, needs the API URL given explicitly.
  - `--api-url` takes `prod`, `eu` and `test` as shortcuts.
- **Activation and lease** use the real paths
  (`/api/v1/integration/collector/activations/{instanceId}`):
  - no request body;
  - renewal answers `202` (previously treated as a failure);
  - the lease length comes from `leaseExpiryDate`;
  - a clock more than 2 minutes off the platform's is warned about.
- **The configuration comes with the health check** (`POST
  /api/v1/integration/collector/health`, every 5 minutes):
  - the flat fields of document 05, `ldapPort` used as given;
  - a portal change applies within 5 minutes;
  - `configVersion` and the image `version` go back in the health report;
  - nulls mean "not configured yet": no run, keep polling.
- **Secrets stay in memory.**
  - They arrive over TLS only, as the platform decided: the key pair and
    the secret encryption are removed.
  - The last configuration is cached on disk without its secrets. A
    restart during a platform outage therefore waits for the platform
    before running.
- **Collector status:**
  - `EXPIRED`, or a `404` from the health check (no collector, or
    deleted): no scans, keep reporting;
  - `FAILED`: ignored.
- **Updates:** a newer `targetVersion` is logged and reported, together with
  `autoUpgrade` and `imageName`. Installing it is the updater's job, still
  to be built.
- **Schedule offset:** scheduled runs start a per-installation random 0–30
  minutes after the set time, so clients do not all start together.

### Schema baseline and `migrations/` (2026-11-05)

`schema_setup.py` 1.2, collector_daemon.py 1.0.4 (image 1.0.4). Schema
unchanged (v50).

- **The schema is now a frozen baseline plus a migration chain.**
  - `schema_init.sql` is the v50 baseline and is never edited again.
  - Every later change is one file in the new `migrations/` folder:
    `schema_migration_v51.sql`, `v52`, and so on. It is empty for now.
- **`schema_setup.py` plays the chain back:**
  - a new database gets the baseline, then every migration in order;
  - an existing database (v50 or later) gets every migration above its
    version, so a client who skipped updates (v50 to v55) is brought up in
    one run;
  - it refuses a gap in the chain, a database older than v50, and a
    migration file outside `migrations/`.
- **Full rescans:** a migration that needs one says so in its header. The
  daemon then runs the next collection with `--full-rescan`, once.
- The rules for writing a migration are in `MAINTAINERS.md` ("Schema
  changes").

### Schema migration files removed (2026-11-05)

`schema_setup.py` 1.1, adprofiler.py 1.0.10, adaudit.py 1.0.10,
collector_daemon.py 1.0.3 (no change of its own; image 1.0.3). Schema
unchanged (v50).

- **`schema_migration_v30.sql` to `v50.sql` are removed.** They served
  testing; a production installation starts from an empty database, which
  `schema_init.sql` creates at v50.
- **`schema_setup.py` 1.1:**
  - It takes its target version from `schema_init.sql`.
  - Migration files are optional. A later schema change ships as
    `schema_migration_v51.sql` (and onward), and it applies those to an
    installed database in order, as before.
  - **A database older than v50 can no longer be upgraded.** For such a
    database it says to create a new, empty one. This applies to test
    databases from before this change; in the containers, use
    `docker compose down -v`, then `up -d`.
- **adprofiler.py and adaudit.py** no longer name migration files in their
  messages. For a database that is behind, they say to run
  `schema_setup.py`. For missing partitions, adprofiler.py says to run
  `SELECT ad_intel.run_partition_maintenance();` as the schema owner.

### Documentation moved to `docs/` (2026-11-05)

All documents (`SETUP.md`, `RELEASE_NOTES.md`, `PERMISSIONS.md`,
`DAEMON.md`, `CONTAINER.md`, `COMPLIANCE_TAGS.md`, `MAINTAINERS.md` and
`changelog.txt`) are now in `docs/`. The scripts' messages and comments
point there. The collector image carries the whole folder. No code
change.

### Entra failures, integrity check, permissions guide (2026-11-05)

adprofiler.py 1.0.9, adaudit.py 1.0.9, entra_graph_collector.py 1.0.7,
collector_daemon.py 1.0.2, schema v50 (`schema_migration_v50.sql`), new
`PERMISSIONS.md`. Collector image 1.0.2.

- **A failed Entra collection no longer blocks the AD results.** The daemon
  evaluates and pushes the AD data, and the run ends with a warning.
  - **New option:** `adaudit.py --skip-entra` makes the Entra checks NOT
    ASSESSED and does not run them against the older Entra data kept in
    the database. Their open findings stay open.
  - **The bug it avoids:** evaluating anyway would have assessed the last
    successful Entra collection as if it were current. adaudit.py already
    handled SYSVOL data this way.
  - **When Entra is not configured,** the daemon also passes
    `--skip-entra`.
- **The database integrity check works.**
  - **What it does:** `check_scd2_integrity()` finds objects and edges with
    more than one current row, which would be a collector bug.
  - **What was wrong:** it failed for every caller (unqualified table
    names), its ACL key was incomplete (false duplicates), and it covered 7
    of the 36 history tables.
  - **Schema v50** fixes all three. The daemon runs the check after every
    collection and reports any duplicate in its health report.
  - adprofiler.py 1.0.9 and adaudit.py 1.0.9 require v50, which the daemon
    (`schema_setup.py`) applies automatically.
- **`PERMISSIONS.md`** is the client's setup guide:
  - the AD service account (`adprofiler.py`): what it needs, and how to
    grant the two rights an ordinary domain user lacks;
  - the Entra ID App Registration: portal steps, a PowerShell alternative,
    every Graph permission and what it unlocks;
  - network access.
- **adprofiler.py 1.0.9 says when those two rights are missing.**
  - AD answers an account that may not list `CN=Deleted Objects` with an
    empty list, not an error. So 0 visible deleted objects now logs a
    warning, and 0 visible fine-grained password policies logs a note.
  - The capability probe no longer names a "View Deleted Objects"
    extended right, which does not exist.
  - SETUP.md no longer suggests dropping `--ssl`: plain LDAP sends the
    password unencrypted and fails wherever LDAP signing is required.
- `entra_graph_collector.py` 1.0.7 is named for what it collects ("Microsoft
  Entra ID collector", no longer "email collector"). `schema_init.sql`'s
  header is brought up to date.

Upgrading: replace the scripts; `schema_setup.py` (or the daemon) applies v50.
Without the daemon: `psql -f schema_migration_v50.sql`, or run
`schema_setup.py`.

### Container packaging (2026-11-05)

collector_daemon.py 1.0.1; new `Dockerfile`, `.dockerignore`, `docker/`
(`compose.yaml`, `collector.toml`, `install.sh`) and `CONTAINER.md`. The
scripts, the schema and the plugins are unchanged.

- **Two containers under docker compose:**
  - the collector (`collector_daemon.py`, the scripts and plugins; Python
    3.13);
  - PostgreSQL 17, on an internal network with no outside access and no
    published port.
- **Hardened collector container:** non-root, read-only root filesystem,
  no capabilities, `no-new-privileges`. Secrets are mounted from files,
  logs are capped, and the healthcheck uses `--healthcheck`. The 5-minute
  stop grace period lets a running step stop cleanly and the lease be
  released.
- **`docker/install.sh`** creates the installation directory:
  configuration, secret files (it generates the database password), data
  directories and `.env`. Run again for an upgrade, it never overwrites the
  configuration or a secret.
- **collector_daemon.py 1.0.1:** `--check-config` works while the daemon
  runs (it no longer takes the one-process lock, and logs only to standard
  error).

### Unattended collector daemon (2026-11-05)

New `collector_daemon.py` 1.0.0 and `platform_client.py` 1.0;
`secret_input.py` 1.1; new `collector_daemon.example.toml` and `DAEMON.md`;
`tzdata` added to `requirements.txt`. The scripts, the schema and the
plugins are unchanged.

- **`collector_daemon.py`** runs a client installation unattended. Once a
  day, at a set time in a set time zone, it runs `schema_setup.py`,
  `adprofiler.py`, `entra_graph_collector.py` (when configured) and
  `adaudit.py` (with `--push` when an activation key is configured), each as
  a child process. It never exits by itself. It reports its health every 5
  minutes in `status.json` (and to the platform), and logs every step's
  output.
- **Secrets reach the scripts through pipes** (`<VAR>_FILE=/dev/fd/N`),
  never on a command line or in a child's environment, and are never
  logged or written to disk by the daemon.
- **Failures are handled, not retried blindly.**
  - A failed collection skips the evaluation and still pushes earlier runs.
  - A failed run waits for the next scheduled time, unless its
    configuration changes: a new password is tried at once, and a wrong one
    is not retried into an account lockout.
  - A held run lock postpones the run by 5 minutes.
  - A failed push is retried hourly.
  - A missed run is caught up on start.
- **Two modes.**
  - Local: the configuration and secrets come from the daemon's own TOML
    file and secret files. Works today, including the push.
  - FortifyData: lease, configuration with encrypted secrets, and health
    through the platform. Its endpoints are provisional until the platform
    developer specifies them; tested against a mock only.
- `secret_input.py` 1.1: `resolve_secret(..., allow_prompt=False)` and
  `read_secret_file()`, for the daemon. The scripts behave as before.

### Push authentication by activation key (2026-11-05)

adaudit.py 1.0.8, `adaudit_push.py` (contract 1.0, unchanged). No schema or
plugin change.

- **The push authenticates with the activation key** the client copies from
  the FortifyData portal (the platform's documents 01 and 03): give it as
  `FD_ACTIVATION_KEY`, the file named by `FD_ACTIVATION_KEY_FILE`, or
  `--activation-key`. It is checked before anything is sent, sent as
  `Authorization: LicenseKey <license key>`, and supplies the company id for
  the request paths and the environment that picks the server. Request
  paths, payloads and batching are unchanged.
- Two details are assumptions until the platform developer confirms them:
  an activation key without an environment means `us`, and both base64
  alphabets (with or without padding) are accepted.
- **A 401** (key unknown or malformed, or the AD integration switched off)
  stops the push with a message saying so; the runs stay queued (exit 5).
  With the activation key, a 403 without a reason is a refusal, no longer
  read as "waiting for approval" (kept for the older API key only).
- **The older API key still works**, with a warning, until the platform
  stops accepting it. An interactive run without any key now prompts for the
  activation key.

### Ready for a supervising process (2026-11-05)

adprofiler.py 1.0.8, entra_graph_collector.py 1.0.6, adaudit.py 1.0.7, new
`schema_setup.py` 1.0. No schema change, no plugin change.

- **SIGTERM is handled like Ctrl-C** in all three scripts (`docker stop`,
  systemd and a supervising process send it): adprofiler.py rolls back and
  marks its run aborted, entra_graph_collector.py reports which tables were
  refreshed, adaudit.py marks its evaluation run aborted (never pushed); all
  exit `130`. Before, the process was killed outright and its run row stayed
  "running". A signal that arrives during a database statement or network
  call takes effect when it returns: allow a generous stop timeout.
- **`--log-dir DIR`** on all three scripts puts the log file in `DIR`.
  `adaudit.py` now writes a log file too, but only with `--log-dir`.
- **`adaudit.py --no-excel`** skips the workbook; **`--report-dir DIR`** says
  where it goes.
- **`schema_setup.py`** creates the schema on an empty database or applies
  the missing migrations in order, without `psql`: each file is applied
  completely or not at all, and its recorded version is checked. Tested
  against PostgreSQL 17: a fresh install and an upgrade from v46 produce
  identical schemas. See `SETUP.md`, section 5.

Upgrading: replace the scripts and add `schema_setup.py` (optional; the
scripts do not need it to run).

### Secrets without a terminal (2026-11-05)

adprofiler.py 1.0.7, entra_graph_collector.py 1.0.5, adaudit.py 1.0.6, new
`secret_input.py` 1.0. No schema change, no plugin change.

The AD bind password, the Entra ID client secret and the PostgreSQL
password came only from a command-line option or an interactive prompt.
Without a terminal the prompt failed with a traceback, which left the
options, and those are visible in process listings and in a container's
recorded command. Each secret is now taken from the first of:

1. its option (`--password`, `--app-secret`, `--pg-password`), with a
   warning, as before;
2. its environment variable: `AD_BIND_PASSWORD`, `ENTRA_APP_SECRET`,
   `PGPASSWORD`;
3. the file named by `AD_BIND_PASSWORD_FILE`, `ENTRA_APP_SECRET_FILE` or
   `PGPASSWORD_FILE` (first line): a mounted Docker or Kubernetes secret,
   or `/dev/fd/N` for a pipe from a supervising process, so the secret
   never touches disk, a command line or an environment;
4. a hidden prompt, when there is a terminal.

Without a terminal, a missing bind password or client secret stops the
script with exit status 1 and a message naming the variables. A missing
PostgreSQL password is left to the PostgreSQL client library (`~/.pgpass`,
`PGPASSFILE`, or a password-less method). Setting a variable and its
`_FILE` variant together is refused. `PGPASSWORD` was ignored before (the
scripts always prompted). The logs say where each secret came from, never
the secret. The FortifyData API key is unchanged (`--api-key`,
`FD_API_KEY`, `--api-key-file`, which also accepts `/dev/fd/N`, or the
prompt). See `SETUP.md`, "Passwords and secrets without a terminal".

Upgrading: replace the scripts and **add `secret_input.py`** next to them;
all three import it and fail to start without it. Interactive use is
unchanged.

## Plugin update (2026-11-01): security bulletin review

From a review of the January-October 2026 Microsoft security updates and
other published research on Active Directory and Entra ID, against the
plugin set. Each new check reads data the collectors already store. No
script or schema change.

### New plugins

| Plugin | Checks |
|---|---|
| 6015 Enterprise CA Exposed to CertiGhost (CVE-2026-54121) Preconditions | An Enterprise CA publishes a client-authentication template whose subject is built from the requester's DNS name (such as Machine) that Domain Computers or another broad group can enroll in. High when an ordinary user can also come by a computer account (MachineAccountQuota, or computers owned outside Tier 0). The CA's patch level and EditFlags are not visible, so it asks for them to be confirmed. |
| 5022 AD FS Is Deployed -- Confirm the July and October 2026 AD FS Updates | An AD FS farm (DKM container and keys) is in the domain, or Entra ID federates domains to an AD FS endpoint hosted elsewhere. July 2026 fixed an exploited elevation of privilege (CVE-2026-56155); October 2026 fixed two Critical spoofing flaws (CVE-2026-108131, CVE-2026-96222). Names the AD FS servers through the farm's gMSA. |
| 9043 RC4 or DES Re-Enabled for Kerberos on Domain Controllers by Group Policy | The DCs' Group Policy sets the KDC's `DefaultDomainSupportedEncTypes` with RC4 or DES (undoes the CVE-2026-20833 hardening for every account), or "Configure encryption types allowed for Kerberos" allows DES or RC4 on the DC. Needs SYSVOL. |
| 9044 Domain Controllers Allow Vulnerable Netlogon Secure Channels (ZeroLogon Exception) | The DCs' Group Policy sets `VulnerableChannelAllowList`, re-opening ZeroLogon (CVE-2020-1472) for the accounts it allows; critical when that includes domain controllers. Needs SYSVOL. |
| 10122 External MFA Provider Backed by an Untrusted Application (TrustSink) | An enabled external authentication method is backed by an application registered in the tenant itself, by an application with no service principal, or by a third-party application without a verified publisher -- the pattern of the TrustSink technique (Varonis, September 2026), where a rogue provider collects users' passwords at sign-in. |

### Changed plugins

- **1024 v1.7, 2018 v1.4 (RC4 accounts):** since the CVE-2026-20833
  enforcement (April 2026; rollback removed July 2026) domain controllers
  issue AES-only service tickets for accounts whose
  `msDS-SupportedEncryptionTypes` is not set. Those accounts are no longer
  reported unless Group Policy puts RC4 back into the KDC default (as 9043
  reads it). This removes most of their findings -- on a typical domain,
  2018 reported every NAS, Linux host and cluster object. Accounts set
  explicitly without AES are still reported; 1024 rates them high (the
  remaining RC4 exposure). Both now run without SYSVOL (the Group Policy
  check is then skipped).
- **1045 v1.1 (no AES keys):** text brought up to the July 2026
  enforcement; for a service account the summary says whether its service
  tickets now fail or still work only because RC4 is explicitly allowed.
- **11026 v1.2 (tenant policy changed):** an external authentication method
  added enabled, or switched to enabled, is now high. Before, a newly added
  method was treated as a newly collected field and not reported at all.
- **4009 v1.6 (MachineAccountQuota):** the Microsoft Entra Kerberos server
  object no longer makes "Add workstations to domain" read as not configured
  (medium) in tenants that use Entra Kerberos; CertiGhost added to the
  explanation and references.

### Coverage

390 active plugins (386 finding checks, 4 inventory reports) plus 5 retired
stubs.

### Upgrading

Replace `plugins/`. No migration, no collection change; schema v49 as
before. Findings of 1024 and 2018 for accounts without
`msDS-SupportedEncryptionTypes` close as remediated at the next adaudit run
(unless Group Policy re-enables RC4 in the KDC default).

## Release 1.0.x updates (2026-10-30)

Fixes and hardening made after release 1.0, from running it against a live
domain and tenant and from a full code review. Three schema migrations (v47,
v48, v49); no plugin added or removed.

### Components

| Component | Version |
|---|---|
| `adprofiler.py` (Active Directory collector) | 1.0.6 |
| `sysvol_collector.py` (used by `adprofiler.py --sysvol`) | 1.2 |
| `entra_graph_collector.py` (Entra ID collector) | 1.0.4 |
| `adaudit.py` (plugin runner and report writer) | 1.0.5 |
| `adaudit_push.py` (ingest API push contract) | contract 1.0 |
| `run_lock.py` (one run at a time; new) | 1.1 |
| PostgreSQL schema (`schema_init.sql`) | v49 |

### Changes

adprofiler.py 1.0.6 (2026-10-31): the domain controller's host name is read
correctly. ldap3 returns dnsHostName as a plain string once the AD schema is
loaded, and its first character was taken, so the log said "Domain
controller D" and sync_run.dc_dns_hostname held "D". The deleted-object
watermark, which compares the DC's invocationId, was not affected. No
schema change.

Code review fixes, low severity (2026-10-30, adprofiler.py 1.0.5,
entra_graph_collector.py 1.0.4, adaudit.py 1.0.5, run_lock.py 1.1, schema
v49):

- **Partitions no longer depend on the session time zone.** Monthly
  partitions are made on UTC month boundaries; runs from sessions in
  different time zones could make overlapping partitions (the run aborted)
  or leave a gap. The migration also rebuilds empty future partitions so an
  existing gap or overlap is removed.
- **The run lock survives an idle network path.** Its connection, idle for
  the whole run, now uses TCP keepalives and is exempt from
  `idle_session_timeout`; a dropped connection released the lock silently.
- **LDAPS certificates can be verified:** new optional `--ca-cert FILE`
  (with `--ssl`) checks the domain controller's certificate and name.
  Without it the certificate is still not checked, and the log now says so.
- **Collector details:** an ACE that changed between explicit and inherited
  is versioned; the gMSA "unresolved" count in the log is right; log files
  are UTF-8; PIM-eligible synced admins are matched to their AD accounts;
  a repeated Graph page no longer breaks the Entra run; the partial-run
  report lists every source; a non-GUID `--client-id` gives a clear error.
- **Change detection:** a group is no longer a member of itself through a
  nesting cycle; 11003 no longer reports a membership that only changed its
  primary-group flag; 11027 uses the real time of the previous Entra
  collection; a delegated grant whose resource could not be looked up no
  longer churns the history; a changed STIG or tool reference is recorded;
  the push sends a reopened finding with the date it reopened.
- **Plugin accuracy:** 9035 reads the KDC armoring level
  (`CbacAndArmorLevel`); 9020 and 9040 ignore the disabled half of a GPO;
  5020 accepts SYSVOL paths through the NetBIOS or a DC name; 1001 and 1002
  leave out the disabled built-in Guest and DefaultAccount; 2024, 2027,
  2028, 10042-10044 and 10110 measure age from the collection, not from
  when adaudit.py runs; 10076 no longer lists secret-lifetime gaps when
  secrets are blocked; 10021 checks the device filter's mode.

Code review fixes, medium severity (2026-10-30, adprofiler.py 1.0.4,
sysvol_collector.py 1.2, entra_graph_collector.py 1.0.3, adaudit.py 1.0.4,
schema v48):

- **Group Policy deletions take effect.** A Registry.pol "delete this
  value" entry was stored under its own key, so a value a higher-precedence
  GPO deleted still looked set to the Group Policy checks (9010-9038). It
  now overrides the value it deletes, and the Hardened UNC Paths (9029) and
  ASR rules (9037) lists honour a GPO that replaces the whole list.
- **Group Policy OU matching treats `_` and `%` in OU names literally**
  (schema view `v_gpo_dc_application`, plugin 9039). They acted as
  wildcards, so GPOs could be applied to the wrong DCs.
- **A failed optional read no longer looks like everything was removed.**
  When the OUs, GPOs, sites, KDS keys, AD FS, DNS zones or certificate
  services objects could not be read, adprofiler.py closed all their ACL,
  GPO link and SYSVOL records, and the next good run reported them all as
  newly granted. They are now kept unchanged for that run; if the GPOs
  could not be read, SYSVOL is not read either (the Group Policy checks are
  NOT ASSESSED for that run).
- **Descriptions are stored as text** for users, computers and groups,
  instead of as `{"..."}` array literals. The first adprofiler.py 1.0.4 run
  rescans every object once to rewrite them (automatic).
- **Members who can add themselves to Domain Admins count as privileged**
  (schema view `v_privileged_principal`): write access to the member
  attribute of Tier 0 groups or AdminSDHolder, reset-password on
  AdminSDHolder, and inheritable domain-root ACEs aimed at OUs.
- **Entra licences in their grace period count as licensed**
  (`v_entra_tenant_capability`); 10121 reported "no P1/P2" and 10025, 10037
  and 10038 were suppressed.
- **Entra change detection** (11020, 11027, 11029): a group that becomes
  sensitive no longer reports all its existing members and owners as
  added; a privileged role that was removed and later granted again is
  reported; groups sensitive through an app role stay sensitive when that
  app's assignments can't be read.
- **Group Policy change detection** (11021): the first settings added to a
  GPO that was empty when SYSVOL was first read are reported.
- **Fewer false findings:** 6007 ignores inherit-only ACEs (false critical
  ESC5 on CA hosts); 5009 ignores read-only Enterprise Key Admins ACEs;
  1025 treats Key Admins and Enterprise Key Admins as protected groups and
  honours dwAdminSDExMask; 2006 and 2007 leave out the Seamless SSO account
  AZUREADSSOACC$ (10008 covers it); 10058 no longer reports an active and an
  eligible assignment twice.
- **Fewer missed findings:** 10004 treats "MFA or terms of use" as optional
  MFA; 10053 and 10058 match custom-role actions written for
  `.myOrganization`; 2024, 2025, 2027 and 2028 match "Windows Server(R)
  2008" hosts.
- **adaudit.py counts the open findings of NOT ASSESSED plugins.** They are
  kept open and pushed, but were left out of `--fail-on`, the console report
  and the compliance sheets; they are now listed there, marked as kept from
  the last assessment.

Code review fixes, high severity (2026-10-30, adprofiler.py 1.0.3, adaudit.py
1.0.3, schema v47):

- **Domains with more than 1,000 deleted objects** could not be collected:
  the deleted-objects capability check used an unpaged search, which a domain
  controller refuses past its MaxPageSize, so every run failed (with advice
  to grant a right the account already had). The check now pages.
- **Deletions are found whichever domain controller is queried.** The
  deleted-object watermark (an update sequence number) is local to one DC,
  but was reused against whatever DC the next run reached, e.g. with
  `--dc-host` set to the domain name: deletions were missed and the deleted
  accounts stayed in the findings for good. Each run now records its DC's
  identity (schema v47); a run against another DC, or a restored one,
  checks every deleted object. Per-DC USN counters no longer make every
  object look modified after a DC change. An object changed and deleted
  within the same run no longer rolls the whole run back.
- **LDAP referrals are no longer followed.** ldap3 followed them by default
  and re-sent the bind password, unencrypted, to the referred host.
- **Grants to Everyone, Authenticated Users and other broad principals are
  reported** by the ACL and certificate-services checks (5001-5005, 5008,
  5010, 6006-6008). When the domain had no object for such a principal, its
  ACEs were dropped, so DCSync, AdminSDHolder, domain-root and ESC4/ESC5
  grants to Everyone produced no finding.
- **5021 no longer reports routine delegations as critical attack paths.**
  Inherit-only ACEs are applied to the descendants they reach instead of
  the object that carries them, and a lone replication right is no longer
  called DCSync.
- **Conditional Access coverage needs an unconditional policy** (10014,
  10021, 10022, 10024, 10026). A policy narrowed by client app types,
  locations, platforms, risk levels, a device filter or authentication
  flows no longer counts; the standard "Block legacy authentication" policy
  had been taken as MFA coverage for admin portals and excluded users.
- **Push: findings fixed during a skipped run are now reported as fixed.**
  Change labels are relative to the last run the platform received, not a
  skipped or expired one, which had left such findings open on the platform
  for good.

Earlier 1.0.x changes:

- **Group Policy checks need SYSVOL from the run being evaluated**
  (adaudit.py 1.0.1, adprofiler.py 1.0.1, plugin 4009 v1.5). The Group
  Policy settings checks are NOT ASSESSED unless that collection run read
  SYSVOL (`adprofiler.py --sysvol`). Before, a run without `--sysvol`, or
  whose SMB read failed, was checked against the Group Policy data of the
  last `--sysvol` run as if it were current. adprofiler.py says when a run
  does not collect Group Policy settings. Plugin 4009 (MachineAccountQuota)
  now reports from LDAP alone without SYSVOL instead of NOT ASSESSED.
- **One run at a time** (adprofiler.py 1.0.2, entra_graph_collector.py
  1.0.1, adaudit.py 1.0.2, new `run_lock.py`). The three scripts share a
  PostgreSQL advisory lock taken right after the PostgreSQL settings are
  read. A script started while another run holds it logs who holds it and
  how to clear the lock, and exits with status **75** without doing
  anything. PostgreSQL releases the lock whenever the holding process
  exits, crashes or is killed. Before, overlapping collections could leave
  duplicate current versions of objects.
- **A throttled optional Entra source no longer aborts the collection**
  (entra_graph_collector.py 1.0.2). An optional source that Microsoft keeps
  throttling (HTTP 429), or that keeps failing with a temporary server or
  network error, is recorded as not read and its checks are NOT ASSESSED,
  as for a missing licence. The required reads (users, directory roles,
  security posture, applications, Graph permission grants) still abort.
- `.gitignore` keeps compiled files, collected output (`*.log`, `*.xlsx`),
  the virtual environment and credentials out of the repository.

### Exit status

For a scheduler or supervising process: every script exits non-zero when it
did not complete. adprofiler.py and entra_graph_collector.py: 0 success, 1
failed, 75 not started (another run holds the run lock), 130 interrupted.
adaudit.py: 0 complete, 1 fatal error, 3 complete but a plugin errored, 4
findings at or above `--fail-on`, 5 push failed, 75 not started, 130
interrupted.

### Upgrading from 1.0 or an earlier 1.0.x

Replace the scripts and `plugins/`, **add `run_lock.py`** next to them (all
three scripts import it and fail to start without it), and **apply the
schema migrations the database does not have yet, in order**:
`schema_migration_v47.sql`, `schema_migration_v48.sql`, then
`schema_migration_v49.sql` (`psql -v ON_ERROR_STOP=1 -f
schema_migration_v47.sql`, and the same for the others). adprofiler.py 1.0.5
and adaudit.py 1.0.5 refuse to run against an older schema. No
`--full-rescan` is needed:

- the first adprofiler.py 1.0.3+ run checks every deleted object once;
- the first adprofiler.py 1.0.4 run rescans every object once by itself
  (descriptions), so it takes as long as a first collection;
- the first entra_graph_collector.py 1.0.3 run stores a new version of each
  sensitive-group member's change history (not reported by any plugin).

## Release 1.0 (2026-10-22)

The first release of ad-security-profiler, made from the `api-push` branch
(since merged into `release`, the default branch) at the point where Entra ID
coverage waves 1 and 2 were merged and verified against a live tenant.

### Components

| Component | Version |
|---|---|
| `adprofiler.py` (Active Directory collector) | 1.0.0 |
| `sysvol_collector.py` (used by `adprofiler.py --sysvol`) | 1.1 |
| `entra_graph_collector.py` (Entra ID collector) | 1.0.0 |
| `adaudit.py` (plugin runner and report writer) | 1.0.0 |
| `adaudit_push.py` (ingest API push contract) | contract 1.0 |
| PostgreSQL schema (`schema_init.sql`) | v46 |

The version numbers change from adprofiler.py 0.9.1, entra_graph_collector.py
0.9.1 and adaudit.py 0.10.6. Behavior does not change: the release adds no
collection, no plugin change and no schema change.

### Coverage

385 active plugins -- 381 finding checks and 4 inventory reports -- plus 5
retired stubs:

| Category | Plugins |
|---|---|
| Hybrid Identity (Entra ID) | 101 |
| User Accounts | 48 |
| Computer Accounts | 46 |
| Domain | 38 |
| Groups | 31 |
| Change Detection | 31 |
| Organizational Units | 24 |
| ACLs | 19 |
| Certificate Services | 14 |
| Trusts | 9 |
| Inventory | 4 |

Plugins that need an optional Entra data source (66 of them) are reported as
NOT ASSESSED when the source could not be read, for example when the tenant
has no Entra ID P1/P2 licence or a Graph permission was not granted. The
reason is stored per source in `entra_collection_status`.

### Requirements

- Python 3 with the packages in `requirements.txt`, in a virtual environment.
- PostgreSQL 17.
- A read-only AD bind account, and an Entra ID app registration with the
  Graph application permissions listed in `SETUP.md`.

### Installing

Follow `SETUP.md`. A new database is created from `schema_init.sql` alone.

### Upgrading to 1.0

- **From schema v46** (adprofiler.py 0.9.1 / entra_graph_collector.py 0.9.x /
  adaudit.py 0.10.6): replace the scripts and `plugins/`. No migration and no
  `--full-rescan` are needed.
- **From an older schema:** apply each `schema_migration_vNN.sql` after the
  database's current version, in order, up to v46 (adprofiler.py names the
  files it needs). Then run `adprofiler.py` once with `--full-rescan`, as
  `SETUP.md` (Troubleshooting) describes.

Never run `schema_init.sql` against a database that already holds data.

### Known limitations

- `adaudit.py` needs at least one successful `adprofiler.py` run for the
  client. An Entra-only tenant (no Active Directory) is not supported.
- Security descriptors are read for targeted objects only (domain root,
  AdminSDHolder, OUs, well-known and PKI containers, certificate templates,
  CAs, DNS zones, domain controllers and protected objects), not for every
  directory object.
- Group Policy settings are read only with `adprofiler.py --sysvol`.
- Secrets are never collected: no passwords, LAPS or gMSA passwords, KDS
  root keys or AD FS DKM key.
