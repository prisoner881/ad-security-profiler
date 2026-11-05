# collector_daemon.py -- the unattended collector

`collector_daemon.py` runs a client installation unattended. It wraps the
existing scripts without changing them. It starts once and then never stops
on its own; it is stopped from outside. Once a day it runs the collection,
the evaluation and the push. Every 5 minutes it reports its health. It logs
everything it does.

**Status:** both modes are complete.
- **Local mode** takes its configuration from its own file, and pushes
  results when an activation key is configured.
- **FortifyData mode** uses the platform's collector API as the platform
  developer specified it (lease, health check carrying the configuration).
  It has been tested against a mock built to their specification; their
  test environment has the real API.

| File | What it is |
|---|---|
| `collector_daemon.py` | The daemon: scheduling, the run, health, logging, stopping |
| `platform_client.py` | The platform interface: `LocalPlatform` and `FortifyDataPlatform`, configuration parsing |
| `collector_daemon.example.toml` | Annotated configuration file |
| `secret_input.py` 1.1 | Adds `allow_prompt=False` and `read_secret_file()` for the daemon |

Requirements:
- Python 3.11 or later (`tomllib`, `zoneinfo`);
- the packages in `requirements.txt` (`cryptography` and `requests` are
  already there; `tzdata` is new);
- the schema files and scripts in `scripts_dir`.

## 1. What it does

```
start
  ├─ lease thread   (FortifyData mode) activate → renew every 2 min → re-activate if lost
  ├─ health thread  every 5 min: status.json + health report to the platform
  └─ main loop
       wait for the lease
       fetch the run configuration (hourly; every 5 min after an error or a failed run)
       at the scheduled time:
           schema_setup.py → adprofiler.py → entra_graph_collector.py → adaudit.py [--push]
       an hour after a failed push: adaudit.py --push-only
SIGTERM/SIGINT → stop the running step → release the lease → exit 0
```

### The run

| Step | Command (the daemon adds `--pg-*` and `--log-dir`) | Exit status → what the daemon does |
|---|---|---|
| 1 | `schema_setup.py --rescan-file … --backup-dir …`: creates the schema, or backs the database up and applies the migrations above its version | `0` next step; `1` run failed, nothing else runs (database problem) |
| 2 | `adprofiler.py --dc-host … --username … [--ssl] [--port] [--ca-cert] [--sysvol …]` | `0` next step; `1` collection failed (see below) |
| 3 | `entra_graph_collector.py --tenant-id … --app-id … --domain-fqdn …` or `--client-id …`; only when Entra is configured | `0` next step; `1` the AD data is still evaluated, with the Entra checks not assessed (see below) |
| 4 | `adaudit.py --report-dir … --no-excel [--push] [--skip-entra]` | `0` ok; `3` ok with a warning (the evaluation is incomplete; adaudit.py reports this before a failed push, so the daemon checks for runs still waiting and schedules the push retry); `5` evaluated but the push failed, so `--push-only` is retried every hour; `1` run failed |
| any | | `75` (the run lock is held, e.g. by someone running a script by hand): the whole run is postponed by `retry_interval` (5 min). `130` after a stop request: the run stops. `130` without one (someone else signalled the step): the run failed. |

**When the AD collection fails, the evaluation is skipped.** This also
applies when `schema_setup.py` fails. Evaluating stale or partial data
would produce misleading findings. Instead, `adaudit.py --push-only`
delivers any earlier run that is still waiting. This is skipped when the
database says nothing is waiting.

**When only the Entra collection fails, the AD data is still evaluated and
pushed.** It runs with `adaudit.py --skip-entra`:
- the Entra checks are **NOT ASSESSED** and their queries are not run;
- their open findings stay open, neither closed nor confirmed.

Otherwise the Entra data in the database, kept from the last successful
collection, would be evaluated as if it were current. The run ends
`warning`, with the Entra error in its note. `--skip-entra` is also passed
when Entra is not configured, so Entra data left from an earlier
configuration is never evaluated as current.

**Full rescan after a migration.** A migration can declare that existing
objects need one `adprofiler.py --full-rescan`. `schema_setup.py` then
creates `<state_dir>/full_rescan_needed`, and the next AD collection runs
with `--full-rescan`. The file is removed once that collection succeeds:
one rescan, however many such migrations were applied at once.

**Backup before a migration.** When the database exists and has
migrations to apply, `schema_setup.py` first dumps it with `pg_dump
--format=custom` to `<state_dir>/backups/adprofiler-v<from>-before-v<to>-<UTC
time>.dump` (mode `0600`; the password reaches `pg_dump` only through its
environment). A failed backup means no migration is applied and the run
fails. The newest 3 are kept. Restoring one is described in `CONTAINER.md`,
section 5.

**Integrity check.** After every successful AD collection the daemon runs
the database's `check_scd2_integrity()` (schema v50). It finds any object
or edge with more than one current row, which would be a collector bug. A
finding is logged as a warning and reported in the health report
(`integrity`); the run is not failed for it.

**Entra target.** Without `ad.domain_fqdn`, the Entra step uses the
`client_id` of the only domain in the database. With no domain or with
several, the step does not run and the reason is logged and reported.

### Schedule and retries

- **Once a day**, at `schedule.time` in `schedule.timezone` (IANA name).
  Daylight-saving changes follow the time zone: a time that does not exist
  on the spring-forward day runs an hour later on the wall clock.
- **Catch-up on start.** If the most recent scheduled time passed and no
  run started since, the daemon runs at once. This covers a machine that
  was down at the scheduled time, and a first start.
- **A failed run is not retried until the next scheduled time.** Retrying a
  wrong bind password every few minutes would lock the account out. The
  exception: the run configuration changes, for example a new password in
  the portal. The configuration is re-read every 5 minutes after a failure,
  and the run starts again as soon as any setting or secret differs, also
  when the change was made while the daemon was stopped. Change detection
  uses a keyed hash (HMAC-SHA-256). The random key is kept in
  `state_dir/fingerprint.key` (mode `0600`) and the hash in `state.json`;
  neither is sent or logged.
- **Postponed** runs (exit `75`) are retried every `retry_interval`.
- **A failed push** is retried with `--push-only` every hour, until nothing
  is waiting. The retry survives a failed or postponed run, and is dropped
  when the push is switched off.
- **Interrupted** runs (the daemon was stopped mid-run) do not count as
  attempts, so the run starts again after the restart.
- If a configuration or platform problem means the run configuration cannot
  be fetched when a run is due, the run waits and the fetch is retried every
  `retry_interval`.

## 2. Modes

### Local (`[platform] mode = "local"`)

The run configuration comes from the `[schedule]`, `[ad]` and `[entra]`
sections of the daemon's own configuration file. The file is re-read before
every run, so an edit takes effect without a restart.

There is no lease. The health report goes only to `status.json` and the log.

With an activation key (`activation_key_file`, or `FD_ACTIVATION_KEY` /
`FD_ACTIVATION_KEY_FILE`), the evaluation is pushed to the ingest API
(contract 1.0).

### FortifyData (`[platform] mode = "fortifydata"`)

This mode uses the platform's collector API as the platform developer
specified it (their documents 04 and 05). It is deployed on their test
environment.

**The activation key** is required. It gives:
- the license key, sent as `Authorization: LicenseKey …` on every call;
- the company;
- the environment `e`, which picks the API server:

| `e` | API server |
|---|---|
| `prod` (US production; `us` is never issued) | `https://api.fortifydata.com` |
| `eu` | `https://api.eu.fortifydata.com` |
| `test` | `https://api.test.fortifydata.com` |

Any other environment, and a bare license key, need `[platform] api_url`;
without it the daemon refuses to start. A key without `e` is refused: no
server is guessed.

**Instance id.** On first start the daemon creates a random instance id in
`state_dir`. Keep `state_dir` on a persistent volume. Restarting with the
same id resumes the lease at once; there is no wait.

**The calls**, all relative to the API server:

| Call | Request | Answers |
|---|---|---|
| Take the lease | `POST /api/v1/integration/collector/activations/{instanceId}`, no body | `201` with `leaseExpiryDate` and `serverDate`; `409` license in use by another instance |
| Renew | `PUT …/activations/{instanceId}`, every 2 minutes (or a third of the lease, if shorter) | `202`; `404` or `409` lease lost → take it again |
| Release | `DELETE …/activations/{instanceId}`, on stop | `202` |
| Health check | `POST /api/v1/integration/collector/health`, every 5 minutes, with the health report (section 5) | `200` with the collector's record **and its configuration**; `404` no collector for this key, or deleted |

- **401:** the key is not recognised, or the integration is switched off.
  The client must fetch a new activation key from the portal; the daemon
  retries every 5 minutes.
- **403:** the key is valid but may not call these endpoints.

**Lease and clock.** The lease length comes from `leaseExpiryDate` minus
`serverDate`. The daemon warns when its clock is more than 2 minutes off
the platform's.

**The configuration comes with the health check.** There is no separate
configuration call. Every health answer carries the collector's whole
configuration, and is the current truth:
- **Flat fields:** `host`, `username`, `password`, `useLdaps`, `ldapPort`,
  `caCertificate`, `domainFqdn`, `readSysvol`, `sysvolKerberos`,
  `entraTenantId`, `entraClientId`, `entraClientSecret`, `readPtaAgents`,
  `scheduleTime`, `scheduleTimeZone` and `configVersion`. They map onto the
  same run settings as the local mode's `[ad]`, `[entra]` and `[schedule]`.
- **`ldapPort`** is always passed to adprofiler.py as given.
- **`host`, `username` or `password` null:** the collector is not
  configured yet. No run; the health checks continue.
- **`entraTenantId` null:** no Entra step (`adaudit.py --skip-entra`).
- **A password changed in the portal** applies within 5 minutes.
- **`configVersion`** is logged (never the content) and sent back in the
  health report.

**Secrets** arrive as plain strings over TLS. That is the platform's
decision: there is no key pair and no encryption. The daemon keeps them in
memory only and passes them to the scripts through pipes (section 4).

**The cache.** The last health answer is cached in
`state_dir/platform_config.json` (mode `0600`) **without its secrets**.
- **Platform outage while running:** runs continue with the configuration
  in memory.
- **Restart during an outage:** runs wait for the platform's next answer,
  because the secrets are not on disk.

**Collector status** in the health answer:

| Status | The daemon |
|---|---|
| `EXPIRED` | Runs no scan; keeps sending health checks |
| `FAILED` | Ignores it (the platform sets it from our own error report) |
| A `404` from the health check (no collector, or deleted) | Reports itself `collector_decommissioned`, runs no scan, keeps polling |
| Anything else (`CONFIGURED`, `HEALTHY`, `OUTDATED`, …) | Runs normally |

**Updates.** When `targetVersion` differs from the running version, the
daemon logs it once, with `autoUpgrade` and `imageName`, and reports it in
its health and status (`platform.update_available`). Installing the new
image is the Collector Manager's job. Our health report's top-level
`version` is the image version (the `COLLECTOR_VERSION` given when the
image was built, e.g. `1.2.0` or `1.2.0-dev.17`, without a `v`; outside an
image, the daemon's own version); the platform compares it with
`targetVersion` to show a collector as `OUTDATED`. A `v` in front of
`targetVersion` is ignored in that comparison.

**Schedule offset.** Each installation starts its scheduled runs a random 0
to 30 minutes after the time set in the portal. The offset is chosen once,
kept in `state.json`, and logged at start, so clients do not all start
together.

**Push.** The push to the ingest API does not check the lease: a scan that
loses its lease midway still finishes and pushes.

**Error handling.** Each problem has its own state, logged once and
reported, and is retried:

| State | Meaning | Retried |
|---|---|---|
| `license_in_use` | Another instance holds the license | Every 5 min |
| `license_refused` | 401 or 403 | Every 5 min |
| `platform_unreachable` | | With backoff from 30 s to 5 min |
| `waiting_for_configuration` | No health answer yet | At the next health check |
| `not_configured` | The portal has no AD settings yet | At the next health check |
| `config_error` | A setting from the portal is unusable | At the next health check |
| `collector_expired`, `collector_decommissioned` | See the status table | At the next health check |

Behind a TLS-inspecting proxy, set `ca_bundle`. The daemon uses it for its
own requests, and passes it to the scripts as `REQUESTS_CA_BUNDLE`, so the
push uses it too. `HTTPS_PROXY` and `NO_PROXY` are honoured.

## 3. Configuration file

See `collector_daemon.example.toml` for every setting, with comments.

- **Validating:** check a file with `--check-config`. In local mode this
  also parses the run configuration and reads its secret files.
- **Paths:** relative paths are relative to the configuration file.
- **Typos:** unknown settings are logged as warnings.
- **Errors in the daemon's own settings** stop it at start with exit `78`
  (EX_CONFIG). These are the `[daemon]`, `[platform]` and `[database]`
  sections, an unreadable activation key or database password file, or a
  missing script. This is the only reason the daemon exits by itself.
- **A wrong AD or Entra setting does not stop the daemon:** it reports the
  problem and keeps retrying.
- **One process per state directory.** The daemon holds a lock on
  `state_dir/daemon.lock`. A second daemon, or `--once` while the daemon
  runs, stops with exit `75`: it would share the lease, the instance id and
  the status file.
- **A CA certificate without LDAPS** (`ssl = false`) is not used, and a
  warning says so.

## 4. Secrets

| Secret | Where the daemon gets it | How the step gets it |
|---|---|---|
| PostgreSQL password | `[database] password_file`, `PGPASSWORD`, `PGPASSWORD_FILE`, or none (libpq's `.pgpass`) | `PGPASSWORD_FILE=/dev/fd/N` |
| AD bind password | Platform (health answer, in memory only), or local `[ad] password_file` / `AD_BIND_PASSWORD(_FILE)` | `AD_BIND_PASSWORD_FILE=/dev/fd/N` |
| Entra client secret | Platform (health answer, in memory only), or local `[entra] client_secret_file` / `ENTRA_APP_SECRET(_FILE)` | `ENTRA_APP_SECRET_FILE=/dev/fd/N` |
| Activation key | `[platform] activation_key_file`, `FD_ACTIVATION_KEY(_FILE)` | `FD_ACTIVATION_KEY_FILE=/dev/fd/N` |

How each step receives its secrets:
- **Through a pipe.** The daemon writes each secret into a pipe before the
  child starts, closes its end, and passes the read end to the child.
  `secret_input.py` reads it.
- **Never in the open.** A secret never appears on a command line (`ps`),
  in a child's environment (`/proc/<pid>/environ`), on disk, or in a log.
  Inline secrets in the configuration file are refused.
- **Environment cleaned.** The children's environment is the daemon's own,
  minus every secret variable and its `_FILE` form. `FD_API_KEY`,
  `FD_API_URL` and `FD_COMPANY_ID` are removed too.
- **No prompts.** Standard input is `/dev/null`, so a script can never wait
  at a prompt.

In local mode, `AD_BIND_PASSWORD_FILE` and `ENTRA_APP_SECRET_FILE` may
name a pipe (`/dev/fd/N`). A pipe can be read only once, so the value is
kept in memory for the later configuration reads.

Exceptions:
- In FortifyData mode, the AD bind password and Entra secret exist only in
  the daemon's memory.
- The LDAPS CA certificate is not secret. It is written to
  `state_dir/ldaps_ca.pem` for `--ca-cert`.

## 5. Health

The health thread writes `state_dir/status.json` every `health_interval`
and at every state change. In FortifyData mode it also posts the same
report to the platform. The report contains:

- **identity:** instance id, host name, mode, the version of the daemon
  and of each script;
- **state:** `starting`, `waiting_for_lease`, `license_in_use`,
  `license_refused`, `platform_unreachable`, `config_error`, `waiting`,
  `running`, `pushing`, `postponed`, `error`, `stopping`, `stopped`; with
  the detail (the error message) and the time it was entered;
- **lease:** held or not, last renewal, last error;
- **configuration:** version, schedule, whether Entra is configured, last
  fetch, last error;
- **current step**, if a run is in progress;
- **last run:** start and end, outcome (`ok`, `warning`, `failed`,
  `interrupted`), note, and each step's exit status and one-line error (the
  first `[FAIL]`/`[ERROR]` line of its output); also the last success and
  the next run;
- **push:** on or off, number of evaluation runs waiting, next retry;
- **database:** reachable, schema version, size, partitions missing for
  the current month, Entra sources that could not be read;
- **integrity:** the result of the last integrity check (tables with
  duplicate current rows, or none);
- **free disk space** for the state and log directories.

`collector_daemon.py --config FILE --healthcheck` exits `0` while
`status.json` is fresh (younger than twice the health interval plus a
minute) and the daemon has not stopped. Use it as the container
healthcheck.

It deliberately does not fail on a wrong AD password: restarting the
container would not fix that, and the report already says what is wrong.

## 6. Files and logs

| Path | Contents |
|---|---|
| `log_dir/collector_daemon.log` | Everything: the daemon's own messages and every line each step prints, prefixed `[step]`. Also on standard error (`docker logs`). Rotated at midnight UTC and kept `log_retention_days`. |
| `log_dir/scripts/` | Each script's own log file (`--log-dir`). Files named `*-results_*.log` are pruned after `log_retention_days`. |
| `state_dir/status.json` | The latest health report |
| `state_dir/state.json` | Last attempt, last run, last success, pending push retry (mode `0600`) |
| `state_dir/instance_id` | The installation's identity (FortifyData mode) |
| `state_dir/platform_config.json` | The last configuration from the platform, without its secrets (mode `0600`) |
| `state_dir/fingerprint.key`, `daemon.lock` | Configuration-change key (mode `0600`); one-process lock |
| `state_dir/reports/` | Excel workbooks when `[run] excel = true`. Files named `adaudit-findings_*.xlsx` are pruned after `log_retention_days`; nothing else is deleted. |
| `state_dir/work/` | The children's working directory |

The logs contain host, account and object names from the directory, never
a secret.

## 7. Stopping

SIGTERM or SIGINT stops the daemon:

1. SIGTERM is forwarded to the running step. (The signal handler only
   writes to a pipe; a separate thread does the work, so a signal can never
   deadlock the daemon.) Each script stops at its next
   safe point (rolls back, marks its run aborted) and exits `130`.
2. If the step has not ended after `stop_timeout` seconds (default 240),
   it is killed.
3. The daemon releases the lease, writes `stopped` and exits `0`.

A signal that arrives during a long database statement or LDAP call takes
effect when that call returns. Give the service manager a longer grace
period than `stop_timeout`:
- docker: `stop_grace_period: 5m`;
- systemd: `TimeoutStopSec=300`.

## 8. Running it

**First start, or a manual test:**

```
python3 collector_daemon.py --config collector.toml --check-config
python3 collector_daemon.py --config collector.toml --once     # one run now, exit 0/1/75 (not while the daemon runs)
python3 collector_daemon.py --config collector.toml            # the daemon
```

**systemd** (outline):

```
[Service]
User=adaudit
ExecStart=/opt/ad-security-profiler/venv/bin/python /opt/ad-security-profiler/collector_daemon.py --config /etc/fortifydata/collector.toml
Restart=always
RestartSec=60
TimeoutStopSec=300
```

**Container.** See `CONTAINER.md`: the image (`Dockerfile`), docker compose
with a PostgreSQL 17 container (`docker/compose.yaml`), the installation
script and day-to-day operation.

## 9. Testing done

Every behaviour below was tested in a container, against PostgreSQL 17 and
a mock of the platform. The mock now follows the platform developer's
specification (documents 04 and 05), alongside the ingest API.

**With stand-in scripts:**
- each secret arrives only through `/dev/fd`, with no TTY and an empty
  standard input, and is not visible on the command line;
- a secret in the daemon's environment does not reach a child;
- the catch-up run on first start, and no extra run after a restart;
- the scheduled time fires on the minute;
- a failed AD collection skips the evaluation and runs push-only;
- a failed Entra collection still evaluates and pushes the AD data, with
  `--skip-entra`, and the run ends `warning`; `--skip-entra` is also passed
  when Entra is not configured;
- the integrity check runs after a collection and reports a planted
  duplicate;
- no retry without a configuration change, and an immediate retry after a
  password change in the mock portal;
- SIGTERM during a step, both a step that stops cleanly and one that
  ignores SIGTERM and is killed after `stop_timeout`; the lease is released
  both times;
- the platform answering 409 and 401 on activation, 202 and 404 on renewal,
  a clock skew, a non-standard LDAPS port, a newer target version, the
  configuration cleared in the portal, the collector `EXPIRED`, a 404
  (decommissioned) and 500 and 401 from the health check;
- the push retry, including after an incomplete evaluation and when the
  push is switched off;
- a second process on the same state directory is refused;
- a password changed while the daemon was stopped is picked up at start;
- 50 SIGTERMs in a row still give one clean stop.

**With the real scripts:**
- `schema_setup.py` created schema v49 on an empty database;
- `adprofiler.py` read its secrets from the pipes and failed cleanly on an
  unreachable DC, and its summary line was captured;
- `entra_graph_collector.py` was given `--client-id` from the single domain
  in the database and reported Microsoft's AADSTS error;
- `adaudit.py` evaluated 390 plugins and pushed the run, sending the
  catalogue, the run and its completion with `LicenseKey` authentication.

**Unit checks:**
- next and previous scheduled time across both daylight-saving changes;
- run configuration validation;
- activation keys: `prod`/`eu`/`test`, no `e`, any other environment, bare
  keys, explicit API URL.

## 10. Open questions

- **Still with the platform:** a `reason` body on 401 and 403 (then the
  "403 without reason = waiting for approval" rule is removed from the
  push), activation key reissue, and installation approval under
  licensing.
- **The Collector Manager** acts on `targetVersion` and `autoUpgrade`:
  it pulls and switches the image. How it runs the containers, and how it
  rolls back with the pre-migration backup (`CONTAINER.md`, section 5), is
  being agreed with its author.
- **Several AD domains per database.** Deferred; the Entra step then needs
  `ad.domain_fqdn`.
