# Release Notes

## Release 1.0.x updates (2026-10-30)

Fixes and hardening made after release 1.0, from running it against a live
domain and tenant and from a full code review. One schema migration (v47);
no plugin added or removed.

### Components

| Component | Version |
|---|---|
| `adprofiler.py` (Active Directory collector) | 1.0.3 |
| `sysvol_collector.py` (used by `adprofiler.py --sysvol`) | 1.1 |
| `entra_graph_collector.py` (Entra ID collector) | 1.0.2 |
| `adaudit.py` (plugin runner and report writer) | 1.0.3 |
| `adaudit_push.py` (ingest API push contract) | contract 1.0 |
| `run_lock.py` (one run at a time; new) | 1.0 |
| PostgreSQL schema (`schema_init.sql`) | v47 |

### Changes

Code review fixes (2026-10-30, adprofiler.py 1.0.3, adaudit.py 1.0.3, schema
v47):

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
three scripts import it and fail to start without it), and **apply
`schema_migration_v47.sql`** to the existing database
(`psql -v ON_ERROR_STOP=1 -f schema_migration_v47.sql`); adprofiler.py 1.0.3
refuses to run against v46. No `--full-rescan` is needed. The first
adprofiler.py run afterwards checks every deleted object once.

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
