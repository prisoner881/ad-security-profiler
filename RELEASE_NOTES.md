# Release Notes

## Release 1.0.x updates (2026-10-30)

Fixes and hardening made after release 1.0, from running it against a live
domain and tenant and from a full code review. Two schema migrations (v47,
v48); no plugin added or removed.

### Components

| Component | Version |
|---|---|
| `adprofiler.py` (Active Directory collector) | 1.0.4 |
| `sysvol_collector.py` (used by `adprofiler.py --sysvol`) | 1.2 |
| `entra_graph_collector.py` (Entra ID collector) | 1.0.3 |
| `adaudit.py` (plugin runner and report writer) | 1.0.4 |
| `adaudit_push.py` (ingest API push contract) | contract 1.0 |
| `run_lock.py` (one run at a time; new) | 1.0 |
| PostgreSQL schema (`schema_init.sql`) | v48 |

### Changes

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
`schema_migration_v47.sql`, then `schema_migration_v48.sql`
(`psql -v ON_ERROR_STOP=1 -f schema_migration_v47.sql`, and the same for
v48). adprofiler.py 1.0.4 and adaudit.py 1.0.4 refuse to run against an
older schema. No `--full-rescan` is needed:

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
