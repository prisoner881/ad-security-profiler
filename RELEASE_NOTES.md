# Release Notes

## Release 1.0 (2026-10-22)

The first release of ad-security-profiler, made from `api-push` at the point
where Entra ID coverage waves 1 and 2 were merged and verified against a
live tenant.

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

385 active finding plugins (5 more are retired stubs):

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
