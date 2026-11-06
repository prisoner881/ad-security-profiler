# Maintainers

This file lists the people responsible for **ad-security-profiler** and explains how the project is maintained. This is the **standalone** edition, on the `standalone` branch: the scripts are run by hand, interactively, and the results are the console report and an Excel workbook. It covers:

- `adprofiler.py`, the Active Directory collector, with `sysvol_collector.py` (Group Policy content)
- `entra_graph_collector.py`, the Entra ID collector
- `adaudit.py`, the plugin runner and report writer (console and Excel workbook)
- `run_lock.py`, the run lock shared by the three scripts
- `secret_input.py`, how the three scripts read passwords and secrets
- the finding plugins in `plugins/`
- the PostgreSQL schema (`schema_init.sql`, the v50 baseline, and the migrations in `migrations/`), with `schema_setup.py`, which applies them

## Current maintainers

| Name | GitHub | Email | Role | Areas |
|---|---|---|---|---|
| Eric Smith | [@prisoner881](https://github.com/prisoner881) | — | Lead maintainer | All |

## Areas of responsibility

Each area lists the files it covers. Any change to an area needs approval from one of its maintainers.

| Area | Files | Maintainers |
|---|---|---|
| AD collector | `adprofiler.py`, `sysvol_collector.py`, `docs/changelog.txt` | @prisoner881 |
| Entra ID collector | `entra_graph_collector.py` | @prisoner881 |
| Plugin runner and reporting | `adaudit.py` | @prisoner881 |
| Run lock and secret input | `run_lock.py`, `secret_input.py` | @prisoner881 |
| Finding and inventory plugins | `plugins/`, `docs/COMPLIANCE_TAGS.md` | @prisoner881 |
| Database schema | `schema_init.sql`, `migrations/`, `schema_setup.py` | @prisoner881 |
| Tests | `tests/`, `.github/workflows/tests.yml` | @prisoner881 |
| Documentation | `docs/SETUP.md`, `docs/RELEASE_NOTES.md`, `docs/MAINTAINERS.md`, `docs/PERMISSIONS.md` | @prisoner881 |

## Maintainer responsibilities

Maintainers:

- review and merge pull requests in their areas;
- keep the `standalone` branch in a releasable state;
- triage issues and security reports, and respond within a reasonable time;
- keep the collectors, `adaudit.py` and the schema version in step, as described under "Project conventions" below;
- keep `SETUP.md` accurate for the permissions, setup steps and outputs a client sees;
- make sure findings stay reproducible: deterministic summaries, one finding per identity, and no client data committed to the repository.

## Contribution and review process

1. Work on a feature branch and open a pull request against `standalone`.
2. A maintainer for every affected area must approve the pull request before it is merged.
3. A pull request that changes the schema, or how collected data is interpreted, must include:
   - the matching migration file in `migrations/` (see "Schema changes" below);
   - the version bumps listed under "Project conventions";
   - a note on whether existing databases need `adprofiler.py --full-rescan`.
4. A pull request must not contain:
   - client data, credentials, or collected output (`*.log`, `*.xlsx`);
   - compiled files (`__pycache__/`).

   `.gitignore` keeps these out of `git add`; it does not remove a file that is already committed (use `git rm --cached`).

## Project conventions

Maintainers check pull requests against these conventions.

- **Schema changes:**
  - **The model:** `schema_init.sql` is the **v50 baseline and is never edited**. Every later change is one migration in `migrations/`: `schema_migration_v51.sql`, `v52`, and so on, with no gap. `schema_setup.py` creates a new database from the baseline and then applies every migration in order. It brings an existing database (v50 or later) up the same chain, however many versions behind it is, so a fresh install and an upgraded database run the same SQL. The migration files up to v50 were removed; they remain in the git history. (The standalone branch's `schema_init.sql` differs from the other branches' only in the wording of a few comments.)
  - **One file per version:** `migrations/schema_migration_vNN.sql`, NN one more than the newest one there.
  - **All or nothing:** wrapped in `BEGIN;` … `COMMIT;`, ending with its own row: `INSERT INTO ad_intel.schema_migration_history (version_number, description) VALUES (NN, '…') ON CONFLICT (version_number) DO NOTHING;`. `schema_setup.py` checks that the row was written.
  - **Schema-qualified names** (`ad_intel.…`). No psql meta-commands (`\i`, `\set`, …): the file is sent through psycopg2.
  - **Self-contained.** A migration may assume only the schema that vNN-1 left. Clients skip updates: one going from v50 to v55 never ran the code of v51 to v54, so a migration must not rely on data that an intermediate version's collector or adaudit.py would have written. Any backfill is done in the migration's SQL.
  - **Full rescan:** when existing objects need one `adprofiler.py --full-rescan` to fill new columns, put the line `-- adprofiler: full-rescan` in the header. `schema_setup.py` then says that one `adprofiler.py --full-rescan` is needed (and creates the `--rescan-file`, if given), however many such migrations are applied at once.
  - **Never edited once released.** A mistake is fixed by the next migration.
  - **Code follows:** `EXPECTED_SCHEMA_VERSION` in `adprofiler.py` (an exact match) and `REQUIRED_SCHEMA_VERSION` in `adaudit.py` are raised to NN in the same pull request, and adprofiler.py's structural check (`validate_schema()`) learns any table or column it now writes.
  - **Tested before release** on PostgreSQL 17:
    - a fresh install (the baseline plus the whole chain);
    - an upgrade from every earlier released version, with data;
    - the two schemas compared with `pg_dump --schema-only`.

    `tests/test_schema_setup.py` does the first and the third on every CI run (a v50 database upgraded through the repository's chain must equal a fresh install); the upgrade with data from each released version is still done by hand.
- **Documentation** lives in `docs/`. A script's message or comment names a document by its path (`docs/PERMISSIONS.md`); documents refer to one another by file name alone.
- **Versioning:**
  - Each script carries its own `VERSION`, and changes are recorded in its docstring or in `changelog.txt`.
  - Plugins carry their own `version` and `revision_date`, plus a `[vX.Y]` note in the docstring explaining what changed.
- **Plugins:**
  - The query returns the nine-column contract that `adaudit.py` documents.
  - There is one row per finding identity, summaries are deterministic, and well-known groups are matched by SID or RID, never by name.
  - `references` is a list of `{"title", "url"}` entries.
  - `framework_tags` follows `COMPLIANCE_TAGS.md`.
  - A plugin is retired with a stub, not deleted (see `adaudit.py`).
- **Collection safety:**
  - Collectors only read; they never write to Active Directory or Entra ID.
  - Secrets are never stored. That includes passwords, LAPS and gMSA passwords, KDS root keys and the AD FS DKM key.
  - Secrets the scripts need are read through `secret_input.py` (option, environment variable, `_FILE`, prompt) and are never logged.
  - New optional reads must not stop a run when they fail.
  - A new AD read that an ordinary domain user cannot do, or a new Graph permission, needs a matching entry in `PERMISSIONS.md` (the client's setup guide) and, for Graph, in SETUP.md's permission table. `PERMISSIONS.md` is written for the client's administrators: it says what to set up and why, never which script, option, file or setting uses it. Keep its section numbers stable; adprofiler.py's messages and SETUP.md refer to them.

## Tests

From the repository root, with the dependencies installed:

```
python -m unittest discover -s tests -t . -v
```

The schema tests need a PostgreSQL 17 server and a role that may create databases (`ADPROFILER_TEST_PGHOST`, `_PGPORT`, `_PGUSER`, `_PGPASSWORD`; see `tests/test_schema_setup.py`), and `pg_dump` 17 for the backup and comparison tests. Without them those tests are skipped. CI runs everything. A pull request that changes behaviour adds or updates a test.

## Releasing

The standalone edition is handed over as the files themselves (`SETUP.md`, section 2). To release:

1. Make sure CI is green on `standalone`, and add the release to `RELEASE_NOTES.md`.
2. Tag the commit on `standalone`, for example `standalone-2026-11-06`, and push the tag.
3. Hand over the files from that tag.

A tag is never moved or reused. A mistake is fixed by the next release.

## Reporting security issues

Do not open a public issue for a vulnerability in this project, or for a flaw that could expose client data. Contact the lead maintainer privately (GitHub: [@prisoner881](https://github.com/prisoner881)) with a description and steps to reproduce. The maintainer will acknowledge the report and coordinate the fix and its disclosure.

## Becoming a maintainer

Contributors with a record of good-quality pull requests and reviews in an area can be nominated by an existing maintainer. The nomination is made in a pull request that adds the contributor to this file, and all current maintainers must approve it. New maintainers start with a single area and can take on more over time.

## Stepping down and emeritus maintainers

A maintainer who can no longer take part should open a pull request that moves them to the list below and reassigns their areas. A maintainer with no review activity for six months may be moved there by the other maintainers, after they have tried to contact them. Emeritus maintainers can return through the normal nomination process.

### Emeritus maintainers

None.
