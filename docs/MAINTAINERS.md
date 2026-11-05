# Maintainers

This file lists the people responsible for **ad-security-profiler** and explains how the project is maintained. It covers:

- `adprofiler.py`, the Active Directory collector, with `sysvol_collector.py` (Group Policy content)
- `entra_graph_collector.py`, the Entra ID collector
- `adaudit.py`, the plugin runner and report writer, with `adaudit_push.py` (push to the FortifyData API)
- `run_lock.py`, the run lock shared by the three scripts
- `secret_input.py`, how the three scripts read passwords and secrets
- the finding plugins in `plugins/`
- the PostgreSQL schema (`schema_init.sql`, and from v51 on the `schema_migration_vNN.sql` files), with `schema_setup.py`, which applies them unattended
- `collector_daemon.py`, the unattended daemon that runs the scripts daily, with `platform_client.py` (the FortifyData platform side)
- the container packaging (`Dockerfile`, `docker/`)

## Current maintainers

| Name | GitHub | Email | Role | Areas |
|---|---|---|---|---|
| Eric Smith | [@prisoner881](https://github.com/prisoner881) | eric.smith@fortifydata.com | Lead maintainer | All |

## Areas of responsibility

Each area lists the files it covers. Any change to an area needs approval from one of its maintainers.

| Area | Files | Maintainers |
|---|---|---|
| AD collector | `adprofiler.py`, `sysvol_collector.py`, `docs/changelog.txt` | @prisoner881 |
| Entra ID collector | `entra_graph_collector.py` | @prisoner881 |
| Plugin runner and reporting | `adaudit.py`, `adaudit_push.py` | @prisoner881 |
| Run lock and secret input | `run_lock.py`, `secret_input.py` | @prisoner881 |
| Finding and inventory plugins | `plugins/`, `docs/COMPLIANCE_TAGS.md` | @prisoner881 |
| Database schema | `schema_init.sql`, `schema_migration_v*.sql`, `schema_setup.py` | @prisoner881 |
| Collector daemon | `collector_daemon.py`, `platform_client.py`, `collector_daemon.example.toml`, `docs/DAEMON.md` | @prisoner881 |
| Container packaging | `Dockerfile`, `.dockerignore`, `docker/`, `docs/CONTAINER.md` | @prisoner881 |
| Documentation | `docs/SETUP.md`, `docs/RELEASE_NOTES.md`, `docs/MAINTAINERS.md`, `docs/DAEMON.md`, `docs/CONTAINER.md`, `docs/PERMISSIONS.md` | @prisoner881 |

## Maintainer responsibilities

Maintainers:

- review and merge pull requests in their areas;
- keep the default branch (`release`) in a releasable state;
- triage issues and security reports, and respond within a reasonable time;
- keep the collectors, `adaudit.py` and the schema version in step, as described under "Project conventions" below;
- keep `SETUP.md` accurate for the permissions, setup steps and outputs a client sees;
- make sure findings stay reproducible: deterministic summaries, one finding per identity, and no client data committed to the repository.

## Contribution and review process

1. Work on a feature branch and open a pull request against `release`.
2. A maintainer for every affected area must approve the pull request before it is merged.
3. A pull request that changes the schema, or how collected data is interpreted, must include:
   - the matching migration file;
   - the version bumps listed under "Project conventions";
   - a note on whether existing databases need `adprofiler.py --full-rescan`.
4. A pull request must not contain:
   - client data, credentials, or collected output (`*.log`, `*.xlsx`);
   - compiled files (`__pycache__/`).

   `.gitignore` keeps these out of `git add`; it does not remove a file that is already committed (use `git rm --cached`).

## Project conventions

Maintainers check pull requests against these conventions.

- **Schema changes:**
  - `schema_init.sql` is the complete current schema; a production installation starts from it on an empty database. The migration files up to v50 were removed (they remain in the git history).
  - From v51 on, every schema change ships as a new `schema_migration_vNN.sql` (so installed databases can be upgraded) and is also folded into `schema_init.sql`. A fresh install and an upgrade must produce the same schema.
  - `EXPECTED_SCHEMA_VERSION` in `adprofiler.py` and `REQUIRED_SCHEMA_VERSION` in `adaudit.py` are raised to match.
  - Migrations are never edited after release.
  - `schema_setup.py` takes the version `schema_init.sql`'s fresh-install row records as the target, and refuses a migration file newer than it; raise that row with every migration. A migration must insert its own row into `schema_migration_history` (the script checks it), and must not contain psql meta-commands (only pg_dump's `\restrict`/`\unrestrict` lines in `schema_init.sql` are skipped).
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
  - `collector_daemon.py` passes secrets to the scripts only through pipes (`<VAR>_FILE=/dev/fd/N`), never as options or environment values. A script's exit status is the daemon's only signal, so a new exit status, or a new secret, needs a matching change in the daemon.
  - The image version appears in `Dockerfile` (`VERSION`), `docker/compose.yaml` and `docker/install.sh` (the default image tag), and `CONTAINER.md`; raise them together with `collector_daemon.py`'s `VERSION`. A new top-level file the scripts need must also be added to the `COPY` lines in `Dockerfile`.
  - New optional reads must not stop a run when they fail.
  - A new AD read that an ordinary domain user cannot do, or a new Graph permission, needs a matching entry in `PERMISSIONS.md` (the client's setup guide) and, for Graph, in SETUP.md's permission table. `PERMISSIONS.md` is written for the client's administrators: it says what to set up and why, never which script, option, file or setting uses it. Keep its section numbers stable; adprofiler.py's messages, SETUP.md and CONTAINER.md refer to them.

## Reporting security issues

Do not open a public issue for a vulnerability in this project, or for a flaw that could expose client data. Email the lead maintainer at the address above with a description and steps to reproduce. The maintainer will acknowledge the report and coordinate the fix and its disclosure.

## Becoming a maintainer

Contributors with a record of good-quality pull requests and reviews in an area can be nominated by an existing maintainer. The nomination is made in a pull request that adds the contributor to this file, and all current maintainers must approve it. New maintainers start with a single area and can take on more over time.

## Stepping down and emeritus maintainers

A maintainer who can no longer take part should open a pull request that moves them to the list below and reassigns their areas. A maintainer with no review activity for six months may be moved there by the other maintainers, after they have tried to contact them. Emeritus maintainers can return through the normal nomination process.

### Emeritus maintainers

None.
