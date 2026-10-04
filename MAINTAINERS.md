# Maintainers

This file lists the people responsible for **ad-security-profiler** and explains how the project is maintained. It covers:

- `adprofiler.py`, the Active Directory collector
- `entra_graph_collector.py`, the Entra ID collector
- `adaudit.py`, the plugin runner and report writer
- the finding plugins in `plugins/`
- the PostgreSQL schema (`schema_init.sql` and the `schema_migration_vNN.sql` files)

## Current maintainers

| Name | GitHub | Email | Role | Areas |
|---|---|---|---|---|
| Eric Smith | [@prisoner881](https://github.com/prisoner881) | eric.smith@fortifydata.com | Lead maintainer | All |

## Areas of responsibility

Each area lists the files it covers. Any change to an area needs approval from one of its maintainers.

| Area | Files | Maintainers |
|---|---|---|
| AD collector | `adprofiler.py`, `changelog.txt` | @prisoner881 |
| Entra ID collector | `entra_graph_collector.py` | @prisoner881 |
| Plugin runner and reporting | `adaudit.py` | @prisoner881 |
| Finding and inventory plugins | `plugins/`, `COMPLIANCE_TAGS.md` | @prisoner881 |
| Database schema | `schema_init.sql`, `schema_migration_v*.sql` | @prisoner881 |
| Documentation | `SETUP.md`, `MAINTAINERS.md` | @prisoner881 |

## Maintainer responsibilities

Maintainers:

- review and merge pull requests in their areas;
- keep the default branch (`client-test`) in a releasable state;
- triage issues and security reports, and respond within a reasonable time;
- keep the collectors, `adaudit.py` and the schema version in step, as described under "Project conventions" below;
- keep `SETUP.md` accurate for the permissions, setup steps and outputs a client sees;
- make sure findings stay reproducible: deterministic summaries, one finding per identity, and no client data committed to the repository.

## Contribution and review process

1. Work on a feature branch and open a pull request against `client-test`.
2. A maintainer for every affected area must approve the pull request before it is merged.
3. A pull request that changes the schema, or how collected data is interpreted, must include:
   - the matching migration file;
   - the version bumps listed under "Project conventions";
   - a note on whether existing databases need `adprofiler.py --full-rescan`.
4. A pull request must not contain:
   - client data, credentials, or collected output (`*.log`, `*.xlsx`);
   - compiled files (`__pycache__/`).

## Project conventions

Maintainers check pull requests against these conventions.

- **Schema changes:**
  - Every schema change ships as a new `schema_migration_vNN.sql` and is also folded into `schema_init.sql`. A fresh install and an upgrade must produce the same schema.
  - `EXPECTED_SCHEMA_VERSION` in `adprofiler.py` and `REQUIRED_SCHEMA_VERSION` in `adaudit.py` are raised to match.
  - Migrations are never edited after release.
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
  - New optional reads must not stop a run when they fail.

## Reporting security issues

Do not open a public issue for a vulnerability in this project, or for a flaw that could expose client data. Email the lead maintainer at the address above with a description and steps to reproduce. The maintainer will acknowledge the report and coordinate the fix and its disclosure.

## Becoming a maintainer

Contributors with a record of good-quality pull requests and reviews in an area can be nominated by an existing maintainer. The nomination is made in a pull request that adds the contributor to this file, and all current maintainers must approve it. New maintainers start with a single area and can take on more over time.

## Stepping down and emeritus maintainers

A maintainer who can no longer take part should open a pull request that moves them to the list below and reassigns their areas. A maintainer with no review activity for six months may be moved there by the other maintainers, after they have tried to contact them. Emeritus maintainers can return through the normal nomination process.

### Emeritus maintainers

None.
