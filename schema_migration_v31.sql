-- schema_migration_v31.sql
-- Adds schema_migration_history: an append-only log of which migrations
-- have actually been applied, letting scripts compare their expected
-- schema version against the database's real one with a single integer
-- comparison instead of parsing prose error messages (which have gone
-- stale before -- see v0.5.7's fix to adprofiler.py's schema-error
-- message for a real example of exactly that happening).
--
-- Kept alongside the existing table/column/function structural check,
-- not as a replacement for it: the version number gives fast, precise
-- diagnosis for the common case (a database that's simply behind on
-- migrations); the structural check remains the backstop for the rarer
-- case of a schema altered outside the approved migration files, where
-- the version number could claim to be current while the actual
-- structure doesn't match it.

SET search_path TO ad_intel, public;

CREATE TABLE schema_migration_history (
    version_number  INTEGER NOT NULL PRIMARY KEY,
    applied_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    description     TEXT NOT NULL
);

-- Backfill: any database applying this migration already has everything
-- through v30 (schema_init.sql's own consolidated baseline, or an
-- unbroken chain of prior incremental migrations) -- but the exact
-- historical applied_at timestamps for those prior versions were never
-- recorded, so this single row honestly represents "known to be at
-- least v30 as of now," not a reconstructed history.
INSERT INTO schema_migration_history (version_number, description) VALUES
    (30, 'Backfilled: consolidated baseline through v30 (schema tracking did not exist before v31)'),
    (31, 'Added schema_migration_history itself');
