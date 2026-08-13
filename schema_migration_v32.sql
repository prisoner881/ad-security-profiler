-- schema_migration_v32.sql
-- Fixes a real, confirmed bug: unresolved_delegation_target_edge.edge_id
-- was created as a plain "bigint NOT NULL" with no auto-generation
-- mechanism at all -- every other edge table in this schema gets its
-- edge_id via a separate ALTER TABLE ... ADD GENERATED ALWAYS AS
-- IDENTITY statement after CREATE TABLE, and that statement was simply
-- never added for this one table. Confirmed by direct comparison
-- against delegation_edge's (correct) definition before writing this
-- fix, not guessed at -- and fixed using that exact same syntax for
-- consistency, not a different auto-increment mechanism.
--
-- Sat dormant since this table was first added (schema_migration_v29.sql)
-- because nothing in any prior test lab or client run had a genuine
-- unresolved ("ghost") delegation target -- an SPN listed in
-- msDS-AllowedToDelegateTo that doesn't resolve to any collected
-- object -- until a real production run at scale (Robert Morris
-- University, 30,014 active SPNs) hit one for the first time and the
-- INSERT failed with a NOT NULL violation on edge_id.
--
-- Safe to apply regardless of current table content: every insert
-- attempt against this table has been failing outright (the whole
-- transaction rolls back on the NOT NULL violation), so in practice
-- every real deployment's copy of this table is empty. ADD GENERATED
-- ALWAYS AS IDENTITY requires an empty table if any rows did somehow
-- exist without edge_id populated, which cannot happen given the
-- column is NOT NULL -- so this is unconditionally safe.

SET search_path TO ad_intel, public;

ALTER TABLE unresolved_delegation_target_edge
    ALTER COLUMN edge_id ADD GENERATED ALWAYS AS IDENTITY (
        SEQUENCE NAME unresolved_delegation_target_edge_edge_id_seq
    );

INSERT INTO schema_migration_history (version_number, description) VALUES
    (32, 'Fixed missing IDENTITY on unresolved_delegation_target_edge.edge_id (real NOT NULL violation hit in production)');
