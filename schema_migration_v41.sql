-- ============================================================================
-- schema_migration_v41.sql
--
-- Partition maintenance that actually runs, and retention that never deletes
-- current state (adprofiler.py 0.7.2).
--
-- The 21 history tables in partitioned_table_registry are partitioned by
-- month on valid_from, with no DEFAULT partition. Three problems, all fixed
-- here:
--
--   1. Partitions were only ever created by schema_init.sql (install month
--      plus two). Nothing called ensure_partitions_for_horizon() or
--      run_partition_maintenance(), so from the first day after the last
--      partition every collection failed with "no partition of relation ...
--      found for row". adprofiler.py now calls run_partition_maintenance()
--      at the start of every run, and this migration creates the missing
--      partitions immediately.
--   2. drop_partitions_older_than() dropped whole partitions by valid_from
--      month. In these SCD2 tables the CURRENT row of anything unchanged for
--      longer than the retention period lives in an old partition, so
--      retention deleted live state: current objects, group memberships and
--      ACEs vanished, findings closed as remediated, and the next collection
--      re-created everything as new (false "added to Domain Admins" alerts).
--      Retention now deletes only CLOSED history rows (valid_to older than
--      the client's retention_months), and a partition is dropped only once
--      it is completely empty.
--   3. The functions referenced partitioned_table_registry without a schema
--      and so only worked when the caller had set search_path; creating a
--      partition also needs ownership of the parent table. The functions are
--      now schema-qualified, pin their search_path, and are SECURITY
--      DEFINER (they run with the rights of the role that applied this
--      migration -- the schema owner), so a collector connecting as a
--      non-owner role can still run maintenance. A transaction-level
--      advisory lock serialises concurrent callers.
--
-- client.retention_months (default 12, previously unused) is now the
-- retention period for closed history, per client. The adaudit findings
-- history (control_evidence_fact) is not partitioned and is not touched.
-- ============================================================================

BEGIN;

SET search_path TO ad_intel, public;

CREATE TABLE IF NOT EXISTS ad_intel.partition_maintenance_log (
    maintenance_id      BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    ran_at              TIMESTAMPTZ NOT NULL DEFAULT now(),
    partitions_created  INTEGER NOT NULL DEFAULT 0,
    purge_ran           BOOLEAN NOT NULL DEFAULT false,
    rows_purged         BIGINT NOT NULL DEFAULT 0,
    partitions_dropped  TEXT[] NOT NULL DEFAULT '{}'
);
COMMENT ON TABLE ad_intel.partition_maintenance_log IS
    'One row per run_partition_maintenance() call that did any work or ran the purge. The purge '
    'of closed history runs at most once per p_purge_interval (default 28 days); its last run is '
    'read from here. (schema v41)';

-- Return type changes (void -> boolean): drop and recreate.
DROP FUNCTION IF EXISTS ad_intel.create_monthly_partition(text, date);
CREATE FUNCTION ad_intel.create_monthly_partition(p_table text, p_month date)
    RETURNS boolean
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = ad_intel, pg_temp
    AS $$
-- Creates the monthly partition of p_table (a table registered in
-- partitioned_table_registry) for the month containing p_month. Returns TRUE
-- if it was created, FALSE if it already existed.
DECLARE
    v_start      DATE := date_trunc('month', p_month);
    v_end        DATE := v_start + INTERVAL '1 month';
    v_part       TEXT := format('%s_%s', p_table, to_char(v_start, 'YYYY_MM'));
    v_high_churn BOOLEAN;
BEGIN
    SELECT high_churn INTO v_high_churn
    FROM ad_intel.partitioned_table_registry WHERE table_name = p_table;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'table % is not in partitioned_table_registry', p_table;
    END IF;
    IF to_regclass(format('ad_intel.%I', v_part)) IS NOT NULL THEN
        RETURN false;
    END IF;
    EXECUTE format(
        'CREATE TABLE ad_intel.%I PARTITION OF ad_intel.%I FOR VALUES FROM (%L) TO (%L)',
        v_part, p_table, v_start, v_end
    );
    IF v_high_churn THEN
        EXECUTE format(
            'ALTER TABLE ad_intel.%I SET (autovacuum_vacuum_scale_factor = 0.02, '
            'autovacuum_analyze_scale_factor = 0.02)', v_part);
    END IF;
    RETURN true;
END;
$$;

-- The return type changes (void -> integer), which CREATE OR REPLACE cannot do.
DROP FUNCTION IF EXISTS ad_intel.ensure_partitions_for_horizon(integer);
CREATE FUNCTION ad_intel.ensure_partitions_for_horizon(p_months_ahead integer DEFAULT 2)
    RETURNS integer
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = ad_intel, pg_temp
    AS $$
-- Creates every registered table's partitions for the current month and the
-- next p_months_ahead months (0..24). Returns how many were created.
DECLARE
    v_table   TEXT;
    v_month   DATE;
    v_created INTEGER := 0;
BEGIN
    IF p_months_ahead IS NULL OR p_months_ahead < 0 OR p_months_ahead > 24 THEN
        RAISE EXCEPTION 'p_months_ahead must be between 0 and 24';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('ad_intel.partition_maintenance'));
    FOR v_table IN SELECT table_name FROM ad_intel.partitioned_table_registry ORDER BY table_name LOOP
        FOR v_month IN
            SELECT (date_trunc('month', now()) + make_interval(months => n))::date
            FROM generate_series(0, p_months_ahead) AS n
        LOOP
            IF ad_intel.create_monthly_partition(v_table, v_month) THEN
                v_created := v_created + 1;
            END IF;
        END LOOP;
    END LOOP;
    RETURN v_created;
END;
$$;

CREATE OR REPLACE FUNCTION ad_intel.purge_closed_history()
    RETURNS bigint
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = ad_intel, pg_temp
    AS $$
-- Deletes CLOSED history rows (valid_to set and older than the owning client's
-- retention_months) from every registered table. Open rows (valid_to IS
-- NULL) -- the current state -- are never deleted, however old their
-- valid_from. Returns the number of rows deleted.
DECLARE
    v_table TEXT;
    v_rows  BIGINT;
    v_total BIGINT := 0;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('ad_intel.partition_maintenance'));
    FOR v_table IN SELECT table_name FROM ad_intel.partitioned_table_registry ORDER BY table_name LOOP
        EXECUTE format(
            'DELETE FROM ad_intel.%I t USING ad_intel.client c '
            'WHERE t.client_id = c.client_id AND t.valid_to IS NOT NULL '
            '  AND t.valid_to < now() - make_interval(months => c.retention_months)',
            v_table);
        GET DIAGNOSTICS v_rows = ROW_COUNT;
        v_total := v_total + v_rows;
    END LOOP;
    RETURN v_total;
END;
$$;

-- Same signature as before (callers and any scheduled job keep working), new
-- behaviour: only EMPTY partitions are dropped.
DROP FUNCTION IF EXISTS ad_intel.drop_partitions_older_than(text, integer);
CREATE FUNCTION ad_intel.drop_partitions_older_than(p_table text, p_retention_months integer DEFAULT 12)
    RETURNS text[]
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = ad_intel, pg_temp
    AS $_$
-- Drops monthly partitions of p_table older than p_retention_months that hold
-- NO rows. A partition still holding any row -- in particular a current
-- (open) row of something unchanged since that month -- is kept: dropping it
-- would delete live state. Closed rows are removed by purge_closed_history(),
-- after which old partitions empty out and are dropped here. Returns the
-- names of the partitions dropped.
DECLARE
    v_cutoff  DATE := (date_trunc('month', now()) - make_interval(months => p_retention_months))::date;
    v_rec     RECORD;
    v_has_row BOOLEAN;
    v_dropped TEXT[] := '{}';
BEGIN
    IF p_retention_months IS NULL OR p_retention_months < 1 THEN
        RAISE EXCEPTION 'p_retention_months must be at least 1';
    END IF;
    PERFORM pg_advisory_xact_lock(hashtext('ad_intel.partition_maintenance'));
    FOR v_rec IN
        SELECT c.relname AS partition_name
        FROM pg_inherits i
        JOIN pg_class c      ON c.oid = i.inhrelid
        JOIN pg_class parent ON parent.oid = i.inhparent
        JOIN pg_namespace n  ON n.oid = parent.relnamespace AND n.nspname = 'ad_intel'
        WHERE parent.relname = p_table
          AND c.relname ~ '_\d{4}_\d{2}$'
          AND to_date(right(c.relname, 7), 'YYYY_MM') < v_cutoff
        ORDER BY c.relname
    LOOP
        EXECUTE format('SELECT EXISTS (SELECT 1 FROM ad_intel.%I)', v_rec.partition_name) INTO v_has_row;
        IF NOT v_has_row THEN
            EXECUTE format('DROP TABLE ad_intel.%I', v_rec.partition_name);
            v_dropped := v_dropped || v_rec.partition_name;
        END IF;
    END LOOP;
    RETURN v_dropped;
END;
$_$;

DROP FUNCTION IF EXISTS ad_intel.run_partition_maintenance();
CREATE FUNCTION ad_intel.run_partition_maintenance(p_months_ahead integer DEFAULT 2,
                                                   p_purge_interval interval DEFAULT '28 days')
    RETURNS jsonb
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = ad_intel, pg_temp
    AS $$
-- Called by adprofiler.py at the start of every run:
--   1. create partitions for this month and the next p_months_ahead;
--   2. at most once per p_purge_interval: delete closed history older than
--      each client's retention_months, then drop partitions that are empty
--      and older than the longest client retention.
-- Returns {"partitions_created", "purge_ran", "rows_purged",
-- "partitions_dropped"}.
DECLARE
    v_created  INTEGER;
    v_purge    BOOLEAN;
    v_rows     BIGINT := 0;
    v_dropped  TEXT[] := '{}';
    v_table    TEXT;
    v_keep     INTEGER;
BEGIN
    PERFORM pg_advisory_xact_lock(hashtext('ad_intel.partition_maintenance'));
    v_created := ad_intel.ensure_partitions_for_horizon(p_months_ahead);

    SELECT NOT EXISTS (
        SELECT 1 FROM ad_intel.partition_maintenance_log
        WHERE purge_ran AND ran_at > now() - p_purge_interval
    ) INTO v_purge;

    IF v_purge THEN
        v_rows := ad_intel.purge_closed_history();
        SELECT GREATEST(COALESCE(max(retention_months), 12), 1) INTO v_keep FROM ad_intel.client;
        FOR v_table IN SELECT table_name FROM ad_intel.partitioned_table_registry ORDER BY table_name LOOP
            v_dropped := v_dropped || ad_intel.drop_partitions_older_than(v_table, v_keep);
        END LOOP;
    END IF;

    IF v_created > 0 OR v_purge THEN
        INSERT INTO ad_intel.partition_maintenance_log
            (partitions_created, purge_ran, rows_purged, partitions_dropped)
        VALUES (v_created, v_purge, v_rows, v_dropped);
    END IF;

    RETURN jsonb_build_object('partitions_created', v_created, 'purge_ran', v_purge,
                              'rows_purged', v_rows, 'partitions_dropped', to_jsonb(v_dropped));
END;
$$;

CREATE OR REPLACE FUNCTION ad_intel.missing_current_partitions()
    RETURNS text[]
    LANGUAGE sql
    STABLE
    SET search_path = ad_intel, pg_temp
    AS $$
-- Registered tables with no partition for the current month: a collection run
-- would fail on them.
    SELECT COALESCE(array_agg(r.table_name ORDER BY r.table_name), '{}')
    FROM ad_intel.partitioned_table_registry r
    WHERE to_regclass(format('ad_intel.%I', r.table_name || '_' || to_char(now(), 'YYYY_MM'))) IS NULL;
$$;

COMMENT ON COLUMN ad_intel.client.retention_months IS
    'How long CLOSED history (superseded versions, removed edges) is kept in the partitioned '
    'history tables, in months. Current state is never purged. Applied by '
    'run_partition_maintenance() / purge_closed_history(). (used since schema v41)';

-- Fix the partitions of an existing database now (a database already past
-- its last partition cannot collect until this runs).
SELECT ad_intel.ensure_partitions_for_horizon(2);

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (41, 'Partition maintenance: created every run, retention purges closed history only')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;
