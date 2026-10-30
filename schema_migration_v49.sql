-- ============================================================================
-- schema_migration_v49.sql
--
-- Fixes from the code review, low severity (adprofiler.py / adaudit.py 1.0.5):
--
--   * Partition functions work in UTC. A monthly partition's bounds came
--     from a date cast to timestamptz in the session's time zone, so runs
--     from sessions in different zones made partitions that overlapped (the
--     CREATE failed and the run aborted) or left a gap. They are now UTC
--     month boundaries, and a new partition reuses the bound of an existing
--     neighbouring month, so partitions made before v49 under another zone
--     still meet exactly. Empty partitions of future months are made again
--     the same way, which removes a gap or overlap already left there.
--   * v_effective_group_membership: a group is no longer listed as a member
--     of itself when group nesting forms a cycle.
--   * entra_change_baseline.previous_run_at: the previous history update
--     (plugin 11027's "since the previous collection").
--
-- No rescan needed.
-- ============================================================================

BEGIN;

CREATE OR REPLACE FUNCTION ad_intel.create_monthly_partition(p_table text, p_month date)
    RETURNS boolean
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = ad_intel, pg_temp
    SET TimeZone = 'UTC'
    AS $$
-- Creates the monthly partition of p_table (a table registered in
-- partitioned_table_registry) for the month containing p_month. Returns TRUE
-- if it was created, FALSE if it already existed.
-- [v49] The bounds are UTC month boundaries whatever the caller's TimeZone
-- setting (a date cast to timestamptz used the session's zone, so sessions
-- in different zones made partitions that overlapped -- the CREATE failed and
-- the run aborted -- or left a gap). Where the previous or next month's
-- partition already exists, its bound is reused, so partitions made under
-- another zone before v49 still meet exactly.
DECLARE
    v_start      DATE := date_trunc('month', p_month);
    v_from       TIMESTAMPTZ := v_start::timestamp AT TIME ZONE 'UTC';
    v_to         TIMESTAMPTZ := (v_start + INTERVAL '1 month')::timestamp AT TIME ZONE 'UTC';
    v_part       TEXT := format('%s_%s', p_table, to_char(v_start, 'YYYY_MM'));
    v_bound      TEXT;
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
    SELECT pg_get_expr(c.relpartbound, c.oid) INTO v_bound
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'ad_intel'
    WHERE c.relname = format('%s_%s', p_table, to_char(v_start - INTERVAL '1 month', 'YYYY_MM'));
    IF v_bound ~ 'TO \(''[^'']+''\)' THEN
        v_from := substring(v_bound FROM 'TO \(''([^'']+)''\)')::timestamptz;
    END IF;
    v_bound := NULL;
    SELECT pg_get_expr(c.relpartbound, c.oid) INTO v_bound
    FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace AND n.nspname = 'ad_intel'
    WHERE c.relname = format('%s_%s', p_table, to_char(v_start + INTERVAL '1 month', 'YYYY_MM'));
    IF v_bound ~ 'FROM \(''[^'']+''\)' THEN
        v_to := substring(v_bound FROM 'FROM \(''([^'']+)''\)')::timestamptz;
    END IF;
    EXECUTE format(
        'CREATE TABLE ad_intel.%I PARTITION OF ad_intel.%I FOR VALUES FROM (%L) TO (%L)',
        v_part, p_table, v_from, v_to
    );
    IF v_high_churn THEN
        EXECUTE format(
            'ALTER TABLE ad_intel.%I SET (autovacuum_vacuum_scale_factor = 0.02, '
            'autovacuum_analyze_scale_factor = 0.02)', v_part);
    END IF;
    RETURN true;
END;
$$;

CREATE OR REPLACE FUNCTION ad_intel.ensure_partitions_for_horizon(p_months_ahead integer DEFAULT 2)
    RETURNS integer
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = ad_intel, pg_temp
    SET TimeZone = 'UTC'
    AS $$
-- Creates every registered table's partitions for the current month and the
-- next p_months_ahead months (0..24). Returns how many were created.
-- [v49] Months are UTC months, whatever the caller's TimeZone.
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

CREATE OR REPLACE FUNCTION ad_intel.drop_partitions_older_than(p_table text, p_retention_months integer DEFAULT 12)
    RETURNS text[]
    LANGUAGE plpgsql
    SECURITY DEFINER
    SET search_path = ad_intel, pg_temp
    SET TimeZone = 'UTC'
    AS $_$
-- Drops monthly partitions of p_table older than p_retention_months that hold
-- NO rows. A partition still holding any row -- in particular a current
-- (open) row of something unchanged since that month -- is kept: dropping it
-- would delete live state. Closed rows are removed by purge_closed_history(),
-- after which old partitions empty out and are dropped here. Returns the
-- names of the partitions dropped. [v49] The cutoff month is a UTC month.
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

CREATE OR REPLACE FUNCTION ad_intel.missing_current_partitions()
    RETURNS text[]
    LANGUAGE sql
    STABLE
    SET search_path = ad_intel, pg_temp
    SET TimeZone = 'UTC'
    AS $$
-- Registered tables with no partition for the current month: a collection run
-- would fail on them. [v49] The current UTC month, as the partitions are made.
    SELECT COALESCE(array_agg(r.table_name ORDER BY r.table_name), '{}')
    FROM ad_intel.partitioned_table_registry r
    WHERE to_regclass(format('ad_intel.%I', r.table_name || '_' || to_char(now(), 'YYYY_MM'))) IS NULL;
$$;

CREATE OR REPLACE VIEW ad_intel.v_effective_group_membership AS
 WITH RECURSIVE membership_closure AS (
         SELECT group_member_edge.group_guid,
            group_member_edge.member_guid,
            group_member_edge.client_id,
            ARRAY[group_member_edge.group_guid] AS path,
            1 AS depth,
            (group_member_edge.member_guid = group_member_edge.group_guid) AS is_direct
           FROM ad_intel.group_member_edge
          WHERE (group_member_edge.valid_to IS NULL)
        UNION ALL
         SELECT mc.group_guid,
            gme.member_guid,
            mc.client_id,
            (mc.path || gme.group_guid),
            (mc.depth + 1),
            false AS is_direct
           FROM (membership_closure mc
             JOIN ad_intel.group_member_edge gme ON (((gme.group_guid = mc.member_guid) AND (gme.valid_to IS NULL) AND (gme.client_id = mc.client_id))))
          WHERE ((NOT (gme.group_guid = ANY (mc.path))) AND (mc.depth < 20))
        )
 SELECT DISTINCT group_guid,
    member_guid,
    client_id,
    min(depth) AS min_depth,
    bool_or((depth = 1)) AS is_direct
   FROM membership_closure
  WHERE (member_guid <> group_guid)
  GROUP BY group_guid, member_guid, client_id;

COMMENT ON VIEW ad_intel.v_effective_group_membership IS 'Transitive closure over group_member_edge -- "is member_guid a member of group_guid, directly or through any chain of nested groups". min_depth=1 means direct membership. A group is never listed as a member of itself, even when nesting forms a cycle (schema v49). Recomputed on every query (not materialized); for a large, deeply-nested directory this may be worth converting to a materialized view refreshed after each collection run if query latency becomes a concern.';

ALTER TABLE ad_intel.entra_change_baseline
    ADD COLUMN IF NOT EXISTS previous_run_at timestamptz;
COMMENT ON COLUMN ad_intel.entra_change_baseline.previous_run_at IS
    'last_run_at before the latest update: the previous successful history update of this entity '
    'type (NULL until two updates by entra_graph_collector.py 1.0.4+). (schema v49)';

-- Partitions of months after the current (UTC) one are normally empty: drop
-- the empty ones and make them again with the functions above, so a gap or
-- overlap left by pre-v49 runs in different time zones is gone before a run
-- reaches it. Partitions holding rows are left as they are.
DO $$
DECLARE
    r       RECORD;
    v_empty BOOLEAN;
BEGIN
    FOR r IN
        SELECT c.relname
        FROM pg_inherits i
        JOIN pg_class c      ON c.oid = i.inhrelid
        JOIN pg_class parent ON parent.oid = i.inhparent
        JOIN pg_namespace n  ON n.oid = parent.relnamespace AND n.nspname = 'ad_intel'
        WHERE parent.relname IN (SELECT table_name FROM ad_intel.partitioned_table_registry)
          AND c.relname ~ '_\d{4}_\d{2}$'
          AND to_date(right(c.relname, 7), 'YYYY_MM') > date_trunc('month', now() AT TIME ZONE 'UTC')
        ORDER BY c.relname
    LOOP
        EXECUTE format('SELECT NOT EXISTS (SELECT 1 FROM ad_intel.%I)', r.relname) INTO v_empty;
        IF v_empty THEN
            EXECUTE format('DROP TABLE ad_intel.%I', r.relname);
        END IF;
    END LOOP;
    PERFORM ad_intel.ensure_partitions_for_horizon(2);
END;
$$;

INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (49, 'Partition functions in UTC (aligned to existing neighbours); no group self-membership in '
            'v_effective_group_membership; entra_change_baseline.previous_run_at')
ON CONFLICT (version_number) DO NOTHING;

COMMIT;
