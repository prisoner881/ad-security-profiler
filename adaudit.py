#!/usr/bin/env python3
"""
adaudit.py -- AD Security & Compliance Plugin Runner
======================================================
VERSION: 0.7.0

Companion to adprofiler.py. Where adprofiler.py collects AD data,
adaudit.py analyzes it: discovers every plugin file in plugins/, runs each
against the most recent successful collection, and reports PASS/WARN/FAIL
findings.

DESIGN:
    - A "plugin" is a standalone .py file in plugins/, containing one
      PLUGIN dict: metadata (plugin_id, category, name, ...) plus the
      actual SQL check as a string. This is data, not a scripting
      language -- no plugin file contains control flow or logic beyond
      the dict literal itself.
    - The plugins/ directory IS the plugin registry. Adding a plugin
      means adding a file; nothing else needs to change, and no database
      row needs to be hand-written. The runner syncs control_catalog/
      control_test from the discovered files automatically, every run --
      those tables are a queryable reflection of the files, not a
      separately-maintained source of truth.
    - Every plugin's query returns zero or more rows, each shaped exactly
      as: (status, object_guid, stig_severity, stig_reference,
      tool_severity, tool_reference, fd_severity, summary, detail).
      Zero rows returned = clean pass, nothing to report.
    - [v0.7.0] A second, parallel plugin type: "inventory" plugins
      (PLUGIN["plugin_type"] = "inventory"; absence of this key means
      "finding", so every plugin written before this existed is
      unaffected). An inventory plugin reports information, not a
      finding -- a snapshot listing (every user, every computer, every
      non-empty group), not a pass/fail check. Accordingly:
        * No base_severity, no remediation, no framework_tags-as-
          citation, no references, no per-row status/severity/detail
          contract -- REQUIRED_INVENTORY_PLUGIN_KEYS is a smaller set
          than REQUIRED_PLUGIN_KEYS, and each inventory plugin's query
          returns whatever columns make sense for that listing (a user
          inventory and a group inventory share no columns at all).
        * No persistence: inventory plugins never touch control_catalog,
          control_test, or control_evidence_fact. They run fresh every
          invocation and print the current snapshot -- no history, no
          change tracking, by design.
        * Rendered by print_inventory_report(), a plain key=value
          listing -- deliberately not styled like a finding's [FAIL]/
          [WARN] output, since there's no status to display.
    - [v0.6.0] A plugin's PLUGIN dict may also carry a "references" key:
      a list of {"title": ..., "url": ...} dicts pointing to external
      guidance (vendor docs, MITRE ATT&CK, DISA STIG text, established
      tool documentation) for that finding. Unlike "detail" (which is
      per-row, data-driven, and comes from the query), references are
      static per-plugin metadata -- the same list applies to every
      instance of that finding regardless of which object triggered it
      -- so they live on the plugin dict itself, not the SQL contract.
      Optional; omit or leave empty if no good source exists rather than
      including a weak one.
    - detail ("Evidence" in console output and the eventual API payload)
      and references are only shown for actual FAIL/WARN findings -- a
      clean PASS result has no triggering data point or remediation
      guidance to show.
    - Three independent, non-blended severity ratings per finding:
        stig_severity  -- DISA AD STIG CAT rating, if directly applicable.
                           NULL means no matching STIG rule exists, not
                           "not checked".
        tool_severity  -- rating from a comparable established AD tool
                           (e.g. PingCastle), if one exists. NULL if none.
        fd_severity    -- this project's own rating. ALWAYS populated.
                           May be tier-escalated (never reduced) via a
                           LEFT JOIN against object_classification in the
                           plugin's own query; the summary text should
                           reflect why when that happens (e.g. a
                           "Tier-0 " prefix).
    - Plugin queries may reference %(client_id)s / %(run_id)s as bound
      parameters -- always passed through psycopg2 parameter binding,
      never string-interpolated, even though plugin authors are trusted.
    - One broken plugin (bad SQL, malformed PLUGIN dict, etc.) must not
      abort the whole run. Each plugin's query executes inside its own
      SAVEPOINT; a failure rolls back just that plugin and the run
      continues. A malformed PLUGIN dict is caught at load time, before
      any database work, for the same reason.

USAGE:
    python3 adaudit.py                          # run every plugin
    python3 adaudit.py --plugin-id 1001 1002     # run only these plugins
    python3 adaudit.py --category "User Accounts"  # run only this category
    python3 adaudit.py --plugins-dir ./plugins   # override plugin location
"""

import sys
import argparse
import importlib.util
from pathlib import Path
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

VERSION = "0.7.1"

PG_HOST = "192.168.1.125"
PG_PORT = 5432
PG_DBNAME = "adprofiler"
PG_USER = "postgres"
PG_PASSWORD = "Project2501"

DEFAULT_PLUGINS_DIR = Path(__file__).parent / "plugins"

SEVERITY_VALUES = {"info", "low", "medium", "high", "critical"}
STATUS_ORDER = {"fail": 2, "warn": 1, "pass": 0}

REQUIRED_PLUGIN_KEYS = {"plugin_id", "category", "name", "base_severity", "query",
                         "version", "revision_date", "remediation"}
REQUIRED_ROW_KEYS = {
    "status", "object_guid", "stig_severity", "stig_reference",
    "tool_severity", "tool_reference", "fd_severity", "summary", "detail",
}

# [v0.7.0] Inventory plugins are a second, parallel plugin type: they
# report information (a snapshot listing), not findings. No severity, no
# remediation, no pass/fail status, no evidence persistence, and no
# change tracking across runs -- deliberately simpler, since none of the
# finding-plugin machinery (control_catalog/control_test/
# control_evidence_fact) applies to "here's the current list of X."
# Existing finding plugins are entirely unaffected: they have no
# "plugin_type" key at all, and discover_plugins() treats that absence
# as the "finding" default, so nothing about them needed to change.
REQUIRED_INVENTORY_PLUGIN_KEYS = {"plugin_id", "plugin_type", "category", "name",
                                   "query", "version", "revision_date", "description"}


def log(msg):
    ts = datetime.now().strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")


# ============================================================================
# Plugin discovery
# ============================================================================

def discover_plugins(plugins_dir):
    """Imports every plugins/*.py file, validates its PLUGIN dict, and
    returns a sorted list of plugin dicts (each annotated with its source
    file path for error reporting). A malformed plugin is skipped with a
    clear error rather than crashing discovery for every other plugin --
    same isolation philosophy as query-execution failures, just applied
    one step earlier."""
    plugins = []
    seen_ids = {}

    if not plugins_dir.is_dir():
        raise RuntimeError(f"Plugins directory not found: {plugins_dir}")

    for path in sorted(plugins_dir.glob("*.py")):
        if path.name.startswith("_"):
            continue  # allow underscore-prefixed helper files to coexist, unloaded
        try:
            spec = importlib.util.spec_from_file_location(path.stem, path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception as exc:
            log(f"  [ERROR] failed to load {path.name}: {exc}")
            continue

        plugin = getattr(module, "PLUGIN", None)
        if plugin is None:
            log(f"  [ERROR] {path.name} has no PLUGIN dict -- skipped")
            continue

        # Absence of "plugin_type" means "finding" -- every plugin written
        # before this key existed is unaffected by its introduction.
        plugin_type = plugin.get("plugin_type", "finding")
        if plugin_type not in ("finding", "inventory"):
            log(f"  [ERROR] {path.name}: plugin_type '{plugin_type}' is not "
                f"'finding' or 'inventory' -- skipped")
            continue

        required_keys = REQUIRED_INVENTORY_PLUGIN_KEYS if plugin_type == "inventory" else REQUIRED_PLUGIN_KEYS
        missing = required_keys - set(plugin.keys())
        if missing:
            log(f"  [ERROR] {path.name}: PLUGIN dict missing required key(s): "
                f"{', '.join(sorted(missing))} -- skipped")
            continue

        if plugin_type == "finding" and plugin["base_severity"] not in SEVERITY_VALUES:
            log(f"  [ERROR] {path.name}: base_severity '{plugin['base_severity']}' "
                f"is not one of {sorted(SEVERITY_VALUES)} -- skipped")
            continue

        try:
            datetime.strptime(str(plugin["revision_date"]), "%Y-%m-%d")
        except ValueError:
            log(f"  [ERROR] {path.name}: revision_date '{plugin['revision_date']}' "
                f"is not in YYYY-MM-DD format -- skipped")
            continue

        pid = plugin["plugin_id"]
        if pid in seen_ids:
            log(f"  [ERROR] {path.name}: plugin_id {pid} already used by "
                f"{seen_ids[pid]} -- skipped")
            continue
        seen_ids[pid] = path.name

        plugin = dict(plugin)  # copy, don't mutate the module's own dict
        plugin["plugin_type"] = plugin_type
        plugin.setdefault("control_id", None)
        plugin.setdefault("framework_tags", [])
        plugin.setdefault("description", plugin["name"])
        plugin["_source_file"] = path.name
        plugins.append(plugin)

    return sorted(plugins, key=lambda p: p["plugin_id"])


# ============================================================================
# Registry sync -- plugins/ files are authoritative; control_catalog and
# control_test are kept as a queryable, always-current reflection of them.
# ============================================================================

def sync_plugin_registry(pg_cur, plugin):
    control_id = plugin["control_id"] or f"PLUGIN-{plugin['plugin_id']}"

    pg_cur.execute("""
        INSERT INTO control_catalog (control_id, framework_tags, title, description, severity, remediation)
        VALUES (%(control_id)s, %(framework_tags)s, %(title)s, %(description)s, %(severity)s, %(remediation)s)
        ON CONFLICT (control_id) DO UPDATE SET
            framework_tags = EXCLUDED.framework_tags,
            title = EXCLUDED.title,
            description = EXCLUDED.description,
            severity = EXCLUDED.severity,
            remediation = EXCLUDED.remediation;
    """, {
        "control_id": control_id, "framework_tags": plugin["framework_tags"],
        "title": plugin["name"], "description": plugin["description"],
        "severity": plugin["base_severity"], "remediation": plugin["remediation"],
    })

    pg_cur.execute("""
        INSERT INTO control_test (control_id, plugin_id, category, test_name, query_definition,
                                   plugin_version, revision_date, is_active)
        VALUES (%(control_id)s, %(plugin_id)s, %(category)s, %(name)s, %(query)s,
                %(version)s, %(revision_date)s, TRUE)
        ON CONFLICT (plugin_id) DO UPDATE SET
            control_id = EXCLUDED.control_id,
            category = EXCLUDED.category,
            test_name = EXCLUDED.test_name,
            query_definition = EXCLUDED.query_definition,
            plugin_version = EXCLUDED.plugin_version,
            revision_date = EXCLUDED.revision_date,
            is_active = TRUE
        RETURNING control_test_id;
    """, {
        "control_id": control_id, "plugin_id": plugin["plugin_id"],
        "category": plugin["category"], "name": plugin["name"], "query": plugin["query"],
        "version": plugin["version"], "revision_date": plugin["revision_date"],
    })
    return pg_cur.fetchone()[0]


# ============================================================================
# Postgres
# ============================================================================

def connect_postgres():
    conn = psycopg2.connect(
        host=PG_HOST, port=PG_PORT, dbname=PG_DBNAME,
        user=PG_USER, password=PG_PASSWORD,
    )
    conn.autocommit = False
    with conn.cursor() as cur:
        cur.execute("SET search_path TO ad_intel, public;")
    conn.commit()
    return conn


def get_latest_client_and_run(conn):
    """Single-client assumption for now, matching adprofiler.py's own
    current scope -- picks the most recently collected client and its
    latest successful sync_run. A --client-id flag can be added later
    if/when multi-client support is needed."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT sr.client_id, sr.run_id, c.client_name, sr.completed_at
            FROM sync_run sr
            JOIN client c ON c.client_id = sr.client_id
            WHERE sr.status = 'succeeded'
            ORDER BY sr.completed_at DESC
            LIMIT 1;
        """)
        row = cur.fetchone()
    if row is None:
        raise RuntimeError("No successful sync_run found -- run adprofiler.py first.")
    return row


def run_plugin_query(conn, plugin, client_id, run_id):
    """Executes one plugin's query inside its own SAVEPOINT, so a broken
    plugin can't poison the rest of the evidence run's transaction."""
    savepoint = f"plugin_{plugin['plugin_id']}"
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(f"SAVEPOINT {savepoint};")
        try:
            cur.execute(plugin["query"], {"client_id": client_id, "run_id": run_id})
            rows = cur.fetchall()
        except Exception as exc:
            cur.execute(f"ROLLBACK TO SAVEPOINT {savepoint};")
            log(f"  [ERROR] plugin {plugin['plugin_id']} ({plugin['name']}) "
                f"failed to execute: {exc}")
            return None
        cur.execute(f"RELEASE SAVEPOINT {savepoint};")

    for row in rows:
        row_keys = set(row.keys())
        missing = REQUIRED_ROW_KEYS - row_keys
        extra = row_keys - REQUIRED_ROW_KEYS
        if missing or extra:
            problems = []
            if missing:
                problems.append(f"missing {', '.join(sorted(missing))}")
            if extra:
                problems.append(f"unexpected extra column(s) {', '.join(sorted(extra))}")
            log(f"  [ERROR] plugin {plugin['plugin_id']} ({plugin['name']}) returned a row with "
                f"{'; '.join(problems)} -- skipping plugin. Extra columns are rejected, not just "
                f"missing ones: anything outside the 9-column contract (e.g. a raw timestamp/UUID "
                f"placed outside detail) would otherwise pass silently today and only break once "
                f"this data is serialized to JSON for external consumption.")
            return None

    return rows


def run_inventory_query(conn, plugin, client_id, run_id):
    """Same SAVEPOINT-isolation philosophy as run_plugin_query (one broken
    plugin can't poison the rest of the run), but deliberately no
    REQUIRED_ROW_KEYS validation: unlike finding plugins, which all share
    one fixed 9-column contract so they can be processed generically,
    each inventory plugin legitimately returns its own different set of
    columns (a user listing and a group listing have nothing in common
    schema-wise), so there's no single shape to validate against here."""
    savepoint = f"inv_plugin_{plugin['plugin_id']}"
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(f"SAVEPOINT {savepoint};")
        try:
            cur.execute(plugin["query"], {"client_id": client_id, "run_id": run_id})
            rows = cur.fetchall()
        except Exception as exc:
            cur.execute(f"ROLLBACK TO SAVEPOINT {savepoint};")
            log(f"  [ERROR] inventory plugin {plugin['plugin_id']} ({plugin['name']}) "
                f"failed to execute: {exc}")
            return None
        cur.execute(f"RELEASE SAVEPOINT {savepoint};")
    return rows


def get_open_evidence_map(pg_cur, control_test_id, client_id):
    """Currently-open finding versions for this plugin, keyed by
    identity_guid, so this run's results can be diffed against them."""
    pg_cur.execute("""
        SELECT evidence_fact_id, identity_guid, version_id, status,
               stig_severity, stig_reference, tool_severity, tool_reference,
               fd_severity, summary, detail
        FROM control_evidence_fact
        WHERE control_test_id = %(control_test_id)s AND client_id = %(client_id)s
          AND valid_to IS NULL;
    """, {"control_test_id": control_test_id, "client_id": client_id})
    return {row["identity_guid"]: row for row in pg_cur.fetchall()}


def close_evidence_version(pg_cur, evidence_fact_id, valid_to, evidence_run_id_valid_to, change_status):
    pg_cur.execute("""
        UPDATE control_evidence_fact
        SET valid_to = %(valid_to)s, evidence_run_id_valid_to = %(evidence_run_id_valid_to)s,
            change_status = %(change_status)s
        WHERE evidence_fact_id = %(evidence_fact_id)s;
    """, {
        "valid_to": valid_to, "evidence_run_id_valid_to": evidence_run_id_valid_to,
        "evidence_fact_id": evidence_fact_id, "change_status": change_status,
    })


def insert_evidence_version(pg_cur, evidence_run_id, control_test_id, client_id, row,
                             plugin, valid_from, version_id, change_status):
    pg_cur.execute("""
        INSERT INTO control_evidence_fact
            (evidence_run_id, control_test_id, client_id, object_guid,
             status, stig_severity, stig_reference, tool_severity,
             tool_reference, fd_severity, summary, detail,
             plugin_version, plugin_revision_date,
             version_id, valid_from, evidence_run_id_valid_from, change_status)
        VALUES (%(evidence_run_id)s, %(control_test_id)s, %(client_id)s, %(object_guid)s,
                %(status)s, %(stig_severity)s, %(stig_reference)s, %(tool_severity)s,
                %(tool_reference)s, %(fd_severity)s, %(summary)s, %(detail)s,
                %(plugin_version)s, %(plugin_revision_date)s,
                %(version_id)s, %(valid_from)s, %(evidence_run_id)s, %(change_status)s);
    """, {
        "evidence_run_id": evidence_run_id, "control_test_id": control_test_id,
        "client_id": client_id, "object_guid": row["object_guid"],
        "status": row["status"], "stig_severity": row["stig_severity"],
        "stig_reference": row["stig_reference"], "tool_severity": row["tool_severity"],
        "tool_reference": row["tool_reference"], "fd_severity": row["fd_severity"],
        "plugin_version": plugin["version"], "plugin_revision_date": plugin["revision_date"],
        "summary": row["summary"],
        "detail": psycopg2.extras.Json(row["detail"]) if row["detail"] is not None else None,
        "version_id": version_id, "valid_from": valid_from, "change_status": change_status,
    })


def sync_evidence(pg_cur, evidence_run_id, control_test_id, client_id, rows, plugin, run_timestamp):
    """
    SCD2-versions control_evidence_fact for one plugin's results against
    whatever was already open for it -- the same diff-only reconciliation
    every other table in this schema already uses (compare with
    sync_edges()/write_object_version() in adprofiler.py). A finding
    identity (control_test_id, client_id, identity_guid) with no prior
    open version is 'new'. One that already existed but whose content
    differs is 'changed' -- the old version is closed and a new one
    opened. One that already existed, still does, and is unchanged is
    left completely untouched (no new row -- this is the diff-only
    property that keeps the table from growing every single run
    regardless of whether anything actually changed). Anything that WAS
    open but doesn't appear in this run's results at all is closed with
    change_status='remediated' -- deliberately not distinguishing *why*
    it disappeared (object deleted, setting fixed, or anything else);
    per design discussion, disappearing is remediation, full stop.

    Returns a flat list of fully self-contained finding dicts -- each one
    carries its own plugin_id/plugin_version/category/name alongside its
    own status/change_status/severities/summary, rather than that
    identity being inherited from a parent grouping. This is deliberate:
    a plugin run is commonly a MIX of new/changed/unchanged/remediated
    findings, not a single uniform state, so every individual finding
    needs to be independently taggable -- and this is also exactly the
    shape a future per-finding API push needs, so the console report and
    that future consumer can share one data structure rather than two.
    """
    open_evidence = get_open_evidence_map(pg_cur, control_test_id, client_id)
    seen_identity_guids = set()
    findings = []

    def finding_dict(row_like, change_status):
        return {
            "plugin_id": plugin["plugin_id"], "plugin_version": plugin["version"],
            "category": plugin["category"], "name": plugin["name"],
            "status": row_like["status"], "change_status": change_status,
            "stig_severity": row_like["stig_severity"], "stig_reference": row_like.get("stig_reference"),
            "tool_severity": row_like["tool_severity"], "tool_reference": row_like.get("tool_reference"),
            "fd_severity": row_like["fd_severity"], "summary": row_like["summary"],
            "detail": row_like.get("detail"),
            "references": plugin.get("references"),
        }

    for row in rows:
        # [v0.7.1 fix] Previously: identity_guid = row["object_guid"] or
        # "00000000-0000-0000-0000-000000000000" -- a fixed sentinel for
        # every object-less finding regardless of which one it actually
        # was. Broke in production the moment a plugin (10002, cloud-only
        # Global Administrator) produced MORE THAN ONE object-less
        # finding in the same run: both collapsed onto the same
        # sentinel identity, and the second INSERT hit
        # idx_cef_one_open_version's uniqueness constraint directly.
        # Fixed by computing identity_guid via the exact same SQL
        # function the generated column itself uses
        # (compute_finding_identity_guid(), schema_migration_v26) --
        # not reimplemented in Python, deliberately, since Python's
        # json.dumps() and PostgreSQL's jsonb::text cast are not
        # guaranteed to produce identical byte sequences for the same
        # logical content, which would have silently broken this
        # comparison in a far harder way to notice than the crash this
        # replaced.
        pg_cur.execute(
            "SELECT compute_finding_identity_guid(%(object_guid)s, %(summary)s, %(detail)s) AS identity_guid;",
            {
                "object_guid": row["object_guid"], "summary": row["summary"],
                "detail": psycopg2.extras.Json(row["detail"]) if row["detail"] is not None else None,
            },
        )
        identity_guid = pg_cur.fetchone()["identity_guid"]
        seen_identity_guids.add(identity_guid)
        existing = open_evidence.get(identity_guid)

        if existing is None:
            insert_evidence_version(pg_cur, evidence_run_id, control_test_id, client_id, row,
                                     plugin, run_timestamp, version_id=1, change_status="new")
            findings.append(finding_dict(row, "new"))
            continue

        content_changed = (
            existing["status"] != row["status"]
            or existing["fd_severity"] != row["fd_severity"]
            or existing["stig_severity"] != row["stig_severity"]
            or existing["tool_severity"] != row["tool_severity"]
            or existing["summary"] != row["summary"]
        )
        if not content_changed:
            findings.append(finding_dict(row, "unchanged"))
            continue

        close_evidence_version(pg_cur, existing["evidence_fact_id"], run_timestamp,
                                evidence_run_id, "changed")
        insert_evidence_version(pg_cur, evidence_run_id, control_test_id, client_id, row,
                                 plugin, run_timestamp, version_id=existing["version_id"] + 1,
                                 change_status="changed")
        findings.append(finding_dict(row, "changed"))

    for identity_guid, existing in open_evidence.items():
        if identity_guid not in seen_identity_guids:
            close_evidence_version(pg_cur, existing["evidence_fact_id"], run_timestamp,
                                    evidence_run_id, "remediated")
            findings.append(finding_dict(existing, "remediated"))

    return findings


def close_stale_plugin_evidence(pg_cur, evidence_run_id, client_id, executed_control_test_ids, run_timestamp):
    """
    Safety net for a plugin that stops running entirely (removed from
    plugins/, or its file becomes unloadable) -- without this, its
    previously-open findings would stay open forever, since nothing ever
    visits them again to notice they should close. Only ever called on a
    full, unfiltered run (see main()) -- a deliberate --plugin-id/
    --category filtered run must NOT be treated as "these other plugins
    no longer exist," since that would incorrectly mass-remediate
    everything just because the user chose to run a subset this time.
    """
    pg_cur.execute("""
        SELECT DISTINCT control_test_id FROM control_evidence_fact
        WHERE client_id = %(client_id)s AND valid_to IS NULL;
    """, {"client_id": client_id})
    open_test_ids = {row["control_test_id"] for row in pg_cur.fetchall()}
    stale_test_ids = open_test_ids - executed_control_test_ids
    closed = 0
    for control_test_id in stale_test_ids:
        pg_cur.execute("""
            UPDATE control_evidence_fact
            SET valid_to = %(valid_to)s, evidence_run_id_valid_to = %(evidence_run_id)s,
                change_status = 'remediated'
            WHERE control_test_id = %(control_test_id)s AND client_id = %(client_id)s
              AND valid_to IS NULL;
        """, {"valid_to": run_timestamp, "evidence_run_id": evidence_run_id,
              "control_test_id": control_test_id, "client_id": client_id})
        closed += pg_cur.rowcount
    return closed, len(stale_test_ids)


def rollup_status(rows):
    if not rows:
        return "pass"
    worst = "pass"
    for row in rows:
        if STATUS_ORDER[row["status"]] > STATUS_ORDER[worst]:
            worst = row["status"]
    return worst


# ============================================================================
# Reporting
# ============================================================================

def print_report(plugin_summaries, all_findings):
    print()
    print("=" * 78)
    print("  AD Security & Compliance Findings")
    print("=" * 78)

    findings_by_plugin = {}
    for f in all_findings:
        findings_by_plugin.setdefault(f["plugin_id"], []).append(f)

    by_category = {}
    for p in plugin_summaries:
        by_category.setdefault(p["category"], []).append(p)

    total_fail = sum(1 for p in plugin_summaries if p["rollup"] == "fail")
    total_warn = sum(1 for p in plugin_summaries if p["rollup"] == "warn")
    total_pass = sum(1 for p in plugin_summaries if p["rollup"] == "pass")
    total_error = sum(1 for p in plugin_summaries if p["rollup"] == "error")
    total_new = sum(1 for f in all_findings if f["change_status"] == "new")
    total_changed = sum(1 for f in all_findings if f["change_status"] == "changed")
    total_remediated = sum(1 for f in all_findings if f["change_status"] == "remediated")

    finding_marker = {"fail": "[FAIL]", "warn": "[WARN]"}
    change_tag = {"new": "[NEW]", "changed": "[CHANGED]", "remediated": "[REMEDIATED]", "unchanged": ""}

    for category in sorted(by_category):
        print()
        print(f"--- {category} " + "-" * max(0, 60 - len(category)))
        plugins_in_cat = sorted(by_category[category],
                                  key=lambda p: (STATUS_ORDER.get(p["rollup"], -1), -p["plugin_id"]),
                                  reverse=True)
        for p in plugins_in_cat:
            header_marker = {"fail": "[FAIL]", "warn": "[WARN]", "pass": "[ OK ]",
                              "error": "[ERR!]"}[p["rollup"]]
            print(f"  {header_marker} #{p['plugin_id']:<5} [v{p['version']}] {p['name']}")

            for f in findings_by_plugin.get(p["plugin_id"], []):
                # Every line is fully self-contained on purpose: its own
                # status, plugin_id, version, change tag, and all three
                # severities -- not inherited from the header above it.
                # This matches exactly what a future per-finding API push
                # would send as one record, so the console rendering and
                # that eventual JSON payload share one underlying shape.
                sev_bits = [f"fd:{f['fd_severity']}"]
                if f["stig_severity"]:
                    sev_bits.append(f"stig:{f['stig_severity']}")
                if f["tool_severity"]:
                    sev_bits.append(f"tool:{f['tool_severity']}")
                status_marker = finding_marker.get(f["status"], f"[{f['status'].upper()}]")
                ctag = change_tag.get(f["change_status"], "")
                ctag_str = f" {ctag}" if ctag else ""
                print(f"         {status_marker} #{f['plugin_id']} [v{f['plugin_version']}]"
                      f"{ctag_str} [{'/'.join(sev_bits)}] {f['summary']}")

                # Evidence/References are only meaningful for an actual
                # FAIL/WARN finding -- a clean ("pass") result has no
                # triggering data point to show, and finding_marker's own
                # key set (fail/warn only) is the same filter already
                # used for the status marker above, so reusing it here
                # keeps this consistent rather than introducing a second
                # definition of "is this an actual finding."
                if f["status"] in finding_marker:
                    if f.get("detail"):
                        evidence_str = ", ".join(f"{k}={v}" for k, v in f["detail"].items())
                        print(f"                Evidence: {evidence_str}")
                    references = f.get("references") or []
                    if references:
                        print("                References:")
                        for ref in references:
                            print(f"                  - {ref['title']} ({ref['url']})")

    print()
    print("=" * 78)
    print(f"  Summary: {total_fail} FAIL, {total_warn} WARN, {total_pass} PASS"
          + (f", {total_error} ERROR" if total_error else ""))
    print(f"  Change tracking: {total_new} new, {total_changed} changed, "
          f"{total_remediated} remediated since last run")
    print("=" * 78)


def print_inventory_report(inventory_results):
    """Deliberately not styled like print_report's [FAIL]/[WARN] finding
    output -- there's no status or severity to a listing. Each row is
    printed as a single line of key=value pairs (matching the visual
    language already used for finding evidence, so the tool doesn't
    introduce a third, unrelated formatting style), column order
    preserved as returned by the query rather than sorted, since a
    plugin's own column order is usually the sensible reading order
    (e.g. name before timestamps before the less essential fields)."""
    print()
    print("=" * 78)
    print("  AD Inventory")
    print("=" * 78)

    for plugin, rows in inventory_results:
        print()
        print(f"--- #{plugin['plugin_id']} {plugin['name']} ({len(rows)} row(s)) "
              + "-" * max(0, 40 - len(plugin["name"])))
        if rows is None:
            print("  [ERROR] query failed -- see log above")
            continue
        if not rows:
            print("  (no rows)")
            continue
        for row in rows:
            parts = []
            for key, value in row.items():
                if isinstance(value, list):
                    value = ", ".join(str(v) for v in value) if value else "(none)"
                parts.append(f"{key}={value}")
            print("  " + " | ".join(parts))

    print()
    print("=" * 78)


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(description="AD Security & Compliance Plugin Runner")
    parser.add_argument("--plugins-dir", type=Path, default=DEFAULT_PLUGINS_DIR,
                         help="Directory to load plugin files from (default: ./plugins)")
    parser.add_argument("--plugin-id", type=int, nargs="+", default=None,
                         help="Run only these plugin IDs")
    parser.add_argument("--category", nargs="+", default=None,
                         help="Run only plugins in these categories")
    parser.add_argument("--version", action="store_true")
    args = parser.parse_args()

    if args.version:
        print(f"adaudit.py v{VERSION}")
        return

    print("=" * 62)
    print(f"  adaudit.py v{VERSION} -- AD Security & Compliance Plugin Runner")
    print("=" * 62)

    log(f"Discovering plugins in {args.plugins_dir}...")
    plugins = discover_plugins(args.plugins_dir)
    log(f"Loaded {len(plugins)} valid plugin(s)")

    if args.plugin_id:
        plugins = [p for p in plugins if p["plugin_id"] in args.plugin_id]
        log(f"Filtered to {len(plugins)} plugin(s) by --plugin-id")
    if args.category:
        wanted = {c.lower() for c in args.category}
        plugins = [p for p in plugins if p["category"].lower() in wanted]
        log(f"Filtered to {len(plugins)} plugin(s) by --category")

    if not plugins:
        log("No plugins to run.")
        return

    finding_plugins = [p for p in plugins if p["plugin_type"] == "finding"]
    inventory_plugins = [p for p in plugins if p["plugin_type"] == "inventory"]

    conn = connect_postgres()
    client_id, run_id, client_name, completed_at = get_latest_client_and_run(conn)
    log(f"Analyzing latest collection for {client_name} (run_id={run_id}, {completed_at})")

    # Single shared timestamp for everything this run writes/closes -- same
    # "one run, one timestamp" principle adprofiler.py itself uses, so every
    # version opened or closed by this invocation is exactly attributable
    # to this run, not subject to within-run timing drift.
    run_timestamp = datetime.now(timezone.utc)
    is_unfiltered_run = not args.plugin_id and not args.category

    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO control_evidence_run (client_id, sync_run_id)
            VALUES (%s, %s) RETURNING evidence_run_id;
        """, (client_id, run_id))
        evidence_run_id = cur.fetchone()[0]
    conn.commit()

    plugin_summaries = []
    all_findings = []
    executed_control_test_ids = set()
    for plugin in finding_plugins:
        with conn.cursor() as cur:
            control_test_id = sync_plugin_registry(cur, plugin)
        conn.commit()
        executed_control_test_ids.add(control_test_id)

        rows = run_plugin_query(conn, plugin, client_id, run_id)
        if rows is None:
            plugin_summaries.append({"plugin_id": plugin["plugin_id"], "category": plugin["category"],
                                      "name": plugin["name"], "version": plugin["version"], "rollup": "error"})
            conn.rollback()
            continue

        # [fix, following a real production crash] This call used to have
        # no failure isolation at all -- a bug in any single plugin's
        # query RESULTS (not the query itself, which run_plugin_query
        # above already isolates) could raise all the way out of
        # sync_evidence, through this loop, out of main(), and crash the
        # entire adaudit run before any of the other 155 plugins got a
        # chance to run. Confirmed happening in practice: a plugin
        # returning multiple result rows that shared the same
        # object_guid collided on identity_guid and hit
        # idx_cef_one_open_version's uniqueness constraint. Wrapped in
        # the same SAVEPOINT pattern run_plugin_query already uses
        # above, for the same reason -- one broken plugin's evidence
        # write can't be allowed to poison the whole run.
        savepoint = f"evidence_{plugin['plugin_id']}"
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(f"SAVEPOINT {savepoint};")
            try:
                findings = sync_evidence(
                    cur, evidence_run_id, control_test_id, client_id, rows, plugin, run_timestamp,
                )
            except Exception as exc:
                cur.execute(f"ROLLBACK TO SAVEPOINT {savepoint};")
                log(f"  [ERROR] plugin {plugin['plugin_id']} ({plugin['name']}) "
                    f"failed while recording evidence: {exc}")
                plugin_summaries.append({"plugin_id": plugin["plugin_id"], "category": plugin["category"],
                                          "name": plugin["name"], "version": plugin["version"], "rollup": "error"})
                conn.commit()
                continue
            cur.execute(f"RELEASE SAVEPOINT {savepoint};")
        conn.commit()
        plugin_summaries.append({"plugin_id": plugin["plugin_id"], "category": plugin["category"],
                                  "name": plugin["name"], "version": plugin["version"],
                                  "rollup": rollup_status(rows)})
        all_findings.extend(findings)

    if is_unfiltered_run:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            closed, stale_plugin_count = close_stale_plugin_evidence(
                cur, evidence_run_id, client_id, executed_control_test_ids, run_timestamp,
            )
        conn.commit()
        if stale_plugin_count:
            log(f"Closed {closed} finding(s) from {stale_plugin_count} plugin(s) no longer present "
                f"(removed from plugins/ or failed to load) as remediated.")
    else:
        log("Filtered run (--plugin-id/--category) -- skipping the stale-plugin safety net, "
            "since plugins not selected this run were deliberately skipped, not removed.")

    if finding_plugins:
        print_report(plugin_summaries, all_findings)

    if inventory_plugins:
        # No control_evidence_run/control_catalog/control_test involvement
        # at all -- inventory plugins run fresh every time with no
        # persistence and no change tracking, per their whole design intent.
        inventory_results = []
        for plugin in inventory_plugins:
            rows = run_inventory_query(conn, plugin, client_id, run_id)
            if rows is None:
                conn.rollback()
            inventory_results.append((plugin, rows))
        print_inventory_report(inventory_results)


if __name__ == "__main__":
    main()
