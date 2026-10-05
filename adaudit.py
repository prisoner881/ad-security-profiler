#!/usr/bin/env python3
"""
adaudit.py -- AD Security & Compliance Plugin Runner
======================================================
VERSION: 0.9.0

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
    - [v0.9.0] Requires schema v39 (SYSVOL / Group Policy content tables and
      views, read by plugins 9008-9023 and 11021). Plugins reading SYSVOL
      data are shown as NOT ASSESSED when SYSVOL was never collected for
      the client (adprofiler.py --sysvol), like Entra plugins without Entra
      data (OPTIONAL_DATA_SOURCES).
    - [v0.8.0] Compliance-framework reporting. Each finding plugin's
      framework_tags (format and allowed IDs: COMPLIANCE_TAGS.md) are
      split by prefix into (framework, control id) via FRAMEWORKS /
      split_framework_tag(). The workbook gains a "Compliance Summary"
      sheet right after Summary (per framework: controls referenced,
      failing, warning, passing, incomplete, plugins mapped) and one
      sheet per framework listing every control -> plugin -> result, and
      the console report ends with a short "Compliance coverage" block.
      All of it is built from the same per-plugin rollups the Summary
      sheet uses -- nothing is re-queried. framework_tags must be a list
      of strings (else a load failure); a tag with an unknown prefix is
      allowed but listed once as a warning after discovery, and left off
      the compliance sheets. --framework restricts a run to plugins
      carrying at least one tag of the named framework(s). A plugin that
      reads Entra tables when no Entra ID collection exists for the client
      (or, since v0.9.0, SYSVOL data when SYSVOL was never collected) is
      shown as NOT ASSESSED on the compliance sheets rather than as
      passing (its zero rows mean "nothing to check"). references must be
      a list of {"title", "url"} dicts (else a load failure): a bare URL
      string passed every clean run and crashed the report the first time
      the plugin fired.
    - [v0.7.4] Retiring a plugin: replace its file with a stub whose
      PLUGIN dict is {"plugin_id", "name", "retired": True,
      "superseded_by": <plugin_id>, "revision_date"}. The stub never
      runs; its open findings are closed with change_status 'retired'
      (schema v35), not 'remediated', since the issue still exists and
      is now reported by the successor. adaudit.py also refuses to run
      against a database older than REQUIRED_SCHEMA_VERSION, naming the
      migration files to apply.
    - [v0.7.2] A plugin file that fails to load (syntax error, bad or
      missing PLUGIN dict, duplicate plugin_id) is reported in one
      consolidated [ERROR] block, both right after discovery and again
      at the end of the run; every other plugin still runs. Its open
      findings are left open rather than closed as 'remediated' by the
      stale-plugin safety net, which previously could not tell "file
      removed" from "file broken" and so made a broken plugin's
      findings look fixed (then reappear as 'new' once repaired).
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
    python3 adaudit.py --framework PCI-DSS-4.0 "SOC 2"  # only plugins tagged for these frameworks
    python3 adaudit.py --plugins-dir ./plugins   # override plugin location
    python3 adaudit.py --fail-on warn            # exit 4 if any open WARN/FAIL finding

EXIT STATUS ([v0.7.3]; always 0 before):
    0   Run completed and every selected plugin ran.
    1   Fatal error: no database connection, no successful collection
        run to analyze, the Excel report couldn't be written, or an
        unexpected error. Results are missing or unusable.
    2   Command-line usage error (argparse's own convention).
    3   Run completed, but INCOMPLETE: at least one plugin failed to
        load, a finding plugin's query or evidence write failed, or an
        inventory query failed. Every other plugin's results are valid
        and recorded; the report lists which ones are missing.
    4   Run completed and complete, and --fail-on was given and at least
        one current (not remediated) finding is at or above that level.
        Without --fail-on, findings never affect the exit status --
        finding problems is a successful audit, not a failed run.
    130 Interrupted (Ctrl-C).
    When both 3 and 4 apply, 3 is returned: an incomplete run can't
    vouch for its findings either way.
"""

import sys
import argparse
import getpass
import importlib.util
import re
from pathlib import Path
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras

VERSION = "0.9.0"

# [test-candidate-branch] Always overwritten by main() from
# --pg-host/--pg-port/--pg-dbname/--pg-user/--pg-password before
# connect_postgres() is ever called -- placeholders, not a real
# client's connection details.
PG_HOST = None
PG_PORT = 5432
PG_DBNAME = "adprofiler"
PG_USER = None
PG_PASSWORD = None

DEFAULT_PLUGINS_DIR = Path(__file__).parent / "plugins"

SEVERITY_VALUES = {"info", "low", "medium", "high", "critical"}
STATUS_ORDER = {"fail": 2, "warn": 1, "pass": 0}

# Exit statuses -- see "EXIT STATUS" in the module docstring.
EXIT_OK = 0
EXIT_FATAL = 1
EXIT_INCOMPLETE = 3
EXIT_FINDINGS = 4
EXIT_INTERRUPTED = 130

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

# [v0.8.0] Compliance frameworks, in report order: (key, display name,
# workbook sheet name, tag prefixes). A tag is "<prefix><control id>" --
# see COMPLIANCE_TAGS.md. CISA-SCUBA- must be listed before the generic
# CISA- advisory prefix, since split_framework_tag() takes the first
# match. The advisory bucket keeps the whole tag as its control id
# ("CVE-2021-42278"), since the bare number means nothing on its own.
FRAMEWORKS = [
    ("NIST-800-53", "NIST SP 800-53 Rev. 5", "NIST 800-53", ("NIST-800-53-",)),
    ("NIST-CSF-2.0", "NIST CSF 2.0", "NIST CSF 2.0", ("NIST-CSF-2.0-",)),
    ("PCI-DSS-4.0", "PCI DSS 4.0", "PCI DSS 4.0", ("PCI-DSS-4.0-",)),
    ("CIS-CSC-8", "CIS Controls v8", "CIS v8", ("CIS-CSC-8-",)),
    ("ISO-27001-2022", "ISO/IEC 27001:2022", "ISO 27001", ("ISO-27001-2022-",)),
    ("SOC2", "SOC 2", "SOC 2", ("SOC2-",)),
    ("HIPAA", "HIPAA Security Rule", "HIPAA", ("HIPAA-",)),
    ("CISA-SCUBA", "CISA SCuBA (Entra ID)", "SCuBA", ("CISA-SCUBA-",)),
    ("DISA-STIG", "DISA STIG", "DISA STIG", ("DISA-STIG",)),
    ("MITRE-ATTCK", "MITRE ATT&CK", "MITRE ATT&CK", ("MITRE-ATTCK-",)),
    ("ADVISORIES", "Advisories & CVEs", "Advisories", ("CVE-", "CISA-")),
]
FRAMEWORK_NAMES = {key: name for key, name, _, _ in FRAMEWORKS}
SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def split_framework_tag(tag):
    """Splits one framework tag into (framework key, control id), or
    (None, tag) when no known prefix matches. DISA-STIG is the one prefix
    without a trailing dash: "DISA-STIG-V-243503" -> "V-243503", and the
    bare "DISA-STIG" (a STIG requirement covers it, no specific rule
    cited) -> "(general)"."""
    for key, _, _, prefixes in FRAMEWORKS:
        for prefix in prefixes:
            if key == "DISA-STIG":
                if tag == prefix:
                    return key, "(general)"
                if tag.startswith(prefix + "-") and len(tag) > len(prefix) + 1:
                    return key, tag[len(prefix) + 1:]
            elif key == "ADVISORIES":
                if tag.startswith(prefix) and len(tag) > len(prefix):
                    return key, tag
            elif tag.startswith(prefix) and len(tag) > len(prefix):
                return key, tag[len(prefix):]
    return None, tag


def natural_sort_key(text):
    """AC-2 < AC-2(3) < AC-10 and 8.2.1 < 8.2.10: digit runs compare as
    numbers, everything else case-insensitively as text."""
    return [(0, int(part), "") if part.isdigit() else (1, 0, part.lower())
            for part in re.findall(r"\d+|\D+", text)]


def resolve_framework(value):
    """Maps a --framework argument (tag prefix with or without its
    trailing dash, display name or sheet name, any case) to a framework
    key; argparse type= callback, so an unknown value is a usage error."""
    wanted = value.strip().lower()
    for key, name, sheet, prefixes in FRAMEWORKS:
        candidates = {key.lower(), name.lower(), sheet.lower()}
        candidates.update(p.lower() for p in prefixes)
        candidates.update(p.lower().rstrip("-") for p in prefixes)
        if wanted in candidates:
            return key
    valid = "; ".join(f"{key} ({name})" for key, name, _, _ in FRAMEWORKS)
    raise argparse.ArgumentTypeError(f"unknown framework '{value}'. Valid: {valid}")


def unknown_framework_tags(plugins):
    """[v0.8.0] {tag: [plugin_id, ...]} for every tag no FRAMEWORKS prefix
    matches -- allowed (it's still copied to control_catalog), but left
    off the compliance sheets, so main() warns about it once."""
    unknown = {}
    for plugin in plugins:
        for tag in plugin.get("framework_tags") or []:
            if split_framework_tag(tag)[0] is None:
                unknown.setdefault(tag, []).append(plugin["plugin_id"])
    return unknown


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
    one step earlier.

    Returns (plugins, load_failures, retired). retired lists the
    retired-plugin stubs ({"plugin_id", "superseded_by", "name"}).
    load_failures is a list of
    {"file", "plugin_id", "reason"} dicts, one per skipped file --
    plugin_id is the PLUGIN dict's own value when it got far enough to
    be read, otherwise the numeric filename prefix (every plugin file is
    named <plugin_id>_<name>.py), otherwise None. main() uses it both to
    report the failures and to keep the stale-plugin safety net from
    closing a broken plugin's open findings as 'remediated'."""
    plugins = []
    seen_ids = {}
    load_failures = []
    retired = []

    def fail(path, reason, plugin=None):
        log(f"  [ERROR] {path.name}: {reason} -- skipped")
        pid = plugin.get("plugin_id") if isinstance(plugin, dict) else None
        if not isinstance(pid, int):
            m = re.match(r"(\d+)_", path.name)
            pid = int(m.group(1)) if m else None
        load_failures.append({"file": path.name, "plugin_id": pid, "reason": reason})

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
            fail(path, f"failed to load: {exc}")
            continue

        plugin = getattr(module, "PLUGIN", None)
        if plugin is None:
            fail(path, "has no PLUGIN dict")
            continue

        # [v0.7.4] A retired plugin is kept as a stub naming its successor
        # (see close_retired_plugin_evidence()); it's never run.
        if plugin.get("retired"):
            pid = plugin.get("plugin_id")
            successor = plugin.get("superseded_by")
            if not isinstance(pid, int) or not isinstance(successor, int):
                fail(path, "retired PLUGIN dict needs integer plugin_id and superseded_by", plugin)
                continue
            if pid in seen_ids:
                fail(path, f"plugin_id {pid} already used by {seen_ids[pid]}", plugin)
                continue
            seen_ids[pid] = path.name
            retired.append({"plugin_id": pid, "superseded_by": successor,
                            "name": plugin.get("name", path.stem), "_source_file": path.name})
            continue

        # Absence of "plugin_type" means "finding" -- every plugin written
        # before this key existed is unaffected by its introduction.
        plugin_type = plugin.get("plugin_type", "finding")
        if plugin_type not in ("finding", "inventory"):
            fail(path, f"plugin_type '{plugin_type}' is not 'finding' or 'inventory'", plugin)
            continue

        required_keys = REQUIRED_INVENTORY_PLUGIN_KEYS if plugin_type == "inventory" else REQUIRED_PLUGIN_KEYS
        missing = required_keys - set(plugin.keys())
        if missing:
            fail(path, f"PLUGIN dict missing required key(s): {', '.join(sorted(missing))}", plugin)
            continue

        if plugin_type == "finding" and plugin["base_severity"] not in SEVERITY_VALUES:
            fail(path, f"base_severity '{plugin['base_severity']}' "
                       f"is not one of {sorted(SEVERITY_VALUES)}", plugin)
            continue

        try:
            datetime.strptime(str(plugin["revision_date"]), "%Y-%m-%d")
        except ValueError:
            fail(path, f"revision_date '{plugin['revision_date']}' is not in YYYY-MM-DD format", plugin)
            continue

        # [v0.8.0] The compliance sheets iterate these; a bare string here
        # would be split into one "tag" per character.
        tags = plugin.get("framework_tags", [])
        if not isinstance(tags, list) or not all(isinstance(t, str) for t in tags):
            fail(path, "framework_tags must be a list of strings", plugin)
            continue

        # [v0.8.0] print_report() and the workbook read ref["title"] /
        # ref["url"] only when a plugin FAILs or WARNs -- a bare URL string
        # here used to pass every clean run and then crash the report the
        # first time the plugin fired.
        refs = plugin.get("references") or []
        if not isinstance(refs, list) or not all(
                isinstance(r, dict) and isinstance(r.get("title"), str)
                and isinstance(r.get("url"), str) for r in refs):
            fail(path, 'references must be a list of {"title": ..., "url": ...} dicts', plugin)
            continue

        pid = plugin["plugin_id"]
        if pid in seen_ids:
            fail(path, f"plugin_id {pid} already used by {seen_ids[pid]}", plugin)
            continue
        seen_ids[pid] = path.name

        plugin = dict(plugin)  # copy, don't mutate the module's own dict
        plugin["plugin_type"] = plugin_type
        plugin.setdefault("control_id", None)
        plugin["framework_tags"] = list(tags)
        plugin.setdefault("description", plugin["name"])
        plugin["_source_file"] = path.name
        plugins.append(plugin)

    return sorted(plugins, key=lambda p: p["plugin_id"]), load_failures, retired


def log_load_failures(load_failures):
    """Logs one consolidated [ERROR] block naming every plugin file that
    failed to load. Called right after discovery and again at the end of
    the run, so the failure isn't lost in scrollback above 180+ plugins'
    worth of output."""
    if not load_failures:
        return
    log(f"[ERROR] {len(load_failures)} plugin file(s) failed to load and were NOT run "
        f"(the rest of the run continues; their previously-open findings are left open, "
        f"not marked remediated):")
    for failure in load_failures:
        pid = failure["plugin_id"] if failure["plugin_id"] is not None else "unknown id"
        log(f"    - {failure['file']} (plugin {pid}): {failure['reason']}")


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


# [v0.7.4] Lowest schema version this adaudit.py and its plugins work
# against: v34 added v_privileged_principal and acl_edge.inherit_only
# (used by many plugins), v35 the 'retired' change_status, v36 the RODC /
# primary-group / template columns several plugins read, v37 KeyCredential /
# dSHeuristics / sPNMappings / RBCD-by-SID / Entra eligibility columns, v38
# the columns and tables of the advisory/compliance gap round plugins, v39
# the SYSVOL (Group Policy content) tables and views.
REQUIRED_SCHEMA_VERSION = 39

# [v0.9.0] Data sources a client may not have collected: (table/view names a
# plugin query mentions, probe returning TRUE when the client has the data).
# A plugin that reads one and passes while the data is absent is shown as
# NOT ASSESSED on the compliance sheets.
OPTIONAL_DATA_SOURCES = [
    (("entra_",),
     "SELECT EXISTS (SELECT 1 FROM entra_security_posture WHERE client_id = %(c)s) "
     "    OR EXISTS (SELECT 1 FROM entra_user WHERE client_id = %(c)s);"),
    (("gpo_setting_edge", "gpo_preference_item_edge", "sysvol_script_edge", "ad_gpo_sysvol",
      "v_dc_effective_gpo_setting"),
     "SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol WHERE client_id = %(c)s AND read_status = 'ok');"),
]


def check_schema_version(conn):
    """Fails fast, with the fix, on a database older than this version
    expects -- otherwise every plugin that uses a newer view or column
    errors individually and the run ends 'incomplete' with dozens of
    SQL errors instead of one clear message."""
    with conn.cursor() as cur:
        cur.execute("SELECT to_regclass('ad_intel.schema_migration_history') IS NOT NULL;")
        if not cur.fetchone()[0]:
            raise RuntimeError(
                "Database predates schema version tracking -- apply the "
                "schema_migration_vNN.sql files (v31 onward) to bring it to "
                f"v{REQUIRED_SCHEMA_VERSION}.")
        cur.execute("SELECT max(version_number) FROM schema_migration_history;")
        current = cur.fetchone()[0] or 0
    conn.commit()
    if current < REQUIRED_SCHEMA_VERSION:
        missing = ", ".join(f"schema_migration_v{v}.sql"
                            for v in range(current + 1, REQUIRED_SCHEMA_VERSION + 1))
        raise RuntimeError(
            f"Database schema is v{current}; this adaudit.py needs v{REQUIRED_SCHEMA_VERSION}. "
            f"Apply, in order: {missing} (psql -v ON_ERROR_STOP=1 -f <file>). Never "
            f"re-run schema_init.sql against a database that already has data.")
    return current


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


def close_retired_plugin_evidence(pg_cur, evidence_run_id, client_id, retired, run_timestamp):
    """[v0.7.4] Closes every open finding of each retired plugin with
    change_status 'retired' (schema v35) and marks its control_test
    inactive. A plugin is retired when another plugin now reports the
    same issue; its stub file in plugins/ names the successor. Closing
    those findings as 'remediated' (what the stale-plugin safety net
    would otherwise do once the file stopped running) would claim the
    issue was fixed when it wasn't. Runs on every invocation, filtered
    or not: retirement is declared explicitly, not inferred from a
    plugin's absence. Returns [(retired_plugin, closed_count)]."""
    results = []
    for plugin in retired:
        pg_cur.execute("""
            UPDATE control_evidence_fact cef
            SET valid_to = %(valid_to)s, evidence_run_id_valid_to = %(evidence_run_id)s,
                change_status = 'retired'
            FROM control_test ct
            WHERE ct.control_test_id = cef.control_test_id AND ct.plugin_id = %(plugin_id)s
              AND cef.client_id = %(client_id)s AND cef.valid_to IS NULL;
        """, {"valid_to": run_timestamp, "evidence_run_id": evidence_run_id,
              "plugin_id": plugin["plugin_id"], "client_id": client_id})
        closed = pg_cur.rowcount
        pg_cur.execute("UPDATE control_test SET is_active = FALSE WHERE plugin_id = %s AND is_active;",
                       (plugin["plugin_id"],))
        results.append((plugin, closed))
    return results


def close_stale_plugin_evidence(pg_cur, evidence_run_id, client_id, executed_control_test_ids, run_timestamp,
                                load_failed_plugin_ids=frozenset()):
    """
    Safety net for a plugin that stops running entirely (removed from
    plugins/, or its file becomes unloadable) -- without this, its
    previously-open findings would stay open forever, since nothing ever
    visits them again to notice they should close. Only ever called on a
    full, unfiltered run (see main()) -- a deliberate --plugin-id/
    --category filtered run must NOT be treated as "these other plugins
    no longer exist," since that would incorrectly mass-remediate
    everything just because the user chose to run a subset this time.

    A plugin whose file is still present but failed to load this run
    (load_failed_plugin_ids) is NOT treated as removed: a syntax error or
    bad PLUGIN dict says nothing about whether its findings were fixed,
    and closing them as 'remediated' would silently drop real findings
    from the report until the file was repaired (at which point they'd
    all reappear as 'new'). Those findings are left open, untouched.
    """
    pg_cur.execute("""
        SELECT DISTINCT cef.control_test_id, ct.plugin_id
        FROM control_evidence_fact cef
        LEFT JOIN control_test ct ON ct.control_test_id = cef.control_test_id
        WHERE cef.client_id = %(client_id)s AND cef.valid_to IS NULL;
    """, {"client_id": client_id})
    stale_test_ids = {
        row["control_test_id"] for row in pg_cur.fetchall()
        if row["control_test_id"] not in executed_control_test_ids
        and row["plugin_id"] not in load_failed_plugin_ids
    }
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


def build_compliance(plugin_summaries, all_findings, not_assessed_plugin_ids=()):
    """[v0.8.0] Regroups the per-plugin results print_report() and the
    Summary sheet already use by framework and control -- nothing is
    re-queried. plugin_summaries only ever holds finding plugins that
    were selected and loaded this run, so inventory and retired plugins
    are excluded by construction.

    Returns {framework key: {"rows": [...], "summary": {...}}} for every
    framework in FRAMEWORKS order. Each row is one (control, plugin)
    pair with that plugin's rollup and its open (not remediated) FAIL/
    WARN counts and highest open fd_severity. A control's summary state
    is the worst of its plugins' results: failing > warning > incomplete
    (a plugin errored, nothing worse seen) > passing, so the four counts
    add up to controls_referenced.

    not_assessed_plugin_ids: plugins whose source data was never collected
    for this client (today: every plugin reading Entra tables when no Entra
    ID collection exists). Their zero-row "pass" means "nothing to check",
    not compliance, so it is recorded as 'not_assessed' -- the lowest
    state: a control another plugin actually passed stays passing."""
    not_assessed_plugin_ids = set(not_assessed_plugin_ids)
    open_by_plugin = {}
    for f in all_findings:
        if f["change_status"] == "remediated" or f["status"] not in ("fail", "warn"):
            continue
        entry = open_by_plugin.setdefault(f["plugin_id"], {"fail": 0, "warn": 0, "severity": None})
        entry[f["status"]] += 1
        sev = f.get("fd_severity")
        if sev in SEVERITY_ORDER and (entry["severity"] is None
                                      or SEVERITY_ORDER[sev] > SEVERITY_ORDER[entry["severity"]]):
            entry["severity"] = sev

    result = {key: {"rows": [], "summary": None} for key, _, _, _ in FRAMEWORKS}
    plugins_mapped = {key: set() for key, _, _, _ in FRAMEWORKS}
    for p in plugin_summaries:
        open_counts = open_by_plugin.get(p["plugin_id"], {"fail": 0, "warn": 0, "severity": None})
        seen = set()
        for tag in p.get("framework_tags") or []:
            key, control = split_framework_tag(tag)
            if key is None or (key, control) in seen:
                continue
            seen.add((key, control))
            plugins_mapped[key].add(p["plugin_id"])
            result[key]["rows"].append({
                "control": control, "plugin_id": p["plugin_id"], "name": p["name"],
                "category": p["category"],
                "result": ("not_assessed" if p["rollup"] == "pass"
                           and p["plugin_id"] in not_assessed_plugin_ids else p["rollup"]),
                "open_fail": open_counts["fail"], "open_warn": open_counts["warn"],
                "severity": open_counts["severity"],
            })

    for key, data in result.items():
        data["rows"].sort(key=lambda r: (natural_sort_key(r["control"]), r["plugin_id"]))
        by_control = {}
        for row in data["rows"]:
            by_control.setdefault(row["control"], set()).add(row["result"])
        counts = {"fail": 0, "warn": 0, "error": 0, "pass": 0, "not_assessed": 0}
        for results in by_control.values():
            state = next((s for s in ("fail", "warn", "error", "pass") if s in results), "not_assessed")
            counts[state] += 1
        data["summary"] = {
            "controls": len(by_control), "failing": counts["fail"], "warning": counts["warn"],
            "incomplete": counts["error"], "passing": counts["pass"],
            "not_assessed": counts["not_assessed"],
            "plugins": len(plugins_mapped[key]),
        }
    return result


def print_compliance_summary(compliance):
    """[v0.8.0] One line per framework with any tagged plugin this run."""
    lines = []
    for key, name, _, _ in FRAMEWORKS:
        s = compliance[key]["summary"]
        if not s["controls"]:
            continue
        line = (f"  {name}: {s['controls']} controls — {s['failing']} failing, "
                f"{s['warning']} warning, {s['passing']} passing")
        if s["incomplete"]:
            line += f", {s['incomplete']} incomplete (plugin errored)"
        if s["not_assessed"]:
            line += f", {s['not_assessed']} not assessed (source data not collected)"
        lines.append(line)
    if not lines:
        return
    print()
    print("  Compliance coverage (each control rated by its worst plugin result):")
    for line in lines:
        print(line)
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
        # [v0.7.3] len(rows) used to be evaluated before the None check
        # below, so one failed inventory query raised TypeError here and
        # took the Excel report down with it.
        row_count = "query failed" if rows is None else f"{len(rows)} row(s)"
        print(f"--- #{plugin['plugin_id']} {plugin['name']} ({row_count}) "
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


def write_excel_report(plugin_summaries, all_findings, inventory_results, filename, compliance=None):
    """[test-candidate-branch] Excel companion to the console report,
    for a test client + reviewer going through results together --
    easier to filter/sort/skim in a spreadsheet than a scrollback
    buffer or text log.

    Deliberately reuses the exact same data (plugin_summaries,
    all_findings, inventory_results) and the same category/plugin
    grouping print_report() and print_inventory_report() already
    build, rather than re-querying anything -- this is a second
    rendering of data already assembled, not a separate code path
    that could drift from what the console shows.

    Only FAIL/WARN findings are written to each category tab (a PASS
    result has no triggering data point to show, same reasoning
    print_report() itself already uses to skip evidence/references
    for a pass) -- the Summary tab is where full FAIL/WARN/PASS/ERROR
    counts live, so nothing is actually lost, just not repeated
    per-category. Inventory tabs are the one exception: those get
    every row, unfiltered, since there's no status to filter by at all.

    [v0.8.0] Also a "Compliance Summary" tab right after Summary and one
    tab per framework that any plugin run this time is tagged for, built
    by build_compliance() from the same plugin_summaries/all_findings
    (pass its result as compliance to avoid building it twice).
    """
    import openpyxl
    from openpyxl.styles import Font, PatternFill
    from openpyxl.utils import get_column_letter

    wb = openpyxl.Workbook()
    wb.remove(wb.active)

    header_font = Font(bold=True, color="FFFFFF")
    header_fill = PatternFill(start_color="404040", end_color="404040", fill_type="solid")
    fail_fill = PatternFill(start_color="FFC7CE", end_color="FFC7CE", fill_type="solid")
    warn_fill = PatternFill(start_color="FFEB9C", end_color="FFEB9C", fill_type="solid")
    pass_fill = PatternFill(start_color="C6EFCE", end_color="C6EFCE", fill_type="solid")
    error_fill = PatternFill(start_color="D9D9D9", end_color="D9D9D9", fill_type="solid")
    result_fill = {"fail": fail_fill, "warn": warn_fill, "pass": pass_fill, "error": error_fill,
                   "not_assessed": error_fill}
    if compliance is None:
        compliance = build_compliance(plugin_summaries, all_findings)

    used_sheet_names = set()

    def sheet_name(name):
        # Excel forbids \ / ? * [ ] : in sheet names and caps them at
        # 31 characters -- sanitized generically rather than trusting
        # today's category/plugin names to always be safe, since a
        # future plugin could introduce a name that isn't.
        cleaned = re.sub(r'[\\/?*\[\]:]', '', name)[:31]
        candidate = cleaned
        suffix = 2
        while candidate in used_sheet_names:
            candidate = f"{cleaned[:28]}_{suffix}"
            suffix += 1
        used_sheet_names.add(candidate)
        return candidate

    def write_header_row(ws, headers):
        ws.append(headers)
        for col_idx in range(1, len(headers) + 1):
            cell = ws.cell(row=1, column=col_idx)
            cell.font = header_font
            cell.fill = header_fill
        ws.freeze_panes = "A2"

    # --- Summary tab (first, so it's what opens by default) ---
    ws_summary = wb.create_sheet(sheet_name("Summary"))
    by_category = {}
    for p in plugin_summaries:
        by_category.setdefault(p["category"], []).append(p)

    write_header_row(ws_summary, ["Category", "FAIL", "WARN", "PASS", "ERROR", "Total Plugins"])
    grand_fail = grand_warn = grand_pass = grand_error = 0
    for category in sorted(by_category):
        in_cat = by_category[category]
        n_fail = sum(1 for p in in_cat if p["rollup"] == "fail")
        n_warn = sum(1 for p in in_cat if p["rollup"] == "warn")
        n_pass = sum(1 for p in in_cat if p["rollup"] == "pass")
        n_error = sum(1 for p in in_cat if p["rollup"] == "error")
        ws_summary.append([category, n_fail, n_warn, n_pass, n_error, len(in_cat)])
        grand_fail += n_fail
        grand_warn += n_warn
        grand_pass += n_pass
        grand_error += n_error
    ws_summary.append(["TOTAL", grand_fail, grand_warn, grand_pass, grand_error, len(plugin_summaries)])
    for col_idx in range(1, 7):
        ws_summary.cell(row=ws_summary.max_row, column=col_idx).font = Font(bold=True)
    ws_summary.auto_filter.ref = ws_summary.dimensions
    for col_idx, width in enumerate([28, 8, 8, 8, 8, 14], start=1):
        ws_summary.column_dimensions[get_column_letter(col_idx)].width = width

    # --- [v0.8.0] Compliance Summary tab: one row per framework ---
    # Each control counts once, in the column of its worst plugin result
    # (see build_compliance()), so the four state columns add up to
    # "Controls Referenced".
    ws_comp = wb.create_sheet(sheet_name("Compliance Summary"))
    comp_headers = ["Framework", "Controls Referenced", "Controls Failing (any FAIL)",
                    "Controls Warning (WARN, no FAIL)", "Controls Passing (all PASS)",
                    "Controls Incomplete (plugin errored)",
                    "Controls Not Assessed (source data not collected)", "Plugins Mapped"]
    write_header_row(ws_comp, comp_headers)
    for key, name, _, _ in FRAMEWORKS:
        cs = compliance[key]["summary"]
        ws_comp.append([name, cs["controls"], cs["failing"], cs["warning"], cs["passing"],
                        cs["incomplete"], cs["not_assessed"], cs["plugins"]])
    ws_comp.auto_filter.ref = ws_comp.dimensions
    for col_idx, width in enumerate([26, 12, 14, 16, 14, 18, 20, 10], start=1):
        ws_comp.column_dimensions[get_column_letter(col_idx)].width = width

    # --- One tab per category, FAIL/WARN findings only ---
    findings_by_plugin = {}
    for f in all_findings:
        findings_by_plugin.setdefault(f["plugin_id"], []).append(f)

    finding_headers = ["Plugin ID", "Plugin Name", "Version", "Status", "Severity",
                       "Change Status", "Summary", "Evidence", "References"]
    for category in sorted(by_category):
        ws = wb.create_sheet(sheet_name(category))
        write_header_row(ws, finding_headers)

        plugins_in_cat = sorted(by_category[category],
                                  key=lambda p: (STATUS_ORDER.get(p["rollup"], -1), -p["plugin_id"]),
                                  reverse=True)
        for p in plugins_in_cat:
            for f in findings_by_plugin.get(p["plugin_id"], []):
                if f["status"] not in ("fail", "warn"):
                    continue
                sev_bits = [f"fd:{f['fd_severity']}"]
                if f["stig_severity"]:
                    sev_bits.append(f"stig:{f['stig_severity']}")
                if f["tool_severity"]:
                    sev_bits.append(f"tool:{f['tool_severity']}")
                evidence_str = ", ".join(f"{k}={v}" for k, v in (f.get("detail") or {}).items())
                references_str = "; ".join(
                    f"{r['title']} ({r['url']})" for r in (f.get("references") or [])
                )
                ws.append([
                    f["plugin_id"], p["name"], f["plugin_version"], f["status"].upper(),
                    "/".join(sev_bits), f["change_status"], f["summary"],
                    evidence_str, references_str,
                ])
                fill = fail_fill if f["status"] == "fail" else warn_fill
                for col_idx in range(1, len(finding_headers) + 1):
                    ws.cell(row=ws.max_row, column=col_idx).fill = fill

        if ws.max_row == 1:
            ws.append(["(no FAIL/WARN findings in this category this run)"])
        ws.auto_filter.ref = ws.dimensions
        for col_idx, width in enumerate([10, 45, 8, 8, 22, 14, 65, 55, 55], start=1):
            ws.column_dimensions[get_column_letter(col_idx)].width = width

    # --- [v0.8.0] One tab per framework with any tags this run: every
    # (control, plugin) pair, PASS included -- the point is coverage. ---
    framework_headers = ["Control ID", "Plugin ID", "Plugin Name", "Category", "Result",
                         "Open FAIL", "Open WARN", "Highest Open Severity"]
    for key, _, sheet, _ in FRAMEWORKS:
        rows = compliance[key]["rows"]
        if not rows:
            continue
        ws = wb.create_sheet(sheet_name(sheet))
        write_header_row(ws, framework_headers)
        for r in rows:
            ws.append([r["control"], r["plugin_id"], r["name"], r["category"],
                       r["result"].replace("_", " ").upper(),
                       r["open_fail"], r["open_warn"], r["severity"] or ""])
            ws.cell(row=ws.max_row, column=5).fill = result_fill[r["result"]]
        ws.auto_filter.ref = ws.dimensions
        for col_idx, width in enumerate([22, 10, 45, 22, 14, 10, 10, 20], start=1):
            ws.column_dimensions[get_column_letter(col_idx)].width = width

    # --- One tab per inventory plugin, full data, unfiltered ---
    for plugin, rows in inventory_results:
        ws = wb.create_sheet(sheet_name(plugin["name"]))
        if rows is None:
            ws.append(["(query failed -- see console output/log for detail)"])
            continue
        if not rows:
            ws.append(["(no rows)"])
            continue
        headers = list(rows[0].keys())
        write_header_row(ws, headers)
        for row in rows:
            values = []
            for key in headers:
                v = row.get(key)
                if isinstance(v, list):
                    v = ", ".join(str(x) for x in v) if v else "(none)"
                elif isinstance(v, datetime) and v.tzinfo is not None:
                    # openpyxl rejects timezone-aware datetimes outright
                    # ("Excel does not support timezones in datetimes") --
                    # every timestamp in this project is already stored
                    # and displayed in UTC throughout (confirmed by every
                    # console/log timestamp elsewhere in this codebase
                    # using the same convention), so stripping tzinfo
                    # here doesn't change the actual moment in time being
                    # shown, just what Python object represents it -- and
                    # keeps it a real, sortable Excel date/time cell
                    # rather than degrading it to a plain string.
                    v = v.replace(tzinfo=None)
                values.append(v)
            ws.append(values)
        ws.auto_filter.ref = ws.dimensions
        for col_idx in range(1, len(headers) + 1):
            ws.column_dimensions[get_column_letter(col_idx)].width = 25

    wb.save(filename)


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
    parser.add_argument("--framework", type=resolve_framework, nargs="+", default=None,
                         help="Run only finding plugins tagged with at least one control of "
                              "these frameworks, given as tag prefix (e.g. PCI-DSS-4.0), "
                              "display name (e.g. \"SOC 2\") or report sheet name, any case. "
                              "Valid: " + ", ".join(key for key, _, _, _ in FRAMEWORKS))
    parser.add_argument("--fail-on", choices=["fail", "warn"], default=None,
                         help="Exit with status 4 if any current (not remediated) finding "
                              "is at or above this level: 'fail' = FAIL only, 'warn' = WARN "
                              "or FAIL. Default: findings don't affect the exit status.")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--pg-host", default=None,
                         help="PostgreSQL server hostname or IP. Required unless --version is given.")
    parser.add_argument("--pg-port", type=int, default=5432,
                         help="PostgreSQL server port. Default: 5432.")
    parser.add_argument("--pg-dbname", default="adprofiler",
                         help="PostgreSQL database name. Default: adprofiler.")
    parser.add_argument("--pg-user", default=None,
                         help="PostgreSQL username. Required unless --version is given.")
    parser.add_argument("--pg-password", default=None,
                         help="PostgreSQL password. If omitted, you will be prompted "
                              "securely (recommended).")
    args = parser.parse_args()

    if args.version:
        print(f"adaudit.py v{VERSION}")
        return EXIT_OK

    if not args.pg_host or not args.pg_user:
        parser.error("the following arguments are required: --pg-host, --pg-user")

    global PG_HOST, PG_PORT, PG_DBNAME, PG_USER, PG_PASSWORD
    PG_HOST = args.pg_host
    PG_PORT = args.pg_port
    PG_DBNAME = args.pg_dbname
    PG_USER = args.pg_user
    if args.pg_password:
        print("[WARN] PostgreSQL password supplied via --pg-password is visible in "
              "shell history and process listings. Prefer omitting it and entering "
              "it at the secure prompt.")
        PG_PASSWORD = args.pg_password
    else:
        PG_PASSWORD = getpass.getpass(f"PostgreSQL password for {args.pg_user}@{args.pg_host}: ")

    print("=" * 62)
    print(f"  adaudit.py v{VERSION} -- AD Security & Compliance Plugin Runner")
    print("=" * 62)

    log(f"Discovering plugins in {args.plugins_dir}...")
    plugins, load_failures, retired_plugins = discover_plugins(args.plugins_dir)
    log(f"Loaded {len(plugins)} valid plugin(s)"
        + (f", {len(retired_plugins)} retired stub(s)" if retired_plugins else ""))
    log_load_failures(load_failures)
    unknown_tags = unknown_framework_tags(plugins)
    if unknown_tags:
        log(f"[WARN] {len(unknown_tags)} framework tag(s) match no known framework prefix "
            f"(see COMPLIANCE_TAGS.md); they are kept in control_catalog but left off the "
            f"compliance sheets:")
        for tag in sorted(unknown_tags):
            log(f"    - {tag} (plugin(s) {', '.join(str(i) for i in sorted(unknown_tags[tag]))})")

    if args.plugin_id:
        plugins = [p for p in plugins if p["plugin_id"] in args.plugin_id]
        log(f"Filtered to {len(plugins)} plugin(s) by --plugin-id")
    if args.category:
        wanted = {c.lower() for c in args.category}
        plugins = [p for p in plugins if p["category"].lower() in wanted]
        log(f"Filtered to {len(plugins)} plugin(s) by --category")
    if args.framework:
        wanted = set(args.framework)
        plugins = [p for p in plugins
                   if any(split_framework_tag(t)[0] in wanted for t in p["framework_tags"])]
        log(f"Filtered to {len(plugins)} plugin(s) by --framework "
            f"({', '.join(FRAMEWORK_NAMES[k] for k in args.framework)})")

    if not plugins:
        log("No plugins to run.")
        return EXIT_INCOMPLETE if load_failures else EXIT_OK

    finding_plugins = [p for p in plugins if p["plugin_type"] == "finding"]
    inventory_plugins = [p for p in plugins if p["plugin_type"] == "inventory"]

    conn = connect_postgres()
    check_schema_version(conn)
    client_id, run_id, client_name, completed_at = get_latest_client_and_run(conn)
    log(f"Analyzing latest collection for {client_name} (run_id={run_id}, {completed_at})")

    # Single shared timestamp for everything this run writes/closes -- same
    # "one run, one timestamp" principle adprofiler.py itself uses, so every
    # version opened or closed by this invocation is exactly attributable
    # to this run, not subject to within-run timing drift.
    run_timestamp = datetime.now(timezone.utc)
    is_unfiltered_run = not args.plugin_id and not args.category and not args.framework

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
                                      "name": plugin["name"], "version": plugin["version"], "rollup": "error",
                                      "framework_tags": plugin["framework_tags"]})
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
                                          "name": plugin["name"], "version": plugin["version"], "rollup": "error",
                                          "framework_tags": plugin["framework_tags"]})
                conn.commit()
                continue
            cur.execute(f"RELEASE SAVEPOINT {savepoint};")
        conn.commit()
        plugin_summaries.append({"plugin_id": plugin["plugin_id"], "category": plugin["category"],
                                  "name": plugin["name"], "version": plugin["version"],
                                  "rollup": rollup_status(rows),
                                  "framework_tags": plugin["framework_tags"]})
        all_findings.extend(findings)

    if retired_plugins:
        with conn.cursor() as cur:
            retired_results = close_retired_plugin_evidence(
                cur, evidence_run_id, client_id, retired_plugins, run_timestamp,
            )
        conn.commit()
        for plugin, closed in retired_results:
            if closed:
                log(f"Plugin {plugin['plugin_id']} ({plugin['name']}) is retired, superseded by "
                    f"plugin {plugin['superseded_by']}: closed {closed} open finding(s) as 'retired'.")

    load_failed_plugin_ids = {f["plugin_id"] for f in load_failures if f["plugin_id"] is not None}
    if is_unfiltered_run and any(f["plugin_id"] is None for f in load_failures):
        # A broken file we can't attribute to a plugin_id could be any
        # plugin's -- closing anything as remediated would be a guess.
        log("[WARN] A plugin file with no identifiable plugin_id failed to load -- skipping "
            "the stale-plugin safety net this run so none of its findings are wrongly "
            "marked remediated.")
    elif is_unfiltered_run:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            closed, stale_plugin_count = close_stale_plugin_evidence(
                cur, evidence_run_id, client_id, executed_control_test_ids, run_timestamp,
                load_failed_plugin_ids,
            )
        conn.commit()
        if stale_plugin_count:
            log(f"Closed {closed} finding(s) from {stale_plugin_count} plugin(s) no longer present "
                f"in plugins/ as remediated.")
    else:
        log("Filtered run (--plugin-id/--category/--framework) -- skipping the stale-plugin safety net, "
            "since plugins not selected this run were deliberately skipped, not removed.")

    # [v0.8.0] Entra plugins return zero rows ("pass") when there is no
    # Entra data at all; on the compliance sheets that must read as "not
    # assessed", not as SCuBA/MFA controls passing. [v0.9.0] The same for
    # plugins reading SYSVOL (Group Policy content) data when SYSVOL was
    # never collected (adprofiler.py --sysvol).
    not_assessed_ids = set()
    with conn.cursor() as cur:
        for markers, probe in OPTIONAL_DATA_SOURCES:
            cur.execute(probe, {"c": client_id})
            if not cur.fetchone()[0]:
                not_assessed_ids |= {p["plugin_id"] for p in finding_plugins
                                     if any(m in p["query"] for m in markers)}
    conn.commit()
    compliance = build_compliance(plugin_summaries, all_findings,
                                  not_assessed_plugin_ids=not_assessed_ids)
    if finding_plugins:
        print_report(plugin_summaries, all_findings)
        print_compliance_summary(compliance)

    inventory_results = []
    if inventory_plugins:
        # No control_evidence_run/control_catalog/control_test involvement
        # at all -- inventory plugins run fresh every time with no
        # persistence and no change tracking, per their whole design intent.
        for plugin in inventory_plugins:
            rows = run_inventory_query(conn, plugin, client_id, run_id)
            if rows is None:
                conn.rollback()
            inventory_results.append((plugin, rows))
        print_inventory_report(inventory_results)

    # [test-candidate-branch] Excel companion to the console report --
    # see write_excel_report()'s own docstring for why. Generated
    # whenever there's anything at all to put in it (finding or
    # inventory plugins ran), not gated behind finding_plugins alone,
    # since an inventory-only filtered run (--category "User Accounts"
    # matching only 8001, say) should still get a workbook.
    if finding_plugins or inventory_plugins:
        excel_filename = f"adaudit-findings_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
        write_excel_report(plugin_summaries, all_findings, inventory_results, excel_filename,
                           compliance)
        log(f"Wrote Excel findings report to {excel_filename}")

    # Repeated at the very end so it's the last thing on screen, not
    # buried above the full report.
    log_load_failures(load_failures)

    errored_plugins = [s for s in plugin_summaries if s["rollup"] == "error"]
    failed_inventory = [p for p, rows in inventory_results if rows is None]
    if load_failures or errored_plugins or failed_inventory:
        log(f"[ERROR] Run INCOMPLETE: {len(load_failures)} plugin file(s) failed to load, "
            f"{len(errored_plugins)} finding plugin(s) errored, {len(failed_inventory)} "
            f"inventory plugin(s) failed (exit status {EXIT_INCOMPLETE}).")
        for summary in errored_plugins:
            log(f"    - plugin {summary['plugin_id']} ({summary['name']}): errored")
        for plugin in failed_inventory:
            log(f"    - inventory plugin {plugin['plugin_id']} ({plugin['name']}): query failed")
        return EXIT_INCOMPLETE

    if args.fail_on:
        threshold = STATUS_ORDER[args.fail_on]
        over = [f for f in all_findings
                if f["change_status"] != "remediated" and STATUS_ORDER.get(f["status"], 0) >= threshold]
        if over:
            log(f"{len(over)} current finding(s) at or above --fail-on {args.fail_on} "
                f"(exit status {EXIT_FINDINGS}).")
            return EXIT_FINDINGS
    return EXIT_OK


def cli():
    """Entry point: maps main()'s outcome to the exit statuses documented
    in the module docstring. Fatal errors are logged as one clear line
    rather than a traceback for the expected cases (database unreachable,
    nothing collected yet, report file not writable)."""
    try:
        return main()
    except KeyboardInterrupt:
        log("[ERROR] Interrupted (Ctrl-C).")
        return EXIT_INTERRUPTED
    except (psycopg2.Error, RuntimeError, OSError, ImportError) as exc:
        log(f"[ERROR] Fatal: {exc}".rstrip())
        return EXIT_FATAL


if __name__ == "__main__":
    sys.exit(cli())
