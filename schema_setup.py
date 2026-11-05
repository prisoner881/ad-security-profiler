#!/usr/bin/env python3
"""
schema_setup.py -- creates or upgrades the ad_intel database schema, unattended
==============================================================================
VERSION: 1.2

adprofiler.py, entra_graph_collector.py and adaudit.py refuse to run against a
schema other than the one they were built for, and until now the schema could
only be set up by hand: `psql -f schema_init.sql` for a new database, or each
missing `schema_migration_vNN.sql` in order for an existing one. A supervising
process (a scheduler or container daemon) has nobody to do that, so this
script does it:

[1.2] The schema is a frozen baseline plus a chain of migrations:

    schema_init.sql                       the v50 baseline; never edited
    migrations/schema_migration_v51.sql   each later change, one file per
    migrations/schema_migration_v52.sql   version, never edited once
    ...                                   released

The target version is the newest migration (v50 when there is none). The
chain must be complete: v51, v52, ... up to the target, no gap.

    - Empty database (no ad_intel schema): applies the baseline, then every
      migration in order. A fresh install therefore runs exactly the SQL an
      upgraded database ran, so the two cannot differ. PostgreSQL 17 or
      later is required (two functions use MERGE ... RETURNING
      merge_action()).
    - Existing schema: reads its version (max(version_number) in
      ad_intel.schema_migration_history) and applies every migration above
      it, oldest first, up to the target -- however many versions behind it
      is (a client may skip updates: v50 to v55 applies v51-v55 in one run).
    - Already current: does nothing.
    - Older than the baseline (v50): refused; create a new, empty database.

A migration whose header has the line

    -- adprofiler: full-rescan

needs one adprofiler.py run with --full-rescan afterwards, so that objects
unchanged in AD get the new columns. With --rescan-file FILE, applying such
a migration creates FILE; collector_daemon.py then runs the next collection
with --full-rescan and removes the file once that run succeeds -- once, however
many such migrations were applied.

Each file is sent to the server as one batch. A file without its own
BEGIN/COMMIT then runs as one implicit transaction, applied completely or not
at all (psql would stop half-way, as in the v32 incident, where a migration
failed yet recorded itself); a file with its own BEGIN/COMMIT (v33 onward) is
all-or-nothing inside it. After each migration the script checks that the
file recorded its own version, and after a failure it reports the version the
database is actually at.

The psql meta-commands pg_dump writes (\\restrict / \\unrestrict) are the only
lines of schema_init.sql that psycopg2 cannot send; they are left out. Any
other line starting with a backslash stops the script rather than being
guessed at.

Refused, with a message saying what to do by hand:
    - a database whose ad_intel schema has no schema_migration_history table
      (older than v31);
    - a database older than the baseline (create a new, empty database);
    - [1.2] a gap in the migration chain, or a migration file at or below
      the baseline's version (a mixed set of files);
    - a database whose schema is newer than the files shipped here (upgrade
      the scripts instead);
    - an ad_intel schema that exists but is empty or incomplete;

The partition maintenance functions are SECURITY DEFINER: run this as the
role that owns the schema (normally the role the scripts connect as). A
warning is printed when the connecting role is not the owner.

The run lock (run_lock.py) is held while the schema is changed, so no
collection or evaluation runs against a half-upgraded database.

USAGE:
    python3 schema_setup.py --pg-host <host> --pg-user <user> [--pg-dbname adprofiler]
                            [--pg-port 5432] [--check] [--schema-dir DIR] [--log-dir DIR]

    The PostgreSQL password comes from --pg-password, PGPASSWORD, the file
    named by PGPASSWORD_FILE, or a prompt (secret_input.py).
    --check reports what would be done and changes nothing.

EXIT STATUS:
    0   The schema is current (it already was, or was brought up to date).
    1   Failed or refused; the reason is printed. The database is at the last
        version that applied cleanly.
    2   Command-line usage error.
    3   (--check only) The schema needs to be created or upgraded.
    75  Not started: another adprofiler.py, entra_graph_collector.py,
        adaudit.py or schema_setup.py run holds the run lock.
    130 Interrupted (Ctrl-C or SIGTERM).
"""

import argparse
import atexit
import os
import re
import signal
import sys
from datetime import datetime
from pathlib import Path

try:
    import psycopg2
except ImportError:
    print("ERROR: the 'psycopg2' package is not installed (pip install -r requirements.txt).")
    sys.exit(1)

import run_lock
import secret_input

VERSION = "1.2"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_NEEDS_SETUP = 3
EXIT_LOCKED = run_lock.EXIT_LOCKED  # 75
EXIT_INTERRUPTED = 130

# The oldest version with schema_migration_history (v31 creates it and
# backfills v30). An older database cannot be upgraded automatically.
FIRST_TRACKED_VERSION = 31
# [1.2] A migration that needs adprofiler.py --full-rescan afterwards says so
# in its header (see the module docstring).
FULL_RESCAN_MARKER = re.compile(r"^--\s*adprofiler:\s*full-rescan\s*$", re.MULTILINE)
MIGRATIONS_SUBDIR = "migrations"
# pg_dump's psql-only lines, safe to leave out when sending the file.
PSQL_META_ALLOWED = re.compile(r"^\\(restrict|unrestrict)\b")
MIGRATION_NAME = re.compile(r"^schema_migration_v(\d+)\.sql$")
FRESH_INSTALL_VERSION = re.compile(r"\(\s*(\d+)\s*,\s*'Fresh install via schema_init\.sql")


class SetupError(Exception):
    """A refusal or failure, with the message to print."""


def log(msg):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


class _TeeStream:
    """Writes to the console and to the --log-dir log file."""

    def __init__(self, console_stream, log_fh):
        self._console = console_stream
        self._log_fh = log_fh

    def write(self, data):
        self._console.write(data)
        self._log_fh.write(data)

    def flush(self):
        self._console.flush()
        self._log_fh.flush()

    def isatty(self):
        return self._console.isatty()


INTERRUPTED_BY = "Ctrl-C"


def handle_sigterm(signum, frame):
    """SIGTERM is handled like Ctrl-C (exit 130). The file being applied is
    one batch on the server, so it is committed or rolled back whole."""
    global INTERRUPTED_BY
    INTERRUPTED_BY = "SIGTERM"
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    raise KeyboardInterrupt


signal.signal(signal.SIGTERM, handle_sigterm)


def find_files(schema_dir):
    """(baseline path, baseline version, {version: migration path}, target
    version). [1.2] The migrations are schema_dir/migrations/
    schema_migration_vNN.sql; they must continue the baseline without a gap."""
    init_path = schema_dir / "schema_init.sql"
    if not init_path.is_file():
        raise SetupError(f"{init_path} not found (--schema-dir points at the wrong directory?)")
    m = FRESH_INSTALL_VERSION.search(init_path.read_text(encoding="utf-8"))
    if not m:
        raise SetupError(f"{init_path} does not record the version it installs")
    baseline = int(m.group(1))
    migrations = {}
    migrations_dir = schema_dir / MIGRATIONS_SUBDIR
    if migrations_dir.is_dir():
        for path in migrations_dir.iterdir():
            m = MIGRATION_NAME.match(path.name)
            if m and path.is_file():
                migrations[int(m.group(1))] = path
    stray = sorted(path.name for path in schema_dir.iterdir()
                   if MIGRATION_NAME.match(path.name))
    if stray:
        raise SetupError(f"migration file(s) outside {MIGRATIONS_SUBDIR}/: {', '.join(stray)} "
                         f"-- they belong in {migrations_dir}")
    too_old = sorted(v for v in migrations if v <= baseline)
    if too_old:
        raise SetupError(f"migration file(s) for v{', v'.join(map(str, too_old))} are at or below "
                         f"the baseline (schema_init.sql, v{baseline}): a mixed set of files")
    target = max(migrations, default=baseline)
    gaps = [v for v in range(baseline + 1, target + 1) if v not in migrations]
    if gaps:
        raise SetupError("the migration chain has a gap: "
                         + ", ".join(f"schema_migration_v{v}.sql" for v in gaps) + " missing")
    return init_path, baseline, migrations, target


def needs_rescan(path):
    return bool(FULL_RESCAN_MARKER.search(path.read_text(encoding="utf-8")))


def sql_for_server(path):
    """The file's text without pg_dump's psql-only lines. Any other psql
    meta-command is refused: it cannot be sent through psycopg2."""
    lines = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(keepends=True), 1):
        if line.startswith("\\"):
            if PSQL_META_ALLOWED.match(line):
                continue
            raise SetupError(f"{path.name} line {number} is a psql command this script cannot "
                             f"run: {line.strip()[:60]}")
        lines.append(line)
    return "".join(lines)


def connect(args, password):
    conn = psycopg2.connect(host=args.pg_host, port=args.pg_port, dbname=args.pg_dbname,
                            user=args.pg_user, password=password, connect_timeout=30,
                            application_name=f"schema_setup.py pid={os.getpid()}")
    conn.autocommit = True
    return conn


def database_state(conn):
    """('empty' | 'untracked' | 'tracked', version or None, owner_is_me)."""
    with conn.cursor() as cur:
        cur.execute("SELECT pg_get_userbyid(nspowner) = current_user FROM pg_namespace "
                    "WHERE nspname = 'ad_intel';")
        row = cur.fetchone()
        if row is None:
            return "empty", None, True
        owner_is_me = row[0]
        cur.execute("SELECT to_regclass('ad_intel.schema_migration_history') IS NOT NULL;")
        if not cur.fetchone()[0]:
            return "untracked", None, owner_is_me
        cur.execute("SELECT max(version_number) FROM ad_intel.schema_migration_history;")
        return "tracked", cur.fetchone()[0], owner_is_me


def recorded_version(args, password):
    """max(version_number), or None when there is no history (yet)."""
    conn = connect(args, password)
    try:
        return database_state(conn)[1]
    finally:
        conn.close()


def apply_file(args, password, path, expect_version):
    """Sends one file as a single batch on its own connection (the files set
    session settings such as search_path), then checks the version it
    recorded."""
    sql = sql_for_server(path)
    conn = connect(args, password)
    try:
        with conn.cursor() as cur:
            try:
                cur.execute(sql)
            except psycopg2.Error as exc:
                detail = (exc.pgerror or str(exc)).strip().replace("\n", " ")
                now = recorded_version(args, password)
                raise SetupError(f"{path.name} failed: {detail} -- "
                                 + (f"the database is at schema v{now}" if now is not None
                                    else "no schema was created"))
    finally:
        conn.close()
    conn = connect(args, password)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT EXISTS (SELECT 1 FROM ad_intel.schema_migration_history "
                        "WHERE version_number = %s);", (expect_version,))
            if not cur.fetchone()[0]:
                raise SetupError(f"{path.name} ran but did not record schema version "
                                 f"{expect_version}")
    finally:
        conn.close()


def apply_migrations(args, password, migrations, versions, fresh=False):
    """Applies the migrations, in order. A migration that needs a full
    rescan is recorded as soon as it has applied, so that a later failure in
    the chain cannot lose the request (the next attempt starts after it). A
    new database (fresh) needs none: its first collection writes every
    object in full."""
    for version in versions:
        path = migrations[version]
        log(f"  Applying {MIGRATIONS_SUBDIR}/{path.name}...")
        apply_file(args, password, path, version)
        log(f"  Schema v{version} applied.")
        if needs_rescan(path) and not fresh:
            note_rescan(args, version)


def note_rescan(args, version):
    log(f"[NOTE] Migration v{version} needs one adprofiler.py run with --full-rescan, so "
        f"unchanged objects get the new columns.")
    if args.rescan_file:
        args.rescan_file.parent.mkdir(parents=True, exist_ok=True)
        with open(args.rescan_file, "a", encoding="utf-8") as fh:
            fh.write(f"full rescan needed after schema migration v{version}\n")
        log(f"Recorded in {args.rescan_file}: the next collection runs with --full-rescan.")


def run(args, password):
    init_path, baseline, migrations, target = find_files(args.schema_dir)
    log(f"Schema files in {args.schema_dir}: baseline schema_init.sql (v{baseline})"
        + (f" and {MIGRATIONS_SUBDIR}/ v{min(migrations)}-v{target}; target v{target}."
           if migrations else f", no migrations; target v{target}."))
    conn = connect(args, password)
    try:
        state, current, owner_is_me = database_state(conn)
        server_version = conn.server_version
    finally:
        conn.close()

    if state == "untracked":
        raise SetupError(
            "the database has an ad_intel schema without schema_migration_history: it is older "
            f"than v{FIRST_TRACKED_VERSION}, or incomplete. It cannot be upgraded; create a new, "
            f"empty database and run this script against it.")

    chain = list(range(baseline + 1, target + 1))
    if state == "empty":
        if args.check:
            log(f"Check: the database has no ad_intel schema; the baseline (v{baseline})"
                + (f" and migrations v{chain[0]}-v{target}" if chain else "")
                + " would be applied.")
            return EXIT_NEEDS_SETUP
        if server_version < 170000:
            raise SetupError(f"PostgreSQL {server_version // 10000} found; the schema needs "
                             f"PostgreSQL 17 or later")
        log(f"The database has no ad_intel schema: creating the v{baseline} baseline from "
            f"schema_init.sql...")
        apply_file(args, password, init_path, baseline)
        log(f"Schema v{baseline} created.")
        apply_migrations(args, password, migrations, chain, fresh=True)
        log(f"The database is now at schema v{target}.")
        return EXIT_OK

    if current is None:
        raise SetupError("ad_intel.schema_migration_history is empty: the schema is incomplete. "
                         "It cannot be upgraded automatically.")
    if current > target:
        raise SetupError(f"the database is at schema v{current}, newer than the files here "
                         f"(v{target}): upgrade the scripts, not the database")
    if current == target:
        log(f"The database is at schema v{current}: nothing to do.")
        return EXIT_OK
    if current < baseline:
        raise SetupError(
            f"the database is at schema v{current}, older than the v{baseline} baseline: it "
            f"cannot be upgraded. Create a new, empty database and run this script against it.")

    pending = list(range(current + 1, target + 1))
    if args.check:
        log(f"Check: the database is at schema v{current}; would apply "
            + ", ".join(f"v{v}" for v in pending) + ".")
        return EXIT_NEEDS_SETUP
    if not owner_is_me:
        log("[WARN] The connecting role does not own the ad_intel schema. Migrations that "
            "replace the partition maintenance functions should run as the owner.")
    log(f"The database is at schema v{current}; applying {len(pending)} migration(s).")
    apply_migrations(args, password, migrations, pending)
    log(f"The database is now at schema v{target}.")
    return EXIT_OK


def parse_args():
    parser = argparse.ArgumentParser(
        description="Create or upgrade the ad_intel PostgreSQL schema, unattended.")
    parser.add_argument("--pg-host", default=None, help="PostgreSQL server hostname or IP.")
    parser.add_argument("--pg-port", type=int, default=5432, help="Default: 5432.")
    parser.add_argument("--pg-dbname", default="adprofiler", help="Default: adprofiler.")
    parser.add_argument("--pg-user", default=None, help="PostgreSQL role (the schema owner).")
    parser.add_argument("--pg-password", default=None,
                        help="Prefer PGPASSWORD or PGPASSWORD_FILE, or omit it to be prompted; "
                             "an option is visible in process listings.")
    parser.add_argument("--schema-dir", type=Path, default=Path(__file__).resolve().parent,
                        metavar="DIR",
                        help="Directory holding schema_init.sql (the v50 baseline) and the "
                             "migrations/ folder. Default: this script's directory.")
    parser.add_argument("--rescan-file", type=Path, default=None, metavar="FILE",
                        help="[1.2] Create FILE when an applied migration needs one adprofiler.py "
                             "run with --full-rescan (collector_daemon.py passes this).")
    parser.add_argument("--check", action="store_true",
                        help="Report what would be done; change nothing (exit 3 if needed).")
    parser.add_argument("--log-dir", type=Path, default=None, metavar="DIR",
                        help="Also write the output to DIR/schema-setup-results_<timestamp>.log.")
    parser.add_argument("--version", action="store_true", help="Print the version and exit.")
    args = parser.parse_args()
    if not args.version and (not args.pg_host or not args.pg_user):
        parser.error("the following arguments are required: --pg-host, --pg-user")
    return args


def main():
    args = parse_args()
    if args.version:
        print(f"schema_setup.py v{VERSION}")
        return EXIT_OK
    if args.log_dir is not None:
        try:
            args.log_dir.mkdir(parents=True, exist_ok=True)
            log_path = args.log_dir / (f"schema-setup-results_"
                                       f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            log_fh = open(log_path, "w", encoding="utf-8")
        except OSError as exc:
            print(f"[ERROR] Cannot write a log file in {args.log_dir}: {exc}")
            return EXIT_FAILED
        real_stdout = sys.stdout
        sys.stdout = _TeeStream(real_stdout, log_fh)

        def _restore_stdout():
            sys.stdout = real_stdout
            log_fh.close()
        atexit.register(_restore_stdout)

    log(f"schema_setup.py v{VERSION}: {args.pg_user}@{args.pg_host}:{args.pg_port}/"
        f"{args.pg_dbname}")
    try:
        password, source = secret_input.resolve_secret(
            "PostgreSQL password", args.pg_password, "--pg-password", "PGPASSWORD",
            f"PostgreSQL password for {args.pg_user}@{args.pg_host}: ", required=False)
    except secret_input.SecretUnavailable as exc:
        log(f"[ERROR] Cannot start: {exc}.")
        return EXIT_FAILED
    if source == secret_input.FROM_OPTION:
        log("[WARN] " + secret_input.option_warning("PostgreSQL password", "--pg-password",
                                                    "PGPASSWORD"))
    elif source in (secret_input.FROM_ENV, secret_input.FROM_FILE):
        log("PostgreSQL password: from the "
            + secret_input.describe_source(source, "--pg-password", "PGPASSWORD") + ".")

    try:
        if not args.check:
            run_lock.acquire("schema_setup.py", args.pg_host, args.pg_port, args.pg_dbname,
                             args.pg_user, password)
        return run(args, password)
    except run_lock.RunLocked as exc:
        log(f"[ERROR] {exc}")
        return EXIT_LOCKED
    except SetupError as exc:
        log(f"[ERROR] {str(exc).rstrip('.')}.")
        return EXIT_FAILED
    except psycopg2.Error as exc:
        log(f"[ERROR] PostgreSQL: {str(exc).strip()}")
        return EXIT_FAILED
    except OSError as exc:
        log(f"[ERROR] {exc}")
        return EXIT_FAILED
    except KeyboardInterrupt:
        log(f"[ERROR] Interrupted ({INTERRUPTED_BY}). The file being applied was committed or "
            f"rolled back whole.")
        return EXIT_INTERRUPTED


if __name__ == "__main__":
    sys.exit(main())
