"""schema_setup.py against a real PostgreSQL 17 server: the fresh install,
the migration chain (played back in order, with skipped versions), the
refusals, and the backup taken before migrating.

Needs a server and a role that may create databases, given by:
    ADPROFILER_TEST_PGHOST, ADPROFILER_TEST_PGPORT (5432),
    ADPROFILER_TEST_PGUSER, ADPROFILER_TEST_PGPASSWORD
Without ADPROFILER_TEST_PGHOST these tests are skipped. The backup and
comparison tests also need pg_dump/pg_restore 17 or later: ADPROFILER_TEST_PGBIN
names their directory (default: the PATH, then /usr/lib/postgresql/17/bin).
Each test uses its own database, adprofiler_test_<n>, dropped afterwards."""
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOST = os.environ.get("ADPROFILER_TEST_PGHOST")
PORT = int(os.environ.get("ADPROFILER_TEST_PGPORT") or 5432)
USER = os.environ.get("ADPROFILER_TEST_PGUSER") or "postgres"
PASSWORD = os.environ.get("ADPROFILER_TEST_PGPASSWORD") or ""

if HOST:
    import psycopg2


def pg_tool(name):
    """The path of a PostgreSQL 17+ client tool, or None."""
    candidates = []
    if os.environ.get("ADPROFILER_TEST_PGBIN"):
        candidates.append(Path(os.environ["ADPROFILER_TEST_PGBIN"]) / name)
    if shutil.which(name):
        candidates.append(Path(shutil.which(name)))
    candidates.append(Path("/usr/lib/postgresql/17/bin") / name)
    for path in candidates:
        try:
            out = subprocess.run([str(path), "--version"], capture_output=True, text=True).stdout
        except OSError:
            continue
        m = re.search(r"(\d+)\.", out)
        if m and int(m.group(1)) >= 17:
            return str(path)
    return None


# Test migrations: v51 needs a full rescan, v52 adds a table, v53 fills v51's
# column.
MIGRATIONS = {
    51: """-- test v51: a new column
-- adprofiler: full-rescan
BEGIN;
ALTER TABLE ad_intel.client ADD COLUMN test_note text;
INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (51, 'test v51');
COMMIT;
""",
    52: """BEGIN;
CREATE TABLE ad_intel.test_v52 (id int PRIMARY KEY, note text);
INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (52, 'test v52');
COMMIT;
""",
    53: """BEGIN;
UPDATE ad_intel.client SET test_note = 'backfilled' WHERE test_note IS NULL;
INSERT INTO ad_intel.schema_migration_history (version_number, description)
VALUES (53, 'test v53');
COMMIT;
""",
}


@unittest.skipUnless(HOST, "ADPROFILER_TEST_PGHOST is not set (no test PostgreSQL server)")
class SchemaSetup(unittest.TestCase):
    counter = 0

    def setUp(self):
        SchemaSetup.counter += 1
        self.db = f"adprofiler_test_{os.getpid()}_{SchemaSetup.counter}"
        self.admin("CREATE DATABASE " + self.db)
        self.tmp = Path(tempfile.mkdtemp(prefix="schema-test-"))
        self.baseline = self.schema_dir("baseline", {})

    def tearDown(self):
        self.admin(f"DROP DATABASE IF EXISTS {self.db} WITH (FORCE)")
        for extra in getattr(self, "extra_dbs", []):
            self.admin(f"DROP DATABASE IF EXISTS {extra} WITH (FORCE)")
        shutil.rmtree(self.tmp, ignore_errors=True)

    # --- helpers -------------------------------------------------------------

    def admin(self, sql):
        conn = psycopg2.connect(host=HOST, port=PORT, user=USER, password=PASSWORD,
                                dbname="postgres")
        conn.autocommit = True
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
        finally:
            conn.close()

    def query(self, sql, db=None):
        conn = psycopg2.connect(host=HOST, port=PORT, user=USER, password=PASSWORD,
                                dbname=db or self.db)
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
                rows = cur.fetchall()
            conn.commit()
            return rows
        finally:
            conn.close()

    def version(self, db=None):
        return self.query("SELECT max(version_number) FROM ad_intel.schema_migration_history",
                          db)[0][0]

    def schema_dir(self, name, migrations):
        """A schema directory: the repository's schema_init.sql and the given
        {version: sql} as migrations/."""
        path = self.tmp / name
        (path / "migrations").mkdir(parents=True)
        shutil.copy(ROOT / "schema_init.sql", path / "schema_init.sql")
        for version, sql in migrations.items():
            (path / "migrations" / f"schema_migration_v{version}.sql").write_text(sql)
        return path

    def setup(self, schema_dir, *extra, db=None):
        env = {k: v for k, v in os.environ.items() if not k.startswith("PG")}
        env["PGPASSWORD"] = PASSWORD
        cmd = [sys.executable, str(ROOT / "schema_setup.py"), "--pg-host", HOST,
               "--pg-port", str(PORT), "--pg-user", USER, "--pg-dbname", db or self.db,
               "--schema-dir", str(schema_dir), *map(str, extra)]
        return subprocess.run(cmd, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                              text=True, timeout=600)

    def assertSetup(self, result, rc=0):
        self.assertEqual(result.returncode, rc, result.stdout + result.stderr)
        return result.stdout

    # --- tests ---------------------------------------------------------------

    def test_fresh_install_of_the_repository(self):
        """The repository's own files: the baseline plus every migration."""
        self.assertSetup(self.setup(ROOT))
        migrations = sorted(int(m.group(1)) for p in (ROOT / "migrations").glob("*.sql")
                            if (m := re.match(r"schema_migration_v(\d+)\.sql$", p.name)))
        self.assertEqual(self.version(), max(migrations, default=50))
        self.assertEqual(self.query("SELECT count(*) FROM ad_intel.check_scd2_integrity()"),
                         [(0,)])
        out = self.assertSetup(self.setup(ROOT))
        self.assertIn("nothing to do", out)

    def test_fresh_install_with_a_chain(self):
        rescan = self.tmp / "rescan"
        self.assertSetup(self.setup(self.schema_dir("chain", MIGRATIONS), "--rescan-file", rescan))
        self.assertEqual(self.version(), 53)
        self.assertFalse(rescan.exists(), "a new database needs no rescan")

    def test_upgrade_skipping_versions(self):
        """A v50 database straight to v53: every migration in between, in
        order, one rescan request, a backup first."""
        self.assertSetup(self.setup(self.baseline))
        self.assertEqual(self.version(), 50)
        pg_dump = pg_tool("pg_dump")
        if not pg_dump:
            self.skipTest("no pg_dump 17")
        rescan, backups = self.tmp / "rescan", self.tmp / "backups"
        out = self.assertSetup(self.setup(self.schema_dir("chain", MIGRATIONS),
                                          "--rescan-file", rescan, "--backup-dir", backups,
                                          "--pg-dump", pg_dump))
        self.assertEqual(self.version(), 53)
        self.assertLess(out.index("v51"), out.index("v52"))
        self.assertLess(out.index("Backup written"), out.index("Applying"))
        self.assertEqual(rescan.read_text().count("full rescan"), 1)
        files = list(backups.iterdir())
        self.assertEqual(len(files), 1)
        self.assertRegex(files[0].name, r"^adprofiler-v50-before-v53-\d{8}T\d{6}Z\.dump$")
        self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(backups.stat().st_mode), 0o700)

    def test_upgrade_in_steps(self):
        self.assertSetup(self.setup(self.baseline))
        self.assertSetup(self.setup(self.schema_dir("to51", {51: MIGRATIONS[51]})))
        self.assertEqual(self.version(), 51)
        self.assertSetup(self.setup(self.schema_dir("to53", MIGRATIONS)))
        self.assertEqual(self.version(), 53)

    def test_failed_backup_blocks_the_migration(self):
        self.assertSetup(self.setup(self.baseline))
        out = self.assertSetup(self.setup(self.schema_dir("chain", MIGRATIONS),
                                          "--backup-dir", self.tmp / "backups",
                                          "--pg-dump", self.tmp / "no-such-pg_dump"), rc=1)
        self.assertIn("no migration was applied", out)
        self.assertEqual(self.version(), 50)

    def test_backup_restores_and_is_pruned(self):
        pg_dump, pg_restore = pg_tool("pg_dump"), pg_tool("pg_restore")
        if not (pg_dump and pg_restore):
            self.skipTest("no pg_dump/pg_restore 17")
        self.assertSetup(self.setup(self.baseline))
        self.query("INSERT INTO ad_intel.client (client_name, domain_fqdn) "
                   "VALUES ('restore test', 'corp.example.com') RETURNING client_id")
        backups = self.tmp / "backups"
        for stamp in ("20200101T000000Z", "20200102T000000Z", "20200103T000000Z"):
            (backups / f"adprofiler-v49-before-v50-{stamp}.dump").parent.mkdir(exist_ok=True)
            (backups / f"adprofiler-v49-before-v50-{stamp}.dump").write_text("old")
        (backups / "keep-me.txt").write_text("not a backup")
        self.assertSetup(self.setup(self.schema_dir("chain", MIGRATIONS), "--backup-dir",
                                    backups, "--backup-keep", 2, "--pg-dump", pg_dump))
        names = sorted(p.name for p in backups.iterdir())
        self.assertEqual(len(names), 3, names)
        self.assertIn("keep-me.txt", names)
        self.assertIn("adprofiler-v49-before-v50-20200103T000000Z.dump", names)
        dump = next(backups.glob("adprofiler-v50-before-v53-*.dump"))
        # Restore as CONTAINER.md describes: drop the schema, pg_restore.
        self.assertEqual(self.version(), 53)
        conn = psycopg2.connect(host=HOST, port=PORT, user=USER, password=PASSWORD,
                                dbname=self.db)
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("DROP SCHEMA ad_intel CASCADE")
        conn.close()
        env = dict(os.environ, PGPASSWORD=PASSWORD)
        result = subprocess.run([pg_restore, "-h", HOST, "-p", str(PORT), "-U", USER,
                                 "-d", self.db, "--no-owner", "--exit-on-error", str(dump)],
                                env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.version(), 50)
        self.assertEqual(self.query("SELECT client_name FROM ad_intel.client "
                                    "WHERE client_name = 'restore test'"), [("restore test",)])
        self.assertEqual(self.query("SELECT to_regclass('ad_intel.test_v52') IS NULL"),
                         [(True,)])

    def test_refusals(self):
        cases = [
            ("gap", {51: MIGRATIONS[51], 53: MIGRATIONS[53]}, "gap"),
            ("at baseline", {50: MIGRATIONS[51]}, "at or below"),
        ]
        for name, migrations, needle in cases:
            with self.subTest(name):
                out = self.assertSetup(self.setup(self.schema_dir(name, migrations)), rc=1)
                self.assertIn(needle, out)
        stray = self.schema_dir("stray", {})
        (stray / "schema_migration_v51.sql").write_text(MIGRATIONS[51])
        self.assertIn("outside", self.assertSetup(self.setup(stray), rc=1))
        # A database newer than the files.
        self.assertSetup(self.setup(self.schema_dir("chain", MIGRATIONS)))
        self.assertIn("newer than the files", self.assertSetup(self.setup(self.baseline), rc=1))

    def test_failed_migration_keeps_the_rescan_request(self):
        """v51 (rescan) applies, v52 fails: the database stays at v51 and the
        rescan request is not lost."""
        self.assertSetup(self.setup(self.baseline))
        broken = dict(MIGRATIONS)
        broken[52] = "BEGIN;\nSELECT no_such_function();\nCOMMIT;\n"
        rescan = self.tmp / "rescan"
        self.assertSetup(self.setup(self.schema_dir("broken", broken), "--rescan-file", rescan),
                         rc=1)
        self.assertEqual(self.version(), 51)
        self.assertTrue(rescan.exists())

    def test_upgraded_equals_fresh(self):
        """The repository's chain applied to a v50 database gives the same
        schema as a fresh install: what every future migration must keep."""
        pg_dump = pg_tool("pg_dump")
        if not pg_dump:
            self.skipTest("no pg_dump 17")
        fresh_db = self.db + "_fresh"
        self.extra_dbs = [fresh_db]
        self.admin("CREATE DATABASE " + fresh_db)
        self.assertSetup(self.setup(ROOT, db=fresh_db))
        self.assertSetup(self.setup(self.baseline))
        self.assertSetup(self.setup(ROOT))

        def schema(db):
            env = dict(os.environ, PGPASSWORD=PASSWORD)
            out = subprocess.run([pg_dump, "-h", HOST, "-p", str(PORT), "-U", USER, "-d", db,
                                  "--schema-only", "--no-owner", "--no-privileges"],
                                 env=env, capture_output=True, text=True, check=True).stdout
            return [line for line in out.splitlines()
                    if not line.startswith(("\\restrict", "\\unrestrict", "-- Dumped"))]
        self.assertEqual(schema(self.db), schema(fresh_db))


if __name__ == "__main__":
    unittest.main()
