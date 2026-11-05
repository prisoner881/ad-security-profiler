"""
collector_daemon.py -- runs the AD/Entra collection, evaluation and push
every day, unattended, and reports its health
==============================================================================
VERSION: 1.0.3

The long-running process of a client installation. It starts, and from then
on never exits by itself: it is stopped (SIGTERM, e.g. `docker stop`) or the
machine goes down. Everything it does is logged, and everything it knows
about its own state is in a status file and the health report. See
docs/DAEMON.md for the design, the configuration file and the deployment notes.

What it does, in a loop:

    1. Lease: in FortifyData mode, takes the lease on the license
       (platform_client.py) and renews it every 2 minutes for as long as it
       runs. Without the lease no run starts. (Local mode needs no lease.)
    2. Configuration: fetches the run configuration (AD and Entra settings,
       their secrets and the daily schedule) from the platform, or reads it
       from its own configuration file in local mode. Fetched again before
       every run, hourly while waiting, and every 5 minutes after a failed
       run or a configuration error: a fix made in the portal (or the file)
       is picked up without a restart, and a failed run is retried as soon
       as its configuration changes.
    3. Schedule: once a day at the configured time and time zone. On start,
       a run that was missed while the daemon was down (the most recent
       scheduled time passed with no run started since) is started at once.
       A failed run is NOT retried until the next scheduled time unless its
       configuration changes: retrying a wrong password every few minutes
       would lock the bind account out.
    4. The run, each step a child process (the scripts are unchanged):
           schema_setup.py          creates or upgrades the database schema
           adprofiler.py            AD collection
           entra_graph_collector.py Entra collection (when configured)
           adaudit.py [--push]      evaluation, then push of every unpushed
                                    run (when an activation key is set)
       When schema_setup.py or adprofiler.py fails, the evaluation is
       skipped (it would assess stale or partial data) and adaudit.py
       --push-only still delivers any earlier run that is waiting. When
       only the Entra collection fails (or Entra is not configured), the AD
       data is evaluated and pushed, with the Entra checks NOT ASSESSED
       (adaudit.py --skip-entra) rather than evaluated against older Entra
       data. After a collection the database's integrity check runs
       (duplicate current rows: a collector bug). Exit 75 (another run holds the run lock)
       postpones the whole run by 5 minutes. A push that fails (exit 5) is
       retried with --push-only every hour.
    5. Health: every 5 minutes a report (state, lease, last run and each
       step's exit code and error line, next run, push backlog, Entra
       sources that could not be read, missing partitions, disk space,
       versions) is written to <state_dir>/status.json and, in FortifyData
       mode, sent to the platform.

Secrets never appear on a command line or in a child's environment: each
one is written into a pipe and the child is given <VAR>_FILE=/dev/fd/<n>
(secret_input.py reads it). The daemon's own environment is passed on with
every secret variable removed, standard input is /dev/null, so a script can
never stop at a prompt.

Stopping: SIGTERM or SIGINT forwards SIGTERM to the running step (each
script stops at its next safe point and exits 130), waits up to
[daemon] stop_timeout seconds for it, kills it after that, releases the
lease and exits 0. Give the container a longer stop grace period than
stop_timeout (docker: stop_grace_period: 5m).

Usage:
    collector_daemon.py --config /etc/fortifydata/collector.toml
    collector_daemon.py --config FILE --check-config   validate and exit
    collector_daemon.py --config FILE --once           one run now, then exit
    collector_daemon.py --config FILE --healthcheck    for a container healthcheck
The configuration file can also be named by ADAUDIT_DAEMON_CONFIG.

Exit codes: 0 stopped by a signal (or --once/--healthcheck succeeded);
1 --once run failed, --healthcheck unhealthy, or an unexpected error;
75 --once was postponed (run lock held), or another collector_daemon.py
uses the same state_dir; 78 the daemon's own settings are
unusable ([daemon], [platform], [database]; EX_CONFIG) -- the only reason
it exits on its own. A wrong AD or Entra setting is not one of them: the
daemon keeps running, reports it and retries.

CHANGELOG:
    1.0.3  No change of its own: the version of the collector image, whose
           schema_setup.py (1.1) no longer ships migration files up to v50.
    1.0.2  A failed Entra collection no longer blocks the evaluation and
           push of a successful AD collection: adaudit.py (1.0.9) runs with
           --skip-entra, so the Entra checks are NOT ASSESSED (their open
           findings kept) instead of evaluated against the Entra data of the
           last successful collection; the run ends "warning". --skip-entra
           is also passed when Entra is not configured. After a collection,
           check_scd2_integrity() (schema v50) is run; a duplicate current
           row is logged and reported in the health report ("integrity").
    1.0.1  --check-config no longer takes the one-process lock and logs only
           to standard error, so a configuration can be checked while the
           daemon runs (docker compose run --rm collector --check-config).
           Container packaging added (Dockerfile, docker/).
    1.0.0  First version. platform_client.py 1.0; the platform's activation,
           configuration and health endpoints are PROVISIONAL (not yet
           specified by the platform).
"""

import argparse
import fcntl
import hashlib
import hmac
import json
import logging
import logging.handlers
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import tomllib
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import platform_client as pc
import secret_input

VERSION = "1.0.3"

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_LOCKED = 75      # run_lock.EXIT_LOCKED
EXIT_CONFIG = 78      # sysexits.h EX_CONFIG
EXIT_INTERRUPTED = 130

# Exit codes of the scripts (see each script's docstring).
RC_OK = 0
RC_FAILED = 1
RC_ADAUDIT_INCOMPLETE = 3
RC_ADAUDIT_PUSH_FAILED = 5
RC_LOCKED = 75
RC_INTERRUPTED = 130

SCRIPTS = {
    "schema_setup": "schema_setup.py",
    "adprofiler": "adprofiler.py",
    "entra": "entra_graph_collector.py",
    "adaudit": "adaudit.py",
}

# Every variable that carries a secret, or redirects where a script sends
# one, is removed from the children's environment; the secrets a step needs
# are given to it through pipes instead.
SCRUBBED_ENV = ("AD_BIND_PASSWORD", "ENTRA_APP_SECRET", "PGPASSWORD", "FD_ACTIVATION_KEY",
                "FD_API_KEY", "AD_BIND_PASSWORD_FILE", "ENTRA_APP_SECRET_FILE",
                "PGPASSWORD_FILE", "FD_ACTIVATION_KEY_FILE", "FD_API_URL", "FD_COMPANY_ID",
                "ADAUDIT_DAEMON_CONFIG")

# Every key the configuration file may hold; anything else is reported as a
# probable typo (it would otherwise be ignored without a word).
KNOWN_KEYS = {
    "daemon": {"state_dir", "log_dir", "scripts_dir", "python", "log_retention_days",
               "stop_timeout", "retry_interval"},
    "platform": {"mode", "activation_key_file", "api_url", "ca_bundle", "renew_interval",
                 "health_interval", "request_timeout", "push"},
    "database": {"host", "port", "dbname", "user", "password_file"},
    "run": {"excel", "report_dir"},
    "schedule": {"time", "timezone"},
    "ad": {"dc_host", "username", "password_file", "ssl", "port", "ca_cert_file", "sysvol",
           "sysvol_kerberos", "smb_host", "domain_fqdn"},
    "entra": {"tenant_id", "app_id", "client_secret_file", "include_pta_agents"},
}

CONFIG_REFRESH_SECONDS = 3600
PUSH_RETRY_SECONDS = 3600
LOG_FILE = "collector_daemon.log"
STATUS_FILE = "status.json"
STATE_FILE = "state.json"
LOCK_FILE = "daemon.lock"
FINGERPRINT_KEY_FILE = "fingerprint.key"
INSTANCE_FILE = "instance_id"
CA_CERT_FILE = "ldaps_ca.pem"
# Only these files are pruned: what the scripts write to --log-dir and
# --report-dir. Anything else in those directories is left alone.
PRUNED_PATTERNS = ("*-results_*.log", "adaudit-findings_*.xlsx")
MAX_PIPE_SECRET_BYTES = 60000   # below the 64 KiB pipe buffer: the write never blocks

# Run outcomes.
OK, WARNING, FAILED, DEFERRED, INTERRUPTED = "ok", "warning", "failed", "deferred", "interrupted"

# The first line like this in a failed step's output is its one-line summary
# (the scripts mark errors [FAIL], [ERROR] or [FATAL]).
ERROR_LINE = re.compile(r"\[(FAIL|ERROR|FATAL|CRITICAL)\]|Traceback \(most recent|^\S*Error: ")


# ============================================================================
# Small helpers
# ============================================================================

def utcnow():
    return datetime.now(timezone.utc)


def iso(moment):
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if moment else None


def parse_iso(text):
    if not text:
        return None
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    except (TypeError, ValueError):
        return None


def next_occurrence(schedule, after):
    """The first scheduled time strictly after `after` (UTC result)."""
    zone = schedule.zone
    local = after.astimezone(zone)
    for days in (0, 1, 2):
        day = local.date() + timedelta(days=days)
        candidate = datetime.combine(day, schedule.at, tzinfo=zone).astimezone(timezone.utc)
        if candidate > after:
            return candidate
    raise AssertionError("unreachable")


def previous_occurrence(schedule, now):
    """The last scheduled time at or before `now` (UTC result)."""
    zone = schedule.zone
    local = now.astimezone(zone)
    for days in (0, 1, 2):
        day = local.date() - timedelta(days=days)
        candidate = datetime.combine(day, schedule.at, tzinfo=zone).astimezone(timezone.utc)
        if candidate <= now:
            return candidate
    raise AssertionError("unreachable")


def local_text(moment, schedule):
    """'2026-11-06 02:30 CST (08:30Z)' for logs."""
    if moment is None:
        return "-"
    local = moment.astimezone(schedule.zone) if schedule else moment
    return f"{local:%Y-%m-%d %H:%M %Z} ({moment.astimezone(timezone.utc):%H:%MZ})"


def write_json_atomic(path, data, mode=0o644):
    tmp = path.with_name(f"{path.name}.{os.getpid()}.{threading.get_ident()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, default=str)
        fh.write("\n")
    os.replace(tmp, path)


def read_json(path):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


# ============================================================================
# The daemon's own settings
# ============================================================================

class SettingsError(Exception):
    """The [daemon], [platform] or [database] settings are unusable."""


class DaemonRunning(Exception):
    """Another collector_daemon.py (or --once) uses the same state_dir."""


class Settings:
    """The daemon's own settings. Relative paths are relative to the
    configuration file's directory."""

    def __init__(self, path, doc):
        self.path = Path(path).resolve()
        base = self.path.parent
        daemon = self._table(doc, "daemon")
        platform = self._table(doc, "platform")
        database = self._table(doc, "database")
        run = self._table(doc, "run")

        def path_of(table, key, default=None):
            value = table.get(key, default)
            if value is None:
                return None
            if not isinstance(value, str) or not value.strip():
                raise SettingsError(f"{key} must be a path")
            p = Path(value).expanduser()
            return p if p.is_absolute() else (base / p)

        self.state_dir = path_of(daemon, "state_dir", "state")
        self.log_dir = path_of(daemon, "log_dir", "logs")
        self.scripts_dir = path_of(daemon, "scripts_dir") or Path(__file__).resolve().parent
        self.python = self._text(daemon, "python", sys.executable)
        self.log_retention_days = self._int(daemon, "log_retention_days", 30, 1, 3650)
        self.stop_timeout = self._int(daemon, "stop_timeout", 240, 10, 3600)
        self.retry_interval = self._int(daemon, "retry_interval", 300, 30, 3600)

        self.mode = platform.get("mode", "local")
        if self.mode not in ("local", "fortifydata"):
            raise SettingsError(f"[platform] mode must be \"local\" or \"fortifydata\", "
                                f"not {str(self.mode)[:40]!r}")
        self.activation_key_file = path_of(platform, "activation_key_file")
        api_url = platform.get("api_url")
        if api_url is not None and not isinstance(api_url, str):
            raise SettingsError("[platform] api_url must be text")
        if api_url:
            import adaudit_push
            api_url = adaudit_push.API_SERVERS.get(api_url.lower(), api_url)
            try:
                api_url = pc.check_api_url(api_url)
            except pc.ConfigError as exc:
                raise SettingsError(str(exc))
        self.api_url = api_url or None
        self.ca_bundle = path_of(platform, "ca_bundle")
        self.renew_interval = self._int(platform, "renew_interval", 120, 10, 3600)
        self.health_interval = self._int(platform, "health_interval", 300, 30, 3600)
        self.request_timeout = self._int(platform, "request_timeout", 30, 5, 600)
        push = platform.get("push")
        if push is not None and not isinstance(push, bool):
            raise SettingsError("[platform] push must be true or false")
        self.push = push

        self.db_host = self._text(database, "host", None)
        self.db_user = self._text(database, "user", None)
        if not self.db_host or not self.db_user:
            raise SettingsError("[database] host and user are required")
        self.db_port = self._int(database, "port", 5432, 1, 65535)
        self.db_name = self._text(database, "dbname", "adprofiler")
        self.db_password_file = path_of(database, "password_file")

        self.unknown_keys = []
        for name in ("schedule", "ad", "entra"):
            if name in doc and not isinstance(doc[name], dict):
                raise SettingsError(f"[{name}] must be a table")
        for name, value in doc.items():
            if name not in KNOWN_KEYS:
                self.unknown_keys.append(f"[{name}]" if isinstance(value, dict) else name)
            elif isinstance(value, dict):
                self.unknown_keys += [f"[{name}] {key}" for key in value
                                      if key not in KNOWN_KEYS[name]]

        excel = run.get("excel", False)
        if not isinstance(excel, bool):
            raise SettingsError("[run] excel must be true or false")
        self.excel = excel
        self.report_dir = path_of(run, "report_dir") or (self.state_dir / "reports")

    @staticmethod
    def _table(doc, name):
        value = doc.get(name, {})
        if not isinstance(value, dict):
            raise SettingsError(f"[{name}] must be a table")
        return value

    @staticmethod
    def _text(table, key, default):
        value = table.get(key, default)
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise SettingsError(f"{key} must be text")
        return value.strip()

    @staticmethod
    def _int(table, key, default, low, high):
        value = table.get(key, default)
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise SettingsError(f"{key} must be a whole number from {low} to {high}")
        return value

    @property
    def script_log_dir(self):
        return self.log_dir / "scripts"


def load_document(path):
    """The TOML document, with relative *_file paths in [ad] and [entra]
    made relative to the configuration file."""
    path = Path(path)
    with open(path, "rb") as fh:
        doc = tomllib.load(fh)
    base = path.resolve().parent
    for table in ("ad", "entra"):
        section = doc.get(table)
        if isinstance(section, dict):
            for key, value in list(section.items()):
                if key.endswith("_file") and isinstance(value, str) and value:
                    p = Path(value).expanduser()
                    section[key] = str(p if p.is_absolute() else base / p)
    return doc


# ============================================================================
# Logging
# ============================================================================

def setup_logging(log_dir=None, retention_days=30):
    logger = logging.getLogger("collector_daemon")
    logger.setLevel(logging.INFO)
    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s",
                                  "%Y-%m-%dT%H:%M:%SZ")
    formatter.converter = time.gmtime
    console = logging.StreamHandler(sys.stderr)
    console.setFormatter(formatter)
    logger.addHandler(console)
    if log_dir is not None:
        fh = logging.handlers.TimedRotatingFileHandler(
            Path(log_dir) / LOG_FILE, when="midnight", utc=True, backupCount=retention_days,
            encoding="utf-8")
        fh.setFormatter(formatter)
        logger.addHandler(fh)
    logger.propagate = False
    return logger


# ============================================================================
# The daemon
# ============================================================================

class StepResult:
    def __init__(self, step, rc, started, finished, summary):
        self.step, self.rc, self.started, self.finished, self.summary = (
            step, rc, started, finished, summary)

    def as_dict(self):
        return {"step": self.step, "exit_code": self.rc, "started": iso(self.started),
                "finished": iso(self.finished), "summary": self.summary}


class Daemon:

    def __init__(self, settings, doc_loader, log):
        self.s = settings
        self.load_doc = doc_loader
        self.log = log
        self.stop_event = threading.Event()      # stop requested
        self.threads_stop = threading.Event()    # background threads end
        self.lease_ready = threading.Event()
        self.lock = threading.RLock()
        self.status_lock = threading.Lock()
        self.stop_reason = None
        self._signal_r, self._signal_w = os.pipe()
        os.set_blocking(self._signal_w, False)

        self.state = "starting"
        self.state_detail = ""
        self.state_since = utcnow()

        self.instance_id = None
        self.platform = None
        self.db_password = None
        self.push_enabled = False

        self.lease_status = "not required"
        self.lease_last_renewed = None
        self.lease_seconds = None
        self.lease_error = None

        self.config = None
        self.config_fingerprint = None
        self.config_fetched_at = None
        self.config_error = None
        self._fp_key = None   # set in prepare()

        self.next_due = None
        self.child = None
        self.current_step = None
        self.current_step_started = None
        self.versions = {}
        self.db_snapshot = {}
        self.persist = {}
        self._last_health_error = None

    # --- start-up -------------------------------------------------------------

    def prepare(self, take_lock=True):
        """Directories, persisted state, secrets of the daemon itself and the
        platform client. Raises SettingsError, or DaemonRunning when
        take_lock is set and another process holds the lock."""
        for d in (self.s.state_dir, self.s.log_dir, self.s.script_log_dir, self.s.report_dir,
                  self.s.state_dir / "work"):
            try:
                d.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                raise SettingsError(f"cannot create {d}: {exc.strerror or exc}")
        try:
            os.chmod(self.s.state_dir, 0o700)
        except OSError:
            pass
        # One process per state directory: a second daemon, or --once next to
        # a running daemon, would share its lease, state and status files.
        # Held until the process exits.
        if take_lock:
            self._lock_fh = open(self.s.state_dir / LOCK_FILE, "a")
            try:
                fcntl.flock(self._lock_fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                raise DaemonRunning(f"another collector_daemon.py is running with state_dir "
                                    f"{self.s.state_dir}; stop it first")
        self.persist = read_json(self.s.state_dir / STATE_FILE)
        self._fp_key = self._fingerprint_key()
        self.instance_id = self._instance_id()

        # The PostgreSQL password: [database] password_file, PGPASSWORD,
        # PGPASSWORD_FILE, or none (libpq's ~/.pgpass, or trust/peer).
        try:
            if self.s.db_password_file:
                if os.environ.get("PGPASSWORD") or os.environ.get("PGPASSWORD_FILE"):
                    raise SettingsError("[database] password_file and PGPASSWORD(_FILE) are both "
                                        "set; set only one of them")
                self.db_password = secret_input.read_secret_file(
                    str(self.s.db_password_file), "[database] password_file")
                db_source = f"file {self.s.db_password_file}"
            else:
                self.db_password, how = secret_input.resolve_secret(
                    "PostgreSQL password", None, None, "PGPASSWORD", "", required=False,
                    allow_prompt=False)
                db_source = secret_input.describe_source(how, None, "PGPASSWORD")
        except secret_input.SecretUnavailable as exc:
            raise SettingsError(f"PostgreSQL password: {exc}")

        try:
            lic, key_text, key_source = pc.load_activation_key(
                str(self.s.activation_key_file) if self.s.activation_key_file else None)
        except pc.ConfigError as exc:
            raise SettingsError(str(exc))
        if self.s.mode == "fortifydata":
            if lic is None:
                raise SettingsError("[platform] mode = \"fortifydata\" needs the activation key: "
                                    "activation_key_file, or FD_ACTIVATION_KEY(_FILE)")
            self.platform = pc.FortifyDataPlatform(
                lic, key_text, self.instance_id, pc.DaemonKey(self.s.state_dir), VERSION,
                api_url=self.s.api_url,
                ca_bundle=str(self.s.ca_bundle) if self.s.ca_bundle else None,
                timeout=self.s.request_timeout, log=self.log)
        else:
            self.platform = pc.LocalPlatform(self.load_doc, activation_key=key_text,
                                             api_url_override=self.s.api_url, log=self.log)
        self.push_enabled = bool(key_text) if self.s.push is None else self.s.push
        if self.push_enabled and not key_text:
            raise SettingsError("[platform] push = true needs the activation key: "
                                "activation_key_file, or FD_ACTIVATION_KEY(_FILE)")

        self.log.info(f"collector_daemon.py {VERSION} starting (pid {os.getpid()}, "
                      f"instance {self.instance_id}, configuration {self.s.path})")
        self.log.info(f"Platform: {self.platform.describe()}")
        if lic is not None:
            self.log.info(f"Activation key: company {lic.company_id}, environment "
                          f"{lic.environment_or_default}, from {key_source}; push "
                          f"{'on' if self.push_enabled else 'off'}")
        self.log.info(f"Database: {self.s.db_user}@{self.s.db_host}:{self.s.db_port}/"
                      f"{self.s.db_name}, password from {db_source}")
        if self.s.unknown_keys:
            self.log.warning("Configuration file: unknown setting(s), ignored: "
                             + ", ".join(self.s.unknown_keys))
        self.log.info(f"State in {self.s.state_dir}, logs in {self.s.log_dir} "
                      f"(kept {self.s.log_retention_days} days)")
        self.versions = self._script_versions()

    def _fingerprint_key(self):
        """Key for the configuration fingerprint (see _fingerprint), kept in
        the state directory (mode 0600) so that a configuration fixed while
        the daemon was stopped is noticed after the restart."""
        path = self.s.state_dir / FINGERPRINT_KEY_FILE
        try:
            key = path.read_bytes()
            if len(key) == 32:
                return key
        except OSError:
            pass
        key = os.urandom(32)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(key)
        return key

    def _instance_id(self):
        path = self.s.state_dir / INSTANCE_FILE
        try:
            text = path.read_text(encoding="ascii").strip()
            return str(uuid.UUID(text))
        except (OSError, ValueError):
            pass
        new = str(uuid.uuid4())
        path.write_text(new + "\n", encoding="ascii")
        return new

    def _script_versions(self):
        versions = {"collector_daemon": VERSION, "platform_client": pc.VERSION}
        for step, script in SCRIPTS.items():
            path = self.s.scripts_dir / script
            if not path.exists():
                raise SettingsError(f"{path} does not exist ([daemon] scripts_dir)")
            try:
                out = subprocess.run([self.s.python, str(path), "--version"],
                                     stdin=subprocess.DEVNULL, capture_output=True, text=True,
                                     timeout=120, env=self._child_env(),
                                     cwd=self.s.state_dir / "work")
                text = (out.stdout or out.stderr).strip().splitlines()
                found = re.search(r"\d+\.\d+(\.\d+)?", text[0]) if text else None
                versions[step] = found.group(0) if found else (text[0][:60] if text else "?")
                if out.returncode != 0:
                    raise SettingsError(f"{script} --version failed (exit {out.returncode}): "
                                        f"{(text or ['no output'])[-1][:300]}")
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise SettingsError(f"cannot run {script} with {self.s.python}: {exc}")
        self.log.info("Versions: " + ", ".join(f"{k} {v}" for k, v in versions.items()))
        return versions

    # --- state and status -----------------------------------------------------

    def set_state(self, state, detail=""):
        with self.lock:
            if (state, detail) == (self.state, self.state_detail):
                return
            changed = state != self.state
            self.state, self.state_detail = state, detail
            if changed:
                self.state_since = utcnow()
        self.log.info(f"State: {state}" + (f" -- {detail}" if detail else ""))
        self.write_status()

    def save_persist(self):
        with self.lock:
            write_json_atomic(self.s.state_dir / STATE_FILE, self.persist, mode=0o600)

    def health_report(self):
        with self.lock:
            cfg = self.config
            return {
                "report_format": 1,
                "generated_at": iso(utcnow()),
                "instance_id": self.instance_id,
                "hostname": socket.gethostname(),
                "mode": self.s.mode,
                "versions": dict(self.versions),
                "state": self.state,
                "state_detail": self.state_detail,
                "state_since": iso(self.state_since),
                "lease": {"required": bool(self.platform and self.platform.needs_lease),
                          "status": self.lease_status,
                          "last_renewed": iso(self.lease_last_renewed),
                          "error": self.lease_error},
                "configuration": {"version": cfg.version if cfg else None,
                                  "schedule": str(cfg.schedule) if cfg else None,
                                  "entra_configured": bool(cfg and cfg.entra),
                                  "fetched_at": iso(self.config_fetched_at),
                                  "error": self.config_error},
                "current_step": self.current_step,
                "current_step_started": iso(self.current_step_started),
                "last_run": {k: v for k, v in (self.persist.get("last_run") or {}).items()
                             if k != "config_fingerprint"} or None,
                "last_success": self.persist.get("last_success"),
                "next_run": iso(self.next_due),
                "push": {"enabled": self.push_enabled,
                         "retry_due": self.persist.get("push_retry_due"),
                         "backlog": self.db_snapshot.get("push_backlog")},
                "database": dict(self.db_snapshot),
                "integrity": self.persist.get("integrity"),
                "disk_free_bytes": self._disk_free(),
                "health_interval_seconds": self.s.health_interval,
            }

    def _disk_free(self):
        free = {}
        for name, d in (("state_dir", self.s.state_dir), ("log_dir", self.s.log_dir)):
            try:
                free[name] = shutil.disk_usage(d).free
            except OSError:
                free[name] = None
        return free

    def write_status(self, report=None):
        try:
            with self.status_lock:
                write_json_atomic(self.s.state_dir / STATUS_FILE, report or self.health_report())
        except OSError as exc:
            self.log.warning(f"Cannot write the status file: {exc}")

    # --- database (health details, Entra client lookup) ------------------------

    def db_connect(self):
        import psycopg2
        return psycopg2.connect(host=self.s.db_host, port=self.s.db_port, dbname=self.s.db_name,
                                user=self.s.db_user, password=self.db_password,
                                connect_timeout=10,
                                application_name=f"collector_daemon pid={os.getpid()}")

    def refresh_db_snapshot(self):
        snap = {"reachable": False}
        conn = None
        try:
            conn = self.db_connect()
            conn.autocommit = True
            snap["reachable"] = True
            with conn.cursor() as cur:
                cur.execute("SELECT pg_database_size(current_database()), "
                            "to_regclass('ad_intel.schema_migration_history') IS NOT NULL;")
                size, tracked = cur.fetchone()
                snap["size_bytes"] = size
                if not tracked:
                    snap["schema_version"] = None
                else:
                    cur.execute("SELECT max(version_number) FROM ad_intel.schema_migration_history;")
                    version = cur.fetchone()[0]
                    snap["schema_version"] = version
                    queries = {
                        "push_backlog": (43, "SELECT count(*) FROM ad_intel.control_evidence_run "
                                             "WHERE push_status IN ('pending', 'partial');"),
                        "missing_partitions": (41, "SELECT ad_intel.missing_current_partitions();"),
                        "entra_failed_sources": (42, "SELECT COALESCE(json_agg(json_build_object("
                                                     "'source', source, 'status', left(status, 300)) "
                                                     "ORDER BY source), '[]') FROM "
                                                     "ad_intel.entra_collection_status "
                                                     "WHERE status <> 'ok';"),
                    }
                    for key, (since, sql) in queries.items():
                        if version is None or version < since:
                            continue
                        try:
                            cur.execute(sql)
                            snap[key] = cur.fetchone()[0]
                        except Exception as exc:  # one failed query is not fatal
                            snap[key + "_error"] = str(exc).strip().splitlines()[0][:300]
        except Exception as exc:
            snap["error"] = str(exc).strip().splitlines()[0][:300] if str(exc).strip() else \
                exc.__class__.__name__
        finally:
            if conn is not None:
                conn.close()
        with self.lock:
            self.db_snapshot = snap

    def check_integrity(self):
        """[1.0.2] After a collection: ad_intel.check_scd2_integrity() (schema
        v50) -- no object or edge may have more than one current row. A
        duplicate is a collector bug: it is logged and reported, and the run
        is not failed for it (the data is still usable)."""
        result = {"checked_at": iso(utcnow())}
        try:
            conn = self.db_connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT max(version_number) FROM "
                                "ad_intel.schema_migration_history;")
                    if (cur.fetchone()[0] or 0) < 50:
                        return
                    cur.execute("SELECT source_table, count(*), min(natural_key) FROM "
                                "ad_intel.check_scd2_integrity() GROUP BY 1 ORDER BY 1;")
                    rows = cur.fetchall()
            finally:
                conn.close()
        except Exception as exc:
            result["error"] = (str(exc).strip().splitlines() or [exc.__class__.__name__])[0][:300]
            self.log.warning(f"Integrity check could not run: {result['error']}")
        else:
            result["duplicates"] = {table: count for table, count, _example in rows}
            if rows:
                self.log.warning(
                    "Integrity check: keys with more than one current row (a collector bug; "
                    "please report it): " + "; ".join(
                        f"{table}: {count} (e.g. {example})" for table, count, example in rows))
            else:
                self.log.info("Integrity check: no duplicate current rows")
        with self.lock:
            self.persist["integrity"] = result
        self.save_persist()

    def push_backlog(self):
        """Evaluation runs not yet accepted by the API, or None if unknown."""
        try:
            conn = self.db_connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT count(*) FROM ad_intel.control_evidence_run "
                                "WHERE push_status IN ('pending', 'partial');")
                    return cur.fetchone()[0]
            finally:
                conn.close()
        except Exception:
            return None

    def entra_client_args(self, cfg):
        """--domain-fqdn when configured; otherwise --client-id of the only
        domain in the database. Returns (args, problem)."""
        if cfg.ad.domain_fqdn:
            return ["--domain-fqdn", cfg.ad.domain_fqdn], None
        try:
            conn = self.db_connect()
            try:
                with conn.cursor() as cur:
                    cur.execute("SELECT client_id::text, domain_fqdn FROM ad_intel.client "
                                "ORDER BY domain_fqdn;")
                    rows = cur.fetchall()
            finally:
                conn.close()
        except Exception as exc:
            return None, f"cannot look up the AD domain in the database: {str(exc).strip()[:200]}"
        if len(rows) == 1:
            return ["--client-id", rows[0][0]], None
        if not rows:
            return None, "no AD domain has been collected yet"
        return None, (f"the database holds {len(rows)} AD domains; set ad.domain_fqdn to say "
                      f"which one the Entra tenant belongs to")

    # --- background threads ---------------------------------------------------

    def lease_loop(self):
        """Takes the lease and keeps it. Only in FortifyData mode."""
        backoff = 30
        while not self.threads_stop.is_set():
            try:
                if not self.lease_ready.is_set():
                    try:
                        self.lease_seconds = self.platform.activate()
                    except pc.LicenseInUse as exc:
                        self._lease_problem("license_in_use", exc)
                        self.threads_stop.wait(self.s.retry_interval)
                        continue
                    except pc.LicenseRefused as exc:
                        self._lease_problem("license_refused", exc)
                        self.threads_stop.wait(self.s.retry_interval)
                        continue
                    except pc.PlatformError as exc:
                        self._lease_problem("platform_unreachable", exc)
                        self.threads_stop.wait(min(max(exc.retry_after or 0, backoff),
                                                   self.s.retry_interval))
                        backoff = min(backoff * 2, self.s.retry_interval)
                        continue
                    backoff = 30
                    with self.lock:
                        self.lease_status = "held"
                        self.lease_last_renewed = utcnow()
                        self.lease_error = None
                    self.lease_ready.set()
                    self.log.info(f"Lease taken (instance {self.instance_id}, "
                                  f"{self.lease_seconds} s, renewed every "
                                  f"{self.s.renew_interval} s)")
                    self.write_status()
                    continue
                lease = self.lease_seconds or pc.DEFAULT_LEASE_SECONDS
                if self.threads_stop.wait(max(5, min(self.s.renew_interval, lease / 3))):
                    break
                try:
                    self.platform.renew()
                    with self.lock:
                        self.lease_last_renewed = utcnow()
                        if self.lease_error:
                            self.log.info("Lease renewal works again")
                        self.lease_error = None
                        self.lease_status = "held"
                except pc.LeaseLost as exc:
                    self.lease_ready.clear()
                    self._lease_problem("lost", exc)
                except pc.PlatformError as exc:
                    with self.lock:
                        self.lease_error = str(exc)
                        expired = (utcnow() - self.lease_last_renewed).total_seconds() >= (
                            self.lease_seconds or pc.DEFAULT_LEASE_SECONDS)
                    self.log.warning(f"Lease renewal failed: {exc}")
                    if expired:
                        self.lease_ready.clear()
                        self._lease_problem("expired", "no renewal succeeded within the lease "
                                                       "time; re-activating")
            except Exception:
                self.log.exception("Unexpected error in the lease thread")
                self.threads_stop.wait(30)

    def _lease_problem(self, status, exc):
        with self.lock:
            repeated = self.lease_status == status and self.lease_error == str(exc)
            self.lease_status = status
            self.lease_error = str(exc)
        if not repeated:
            self.log.warning(f"Lease: {status}: {exc}")
        self.write_status()

    def health_loop(self):
        while not self.threads_stop.is_set():
            try:
                self.refresh_db_snapshot()
                report = self.health_report()
                self.write_status(report)
                try:
                    self.platform.report_health(report)
                    if self._last_health_error:
                        self.log.info("Health reports reach the platform again")
                    self._last_health_error = None
                except pc.PlatformError as exc:
                    if str(exc) != self._last_health_error:
                        self.log.warning(f"Health report not delivered: {exc}")
                    self._last_health_error = str(exc)
            except Exception:
                self.log.exception("Unexpected error in the health thread")
            self.threads_stop.wait(self.s.health_interval)

    # --- configuration --------------------------------------------------------

    def _fingerprint(self, cfg):
        """Keyed hash of the whole configuration (secrets included) to notice
        a change. The key is random, kept only in the state directory, and
        the hash is never sent or logged."""
        text = json.dumps({"schedule": vars(cfg.schedule), "ad": vars(cfg.ad),
                           "entra": vars(cfg.entra) if cfg.entra else None,
                           "version": cfg.version}, sort_keys=True, default=str)
        return hmac.new(self._fp_key, text.encode("utf-8"), hashlib.sha256).hexdigest()

    def refresh_config(self):
        """Fetches the run configuration. Returns True when one is usable."""
        try:
            cfg = self.platform.fetch_config()
        except pc.ConfigError as exc:
            self._config_problem("config_error", str(exc))
            return False
        except pc.LicenseRefused as exc:
            self._config_problem("license_refused", str(exc))
            return False
        except pc.PlatformError as exc:
            self._config_problem("platform_unreachable", str(exc))
            return False
        fingerprint = self._fingerprint(cfg)
        with self.lock:
            old, old_fp = self.config, self.config_fingerprint
            self.config, self.config_fingerprint = cfg, fingerprint
            self.config_fetched_at = utcnow()
            had_error, self.config_error = self.config_error, None
        if old is None or old_fp != fingerprint or had_error:
            self.log.info(f"Configuration: {cfg.summary()}")
            for warning in cfg.warnings:
                self.log.warning(f"Configuration: {warning}")
        if old is not None and old_fp != fingerprint:
            self._configuration_changed(old, cfg)
        elif old is None:
            # First fetch since the start: compare with the failed run's.
            last = self.persist.get("last_run") or {}
            if (last.get("outcome") == FAILED and last.get("config_fingerprint")
                    and last["config_fingerprint"] != fingerprint):
                self.log.info("The configuration changed since the last run failed: running "
                              "again now")
                self.next_due = utcnow()
        return True

    def _config_problem(self, state, message):
        with self.lock:
            repeated = self.config_error == message
            self.config_error = message
        if not repeated:
            self.log.error(f"Configuration: {message}")
        self.set_state(state, message)

    def _configuration_changed(self, old, new):
        now = utcnow()
        last = self.persist.get("last_run") or {}
        if (last.get("outcome") == FAILED and self.next_due is not None
                and self.next_due > now):
            self.log.info("The configuration changed since the last run failed: running again "
                          "now")
            self.next_due = now
        elif str(old.schedule) != str(new.schedule) and self.next_due is not None \
                and self.next_due > now:
            self.next_due = next_occurrence(new.schedule, now)
            self.log.info(f"Schedule changed to {new.schedule}: next run "
                          f"{local_text(self.next_due, new.schedule)}")

    def config_refresh_interval(self):
        last = self.persist.get("last_run") or {}
        if self.config_error or last.get("outcome") == FAILED:
            return self.s.retry_interval
        return CONFIG_REFRESH_SECONDS

    # --- scheduling -----------------------------------------------------------

    def initial_due(self, now):
        schedule = self.config.schedule
        last_attempt = parse_iso(self.persist.get("last_attempt_started"))
        missed = previous_occurrence(schedule, now)
        if last_attempt is None:
            self.log.info("No run has been started yet: running now")
            return now
        if last_attempt < missed:
            self.log.info(f"The run scheduled for {local_text(missed, schedule)} was missed "
                          f"(last run started {local_text(last_attempt, schedule)}): running now")
            return now
        return next_occurrence(schedule, now)

    def wait(self, seconds):
        """Sleeps, waking early on a stop request. True when stopping."""
        return self.stop_event.wait(max(0.0, seconds))

    def run_forever(self):
        threads = [threading.Thread(target=self.health_loop, name="health", daemon=True)]
        if self.platform.needs_lease:
            self.lease_status = "activating"
            threads.append(threading.Thread(target=self.lease_loop, name="lease", daemon=True))
        else:
            self.lease_ready.set()
        for t in threads:
            t.start()
        try:
            while not self.stop_event.is_set():
                try:
                    self._tick()
                except Exception:
                    self.log.exception("Unexpected error; continuing in "
                                       f"{self.s.retry_interval} s")
                    self.set_state("error", "unexpected error, see the log")
                    self.wait(self.s.retry_interval)
        finally:
            self.shutdown(threads)

    def _tick(self):
        if not self.lease_ready.is_set():
            with self.lock:
                status, error = self.lease_status, self.lease_error
            self.set_state("waiting_for_lease" if status in ("activating", "lost", "expired")
                           else status, error or "")
            self.lease_ready.wait(5)
            return
        now = utcnow()
        if (self.config is None or self.config_fetched_at is None
                or (now - self.config_fetched_at).total_seconds()
                >= self.config_refresh_interval()):
            if not self.refresh_config():
                self.wait(self.s.retry_interval)
                return
        if self.next_due is None:
            self.next_due = self.initial_due(now)
        if now >= self.next_due:
            # Fresh configuration (and secrets) for the run itself.
            if (now - self.config_fetched_at).total_seconds() > 60 and not self.refresh_config():
                self.wait(self.s.retry_interval)
                return
            outcome = self.run_once()
            if outcome == DEFERRED:
                self.wait(self.s.retry_interval)
            elif outcome != INTERRUPTED:
                self.next_due = next_occurrence(self.config.schedule, utcnow())
                self.log.info(f"Next run: {local_text(self.next_due, self.config.schedule)}")
            return
        push_due = parse_iso(self.persist.get("push_retry_due"))
        if push_due is not None and not self.push_enabled:
            with self.lock:
                self.persist.pop("push_retry_due", None)
            self.save_persist()
            push_due = None
        if push_due is not None and now >= push_due:
            self.push_only("retry of a failed push")
            return
        self.set_state("waiting", f"next run {local_text(self.next_due, self.config.schedule)}")
        until = [self.next_due, now + timedelta(seconds=self.config_refresh_interval())]
        if push_due is not None:
            until.append(push_due)
        self.wait(min(300, (min(until) - now).total_seconds()))

    # --- the run --------------------------------------------------------------

    def run_once(self):
        """One complete run with the current configuration. Returns the
        outcome."""
        cfg = self.config
        started = utcnow()
        previous_attempt = self.persist.get("last_attempt_started")
        with self.lock:
            self.persist["last_attempt_started"] = iso(started)
        self.save_persist()
        self.log.info(f"=== Run starting ({cfg.summary()})")
        steps = []
        outcome, note = self._pipeline(cfg, steps)
        finished = utcnow()
        if outcome in (DEFERRED, INTERRUPTED):
            # Not an attempt that counts: a postponed run is retried shortly,
            # and a run stopped by a stop request is run again after the
            # restart (the scheduled time then counts as missed).
            with self.lock:
                if previous_attempt:
                    self.persist["last_attempt_started"] = previous_attempt
                else:
                    self.persist.pop("last_attempt_started", None)
            self.save_persist()
        if outcome == DEFERRED:
            self.log.warning(f"=== Run postponed: {note}; trying again in "
                             f"{self.s.retry_interval} s")
            self.set_state("postponed", note)
            return outcome
        record = {"started": iso(started), "finished": iso(finished), "outcome": outcome,
                  "note": note, "config_version": cfg.version,
                  "config_fingerprint": self.config_fingerprint,
                  "steps": [s.as_dict() for s in steps]}
        with self.lock:
            self.persist["last_run"] = record
            if outcome in (OK, WARNING):
                self.persist["last_success"] = iso(finished)
        self.save_persist()
        level = logging.INFO if outcome == OK else logging.WARNING
        self.log.log(level, f"=== Run {outcome}" + (f": {note}" if note else "")
                     + f" ({int((finished - started).total_seconds())} s)")
        if any(s.step == "adprofiler" and s.rc == RC_OK for s in steps):
            self.check_integrity()
        self.prune_old_files()
        self.refresh_db_snapshot()
        self.write_status()
        return outcome

    def _pipeline(self, cfg, steps):
        """Runs the steps; returns (outcome, note)."""
        db_secrets = {"PGPASSWORD": self.db_password}

        def step(name, args, secrets):
            result = self.run_step(name, args, secrets)
            steps.append(result)
            return result

        def stopped_or_locked(result):
            if result.rc == RC_LOCKED:
                return DEFERRED, f"{result.step}: another run holds the run lock"
            if self.stop_event.is_set():
                return INTERRUPTED, f"{result.step} interrupted"
            return None

        # 1. Schema
        result = step("schema_setup", self.db_args(), db_secrets)
        if (end := stopped_or_locked(result)) is not None:
            return end
        if result.rc != RC_OK:
            return FAILED, f"schema_setup failed: {result.summary}"

        # 2. AD
        collection_failed = None
        result = step("adprofiler", self.adprofiler_args(cfg) + self.db_args(),
                      dict(db_secrets, AD_BIND_PASSWORD=cfg.ad.password))
        if (end := stopped_or_locked(result)) is not None:
            return end
        if result.rc != RC_OK:
            collection_failed = f"adprofiler failed: {result.summary}"

        # 3. Entra. [1.0.2] A failure no longer blocks the evaluation of the
        # AD data: adaudit.py --skip-entra then shows the Entra checks as NOT
        # ASSESSED instead of evaluating the Entra data kept from the last
        # successful collection as current.
        entra_problem = None
        if cfg.entra and not collection_failed:
            target, problem = self.entra_client_args(cfg)
            if problem:
                now = utcnow()
                steps.append(StepResult("entra", None, now, now, problem))
                self.log.error(f"[entra] not run: {problem}")
                entra_problem = f"Entra collection not run: {problem}"
            else:
                args = ["--tenant-id", cfg.entra.tenant_id, "--app-id", cfg.entra.app_id] + target
                if cfg.entra.include_pta_agents:
                    args.append("--include-pta-agents")
                result = step("entra", args + self.db_args(),
                              dict(db_secrets, ENTRA_APP_SECRET=cfg.entra.client_secret))
                if (end := stopped_or_locked(result)) is not None:
                    return end
                if result.rc != RC_OK:
                    entra_problem = f"Entra collection failed: {result.summary}"

        # 4. Evaluation and push
        if collection_failed:
            if self.push_enabled:
                backlog = self.push_backlog()
                if backlog == 0:
                    self.log.info("Collection failed: the evaluation is skipped; no earlier run "
                                  "is waiting to be pushed")
                else:
                    self.log.info("Collection failed: the evaluation is skipped; pushing "
                                  + (f"the {backlog} earlier run(s)" if backlog else
                                     "any earlier run") + " still waiting")
                    self._push_step(steps, "adaudit_push_only")
            return FAILED, collection_failed
        args = ["--report-dir", str(self.s.report_dir)]
        if not self.s.excel:
            args.append("--no-excel")
        if entra_problem or not cfg.entra:
            # Not collected in this run (failed, or not configured): any
            # Entra data in the database is older and must not be evaluated
            # as current.
            args.append("--skip-entra")
            if entra_problem:
                self.log.warning(f"{entra_problem}; evaluating the AD data, with the Entra "
                                 f"checks NOT ASSESSED")
        secrets = dict(db_secrets)
        if self.push_enabled:
            args += ["--push"] + self.push_args()
            secrets["FD_ACTIVATION_KEY"] = self.platform.activation_key
        result = step("adaudit", args + self.db_args(), secrets)
        if (end := stopped_or_locked(result)) is not None:
            return end
        if result.rc in (RC_OK, RC_ADAUDIT_INCOMPLETE) and self.push_enabled:
            # Exit 0 means the push went through. adaudit.py reports an
            # incomplete evaluation (3) before a failed push (5), so after a
            # 3 look at what is still waiting.
            with self.lock:
                self.persist.pop("push_retry_due", None)
            if result.rc == RC_ADAUDIT_INCOMPLETE:
                backlog = self.push_backlog()
                if backlog != 0:
                    self._schedule_push_retry(
                        f"{backlog} evaluation run(s) still waiting to be pushed"
                        if backlog else "the push may not have completed")
        entra_note = f"{entra_problem}; Entra checks not assessed" if entra_problem else ""
        if result.rc == RC_OK:
            return (WARNING, entra_note) if entra_problem else (OK, "")
        if result.rc == RC_ADAUDIT_INCOMPLETE:
            return WARNING, "; ".join(filter(None, [
                "adaudit: the evaluation is incomplete (some plugins failed)", entra_note]))
        if result.rc == RC_ADAUDIT_PUSH_FAILED:
            self._schedule_push_retry()
            return WARNING, "; ".join(filter(None, [
                f"evaluated, but the push failed: {result.summary}", entra_note]))
        return FAILED, "; ".join(filter(None, [f"adaudit failed: {result.summary}", entra_note]))

    def _push_step(self, steps, label):
        result = self.run_step(label, ["--push-only"] + self.push_args() + self.db_args(),
                               {"PGPASSWORD": self.db_password,
                                "FD_ACTIVATION_KEY": self.platform.activation_key},
                               script="adaudit")
        if steps is not None:
            steps.append(result)
        if result.rc == RC_OK:
            with self.lock:
                self.persist.pop("push_retry_due", None)
        elif result.rc == RC_LOCKED:
            with self.lock:
                self.persist["push_retry_due"] = iso(
                    utcnow() + timedelta(seconds=self.s.retry_interval))
        elif not self.stop_event.is_set():
            self._schedule_push_retry()
        self.save_persist()
        return result

    def _schedule_push_retry(self, why="push failed"):
        due = utcnow() + timedelta(seconds=PUSH_RETRY_SECONDS)
        with self.lock:
            self.persist["push_retry_due"] = iso(due)
        self.log.warning(f"{why[0].upper() + why[1:]}; retrying with --push-only at {iso(due)}")

    def push_only(self, why):
        if self.push_backlog() == 0:
            self.log.info(f"Push retry ({why}): nothing is waiting to be pushed")
            with self.lock:
                self.persist.pop("push_retry_due", None)
            self.save_persist()
            return
        self.log.info(f"=== Push only ({why})")
        self.set_state("pushing", why)
        result = self._push_step(None, "adaudit_push_only")
        self.log.info(f"=== Push only: exit {result.rc}")
        self.refresh_db_snapshot()
        self.write_status()

    def push_args(self):
        """adaudit.py takes the server from the activation key; an override
        ([platform] api_url) is passed on."""
        override = self.platform.api_url_override
        return ["--api-url", override] if override else []

    def db_args(self):
        return ["--pg-host", self.s.db_host, "--pg-port", str(self.s.db_port),
                "--pg-dbname", self.s.db_name, "--pg-user", self.s.db_user,
                "--log-dir", str(self.s.script_log_dir)]

    def adprofiler_args(self, cfg):
        ad = cfg.ad
        args = ["--dc-host", ad.dc_host, "--username", ad.username]
        if ad.ssl:
            args.append("--ssl")
        if ad.port:
            args += ["--port", str(ad.port)]
        if ad.ca_cert_pem and ad.ssl:
            path = self.s.state_dir / CA_CERT_FILE
            path.write_text(ad.ca_cert_pem, encoding="utf-8")
            args += ["--ca-cert", str(path)]
        if ad.sysvol:
            args.append("--sysvol")
            if ad.sysvol_kerberos:
                args.append("--sysvol-kerberos")
            if ad.smb_host:
                args += ["--smb-host", ad.smb_host]
        return args

    # --- one step -------------------------------------------------------------

    def _child_env(self):
        env = {k: v for k, v in os.environ.items() if k not in SCRUBBED_ENV}
        env.update({"PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
                    "PYTHONIOENCODING": "utf-8"})
        if self.s.ca_bundle:
            # adaudit.py's push uses requests, which reads this variable.
            env["REQUESTS_CA_BUNDLE"] = str(self.s.ca_bundle)
        return env

    def run_step(self, name, args, secrets, script=None):
        """Runs one script to completion, its output streamed into the log.
        secrets maps an environment variable name to the secret (None: not
        given); each goes through a pipe as <name>_FILE=/dev/fd/<n>."""
        script_name = SCRIPTS[script or name]
        cmd = [self.s.python, str(self.s.scripts_dir / script_name)] + args
        env = self._child_env()
        fds = []
        started = utcnow()
        try:
            for var, value in secrets.items():
                if value is None:
                    continue
                data = (value + "\n").encode("utf-8")
                if len(data) > MAX_PIPE_SECRET_BYTES:
                    raise ValueError(f"{var} is too long to pass through a pipe")
                read_fd, write_fd = os.pipe()
                fds.append(read_fd)
                try:
                    os.write(write_fd, data)
                finally:
                    os.close(write_fd)
                env[f"{var}_FILE"] = f"/dev/fd/{read_fd}"
            self.log.info(f"[{name}] starting: {script_name} {' '.join(args)}"
                          + (f" (secrets via pipe: {', '.join(sorted(v for v, s in secrets.items() if s is not None))})"
                             if any(s is not None for s in secrets.values()) else ""))
            proc = subprocess.Popen(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, env=env, pass_fds=fds,
                                    cwd=self.s.state_dir / "work", start_new_session=True,
                                    text=True, encoding="utf-8", errors="replace", bufsize=1)
        except (OSError, ValueError) as exc:
            self.log.error(f"[{name}] cannot start: {exc}")
            return StepResult(name, RC_FAILED, started, utcnow(), f"cannot start: {exc}")
        finally:
            for fd in fds:
                os.close(fd)
        with self.lock:
            self.child = proc
            self.current_step = name
            self.current_step_started = started
        self.set_state("running", name)
        if self.stop_event.is_set():   # a stop that came in just before the child existed
            self._terminate_child(proc)
        first_error, last_line = None, None
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            if not line.strip():
                continue
            self.log.info(f"[{name}] {line}")
            last_line = line.strip()
            if first_error is None and ERROR_LINE.search(line):
                first_error = re.sub(r"^\[\d\d:\d\d:\d\d\]\s*", "", line.strip())
        rc = proc.wait()
        with self.lock:
            self.child = None
            self.current_step = None
            self.current_step_started = None
        if rc < 0:
            summary = f"killed by signal {-rc}"
        elif rc == RC_OK:
            summary = ""
        else:
            summary = (first_error or last_line or "no output")[:300]
        finished = utcnow()
        self.log.log(logging.INFO if rc == RC_OK else logging.WARNING,
                     f"[{name}] exit {rc} after {int((finished - started).total_seconds())} s"
                     + (f": {summary}" if summary else ""))
        return StepResult(name, rc, started, finished, summary)

    # --- stopping -------------------------------------------------------------

    def on_signal(self, signum, frame):
        """Runs in the main thread between two bytecodes, possibly while it
        holds a lock (an Event's internal lock in stop_event.wait(), the
        logging lock): so it takes none and only writes the signal number
        to a pipe. signal_watcher() does the rest."""
        try:
            os.write(self._signal_w, bytes([signum]))
        except OSError:
            pass

    def signal_watcher(self):
        """Thread: turns the first signal into a stop request."""
        while True:
            try:
                data = os.read(self._signal_r, 16)
            except OSError:
                return
            if not data:
                return
            if self.stop_event.is_set():
                continue
            self.stop_reason = signal.Signals(data[0]).name
            self.stop_event.set()
            with self.lock:
                child = self.child
            if child is not None:
                self._terminate_child(child)

    def install_signal_handlers(self):
        threading.Thread(target=self.signal_watcher, name="signals", daemon=True).start()
        signal.signal(signal.SIGTERM, self.on_signal)
        signal.signal(signal.SIGINT, self.on_signal)

    def _terminate_child(self, child):
        if child.poll() is not None:
            return
        try:
            child.send_signal(signal.SIGTERM)
        except ProcessLookupError:
            return
        timer = threading.Timer(self.s.stop_timeout, self._kill_child, args=(child,))
        timer.daemon = True
        timer.start()

    def _kill_child(self, child):
        if child.poll() is None:
            self.log.error(f"The running step did not stop within {self.s.stop_timeout} s of "
                           f"SIGTERM; killing it")
            try:
                child.kill()
            except ProcessLookupError:
                pass

    def shutdown(self, threads):
        if self.stop_reason:
            self.log.info(f"Stopping ({self.stop_reason})")
        self.set_state("stopping", self.stop_reason or "")
        self.threads_stop.set()
        for t in threads:
            t.join(timeout=self.s.request_timeout + 5)
        if self.platform is not None and self.platform.needs_lease and self.lease_ready.is_set():
            try:
                self.platform.release()
                self.log.info("Lease released")
            except pc.PlatformError as exc:
                self.log.warning(f"Lease not released ({exc}); it expires on its own")
            self.lease_ready.clear()
            with self.lock:
                self.lease_status = "released"
        self.set_state("stopped", self.stop_reason or "")

    # --- housekeeping ---------------------------------------------------------

    def prune_old_files(self):
        cutoff = time.time() - self.s.log_retention_days * 86400
        removed = 0
        for directory in (self.s.script_log_dir, self.s.report_dir):
            try:
                entries = [e for pattern in PRUNED_PATTERNS for e in directory.glob(pattern)]
            except OSError:
                continue
            for entry in entries:
                try:
                    if entry.is_file() and entry.stat().st_mtime < cutoff:
                        entry.unlink()
                        removed += 1
                except OSError:
                    pass
        if removed:
            self.log.info(f"Removed {removed} script log/report file(s) older than "
                          f"{self.s.log_retention_days} days")


# ============================================================================
# Command line
# ============================================================================

def healthcheck(settings):
    """0 when the status file is fresh and the daemon is not stopped."""
    status = read_json(settings.state_dir / STATUS_FILE)
    generated = parse_iso(status.get("generated_at"))
    if generated is None:
        print("unhealthy: no status file yet")
        return EXIT_FAILED
    interval = status.get("health_interval_seconds") or settings.health_interval
    age = (utcnow() - generated).total_seconds()
    if status.get("state") in ("stopped",):
        print("unhealthy: the daemon has stopped")
        return EXIT_FAILED
    if age > 2 * interval + 60:
        print(f"unhealthy: status not updated for {int(age)} s")
        return EXIT_FAILED
    print(f"healthy: {status.get('state')} {status.get('state_detail') or ''}".rstrip())
    return EXIT_OK


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description=f"collector_daemon.py {VERSION} -- runs the AD/Entra collection, "
                    f"evaluation and push daily and reports health. See docs/DAEMON.md.")
    parser.add_argument("--config", default=os.environ.get("ADAUDIT_DAEMON_CONFIG"),
                        help="TOML configuration file (env ADAUDIT_DAEMON_CONFIG).")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--check-config", action="store_true",
                      help="Check the configuration (and, in local mode, the run "
                           "configuration) and exit.")
    mode.add_argument("--once", action="store_true",
                      help="Take the lease, run once now, release and exit with the run's "
                           "result (0 ok, 1 failed, 75 postponed).")
    mode.add_argument("--healthcheck", action="store_true",
                      help="Exit 0 if the running daemon's status file is fresh (container "
                           "healthcheck).")
    parser.add_argument("--version", action="store_true", help="Print the version and exit.")
    args = parser.parse_args(argv)
    if not args.version and not args.config:
        parser.error("--config (or ADAUDIT_DAEMON_CONFIG) is required")
    return args


def main(argv=None):
    args = parse_args(argv)
    if args.version:
        print(f"collector_daemon.py {VERSION} (platform_client.py {pc.VERSION})")
        return EXIT_OK
    log = setup_logging()
    try:
        doc = load_document(args.config)
        settings = Settings(args.config, doc)
    except (OSError, tomllib.TOMLDecodeError, SettingsError) as exc:
        log.error(f"Configuration file {args.config}: {exc}")
        return EXIT_CONFIG
    if args.healthcheck:
        return healthcheck(settings)

    try:
        settings.log_dir.mkdir(parents=True, exist_ok=True)
        if not args.check_config:  # a check next to the running daemon logs to stderr only
            log = setup_logging(settings.log_dir, settings.log_retention_days)
    except OSError as exc:
        log.error(f"Cannot use the log directory {settings.log_dir}: {exc}")
        return EXIT_CONFIG
    daemon = Daemon(settings, lambda: load_document(args.config), log)
    daemon.install_signal_handlers()
    try:
        daemon.prepare(take_lock=not args.check_config)
    except SettingsError as exc:
        log.error(f"Cannot start: {exc}")
        return EXIT_CONFIG
    except DaemonRunning as exc:
        log.error(str(exc))
        return EXIT_LOCKED

    if args.check_config:
        if settings.mode == "local":
            try:
                cfg = daemon.platform.fetch_config()
            except pc.ConfigError as exc:
                log.error(f"Run configuration: {exc}")
                return EXIT_CONFIG
            log.info(f"Run configuration: {cfg.summary()}")
        else:
            log.info("FortifyData mode: the run configuration comes from the platform after "
                     "activation and is not checked here")
        log.info("Configuration OK")
        return EXIT_OK

    if args.once:
        return run_once_and_exit(daemon)

    daemon.run_forever()
    return EXIT_OK


def run_once_and_exit(daemon):
    threads = [threading.Thread(target=daemon.health_loop, name="health", daemon=True)]
    if daemon.platform.needs_lease:
        threads.append(threading.Thread(target=daemon.lease_loop, name="lease", daemon=True))
    else:
        daemon.lease_ready.set()
    for t in threads:
        t.start()
    outcome = None
    try:
        while not daemon.stop_event.is_set() and not daemon.lease_ready.wait(5):
            with daemon.lock:
                if daemon.lease_status in ("license_refused", "license_in_use"):
                    break
        if daemon.lease_ready.is_set() and not daemon.stop_event.is_set():
            if daemon.refresh_config():
                outcome = daemon.run_once()
    finally:
        daemon.shutdown(threads)
    return {OK: EXIT_OK, WARNING: EXIT_OK, DEFERRED: EXIT_LOCKED,
            INTERRUPTED: EXIT_INTERRUPTED}.get(outcome, EXIT_FAILED)


if __name__ == "__main__":
    sys.exit(main())
