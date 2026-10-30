"""
run_lock.py -- one run at a time for adprofiler.py, entra_graph_collector.py
and adaudit.py
==============================================================================
VERSION: 1.1

adprofiler.py, entra_graph_collector.py and adaudit.py must never run at the
same time against the same database:

    - two adprofiler.py runs both diff AD against the same previous run; the
      second waits on the first one's row locks and then applies changes
      worked out from data that is no longer current, which can leave
      duplicate current versions of objects and edges;
    - two entra_graph_collector.py runs replace the Entra tables step by step
      and interleave;
    - adaudit.py running during a collection evaluates some plugins before
      the collection commits and some after.

Each script calls acquire() once, right after its PostgreSQL settings are
known and before it reads anything from AD, Graph or the database. It opens
a dedicated connection and takes one PostgreSQL session-level advisory lock
(the same lock for all three scripts) on it, without waiting. The lock is
held until the process exits: PostgreSQL releases it when that connection
closes -- normal exit, crash, kill or a lost connection -- so there is no
lock file to go stale. If another run holds it, acquire() raises RunLocked
with a message naming the holder and how to clear the lock by hand; the
script logs it and exits with EXIT_LOCKED (75, EX_TEMPFAIL: nothing was
done, try again later).

The connection's application_name ("<script> pid=<pid> host=<host>") is
what identifies the holder in that message and in pg_stat_activity.

[1.1] The lock connection sits idle for the whole run, so it is kept alive:
TCP keepalives (a NAT or firewall that drops idle connections would close
it, and with it the lock, without the script noticing) and
idle_session_timeout = 0 for that session (a server-wide
idle_session_timeout would end it the same way).
"""

import os
import socket

import psycopg2

# Exit status of a script that did not start because another run holds the
# lock (sysexits.h EX_TEMPFAIL).
EXIT_LOCKED = 75

# The advisory lock: pg_try_advisory_lock(LOCK_KEY1, LOCK_KEY2). In pg_locks
# it appears as locktype 'advisory', classid LOCK_KEY1, objid LOCK_KEY2,
# objsubid 2. LOCK_KEY1 is 'ADSP' as a 32-bit integer.
LOCK_KEY1 = 0x41445350
LOCK_KEY2 = 1

# Kept referenced for the life of the process: if the connection were
# garbage-collected and closed, the lock would be released mid-run.
_held_connection = None


class RunLocked(Exception):
    """Another run holds the lock. str(exc) is the full message to log."""


def _holder(cur):
    """(backend pid, application_name, client address, backend start) of the
    session holding the lock, or None if it can't be seen (it was released a
    moment ago, or the database user may not see other users' sessions)."""
    cur.execute("""
        SELECT l.pid, a.application_name, a.client_addr::text, a.backend_start
        FROM pg_locks l
        LEFT JOIN pg_stat_activity a ON a.pid = l.pid
        WHERE l.locktype = 'advisory' AND l.classid = %s AND l.objid = %s
          AND l.objsubid = 2 AND l.granted
        LIMIT 1;
    """, (LOCK_KEY1, LOCK_KEY2))
    return cur.fetchone()


def _locked_message(script_name, host, port, dbname, user, holder):
    psql = f"psql -h {host} -p {port} -U {user} -d {dbname}"
    if holder:
        backend_pid, app_name, client_addr, backend_start = holder
        held_by = (f"{app_name or 'an unidentified session'}"
                   + (f" from {client_addr}" if client_addr else "")
                   + (f", running since {backend_start:%Y-%m-%d %H:%M:%S %Z}" if backend_start else "")
                   + f" (PostgreSQL session {backend_pid})")
        terminate = f'{psql} -c "SELECT pg_terminate_backend({backend_pid});"'
    else:
        held_by = "another session (details not visible to this database user)"
        terminate = (f'{psql} -c "SELECT pg_terminate_backend(pid) FROM pg_locks '
                     f"WHERE locktype = 'advisory' AND classid = {LOCK_KEY1} "
                     f'AND objid = {LOCK_KEY2} AND objsubid = 2;"')
    return (
        f"Cannot start {script_name}: another adprofiler.py, entra_graph_collector.py or "
        f"adaudit.py run is in progress against database {dbname} on {host}:{port}.\n"
        f"    Held by: {held_by}.\n"
        f"    These scripts run one at a time; this run did nothing (exit status {EXIT_LOCKED}). "
        f"Try again once that run has finished.\n"
        f"    To clear the lock by hand: it is released automatically when the run holding it "
        f"exits. On the machine named by host= above, check the process named by pid=\n"
        f"      (ps -fp <pid>). Let a working run finish; stop a hung one with kill -INT <pid> "
        f"(clean rollback), or kill <pid> if that has no effect.\n"
        f"    Only if that process no longer exists, end its leftover database session "
        f"(as the database owner or a superuser):\n"
        f"      {terminate}"
    )


def acquire(script_name, host, port, dbname, user, password):
    """Takes the run lock for this process, or raises RunLocked. Connection
    errors (psycopg2.Error) propagate: the script reports them as it does any
    other failure to reach the database."""
    global _held_connection
    app_name = f"{script_name} pid={os.getpid()} host={socket.gethostname()}"[:63]
    conn = psycopg2.connect(host=host, port=port, dbname=dbname, user=user, password=password,
                            application_name=app_name, keepalives=1, keepalives_idle=60,
                            keepalives_interval=10, keepalives_count=6)
    conn.autocommit = True
    with conn.cursor() as cur:
        if conn.server_version >= 140000:  # idle_session_timeout is PostgreSQL 14+
            cur.execute("SET idle_session_timeout = 0;")
        cur.execute("SELECT pg_try_advisory_lock(%s, %s);", (LOCK_KEY1, LOCK_KEY2))
        if cur.fetchone()[0]:
            _held_connection = conn
            return
        holder = _holder(cur)
    conn.close()
    raise RunLocked(_locked_message(script_name, host, port, dbname, user, holder))
