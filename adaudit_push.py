"""
adaudit_push.py -- pushes adaudit.py evaluation runs to the FortifyData AD
audit ingest API (contract 1.0, /api/v2/adaudit/...).

Used only by adaudit.py (--push, --push-only, --push-run, --push-skip); not a
standalone script. Kept out of adaudit.py because it is the only part of the
engine that talks HTTP, and it needs `requests`, which adaudit.py itself
does not.

WHAT IS PUSHED
    The unit is an evaluation run (control_evidence_run): one complete,
    unfiltered execution of adaudit.py. Runs are pushed oldest first, each as
    open -> findings batches -> (newest run only) inventory batches ->
    complete. A failure stops the session: later runs are never pushed ahead
    of an earlier one, because the API orders runs by (collected_at,
    evaluated_at) and ignores a run older than one it already holds. The next
    invocation retries from the oldest unpushed run.

    Each run is complete truth: its whole open finding set, plus the findings
    that closed since the previous run (change_status REMEDIATED or RETIRED),
    plus the plugin roster (control_evidence_run_plugin). The API's
    end-of-run sweep closes the findings of plugins whose roster result is
    clean; ERROR and NOT_ASSESSED plugins keep theirs open.

    Findings are RECONSTRUCTED from control_evidence_fact (bitemporal), not
    taken from adaudit.py's memory, so a run pushed days late -- or replayed
    after an outage -- is exactly what would have been sent live. Change
    labels are derived by comparing the finding set open at this run with the
    set open at the previous complete, unfiltered, non-legacy run:
        open now, not open then         NEW
        open now, same version then     UNCHANGED
        open now, other version then    CHANGED
        open then, closed since         REMEDIATED (RETIRED if its plugin was
                                        retired: closed, not counted as fixed)
    The first run after schema v43 has no such predecessor: every open
    finding is NEW and nothing is closed.

    Plugin text (name, category, control id, references, framework tags) is
    read from today's plugin files; plugin_version is the one stored with
    each finding.

IDENTITY
    run_uuid = UUIDv5(RUN_UUID_NAMESPACE, "<client_id>:<evidence_run_id>"),
    stored on the run and never regenerated, so retries and re-pushes after a
    database restore re-send the same run (the API answers already_ingested).
    client.client_id is the installation's identity (client_id); it never
    changes for a client database.

WHAT LEAVES THE NETWORK
    Findings (including their detail evidence), the roster, the newest run's
    inventory (users, computers, groups, subnets), and the plugin catalogue.
    No credentials or secrets are ever collected, so none can be sent.
    detail larger than DETAIL_MAX_BYTES is trimmed (largest lists first) and
    marked "_truncated"; the full evidence stays in the local database.

DRY RUN
    With a dry-run directory, every request body is written there as JSON
    (numbered, uncompressed) and nothing is sent or recorded: push state is
    left unchanged. No API credentials are needed.
"""

import gzip
import hashlib
import json
import math
import random
import time
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

import psycopg2
import psycopg2.extras

CONTRACT_VERSION = "1.0"

API_SERVERS = {
    "test": "https://api.test.fortifydata.com",
    "us": "https://api.fortifydata.com",
    "eu": "https://api.eu.fortifydata.com",
}

# The API's own caps (contract 1.0). Request bodies are gzipped.
FINDINGS_PER_BATCH = 2000
INVENTORY_ROWS_PER_BATCH = 5000
# The API rejects a finding whose serialized detail reaches 65536 bytes;
# stay clear of the limit.
DETAIL_MAX_BYTES = 60000
# The API keeps 14 months; a run older than this would be expired on arrival.
MAX_RUN_AGE = timedelta(days=425)

# Fixed namespace for run_uuid (UUIDv5). Never change it: every run's
# identity on the API side is derived from it.
RUN_UUID_NAMESPACE = uuid.UUID("6f3b1e2a-9c4d-5e7f-8a1b-2c3d4e5f6a7b")

INVENTORY_TYPES = {8001: "USER", 8002: "COMPUTER", 8003: "GROUP", 8004: "SUBNET"}
INVENTORY_NAME_KEY = {"USER": "sam_account_name", "COMPUTER": "sam_account_name",
                      "GROUP": "sam_account_name", "SUBNET": "subnet_name"}

MAX_ATTEMPTS = 5
RETRYABLE_STATUSES = {429, 500, 502, 503, 504}
BACKOFF_MAX_SECONDS = 60
RETRY_AFTER_MAX_SECONDS = 300


def run_uuid_for(client_id, evidence_run_id):
    return uuid.uuid5(RUN_UUID_NAMESPACE, f"{client_id}:{evidence_run_id}")


class PushError(Exception):
    """The push could not continue; the session stops here and the next
    invocation retries from the oldest unpushed run."""


class AwaitingApproval(PushError):
    """403 on open run: the domain is new and waiting for approval at
    FortifyData (or disabled, or the key is not scoped to the company). Not a
    failure of this installation: runs stay queued."""


# ============================================================================
# JSON helpers
# ============================================================================

def iso(moment):
    """ISO-8601 with an explicit offset, as the API parses it."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_default(value):
    if isinstance(value, datetime):
        return iso(value)
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, uuid.UUID):
        return str(value)
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    if isinstance(value, (bytes, bytearray, memoryview)):
        return bytes(value).hex()
    if isinstance(value, (set, frozenset)):
        return sorted(value, key=str)
    raise TypeError(f"not JSON serializable: {type(value).__name__}")


def to_json(payload, indent=None):
    return json.dumps(payload, default=_json_default, ensure_ascii=False,
                      separators=None if indent else (",", ":"), indent=indent)


def json_safe(value):
    """Round-trips through JSON so rows from psycopg2 (datetimes, UUIDs,
    Decimals) become plain JSON values."""
    return json.loads(to_json(value))


def cap_detail(detail):
    """Returns detail unchanged when it fits DETAIL_MAX_BYTES; otherwise a
    deterministic, trimmed copy: the largest top-level lists are shortened
    first, then oversized strings, and "_truncated" records what was cut.
    Deterministic, so a trimmed finding does not look CHANGED run to run."""
    if detail is None:
        return None
    size = len(to_json(detail).encode("utf-8"))
    if size < DETAIL_MAX_BYTES:
        return detail
    if not isinstance(detail, dict):
        return {"_truncated": {"original_bytes": size,
                               "note": "evidence too large to send; see the local adaudit report"}}
    trimmed = dict(detail)
    cut = {}
    marker = {"original_bytes": size, "lists_shortened": cut,
              "note": "evidence trimmed to fit the API limit; full evidence in the local adaudit report"}

    def fits():
        return len(to_json({**trimmed, "_truncated": marker}).encode("utf-8")) < DETAIL_MAX_BYTES

    lists = sorted((k for k, v in trimmed.items() if isinstance(v, list)),
                   key=lambda k: (-len(to_json(trimmed[k])), k))
    for key in lists:
        if fits():
            break
        original = trimmed[key]
        keep = len(original)
        while keep > 0 and not fits():
            keep //= 2
            trimmed[key] = original[:keep]
        cut[key] = len(original)
    if not fits():
        for key in sorted(trimmed, key=lambda k: (-len(to_json(trimmed[k])), k)):
            if fits():
                break
            if isinstance(trimmed[key], (str, dict, list)) and len(to_json(trimmed[key])) > 1024:
                trimmed[key] = "<omitted: too large>"
                cut[key] = "omitted"
    if not fits():
        return {"_truncated": {"original_bytes": size,
                               "note": "evidence too large to send; see the local adaudit report"}}
    trimmed["_truncated"] = marker
    return trimmed


# ============================================================================
# HTTP
# ============================================================================

class ApiClient:
    """One API server and company. In dry-run mode (dry_run_dir set) every
    request body is written to that directory and a plausible success
    response is returned instead; nothing is sent."""

    def __init__(self, base_url, company_id, api_key, log, compress=True, timeout=120,
                 dry_run_dir=None):
        self.base_url = base_url.rstrip("/")
        self.company_id = company_id
        self.log = log
        self.compress = compress
        self.timeout = timeout
        self.dry_run_dir = Path(dry_run_dir) if dry_run_dir else None
        self._dry_seq = 0
        self.session = None
        if self.dry_run_dir is None:
            import requests  # only needed when actually pushing
            self._requests = requests
            self.session = requests.Session()
            self.session.headers.update({
                "Authorization": f"ApiKey {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "adaudit-push",
            })
        else:
            self.dry_run_dir.mkdir(parents=True, exist_ok=True)

    @property
    def dry_run(self):
        return self.dry_run_dir is not None

    def request(self, method, path, payload, what):
        """Sends one request and returns (status_code, body-or-None).
        Retries network errors, 429 and transient 5xx with backoff
        (Retry-After honoured); raises PushError once retries run out."""
        if self.dry_run:
            return self._dry(path, payload, what)
        raw = to_json(payload).encode("utf-8")
        headers = {}
        if self.compress:
            raw = gzip.compress(raw)
            headers["Content-Encoding"] = "gzip"
        url = f"{self.base_url}{path}"
        attempt = 0
        while True:
            attempt += 1
            resp = None
            try:
                resp = self.session.request(method, url, data=raw, headers=headers,
                                            timeout=self.timeout)
            except self._requests.exceptions.RequestException as exc:
                problem = f"network error: {exc}"
            else:
                if resp.status_code not in RETRYABLE_STATUSES:
                    body = None
                    if resp.content:
                        try:
                            body = resp.json()
                        except ValueError:
                            body = None
                    return resp.status_code, body
                problem = f"HTTP {resp.status_code}"
            if attempt >= MAX_ATTEMPTS:
                raise PushError(f"{what}: still failing after {MAX_ATTEMPTS} attempts ({problem})")
            delay = self._delay(resp, attempt)
            self.log(f"  [WARN] {what} failed ({problem}); retrying in {delay:.0f}s "
                     f"(attempt {attempt + 1} of {MAX_ATTEMPTS})")
            time.sleep(delay)

    @staticmethod
    def _delay(resp, attempt):
        retry_after = resp.headers.get("Retry-After") if resp is not None else None
        if retry_after:
            try:
                return min(max(float(retry_after), 1.0), RETRY_AFTER_MAX_SECONDS)
            except ValueError:
                pass
        return min(2 ** attempt, BACKOFF_MAX_SECONDS) + random.uniform(0, 1)

    def _dry(self, path, payload, what):
        self._dry_seq += 1
        name = path.strip("/").replace("/", "_")
        target = self.dry_run_dir / f"{self._dry_seq:04d}_{name}.json"
        target.write_text(to_json(payload, indent=2), encoding="utf-8")
        if path.endswith("/findings"):
            return 200, {"accepted": len(payload["findings"]), "rejected": 0, "rejected_items": []}
        if path.endswith("/inventory"):
            rows = sum(len(i["rows"]) for i in payload["inventories"])
            return 200, {"accepted": rows, "rejected": 0, "rejected_items": []}
        if path.endswith("/complete"):
            return 200, {"ingest_status": "COMPLETE", "run_uuid": payload["run_uuid"]}
        if path.endswith("/catalogue"):
            return 200, {"created": len(payload["plugins"]), "updated": 0, "unchanged": 0,
                         "rejected": 0, "errors": []}
        return 201, {"schema_version": CONTRACT_VERSION, "run_uuid": payload.get("run_uuid"),
                     "run_id": None, "already_ingested": False}

    # -- endpoints -----------------------------------------------------------

    def open_run(self, payload):
        status, body = self.request("POST", f"/api/v2/adaudit/runs/{self.company_id}", payload,
                                    "open run")
        if status == 403:
            raise AwaitingApproval(
                "the API refused the run (403): the domain is waiting for approval at "
                "FortifyData (always the case for the first run from a new installation), is "
                "disabled, or the API key is not scoped to this company. Runs stay queued.")
        if status == 400:
            raise PushError("open run rejected as invalid (400). The API gives no reason; check "
                            "the payload with --push-dry-run.")
        if status == 404:
            raise PushError("open run: the API could not resolve the domain (404).")
        if status not in (200, 201) or body is None:
            raise PushError(f"open run failed (HTTP {status}).")
        server = str(body.get("schema_version") or "")
        if server and server.split(".")[0] != CONTRACT_VERSION.split(".")[0]:
            raise PushError(f"the API speaks contract {server}; this adaudit.py was built for "
                            f"{CONTRACT_VERSION}. Refusing to push -- upgrade adaudit.py.")
        return body

    def send_batch(self, kind, payload):
        status, body = self.request("POST", f"/api/v2/adaudit/runs/{self.company_id}/{kind}",
                                    payload, f"{kind} batch {payload['batch']}/{payload['batch_count']}")
        if status == 200 and body is not None:
            return body
        reasons = {400: "rejected as invalid (batch numbering, or over the per-batch cap)",
                   403: "refused: domain pending or disabled, or key not scoped to the company",
                   404: "the API holds no run with this run_uuid",
                   409: "the run is already complete, or not receiving"}
        raise PushError(f"{kind} batch {payload['batch']}: {reasons.get(status, f'HTTP {status}')} "
                        f"({status}).")

    def complete(self, payload):
        status, body = self.request("POST", f"/api/v2/adaudit/runs/{self.company_id}/complete",
                                    payload, "complete run")
        if status in (200, 409):
            return status, body or {}
        reasons = {400: "rejected as invalid", 403: "refused (domain pending/disabled or key scope)",
                   404: "the API holds no run with this run_uuid"}
        raise PushError(f"complete run: {reasons.get(status, f'HTTP {status}')} ({status}).")

    def put_catalogue(self, payload):
        status, body = self.request("PUT", "/api/v2/adaudit/plugins/catalogue", payload,
                                    "plugin catalogue")
        if status != 200 or body is None:
            raise PushError(f"plugin catalogue rejected (HTTP {status}).")
        return body


# ============================================================================
# Building a run from the local record
# ============================================================================

FACT_COLUMNS = """
    f.evidence_fact_id, f.control_test_id, ct.plugin_id, f.identity_guid, f.object_guid,
    f.status, f.stig_severity, f.stig_reference, f.tool_severity, f.tool_reference,
    f.fd_severity, f.summary, f.detail, f.plugin_version, f.change_status,
    f.evidence_run_id_valid_from, f.evidence_run_id_valid_to, f.valid_from
"""


def _open_at(cur, client_id, run_id):
    """Finding versions open as of evidence run run_id, keyed by
    (control_test_id, identity_guid)."""
    if run_id is None:
        return {}
    cur.execute(f"""
        SELECT {FACT_COLUMNS}
        FROM control_evidence_fact f
        JOIN control_test ct ON ct.control_test_id = f.control_test_id
        WHERE f.client_id = %(c)s
          AND f.evidence_run_id_valid_from <= %(r)s
          AND (f.evidence_run_id_valid_to IS NULL OR f.evidence_run_id_valid_to > %(r)s);
    """, {"c": client_id, "r": run_id})
    return {(r["control_test_id"], r["identity_guid"]): r for r in cur.fetchall()}


def previous_run_id(cur, client_id, evidence_run_id):
    """The run change labels are relative to: the latest earlier run that
    completed, was unfiltered and is not legacy. Deterministic, whatever has
    or has not been pushed, so a live push and a replay agree."""
    cur.execute("""
        SELECT max(evidence_run_id) AS prev FROM control_evidence_run
        WHERE client_id = %s AND evidence_run_id < %s AND status = 'complete'
          AND NOT is_filtered AND push_status <> 'legacy';
    """, (client_id, evidence_run_id))
    return cur.fetchone()["prev"]


def plugin_metadata(cur, plugins):
    """plugin_id -> name/category/control id/tags/references: today's plugin
    files first, then control_test / control_catalog for plugins whose file
    is gone (their last findings are still pushed as they close)."""
    meta = {}
    cur.execute("""
        SELECT ct.plugin_id, ct.control_id, ct.category, ct.test_name, ct.plugin_version,
               cc.framework_tags, cc.severity
        FROM control_test ct LEFT JOIN control_catalog cc ON cc.control_id = ct.control_id
        WHERE ct.plugin_id IS NOT NULL;
    """)
    for r in cur.fetchall():
        meta[r["plugin_id"]] = {
            "name": r["test_name"], "category": r["category"], "control_id": r["control_id"],
            "framework_tags": list(r["framework_tags"] or []), "references": [],
            "base_severity": r["severity"], "version": r["plugin_version"],
        }
    for p in plugins:
        meta[p["plugin_id"]] = {
            "name": p["name"], "category": p["category"], "control_id": p.get("control_id"),
            "framework_tags": list(p.get("framework_tags") or []),
            "references": list(p.get("references") or []),
            "base_severity": p.get("base_severity"), "version": p.get("version"),
        }
    return meta


def _finding_payload(row, label, meta, detected_at):
    m = meta.get(row["plugin_id"], {})
    item = {
        "identity_guid": str(row["identity_guid"]),
        "object_guid": str(row["object_guid"]) if row["object_guid"] else None,
        "plugin_id": row["plugin_id"],
        "plugin_version": row["plugin_version"],
        "category": m.get("category"),
        "name": m.get("name"),
        "control_id": m.get("control_id"),
        "status": row["status"].upper(),
        "change_status": label,
        "fd_severity": row["fd_severity"].upper() if row["fd_severity"] else None,
        "stig_severity": row["stig_severity"],
        "stig_reference": row["stig_reference"],
        "tool_severity": row["tool_severity"].upper() if row["tool_severity"] else None,
        "tool_reference": row["tool_reference"],
        "summary": row["summary"],
        "detail": cap_detail(json_safe(row["detail"])) if row["detail"] is not None else None,
        "references": m.get("references") or None,
        "framework_tags": m.get("framework_tags") or None,
        "detected_at": iso(detected_at),
    }
    return {k: v for k, v in item.items() if v is not None}


def build_findings(conn, client_id, evidence_run_id, meta):
    """The run's finding set with change labels (see module docstring).
    Returns (findings, counts)."""
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        prev = previous_run_id(cur, client_id, evidence_run_id)
        now = _open_at(cur, client_id, evidence_run_id)
        then = _open_at(cur, client_id, prev)
        closed = {}
        if prev is not None:
            cur.execute(f"""
                SELECT DISTINCT ON (f.control_test_id, f.identity_guid) {FACT_COLUMNS}
                FROM control_evidence_fact f
                JOIN control_test ct ON ct.control_test_id = f.control_test_id
                WHERE f.client_id = %(c)s
                  AND f.evidence_run_id_valid_to > %(p)s AND f.evidence_run_id_valid_to <= %(r)s
                ORDER BY f.control_test_id, f.identity_guid,
                         f.evidence_run_id_valid_to DESC, f.evidence_fact_id DESC;
            """, {"c": client_id, "p": prev, "r": evidence_run_id})
            closed = {(r["control_test_id"], r["identity_guid"]): r for r in cur.fetchall()}
        cur.execute("""
            SELECT control_test_id, identity_guid, min(valid_from) AS first_seen
            FROM control_evidence_fact
            WHERE client_id = %s AND evidence_run_id_valid_from <= %s
            GROUP BY control_test_id, identity_guid;
        """, (client_id, evidence_run_id))
        first_seen = {(r["control_test_id"], r["identity_guid"]): r["first_seen"]
                      for r in cur.fetchall()}

    counts = {"new": 0, "changed": 0, "unchanged": 0, "remediated": 0, "retired": 0,
              "skipped_pass": 0}
    findings = []
    for key, row in now.items():
        if row["status"] not in ("fail", "warn"):
            counts["skipped_pass"] += 1
            continue
        earlier = then.get(key)
        if earlier is None:
            label = "NEW"
        elif earlier["evidence_fact_id"] == row["evidence_fact_id"]:
            label = "UNCHANGED"
        else:
            label = "CHANGED"
        counts[label.lower()] += 1
        findings.append(_finding_payload(row, label, meta, first_seen.get(key)))
    for key, earlier in then.items():
        if key in now:
            continue
        row = closed.get(key, earlier)
        if row["status"] not in ("fail", "warn"):
            continue
        label = "RETIRED" if row.get("change_status") == "retired" else "REMEDIATED"
        counts[label.lower()] += 1
        findings.append(_finding_payload(row, label, meta, first_seen.get(key)))
    findings.sort(key=lambda f: (f["plugin_id"], f["identity_guid"]))
    return findings, counts, prev


def build_roster(conn, evidence_run_id, meta):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT plugin_id, plugin_version, rollup, finding_count, error_message
            FROM control_evidence_run_plugin WHERE evidence_run_id = %s ORDER BY plugin_id;
        """, (evidence_run_id,))
        rows = cur.fetchall()
    roster = []
    for r in rows:
        m = meta.get(r["plugin_id"], {})
        entry = {
            "plugin_id": r["plugin_id"], "plugin_version": r["plugin_version"],
            "name": m.get("name"), "category": m.get("category"),
            "control_id": m.get("control_id"),
            "base_severity": m["base_severity"].upper() if m.get("base_severity") else None,
            "plugin_type": "FINDING", "framework_tags": m.get("framework_tags") or None,
            "rollup": r["rollup"].upper(), "finding_count": r["finding_count"],
            "error_message": r["error_message"],
        }
        roster.append({k: v for k, v in entry.items() if v is not None})
    return roster


def build_inventories(inventory_results):
    """inventory_results: [(plugin, rows-or-None)]. Returns {type: rows}, or
    None when any inventory query failed -- then no inventory is sent and the
    API keeps its previous snapshot, rather than removing objects of a type
    that merely failed to query this time."""
    inventories = {}
    for plugin, rows in inventory_results:
        object_type = INVENTORY_TYPES.get(plugin["plugin_id"])
        if object_type is None:
            continue
        if rows is None:
            return None
        name_key = INVENTORY_NAME_KEY[object_type]
        inventories[object_type] = [r for r in json_safe([dict(r) for r in rows])
                                    if r.get(name_key)]
    return inventories


# ============================================================================
# Push state
# ============================================================================

def _set_state(conn, evidence_run_id, **fields):
    sets = ", ".join(f"{k} = %({k})s" for k in fields)
    with conn.cursor() as cur:
        cur.execute(f"UPDATE control_evidence_run SET {sets} WHERE evidence_run_id = %(id)s;",
                    {**fields, "id": evidence_run_id})
    conn.commit()


def skip_run(conn, evidence_run_id, log):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT push_status FROM control_evidence_run WHERE evidence_run_id = %s;",
                    (evidence_run_id,))
        row = cur.fetchone()
    conn.commit()
    if row is None:
        raise PushError(f"no evaluation run {evidence_run_id}")
    if row["push_status"] == "pushed":
        raise PushError(f"run {evidence_run_id} was already pushed; nothing to skip")
    _set_state(conn, evidence_run_id, push_status="skipped",
               last_push_error="skipped by hand (--push-skip)")
    log(f"Run {evidence_run_id} marked skipped: it will not be pushed. Later runs are pushed "
        f"in its place; they still carry complete truth, so the API's state stays correct.")


# ============================================================================
# Catalogue
# ============================================================================

def catalogue_entries(plugins):
    entries = []
    for p in sorted(plugins, key=lambda x: x["plugin_id"]):
        rev = p.get("revision_date")
        entry = {
            "plugin_id": p["plugin_id"], "plugin_version": p.get("version"), "name": p["name"],
            "category": p.get("category"), "control_id": p.get("control_id"),
            "base_severity": p["base_severity"].upper() if p.get("base_severity") else None,
            "plugin_type": "INVENTORY" if p.get("plugin_type") == "inventory" else "FINDING",
            "revision_date": f"{rev}T00:00:00Z" if rev else None,
            "description": p.get("description"), "remediation": p.get("remediation"),
            "references": p.get("references") or None,
            "framework_tags": p.get("framework_tags") or None,
        }
        entries.append({k: v for k, v in entry.items() if v is not None})
    return entries


def sync_catalogue(api, conn, plugins, tool_version, log):
    """Sends the catalogue when its plugin_id:version set differs from what
    this API server last accepted. The API never rewrites an existing
    (plugin_id, version) pair, so changed plugin text needs a new version."""
    entries = catalogue_entries(plugins)
    fingerprint = hashlib.sha256(
        "\n".join(f"{e['plugin_id']}:{e.get('plugin_version')}" for e in entries).encode()
    ).hexdigest()
    with conn.cursor() as cur:
        cur.execute("SELECT fingerprint FROM push_catalogue_state WHERE api_base_url = %s;",
                    (api.base_url,))
        row = cur.fetchone()
    conn.commit()
    if row and row[0] == fingerprint and not api.dry_run:
        return
    body = api.put_catalogue({
        "schema_version": CONTRACT_VERSION, "emitted_at": iso(datetime.now(timezone.utc)),
        "source": {"tool": "adaudit", "tool_version": tool_version}, "plugins": entries,
    })
    log(f"Plugin catalogue sent: {body.get('created', 0)} created, {body.get('updated', 0)} "
        f"updated, {body.get('unchanged', 0)} unchanged, {body.get('rejected', 0)} rejected.")
    if body.get("rejected"):
        for err in (body.get("errors") or [])[:10]:
            log(f"    - {err}")
        log("  [WARN] Some catalogue entries were rejected; the catalogue will be re-sent next time.")
        return
    if api.dry_run:
        return
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO push_catalogue_state (api_base_url, fingerprint, plugin_count, pushed_at)
            VALUES (%s, %s, %s, now())
            ON CONFLICT (api_base_url) DO UPDATE
                SET fingerprint = EXCLUDED.fingerprint, plugin_count = EXCLUDED.plugin_count,
                    pushed_at = EXCLUDED.pushed_at;
        """, (api.base_url, fingerprint, len(entries)))
    conn.commit()


# ============================================================================
# Pushing runs
# ============================================================================

def _run_rows(conn, client_id, only_run_id=None):
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT e.evidence_run_id, e.client_id, e.sync_run_id, e.executed_at, e.status,
                   e.is_filtered, e.run_uuid, e.push_status, e.push_attempts,
                   s.completed_at AS collected_at, s.dc_queried, s.naming_context,
                   s.run_type::text AS run_type, s.collector_version,
                   c.client_name, c.domain_fqdn, c.domain_sid::text AS domain_sid
            FROM control_evidence_run e
            JOIN sync_run s ON s.run_id = e.sync_run_id
            JOIN client c ON c.client_id = e.client_id
            WHERE e.client_id = %(c)s
              AND (%(only)s::bigint IS NULL AND e.status = 'complete' AND NOT e.is_filtered
                       AND e.push_status IN ('pending', 'partial')
                   OR e.evidence_run_id = %(only)s::bigint)
            ORDER BY e.evidence_run_id;
        """, {"c": client_id, "only": only_run_id})
        rows = cur.fetchall()
        cur.execute("SELECT max(run_id) AS r FROM sync_run WHERE client_id = %s AND status = 'succeeded';",
                    (client_id,))
        latest_sync = cur.fetchone()["r"]
        cur.execute("SELECT max(version_number) AS v FROM schema_migration_history;")
        schema_version = cur.fetchone()["v"]
    conn.commit()
    return rows, latest_sync, schema_version


def _push_one(api, conn, run, meta, inventories, tool_version, schema_version, log):
    rid = run["evidence_run_id"]
    run_uuid = str(run["run_uuid"] or run_uuid_for(run["client_id"], rid))
    if not api.dry_run:
        _set_state(conn, rid, run_uuid=run_uuid, push_attempts=run["push_attempts"] + 1,
                   last_push_attempt_at=datetime.now(timezone.utc))

    findings, counts, prev = build_findings(conn, run["client_id"], rid, meta)
    roster = build_roster(conn, rid, meta)
    tally = {r: sum(1 for e in roster if e["rollup"] == r.upper())
             for r in ("fail", "warn", "pass", "error", "not_assessed")}
    log(f"Pushing evaluation run {rid} (collected {iso(run['collected_at'])}, evaluated "
        f"{iso(run['executed_at'])}): {len(findings)} finding(s) -- {counts['new']} new, "
        f"{counts['changed']} changed, {counts['unchanged']} unchanged, {counts['remediated']} "
        f"remediated, {counts['retired']} retired -- and {len(roster)} roster entries"
        + (f"; inventory {', '.join(f'{k} {len(v)}' for k, v in inventories.items())}"
           if inventories else "") + ".")

    body = api.open_run({
        "schema_version": CONTRACT_VERSION,
        "run_uuid": run_uuid,
        "emitted_at": iso(datetime.now(timezone.utc)),
        "source": {"tool": "adaudit", "tool_version": tool_version,
                   "collector_version": run["collector_version"],
                   "db_schema_version": schema_version},
        "client": {k: v for k, v in {
            "client_id": str(run["client_id"]), "client_name": run["client_name"],
            "domain_fqdn": run["domain_fqdn"], "domain_sid": run["domain_sid"],
        }.items() if v},
        "collection": {
            "run_id": rid, "dc_queried": run["dc_queried"], "naming_context": run["naming_context"],
            "collection_mode": (run["run_type"] or "").upper() or None,
            "collected_at": iso(run["collected_at"]), "evaluated_at": iso(run["executed_at"]),
        },
        "plugins": roster,
        "totals": {"plugins_run": len(roster), "fail": tally["fail"], "warn": tally["warn"],
                   "pass": tally["pass"], "error": tally["error"], "not_applicable": 0,
                   "not_assessed": tally["not_assessed"], "findings": len(findings),
                   "new": counts["new"], "changed": counts["changed"],
                   "unchanged": counts["unchanged"], "remediated": counts["remediated"],
                   "retired": counts["retired"]},
    })
    if body.get("already_ingested"):
        log(f"  Run {rid} was already ingested by the API (run_uuid {run_uuid}); marked pushed.")
        if not api.dry_run:
            _set_state(conn, rid, push_status="pushed", pushed_at=datetime.now(timezone.utc),
                       push_server_run_id=body.get("run_id"), last_push_error=None)
        return
    server_run_id = body.get("run_id")

    rejected = []
    batches_sent = 0
    f_batches = [findings[i:i + FINDINGS_PER_BATCH] for i in range(0, len(findings), FINDINGS_PER_BATCH)]
    for number, batch in enumerate(f_batches, start=1):
        resp = api.send_batch("findings", {"run_uuid": run_uuid, "batch": number,
                                           "batch_count": len(f_batches), "findings": batch})
        batches_sent += 1
        for item in resp.get("rejected_items") or []:
            idx = item.get("index")
            rejected.append({"kind": "finding", "batch": number, **item,
                             "plugin_id": batch[idx]["plugin_id"] if isinstance(idx, int)
                             and 0 <= idx < len(batch) else None})

    inventory_rows = 0
    if inventories:
        flat = [(t, row) for t in sorted(inventories) for row in inventories[t]]
        i_batches = [flat[i:i + INVENTORY_ROWS_PER_BATCH]
                     for i in range(0, len(flat), INVENTORY_ROWS_PER_BATCH)]
        for number, batch in enumerate(i_batches, start=1):
            grouped = {}
            for object_type, row in batch:
                grouped.setdefault(object_type, []).append(row)
            plugin_for = {v: k for k, v in INVENTORY_TYPES.items()}
            resp = api.send_batch("inventory", {
                "run_uuid": run_uuid, "batch": number, "batch_count": len(i_batches),
                "inventories": [{"plugin_id": plugin_for[t], "name": t.title(), "rows": rows}
                                for t, rows in grouped.items()]})
            batches_sent += 1
            inventory_rows += len(batch)
            for item in resp.get("rejected_items") or []:
                rejected.append({"kind": "inventory", "batch": number, **item})

    if rejected:
        log(f"  [WARN] The API rejected {len(rejected)} item(s):")
        for item in rejected[:10]:
            log(f"    - {item['kind']} batch {item['batch']} [{item.get('index')}] "
                f"plugin {item.get('plugin_id')} {item.get('identity_guid') or ''}: {item.get('error')}")

    status, done = api.complete({
        "run_uuid": run_uuid, "run_finished_at": iso(datetime.now(timezone.utc)),
        "findings_sent": len(findings), "inventory_rows_sent": inventory_rows,
        "batches_sent": batches_sent, "roster_size": len(roster), "status": "COMPLETE",
    })
    rejection_note = (f"{len(rejected)} item(s) rejected, e.g. "
                      + "; ".join(f"{r['kind']} plugin {r.get('plugin_id')} "
                                  f"{r.get('identity_guid') or ''}: {r.get('error')}"
                                  for r in rejected[:5])) if rejected else None
    ingest = str(done.get("ingest_status") or "").upper()
    if status == 200 or ingest == "COMPLETE":
        log(f"  Run {rid} accepted as COMPLETE (API run id {done.get('run_id') or server_run_id}; "
            f"{done.get('remediated_findings', 0)} remediated, {done.get('retired_findings', 0)} "
            f"retired, {done.get('stale_inventory_removed', 0)} stale inventory removed).")
        if not api.dry_run:
            _set_state(conn, rid, push_status="pushed", pushed_at=datetime.now(timezone.utc),
                       push_server_run_id=done.get("run_id") or server_run_id,
                       last_push_error=rejection_note)
        return
    mismatch = done.get("mismatch") or {}
    message = (f"the API closed run {rid} as {ingest or 'PARTIAL'}: declared and received counts "
               f"disagree ({to_json(mismatch)})" + (f"; {rejection_note}" if rejection_note else ""))
    if not api.dry_run:
        _set_state(conn, rid, push_status="partial", push_server_run_id=server_run_id,
                   last_push_error=message[:4000])
    raise PushError(message + ". It will be re-sent under the same run_uuid next time; if it "
                    "keeps failing, see last_push_error and consider --push-skip.")


def push_runs(conn, client_id, api, plugins, inventory_provider, tool_version, log,
              only_run_id=None):
    """Pushes this client's unpushed runs oldest first (or just only_run_id).
    Returns (pushed_count, awaiting_approval). Raises PushError on failure;
    push state records how far it got."""
    with conn.cursor() as cur:
        cur.execute("SELECT pg_try_advisory_lock(hashtext('adaudit.push'), hashtext(%s));",
                    (str(client_id),))
        locked = cur.fetchone()[0]
    conn.commit()
    if not locked:
        raise PushError("another adaudit.py push for this client is running; not starting a second")
    try:
        runs, latest_sync, schema_version = _run_rows(conn, client_id, only_run_id)
        if only_run_id is not None:
            if not runs:
                raise PushError(f"no evaluation run {only_run_id} for this client")
            r = runs[0]
            if r["status"] != "complete" or r["is_filtered"] or r["push_status"] == "legacy":
                raise PushError(f"run {only_run_id} cannot be pushed: status {r['status']}, "
                                f"filtered {r['is_filtered']}, push status {r['push_status']}")
        if not runs:
            log("Push: nothing to push (every complete run is already pushed).")
            return 0, False
        try:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                meta = plugin_metadata(cur, plugins)
            conn.commit()
            sync_catalogue(api, conn, plugins, tool_version, log)
        except PushError as exc:
            log(f"  [WARN] {exc} Continuing with the runs: findings carry their own plugin names.")

        cutoff = datetime.now(timezone.utc) - MAX_RUN_AGE
        pushed = 0
        log(f"Push: {len(runs)} run(s) to send to {api.base_url}"
            + (" (DRY RUN: written to files, nothing sent)" if api.dry_run else "") + ".")
        for index, run in enumerate(runs):
            if run["collected_at"] is not None and run["collected_at"] < cutoff and only_run_id is None:
                log(f"  Run {run['evidence_run_id']} is older than the API's retention; marked expired.")
                if not api.dry_run:
                    _set_state(conn, run["evidence_run_id"], push_status="expired")
                continue
            newest = index == len(runs) - 1
            inventories = None
            if newest and run["sync_run_id"] == latest_sync:
                inventories = build_inventories(inventory_provider())
                if inventories is None:
                    log("  [WARN] An inventory query failed; sending no inventory with this run "
                        "(the API keeps its previous snapshot).")
            try:
                _push_one(api, conn, run, meta, inventories or {}, tool_version, schema_version, log)
            except AwaitingApproval as exc:
                if not api.dry_run:
                    _set_state(conn, run["evidence_run_id"], last_push_error=str(exc)[:4000])
                log(f"Push paused: {exc}")
                return pushed, True
            except PushError as exc:
                if not api.dry_run:
                    _set_state(conn, run["evidence_run_id"], last_push_error=str(exc)[:4000])
                raise PushError(f"evaluation run {run['evidence_run_id']}: {exc}") from exc
            pushed += 1
        return pushed, False
    finally:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_unlock(hashtext('adaudit.push'), hashtext(%s));",
                        (str(client_id),))
        conn.commit()
