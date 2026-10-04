"""
Plugin 10005: Application Registration Client Secret Has Expired or Expires Soon

An expired client secret isn't a security risk in the usual sense --
it's an outage waiting to happen, the exact failure mode this
project's own entra_graph_collector.py explicitly warns about in its
own credential setup documentation (the person running it needs to
notice and rotate the secret before it lapses). A secret expiring soon
is the same problem, just not yet realized. Flagged here for the same
reason this project already flags computer account password rotation
gaps (plugins 2007/2020): a credential nobody is watching tends to
lapse silently until whatever depends on it breaks.

30 days is used as the "expiring soon" threshold -- long enough to
give whoever owns the integration realistic time to rotate before an
actual outage, short enough that this doesn't fire for secrets that
are in no real danger yet.

[v1.1] Stable identity: object_guid is now md5(application object id ||
secret key_id)::uuid, one finding per secret, so the summary/detail
(which change as a secret crosses its end date) no longer form the
identity -- previously crossing the end date closed the finding as
"remediated" and opened a new one. Dates are judged against the snapshot's
collected_at instead of now(), so results reflect the collected data, not
when adaudit ran. Severity: an expiring-soon secret is a low fail (rotate
before the outage); an already-expired secret is a low warn (inert, just
delete it). New: a still-valid secret with a lifetime over two years is a
medium warn -- long-lived client secrets are a security risk (Microsoft
recommends short lifetimes or certificates/managed identities instead).
"""

PLUGIN = {
    "plugin_id": 10005,
    "category": "Hybrid Identity",
    "name": "Application Registration Client Secret Expired, Expiring Soon, or Long-Lived",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Rotate the secret before (or immediately after, if already "
        "expired) it lapses: Entra admin center -> App registrations -> "
        "select the application -> Certificates & secrets -> New client "
        "secret, then update wherever the old secret's value is "
        "currently configured (this project's own entra_graph_collector.py "
        "included, if this happens to be its own app registration). "
        "Delete the expired/expiring secret entry once the replacement "
        "is confirmed working, rather than leaving stale entries "
        "accumulating indefinitely."
    ),
    "control_id": "HYBRID-005",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Best practices for Microsoft identity platform -- credentials",
         "url": "https://learn.microsoft.com/en-us/entra/identity-platform/security-best-practices-for-app-registration"},
    ],
    "description": (
        "A client secret on an application registration is expired, "
        "expires within 30 days, or (still valid) has a lifetime over "
        "two years. Expiry is an outage risk rather than a security "
        "risk, the failure mode this project's own Graph collector "
        "setup documentation warns about; an already-expired secret is "
        "only a stale entry to delete. A long-lived secret is a "
        "security risk: a leaked value stays usable for years. Dates "
        "are evaluated against the Entra snapshot's collection time. "
        "Only application registrations' passwordCredentials are "
        "collected (not secrets added directly to service principals)."
    ),
    "base_severity": "medium",
    "query": """
        WITH secrets AS (
            SELECT a.entra_object_id, a.display_name, a.app_id, a.collected_at,
                   cred.ord,
                   cred.value->>'display_name' AS secret_display_name,
                   cred.value->>'key_id' AS key_id,
                   (cred.value->>'start_date_time')::timestamptz AS start_date_time,
                   (cred.value->>'end_date_time')::timestamptz AS end_date_time
            FROM entra_application a,
                 jsonb_array_elements(a.password_credentials) WITH ORDINALITY AS cred(value, ord)
            WHERE a.client_id = %(client_id)s
        ),
        classified AS (
            SELECT s.*,
                   CASE WHEN s.end_date_time < s.collected_at THEN 'expired'
                        WHEN s.end_date_time < s.collected_at + interval '30 days' THEN 'expiring'
                        WHEN s.start_date_time IS NOT NULL
                         AND s.end_date_time - s.start_date_time > interval '730 days' THEN 'long_lived'
                   END AS state
            FROM secrets s
            WHERE s.end_date_time IS NOT NULL
        )
        SELECT
            CASE WHEN c.state = 'expiring' THEN 'fail' ELSE 'warn' END AS status,
            md5(c.entra_object_id::text || ':' || COALESCE(c.key_id, 'ord' || c.ord::text))::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.state = 'long_lived' THEN 'medium' ELSE 'low' END AS fd_severity,
            'Application "' || COALESCE(c.display_name, c.app_id::text, c.entra_object_id::text)
                || '" has a client secret that '
                || CASE c.state
                     WHEN 'expired'  THEN 'expired on '
                     WHEN 'expiring' THEN 'expires on '
                     ELSE 'is valid for over two years, until '
                   END
                || to_char(c.end_date_time AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS summary,
            jsonb_build_object(
                'display_name', c.display_name,
                'app_id', c.app_id,
                'secret_display_name', c.secret_display_name,
                'key_id', c.key_id,
                'start_date_time', c.start_date_time,
                'end_date_time', c.end_date_time,
                'state', c.state,
                'already_expired', c.state = 'expired'
            ) AS detail
        FROM classified c
        WHERE c.state IS NOT NULL
    """,
}
