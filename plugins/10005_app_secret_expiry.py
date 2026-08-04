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
"""

PLUGIN = {
    "plugin_id": 10005,
    "category": "Hybrid Identity",
    "name": "Application Registration Client Secret Has Expired or Expires Soon",
    "version": "1.0",
    "revision_date": "2026-07-19",
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
    "references": [],
    "description": (
        "A client secret on an application registration is expired, or "
        "expires within 30 days. Not a security risk in the usual sense "
        "-- an outage risk, the exact failure mode this project's own "
        "Graph collector setup documentation warns about needing to "
        "watch for. Flagged for the same reason as computer account "
        "password rotation gaps (plugins 2007/2020): an unwatched "
        "credential tends to lapse silently until something breaks."
    ),
    "base_severity": "medium",
    "query": """
        WITH secrets AS (
            SELECT a.display_name, a.app_id,
                   cred.value->>'display_name' AS secret_display_name,
                   cred.value->>'key_id' AS key_id,
                   (cred.value->>'end_date_time')::timestamptz AS end_date_time
            FROM entra_application a, jsonb_array_elements(a.password_credentials) AS cred(value)
            WHERE a.client_id = %(client_id)s
        )
        SELECT
            'fail' AS status,
            NULL::uuid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN s.end_date_time < now() THEN 'medium' ELSE 'low' END AS fd_severity,
            'Application "' || s.display_name || '" has a client secret that '
                || (CASE WHEN s.end_date_time < now()
                         THEN 'expired on ' || to_char(s.end_date_time, 'YYYY-MM-DD')
                         ELSE 'expires on ' || to_char(s.end_date_time, 'YYYY-MM-DD') END) AS summary,
            jsonb_build_object(
                'display_name', s.display_name,
                'app_id', s.app_id,
                'secret_display_name', s.secret_display_name,
                'key_id', s.key_id,
                'end_date_time', s.end_date_time,
                'already_expired', s.end_date_time < now()
            ) AS detail
        FROM secrets s
        WHERE s.end_date_time IS NOT NULL
          AND s.end_date_time < (now() + interval '30 days')
    """,
}
