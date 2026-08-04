"""
Plugin 1033: Built-in Administrator Account Used Recently

Distinct from plugin 1004 (which flags the RID-500 built-in
Administrator account simply being enabled): this checks whether it
has actually been used to log on recently. Best practice is that this
account should be reserved for genuine emergencies -- break-glass
access when every named administrative account is unavailable -- with
day-to-day administrative work done through individually attributable
accounts instead. A recent logon means someone is routinely using a
shared, unattributable, lockout-immune account for ordinary work,
which is both a weaker security posture on its own (no individual
accountability for actions taken) and a sign the break-glass
procedure isn't being followed as intended. Confirmed against
PingCastle's own equivalent check, which uses the same 35-day window
and the same underlying attribute (lastLogonTimestamp) this project
already collects.
"""

PLUGIN = {
    "plugin_id": 1033,
    "category": "User Accounts",
    "name": "Built-in Administrator Account Used Recently",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Identify who used this account and why, and move that work to "
        "an individually attributable administrative account instead. "
        "If genuine emergency access was the reason, that's the "
        "correct use case -- document it and move on. If it's routine "
        "use (helpdesk, scheduled tasks, service accounts), that's a "
        "process gap: create named administrative accounts (or a "
        "dedicated service account) for that purpose and reserve this "
        "account exclusively for break-glass scenarios where no other "
        "administrative account is usable."
    ),
    "control_id": "PRIV-110",
    "framework_tags": [],
    "references": [],
    "description": (
        "Distinct from plugin 1004 (which flags this account simply "
        "being enabled): checks whether the built-in Administrator "
        "account (RID 500) has actually logged on within the last 35 "
        "days. Best practice reserves this account for genuine "
        "emergency break-glass access, with day-to-day administrative "
        "work done through individually attributable named accounts. A "
        "recent logon means someone is routinely using a shared, "
        "unattributable, lockout-immune account for ordinary work -- a "
        "weaker security posture with no individual accountability, "
        "and a sign the break-glass procedure isn't being followed. "
        "Confirmed against PingCastle's own equivalent check, which "
        "uses the same 35-day window and the same lastLogonTimestamp "
        "attribute already collected here."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Built-in Administrator account (RID 500, currently named "' || u.sam_account_name
                || '") logged on ' || EXTRACT(DAY FROM now() - u.last_logon_timestamp)::int
                || ' days ago' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'last_logon_timestamp', u.last_logon_timestamp,
                'is_enabled', u.is_enabled
            ) AS detail
        FROM ad_user u
        JOIN directory_object do2 ON do2.object_guid = u.object_guid AND do2.client_id = u.client_id
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND do2.object_sid LIKE '%%-500'
          AND u.last_logon_timestamp IS NOT NULL
          AND u.last_logon_timestamp > now() - INTERVAL '35 days'
    """,
}
