"""
Plugin 1007: Dormant/Stale Enabled User Account

An enabled account that hasn't authenticated in a long time (or has never
authenticated at all, despite existing for a while) is unnecessary attack
surface -- every credential-guessing/enumeration technique that works
against an active account works against a forgotten one too, with nobody
watching for the anomaly.
"""

PLUGIN = {
    "plugin_id": 1007,
    "category": "User Accounts",
    "name": "Dormant Enabled User Account",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
    "Disable or remove accounts inactive beyond the organization's defined "
    'threshold. If an account has a legitimate ongoing but infrequent purpose, '
    'document why explicitly and consider whether it should be reclassified as '
    'a service account with different lifecycle/monitoring expectations rather '
    'than left as an ordinary dormant user account.'
),
    "control_id": "LIFECYCLE-001",
    "framework_tags": [],
    "references": [],
    "description": (
        "An enabled account with no recent authentication activity is "
        "unnecessary attack surface with nobody watching for anomalous "
        "use of it. DoD guidance commonly cites disabling accounts "
        "inactive for 35 days as a baseline; 90 days is used here as a "
        "more conservative, commonly-cited general-purpose threshold "
        "given no single specific STIG rule/threshold was directly "
        "confirmed for this exact check. Covers both accounts that have "
        "gone stale (last_logon_timestamp older than the threshold) and "
        "accounts that appear to have never authenticated at all despite "
        "existing for a while (last_logon_timestamp is NULL but the "
        "account is not brand new)."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || CASE
                     WHEN u.last_logon_timestamp IS NULL THEN ' has never logged on'
                     ELSE ' has not logged on in '
                          || EXTRACT(DAY FROM now() - u.last_logon_timestamp)::int || ' days'
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'last_logon_timestamp', u.last_logon_timestamp,
                'pwd_last_set', u.pwd_last_set,
                'never_logged_on', u.last_logon_timestamp IS NULL
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND (
                (u.last_logon_timestamp IS NOT NULL AND u.last_logon_timestamp < now() - interval '90 days')
                OR (u.last_logon_timestamp IS NULL AND u.pwd_last_set IS NOT NULL
                    AND u.pwd_last_set < now() - interval '90 days')
              )
    """,
}
