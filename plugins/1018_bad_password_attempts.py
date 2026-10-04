"""
Plugin 1018: Account Has Failed Logon Attempts Near the Lockout Threshold

Purely operational awareness. A nonzero bad_pwd_count in isolation is
routine and usually meaningless -- but it's the exact data point that,
in this project's own testing, turned out to trace back to vulnerability
scanner activity rather than anything alarming. Surfaced here as context,
not as a finding to act on by itself.

[v1.3] Reports only counts at or near the lockout threshold
(badPwdCount >= domain lockoutThreshold - 1, or >= 5 when lockout is off
or the threshold is unknown/1) instead of every non-zero count, which
listed every user who ever mistyped a password. The count moved out of
the summary into detail (it made findings "change" on every run); summary
wording changes once. "Recent" dropped: badPwdCount is NOT replicated --
it is the value on the one DC the collector queried (plus PDC-forwarded
attempts) and persists past the observation window until the next logon
attempt, so it is neither complete nor necessarily recent.
"""

PLUGIN = {
    "plugin_id": 1018,
    "category": "User Accounts",
    "name": "Account Has Failed Logon Attempts Near the Lockout Threshold",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
    'Usually benign and not independently actionable -- review Security Event '
    'ID 4625 on the relevant DC for source information if the count is '
    'unexpectedly high or the account is otherwise rarely used, since routine '
    'vulnerability scanning or a stale cached credential on some device are the '
    'most common causes. Treat as a data point to correlate with other findings '
    'on the same account, not a standalone problem to fix in isolation.'
),
    "control_id": "OPS-002",
    "framework_tags": [],
    "references": [],
    "description": (
        "Purely operational awareness, not a finding to act on by "
        "itself -- a nonzero bad_pwd_count is routine and usually "
        "meaningless in isolation (this project's own testing traced an "
        "unexpected bad_pwd_count on a disabled account back to routine "
        "vulnerability-scanner activity, not anything alarming). Surfaced "
        "as context an auditor might want alongside other findings on the "
        "same account, particularly if the count is unexpectedly high or "
        "the account in question is otherwise never used. Reported only "
        "when badPwdCount is at or above the domain lockout threshold "
        "minus one (5 when account lockout is disabled or the threshold "
        "is unknown). badPwdCount is not replicated: it reflects only the "
        "DC the collector queried (plus attempts forwarded to the PDC "
        "Emulator), and it is not reset when the observation window "
        "expires until the next logon attempt, so it is partial and not "
        "necessarily recent."
    ),
    "base_severity": "info",
    "query": """
        WITH dom AS (
            SELECT d.lockout_threshold
            FROM ad_domain d
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
            ORDER BY d.object_guid
            LIMIT 1
        ),
        thr AS (
            SELECT CASE WHEN (SELECT lockout_threshold FROM dom) > 1
                        THEN (SELECT lockout_threshold FROM dom) - 1
                        ELSE 5 END AS min_count
        )
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'info' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has failed logon attempts at or near the lockout threshold' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'bad_pwd_count', u.bad_pwd_count,
                'is_enabled', u.is_enabled,
                'last_logon_timestamp', u.last_logon_timestamp,
                'reporting_threshold', thr.min_count,
                'note', 'badPwdCount is per-DC (not replicated) -- value from the queried DC only'
            ) AS detail
        FROM ad_user u
        CROSS JOIN thr
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.bad_pwd_count IS NOT NULL
          -- [v1.3] near the lockout threshold only
          AND u.bad_pwd_count >= thr.min_count
    """,
}
