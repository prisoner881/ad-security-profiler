"""
Plugin 1018: Account Has Recent Failed Logon Attempts

Purely operational awareness. A nonzero bad_pwd_count in isolation is
routine and usually meaningless -- but it's the exact data point that,
in this project's own testing, turned out to trace back to vulnerability
scanner activity rather than anything alarming. Surfaced here as context,
not as a finding to act on by itself.
"""

PLUGIN = {
    "plugin_id": 1018,
    "category": "User Accounts",
    "name": "Account Has Recent Failed Logon Attempts",
    "version": "1.2",
    "revision_date": "2026-07-15",
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
        "the account in question is otherwise never used."
    ),
    "base_severity": "info",
    "query": """
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'info' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has ' || u.bad_pwd_count || ' recent failed logon attempt(s)' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'bad_pwd_count', u.bad_pwd_count,
                'is_enabled', u.is_enabled,
                'last_logon_timestamp', u.last_logon_timestamp
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.bad_pwd_count IS NOT NULL
          AND u.bad_pwd_count > 0
    """,
}
