"""
Plugin 1017: Account Currently Locked Out

Purely operational awareness, not a vulnerability -- a locked-out account
usually just means someone mistyped a password too many times. Included
because unexpected/unexplained lockouts, especially clustered ones, can
also be a symptom of an active password-guessing attempt in progress.
"""

PLUGIN = {
    "plugin_id": 1017,
    "category": "User Accounts",
    "name": "Account Currently in a Lockout State",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
    'Investigate the cause before unlocking -- check Security Event ID 4740 on '
    'the PDC Emulator to identify the source workstation/IP of the failed '
    'attempts that triggered the lockout. Blindly unlocking without '
    'understanding why risks allowing an ongoing password-guessing attempt to '
    'continue unnoticed. Once the cause is understood and addressed (or '
    'confirmed benign), unlock via ADUC or `Unlock-ADAccount`.'
),
    "control_id": "OPS-001",
    "framework_tags": [],
    "references": [],
    "description": (
        "Purely operational awareness, not a vulnerability by itself -- "
        "most lockouts are mundane (mistyped password, stale cached "
        "credential on a device). Included because unexpected or "
        "clustered lockouts can also be a symptom of an active "
        "password-guessing attempt against the account, and this data "
        "point costs nothing extra to surface since lockout_time is "
        "already collected."
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
                || ' is currently locked out (since ' || u.lockout_time || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'lockout_time', u.lockout_time,
                'bad_pwd_count', u.bad_pwd_count
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND u.lockout_time IS NOT NULL
    """,
}
