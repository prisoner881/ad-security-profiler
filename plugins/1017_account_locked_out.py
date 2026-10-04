"""
Plugin 1017: Account Currently Locked Out

Purely operational awareness, not a vulnerability -- a locked-out account
usually just means someone mistyped a password too many times. Included
because unexpected/unexplained lockouts, especially clustered ones, can
also be a symptom of an active password-guessing attempt in progress.

[v1.3] "lockoutTime is set" is not "locked out": when the lockout
duration expires AD unlocks the account automatically but leaves
lockoutTime set until the next successful logon or an admin unlock, so
expired lockouts were reported as current. An account now counts as locked
only when its effective lockout duration is 0 (locked until an admin
unlocks) or lockoutTime + duration is later than the collection run's
completion time. The effective duration comes from the user's resultant
FGPP (directly applied PSO first, else via group membership, lowest
msDS-PasswordSettingsPrecedence, ties by lowest GUID) or else the domain
policy; when neither is known the account is not reported. (The
authoritative msDS-User-Account-Control-Computed UF_LOCKOUT bit is not
collected.) The summary timestamp is now formatted explicitly in UTC
(was session-TimeZone/DateStyle dependent, with microseconds), so
existing summaries change once.
"""

PLUGIN = {
    "plugin_id": 1017,
    "category": "User Accounts",
    "name": "Account Currently in a Lockout State",
    "version": "1.3",
    "revision_date": "2026-10-04",
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
        "already collected. An account is reported only while its "
        "lockout is still in force at collection time (lockoutTime plus "
        "the resultant FGPP's or domain's lockout duration; duration 0 = "
        "until an administrator unlocks it) -- expired lockouts leave "
        "lockoutTime set and are not reported."
    ),
    "base_severity": "info",
    "query": """
        WITH run AS (
            SELECT COALESCE(completed_at, started_at) AS at
            FROM sync_run
            WHERE run_id = %(run_id)s AND client_id = %(client_id)s
        ),
        dom AS (
            SELECT d.lockout_duration_seconds
            FROM ad_domain d
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
            ORDER BY d.object_guid
            LIMIT 1
        ),
        locked_candidates AS (
            SELECT u.*
            FROM ad_user u
            WHERE u.valid_to IS NULL
              AND u.client_id = %(client_id)s
              AND u.is_enabled
              AND u.lockout_time IS NOT NULL
        ),
        pso_candidates AS (
            -- PSOs applied directly to the user (rank 0) or to a group the
            -- user belongs to, directly or nested (rank 1).
            SELECT lc.object_guid AS user_guid, 0 AS via_group,
                   f.object_guid AS pso_guid, f.policy_name, f.precedence,
                   f.lockout_duration_seconds
            FROM locked_candidates lc
            JOIN fgpp_applies_to_edge e
                ON e.target_guid = lc.object_guid AND e.client_id = lc.client_id
               AND e.valid_to IS NULL
            JOIN ad_fgpp f
                ON f.object_guid = e.pso_guid AND f.client_id = e.client_id
               AND f.valid_to IS NULL
            UNION ALL
            SELECT lc.object_guid, 1,
                   f.object_guid, f.policy_name, f.precedence,
                   f.lockout_duration_seconds
            FROM locked_candidates lc
            JOIN v_effective_group_membership m
                ON m.member_guid = lc.object_guid AND m.client_id = lc.client_id
            JOIN fgpp_applies_to_edge e
                ON e.target_guid = m.group_guid AND e.client_id = m.client_id
               AND e.valid_to IS NULL
            JOIN ad_fgpp f
                ON f.object_guid = e.pso_guid AND f.client_id = e.client_id
               AND f.valid_to IS NULL
        ),
        resultant_pso AS (
            SELECT DISTINCT ON (user_guid)
                   user_guid, pso_guid, policy_name, lockout_duration_seconds
            FROM pso_candidates
            ORDER BY user_guid, via_group, precedence NULLS LAST, pso_guid
        ),
        evaluated AS (
            SELECT lc.*,
                   rp.policy_name AS resultant_pso,
                   CASE WHEN rp.pso_guid IS NOT NULL
                        THEN rp.lockout_duration_seconds
                        ELSE (SELECT lockout_duration_seconds FROM dom)
                   END AS eff_lockout_duration_seconds
            FROM locked_candidates lc
            LEFT JOIN resultant_pso rp ON rp.user_guid = lc.object_guid
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
                || ' is currently locked out (since '
                || to_char(u.lockout_time AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS')
                || ' UTC)' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'lockout_time', u.lockout_time,
                'bad_pwd_count', u.bad_pwd_count,
                'resultant_pso', u.resultant_pso,
                'lockout_duration_seconds', u.eff_lockout_duration_seconds,
                'lockout_expires', CASE WHEN u.eff_lockout_duration_seconds > 0
                    THEN u.lockout_time + make_interval(secs => u.eff_lockout_duration_seconds)
                    END
            ) AS detail
        FROM evaluated u
        CROSS JOIN run
        -- [v1.3] still locked at collection time: duration 0 means locked
        -- until an admin unlocks; NULL (unknown) is not reported.
        WHERE u.eff_lockout_duration_seconds = 0
           OR u.lockout_time + make_interval(secs => u.eff_lockout_duration_seconds) > run.at
    """,
}
