"""
Plugin 1007: Dormant/Stale Enabled User Account

An enabled account that hasn't authenticated in a long time (or has never
authenticated at all, despite existing for a while) is unnecessary attack
surface -- every credential-guessing/enumeration technique that works
against an active account works against a forgotten one too, with nobody
watching for the anomaly.

[v1.3] The summary now states the last logon time as a date (UTC, to the
day) rather than a day count computed from now(). The count differed on
every run, so an unchanged finding was recorded as 'changed' on every
audit; the date only moves when the underlying attribute does. Severity
and inclusion thresholds are unchanged.

[v1.4] A never-logged-on account whose pwdLastSet is 0 ("must change
password at next logon" -- the classic pre-created onboarding account with
an admin-set initial password) was never reported: pwdLastSet 0 is stored
as NULL, so the never-logged-on branch failed. That branch now falls back
to whenCreated: COALESCE(pwd_last_set, when_created) older than 90 days.
Summary wording unchanged.
"""

PLUGIN = {
    "plugin_id": 1007,
    "category": "User Accounts",
    "name": "Dormant Enabled User Account",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
    "Disable or remove accounts inactive beyond the organization's defined "
    'threshold. If an account has a legitimate ongoing but infrequent purpose, '
    'document why explicitly and consider whether it should be reclassified as '
    'a service account with different lifecycle/monitoring expectations rather '
    'than left as an ordinary dormant user account.'
),
    "control_id": "LIFECYCLE-001",
    "framework_tags": [
        "NIST-800-53-AC-2(3)",
        "NIST-800-53-AC-2",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.2.6",
        "CIS-CSC-8-5.3",
        "ISO-27001-2022-A.5.18",
        "SOC2-CC6.2",
        "HIPAA-164.308(a)(3)(ii)(C)",
        "MITRE-ATTCK-T1078.002",
    ],
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
        "account is not brand new: its password was last set, or -- when "
        "pwdLastSet is 0 because a change is pending at next logon -- it "
        "was created, more than 90 days ago)."
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
                     ELSE ' has not logged on since '
                          || to_char(u.last_logon_timestamp AT TIME ZONE 'UTC', 'YYYY-MM-DD')
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'last_logon_timestamp', u.last_logon_timestamp,
                'pwd_last_set', u.pwd_last_set,
                'when_created', u.when_created,
                'never_logged_on', u.last_logon_timestamp IS NULL
            ) AS detail
        FROM ad_user u
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND (
                (u.last_logon_timestamp IS NOT NULL AND u.last_logon_timestamp < now() - interval '90 days')
                -- [v1.4] pwdLastSet 0 (must change at next logon) is NULL;
                -- fall back to whenCreated so pre-created, never-used
                -- accounts are reported.
                OR (u.last_logon_timestamp IS NULL
                    AND COALESCE(u.pwd_last_set, u.when_created) < now() - interval '90 days')
              )
    """,
}
