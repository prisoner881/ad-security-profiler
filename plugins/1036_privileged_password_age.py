"""
Plugin 1036: Privileged Account Password Has Not Rotated in Over 3 Years

Distinct from plugin 1001 (password set to never expire): that flags
the FLAG being set, regardless of how old the password actually is --
a privileged account with a normal expiration policy applied
correctly, but whose policy allows a very long max age, or whose
owner simply hasn't been prompted to change it in practice (some
organizations don't strictly enforce expiration even when it's
configured), would never trigger 1001 at all despite carrying the
same real-world risk: a credential that's been unchanged for years is
more exposure window for it to have been compromised at some point
without anyone knowing.

Confirmed as a genuine gap by comparing against PingCastle's own
P-AdminPwdTooOld rule (a privileged account's raw elapsed password age
against a fixed threshold, independent of pwdNeverExpires) -- no
equivalent existed in this project before. 1,095 days (3 years) is
PingCastle's own threshold; adopted directly rather than inventing a
different number without a specific reason to.

Uses only ad_user.pwd_last_set and admin_count, both already
collected -- no new collector or schema work needed for this one.

[v1.1] The summary now states the password-last-set time as a date (UTC,
to the day) rather than a day count computed from now(). The count
differed on every run, so an unchanged finding was recorded as 'changed'
on every audit; the date only moves when the underlying attribute does.
Severity and inclusion thresholds are unchanged. The day count is still
reported in detail (password_age_days), which is not part of the
finding's identity because object_guid is always set for this plugin.

[v1.2] "Privileged" now comes from the shared Tier 0 view
v_privileged_principal (schema v34) instead of an inline subquery that
counted GenericAll/GenericWrite/WriteDACL/WriteOwner on, or ownership of,
ANY object with a collected ACL -- every OU, every certificate template --
so OU delegates and whoever created an OU were treated as privileged.
Protected-group membership, control of or ownership of a Tier 0 object
(domain root, AdminSDHolder, DCs, CAs, ...), DCSync, and membership in a
group holding any of those still count. detail gains privilege_sources
(the view's reasons, sorted); summary wording is unchanged.

[v1.3] "Privileged" is v_privileged_principal only: adminCount=1 is
never cleared when an account leaves a protected group (plugin 1025
reports those stale markers), so former admins were reported as
privileged. admin_count stays in detail. pwdLastSet = 0 ("must change
password at next logon") reaches the database as 1601-01-01 (ldap3
converts it before the collector sees it) and was reported as "not
rotated since 1601-01-01"; such accounts are now skipped -- the old
password cannot be used to log on until it is changed.
"""

PLUGIN = {
    "plugin_id": 1036,
    "category": "User Accounts",
    "name": "Privileged Account Password Has Not Rotated in Over 3 Years",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Rotate this account's password now, regardless of whether its "
        "expiration policy currently permits it to remain unchanged. A "
        "privileged credential unchanged for multiple years carries a "
        "large, unaccounted-for exposure window -- it may have been "
        "included in a past breach, logged somewhere insecurely, or "
        "shared in ways no longer visible. For service accounts where "
        "manual rotation is impractical, this is also a strong signal "
        "to migrate to a Managed Service Account (gMSA), which rotates "
        "automatically without manual intervention."
    ),
    "control_id": "USR-136",
    "framework_tags": [],
    "references": [
        {"title": "PingCastle: Privileged Accounts rules -- P-AdminPwdTooOld",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "A privileged account's password has not been changed in over "
        "3 years, independent of whether pwdNeverExpires is set (see "
        "plugin 1001 for that separate check). A long-unrotated "
        "credential -- even one technically subject to an expiration "
        "policy on paper -- represents an unaccounted-for exposure "
        "window: more time for it to have been compromised, logged, or "
        "shared without anyone finding out."
    ),
    "base_severity": "medium",
    "query": """
        WITH privileged_check AS (
            -- [v1.2] "Privileged" is the shared Tier 0 definition in
            -- v_privileged_principal (schema v34): membership, direct or
            -- nested, in an AdminSDHolder-protected group; a control right
            -- (GenericAll/GenericWrite/WriteDACL/WriteOwner) on, or
            -- ownership of, a Tier 0 object; DCSync on the domain root; or
            -- membership in a group that holds any of those. The inline
            -- subquery this replaces counted such a right on, or ownership
            -- of, ANY object with a collected ACL, so every OU delegate and
            -- OU creator was treated as privileged.
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Privileged User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has not rotated its password since '
                || to_char(u.pwd_last_set AT TIME ZONE 'UTC', 'YYYY-MM-DD') AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'pwd_last_set', u.pwd_last_set,
                'password_age_days', EXTRACT(DAY FROM now() - u.pwd_last_set)::int,
                'is_enabled', u.is_enabled,
                'admin_count', u.admin_count,
                'privilege_sources', pc.privilege_sources
            ) AS detail
        FROM ad_user u
        LEFT JOIN privileged_check pc ON pc.object_guid = u.object_guid
        WHERE u.client_id = %(client_id)s
          AND u.valid_to IS NULL
          AND pc.object_guid IS NOT NULL   -- [v1.3] not stale adminCount
          AND u.pwd_last_set IS NOT NULL
          -- [v1.3] pwdLastSet = 0 arrives as the FILETIME epoch 1601-01-01.
          AND u.pwd_last_set > TIMESTAMPTZ '1601-01-02 00:00:00+00'
          AND u.pwd_last_set < now() - INTERVAL '1095 days'
          AND u.is_enabled
    """,
}
