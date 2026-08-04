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
"""

PLUGIN = {
    "plugin_id": 1036,
    "category": "User Accounts",
    "name": "Privileged Account Password Has Not Rotated in Over 3 Years",
    "version": "1.0",
    "revision_date": "2026-07-31",
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
            -- Same definition used throughout this project (see plugin
            -- 1001's own copy of this CTE for the full reasoning):
            -- group-membership-based privilege OR ACL-derived privilege
            -- (directly holding a dangerous/DCSync right, or ownership,
            -- on the domain root/AdminSDHolder).
            SELECT DISTINCT vem.member_guid AS object_guid
            FROM v_effective_group_membership vem
            JOIN directory_object pgo
                ON pgo.object_guid = vem.group_guid AND pgo.client_id = vem.client_id
            JOIN ad_group pg
                ON pg.object_guid = pgo.object_guid AND pg.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
              AND pg.is_protected_group
            UNION
            SELECT do_acl.object_guid
            FROM acl_edge a
            JOIN directory_object do_acl ON do_acl.object_sid = a.trustee_sid AND do_acl.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                               '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                  )
            UNION
            SELECT do_owner.object_guid
            FROM directory_object owned_target
            JOIN directory_object do_owner
                ON do_owner.object_sid = owned_target.owner_sid AND do_owner.client_id = owned_target.client_id
            WHERE owned_target.client_id = %(client_id)s
              AND owned_target.owner_sid IS NOT NULL
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
                || ' has not rotated its password in '
                || EXTRACT(DAY FROM now() - u.pwd_last_set)::int || ' days' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'pwd_last_set', u.pwd_last_set,
                'password_age_days', EXTRACT(DAY FROM now() - u.pwd_last_set)::int,
                'is_enabled', u.is_enabled,
                'admin_count', u.admin_count
            ) AS detail
        FROM ad_user u
        LEFT JOIN privileged_check pc ON pc.object_guid = u.object_guid
        WHERE u.client_id = %(client_id)s
          AND u.valid_to IS NULL
          AND (u.admin_count = 1 OR pc.object_guid IS NOT NULL)
          AND u.pwd_last_set IS NOT NULL
          AND u.pwd_last_set < now() - INTERVAL '1095 days'
          AND u.is_enabled
    """,
}
