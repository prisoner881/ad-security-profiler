"""
Plugin 3020: Guest Account Is a Member of a Privileged Group

The built-in Guest account (RID 501) is designed to be the lowest-
trust identity in the domain -- disabled by default, and intended for
accounts with no password and no meaningful access. Membership in any
AdminSDHolder-protected privileged group is a severe contradiction of
that design intent: it would mean the domain's lowest-trust built-in
identity inherits Tier-0 access. This is checked regardless of
whether the account is currently enabled, since a disabled Guest
account with privileged group membership is still one re-enablement
away from being exploitable, and its presence in a privileged group
at all is itself the anomaly worth investigating.
"""

PLUGIN = {
    "plugin_id": 3020,
    "category": "Groups",
    "name": "Guest Account Is a Member of a Privileged Group",
    "version": "1.1",
    "revision_date": "2026-08-04",
    "remediation": (
        "Remove the Guest account from the privileged group(s) listed "
        "in this finding's evidence immediately -- there is no "
        "legitimate reason for the built-in Guest account to carry "
        "privileged group membership. Confirm the Guest account "
        "remains disabled (Microsoft's default) and investigate how "
        "this membership was added, since it is not a default AD "
        "configuration under any normal circumstance."
    ),
    "control_id": "PRIV-308",
    "framework_tags": [],
    "references": [],
    "description": (
        "The built-in Guest account (RID 501) is designed to be the "
        "lowest-trust identity in the domain. Membership in any "
        "AdminSDHolder-protected privileged group severely contradicts "
        "that design intent. Checked regardless of whether the account "
        "is currently enabled, since a disabled Guest account with "
        "privileged group membership is still one re-enablement away "
        "from being exploitable."
    ),
    "base_severity": "critical",
    "query": """
        WITH well_known_roots AS (
            SELECT g.object_guid, g.sam_account_name
            FROM ad_group g
            JOIN directory_object do2
                ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              -- Same verified 11-group AdminSDHolder-protected list used
              -- throughout this project (plugins 1025/3005/3008).
              AND (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-516'
                   OR do2.object_sid LIKE '%%-518' OR do2.object_sid LIKE '%%-519'
                   OR do2.object_sid LIKE '%%-521' OR do2.object_sid LIKE '%%-544'
                   OR do2.object_sid LIKE '%%-548' OR do2.object_sid LIKE '%%-549'
                   OR do2.object_sid LIKE '%%-550' OR do2.object_sid LIKE '%%-551'
                   OR do2.object_sid LIKE '%%-552')
        ),
        matches AS (
            SELECT gdo.object_guid, wkr.sam_account_name AS privileged_group_name, u.is_enabled
            FROM v_effective_group_membership vem
            JOIN well_known_roots wkr ON wkr.object_guid = vem.group_guid
            JOIN directory_object gdo ON gdo.object_guid = vem.member_guid AND gdo.client_id = vem.client_id
            JOIN ad_user u ON u.object_guid = gdo.object_guid AND u.client_id = gdo.client_id AND u.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
              AND gdo.object_sid LIKE '%%-501'
        ),
        -- [fix, applied proactively after the same architectural bug
        -- was found and fixed in plugins 9001/1037/3008/6006/6007/3021
        -- this session -- Guest nested in more than one privileged
        -- root group would collide on identity_guid the same way.]
        aggregated AS (
            SELECT object_guid, bool_or(is_enabled) AS is_enabled,
                   array_agg(DISTINCT privileged_group_name ORDER BY privileged_group_name) AS privileged_group_names
            FROM matches
            GROUP BY object_guid
        )
        SELECT
            'fail' AS status,
            a.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Guest account (RID 501) is a member of privileged group(s): '
                || array_to_string(a.privileged_group_names, ', ') AS summary,
            jsonb_build_object(
                'privileged_groups', a.privileged_group_names,
                'guest_is_enabled', a.is_enabled
            ) AS detail
        FROM aggregated a
    """,
}
