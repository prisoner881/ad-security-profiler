"""
Plugin 1005: Built-in Guest Account Enabled

The built-in Guest account (RID 501) should always be disabled -- there is
essentially no legitimate reason for it to be active on a production
domain. Detected by RID, not name, for the same reason as the
Administrator-account check: STIG guidance recommends renaming this
account too, and a rename doesn't change its RID.
"""

PLUGIN = {
    "plugin_id": 1005,
    "category": "User Accounts",
    "name": "Built-in Guest Account Is Enabled",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
    'Disable the account (`Disable-ADAccount`). Confirm it holds no group '
    'memberships or delegated rights beyond the built-in Guests group defaults '
    'before and after disabling, since a Guest account with unexpected '
    'additional access is a separate finding worth investigating on its own.'
),
    "control_id": "PRIV-102",
    "framework_tags": ["DISA-STIG"],
    "references": [],
    "description": (
        "The built-in Guest account (RID 501) should always be disabled; "
        "there is no legitimate reason for it to be active on a "
        "production domain. Comparable to the recurring 'Accounts: Guest "
        "account status must be Disabled' rule present across DISA "
        "Windows STIG families (e.g. WN10-SO-000010 and equivalents). "
        "Detected by RID (trailing -501 in the account's SID), not by "
        "name, for the same rename-resistance reason as the Administrator "
        "account check."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Windows STIG family: "Accounts: Guest account status" must be '
                'Disabled (e.g. WN10-SO-000010 and equivalents across STIG versions)' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Built-in Guest account (RID 501, currently named "' || u.sam_account_name
                || '") is enabled' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'object_sid', do2.object_sid,
                'last_logon_timestamp', u.last_logon_timestamp,
                'bad_pwd_count', u.bad_pwd_count
            ) AS detail
        FROM ad_user u
        JOIN directory_object do2
            ON do2.object_guid = u.object_guid AND do2.client_id = u.client_id
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND do2.object_sid LIKE '%%-501'
    """,
}
