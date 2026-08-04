"""
Plugin 1004: Built-in Administrator Account Enabled

The RID-500 built-in Administrator account is a predictable, unrenameable
(by RID) target with one property that makes it worse than an ordinary
privileged account: it is hardcoded immune to account lockout policy,
regardless of how lockoutThreshold is configured domain-wide.
"""

PLUGIN = {
    "plugin_id": 1004,
    "category": "User Accounts",
    "name": "Built-in Administrator Account Is Enabled",
    "version": "1.3",
    "revision_date": "2026-07-15",
    "remediation": (
    'Disable the account (`Disable-ADAccount`). Ensure named, '
    'individually-attributable administrative accounts exist to cover whatever '
    "this account was being used for, so disabling it doesn't create pressure "
    'to re-enable it later. Renaming the account is a reasonable complementary '
    'hardening step but does not replace disabling it -- the account is still '
    'RID 500 and still lockout-immune regardless of its name.'
),
    "control_id": "PRIV-101",
    "framework_tags": ["DISA-STIG"],
    "references": [],
    "description": (
        "The built-in Administrator account (RID 500) should be disabled "
        "in favor of named, individually-attributable administrative "
        "accounts. This account is additionally hardcoded immune to "
        "account lockout policy regardless of the domain's configured "
        "lockoutThreshold, making it a standing brute-force target with "
        "no automatic mitigation available. Comparable to the recurring "
        "'Accounts: Administrator account status must be Disabled' rule "
        "present across DISA Windows STIG families (e.g. WN10-SO-000005 "
        "and equivalents in later STIG versions). Detected by RID (the "
        "trailing -500 in the account's SID), not by name -- STIG "
        "guidance separately recommends renaming this account, and a "
        "rename does not change its RID, so a name-only check would miss "
        "a renamed-but-still-enabled instance of this exact account."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            u.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Windows STIG family: "Accounts: Administrator account status" '
                'must be Disabled (e.g. WN10-SO-000005 and equivalents across '
                'STIG versions)' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Built-in Administrator account (RID 500, currently named "' || u.sam_account_name
                || '") is enabled' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'object_sid', do2.object_sid,
                'pwd_last_set', u.pwd_last_set,
                'password_age_days', CASE WHEN u.pwd_last_set IS NOT NULL
                                           THEN EXTRACT(DAY FROM now() - u.pwd_last_set)::int
                                           ELSE NULL END,
                'last_logon_timestamp', u.last_logon_timestamp,
                'pwd_never_expires', u.pwd_never_expires
            ) AS detail
        FROM ad_user u
        JOIN directory_object do2
            ON do2.object_guid = u.object_guid AND do2.client_id = u.client_id
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND do2.object_sid LIKE '%%-500'
    """,
}
