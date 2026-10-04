"""
Plugin 1048: Expired Account Still Enabled, or Temporary Account With No Expiry

Two account-lifecycle hygiene conditions on enabled user accounts:

 (a) Expired but still enabled: accountExpires lies more than 30 days in
     the past and the account is still enabled. Domain controllers
     already refuse logon after the expiry date, so this is not an open
     door by itself -- but the account was meant to be gone. Anyone able
     to edit accountExpires (account operators, help desk, OU delegates)
     can silently revive it with its old password, group memberships and
     rights intact, and it clutters reviews of who has access. The 30-day
     grace avoids flagging contracts that are being extended.

 (b) Temporary account with no expiry: the sAMAccountName, the local part
     of the UPN, the description or the info (Notes) text matches a
     temporary-worker keyword -- temp, temporary, contractor, contract,
     vendor, consultant, intern, seasonal -- as a whole word (bounded by a
     non-letter or the start/end of the text, case-insensitive; so
     "temp_jsmith" and "intern2" match, "internal" and "tempest" do not),
     and accountExpires is never (NULL). Third-party and temporary access
     should end automatically.

NIST SP 800-53 AC-2(2) (automated temporary/emergency account management)
and AC-2(3) (disable accounts), PCI DSS 4.0 8.2.6 (inactive accounts) and
8.2.7 (third-party access), DISA STIG account-expiry requirements.

Data: ad_user.account_expires (schema v38; NULL = never expires -- the
collector maps both 0 and 0x7FFFFFFFFFFFFFFF to NULL). Rows collected
before v38 also have NULL there, which would make every temp-named account
look unbounded, so case (b) requires the row to have been collected by a
v38 collector: cleartext_password_attributes (also v38, always an array
when collected, [] when none) must be non-NULL.

Disabled accounts are excluded (both conditions are only interesting while
the account is enabled). Severity: low. The two cases are mutually
exclusive (b requires no expiry), so there is one row per account. The
summary states the expiry DATE (deterministic), never a day count.
"""

PLUGIN = {
    "plugin_id": 1048,
    "category": "User Accounts",
    "name": "Expired Account Still Enabled, or Temporary Account With No Expiry",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "LIFECYCLE-1048",
    "framework_tags": [
        "NIST-800-53-AC-2", "NIST-800-53-AC-2(3)", "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.2.6", "CIS-CSC-8-5.3", "ISO-27001-2022-A.5.18",
        "SOC2-CC6.2", "HIPAA-164.308(a)(3)(ii)(C)", "MITRE-ATTCK-T1078.002",
    ],
    "references": [
        {"title": "Microsoft: Account-Expires attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-accountexpires"},
        {"title": "MITRE ATT&CK T1078.002: Valid Accounts - Domain Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/002/"},
    ],
    "description": (
        "Either the account expired more than 30 days ago but was never "
        "disabled or removed (anyone who can edit accountExpires can revive "
        "it with its old password and rights), or the account's name or "
        "description marks it as temporary / contractor / vendor access but "
        "it has no expiry date, so the access will not end on its own."
    ),
    "remediation": (
        "Expired accounts: confirm with the owner that the access has ended, "
        "then disable the account (Disable-ADAccount <sam>), remove its group "
        "memberships, and delete it after your retention period. Temporary "
        "accounts: set an expiry matching the contract end "
        "(Set-ADAccountExpiration <sam> -DateTime 'YYYY-MM-DD'), record a "
        "sponsor (manager attribute), and make expiry mandatory in the "
        "provisioning process for third-party and temporary staff. Find "
        "candidates with Search-ADAccount -AccountExpired -UsersOnly | "
        "Where-Object Enabled."
    ),
    "base_severity": "low",
    "query": """
        WITH u AS (
            SELECT u.object_guid, u.sam_account_name, u.user_principal_name,
                   u.description, u.notes, u.account_expires,
                   u.cleartext_password_attributes,
                   array_remove(ARRAY[
                       CASE WHEN lower(COALESCE(u.sam_account_name, '')) ~ '(^|[^a-z])(temp|temporary|contractor|contract|vendor|consultant|intern|seasonal)([^a-z]|$)'
                            THEN 'sAMAccountName' END,
                       CASE WHEN lower(split_part(COALESCE(u.user_principal_name, ''), '@', 1)) ~ '(^|[^a-z])(temp|temporary|contractor|contract|vendor|consultant|intern|seasonal)([^a-z]|$)'
                            THEN 'userPrincipalName' END,
                       CASE WHEN lower(COALESCE(u.description, '')) ~ '(^|[^a-z])(temp|temporary|contractor|contract|vendor|consultant|intern|seasonal)([^a-z]|$)'
                            THEN 'description' END,
                       CASE WHEN lower(COALESCE(u.notes, '')) ~ '(^|[^a-z])(temp|temporary|contractor|contract|vendor|consultant|intern|seasonal)([^a-z]|$)'
                            THEN 'info' END
                   ], NULL) AS temp_fields
            FROM ad_user u
            JOIN directory_object o
              ON o.object_guid = u.object_guid AND o.client_id = u.client_id
             AND NOT o.is_deleted
            WHERE u.client_id = %(client_id)s
              AND u.valid_to IS NULL
              AND u.is_enabled
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            CASE WHEN u.account_expires IS NOT NULL
                 THEN 'User account '
                      || COALESCE(u.user_principal_name, u.sam_account_name, u.object_guid::text)
                      || ' expired on '
                      || to_char(u.account_expires AT TIME ZONE 'UTC', 'YYYY-MM-DD')
                      || ' but is still enabled'
                 ELSE 'Temporary/third-party user account '
                      || COALESCE(u.user_principal_name, u.sam_account_name, u.object_guid::text)
                      || ' has no expiry date (matched in: '
                      || array_to_string(u.temp_fields, ', ') || ')'
            END AS summary,
            jsonb_build_object(
                'condition', CASE WHEN u.account_expires IS NOT NULL
                                  THEN 'expired_but_enabled' ELSE 'temporary_without_expiry' END,
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'description', u.description,
                'account_expires', u.account_expires,
                'days_since_expiry', CASE WHEN u.account_expires IS NOT NULL
                                          THEN EXTRACT(DAY FROM now() - u.account_expires)::int END,
                'matched_fields', to_jsonb(u.temp_fields)
            ) AS detail
        FROM u
        WHERE (u.account_expires IS NOT NULL
               AND u.account_expires < now() - INTERVAL '30 days')
           OR (u.account_expires IS NULL
               AND u.cleartext_password_attributes IS NOT NULL   -- collected by a v38 collector
               AND cardinality(u.temp_fields) > 0)
    """,
}
