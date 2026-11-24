"""
Plugin 1053: Password Age Reset Without a Password Change (pwdLastSet Refreshed)

pwdLastSet records when an account's password was last set, and every
password-age check -- this tool's 1036 (privileged password age) and 1051
(Kerberoastable account with an old password), and the domain's own
maximum password age -- trusts it. It can be refreshed without changing the
password: tick "User must change password at next logon" (pwdLastSet = 0),
then untick it (pwdLastSet = -1, which the DC stores as the current time).
The password stays the same, but looks new, and expiry starts again. Done
to dodge expiry for a service or privileged account, it hides a password
that may be years old; done by an attacker, it keeps a known password
working. PingCastle added rules for this in 4.1.2.0 (November 2026), for
privileged accounts and for all users.

Detection: the directory's own per-attribute replication metadata
(msDS-ReplAttributeMetaData, collected by adprofiler.py with every object
version). A real password change writes unicodePwd and pwdLastSet together;
here the last originating change of pwdLastSet is more than a day later
than the last originating change of unicodePwd. Accounts whose pwdLastSet
is currently 0 (must change at next logon: the next logon changes the
password) are not reported. gMSA / computer-style accounts (sAMAccountName
ending in $) are left out: their passwords are managed by the system.

One finding per account, status 'fail':
  * high: the account is privileged (v_privileged_principal) and enabled;
  * medium: privileged and disabled;
  * low: any other enabled account.
Other disabled accounts are not reported.

Data: directory_object_version (attributes_full -> msDS-ReplAttributeMetaData
of the current version), directory_object, ad_user,
v_privileged_principal. Identity = the account. Related: 1036, 1051, 11016.
"""

PLUGIN = {
    "plugin_id": 1053,
    "category": "User Accounts",
    "name": "Password Age Reset Without a Password Change (pwdLastSet Refreshed)",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "USER-1053",
    "framework_tags": [
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-SI-4",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.9",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1098",
    ],
    "references": [
        {"title": "PingCastle 4.1.2.0 release notes (fake password change rules)",
         "url": "https://github.com/netwrix/pingcastle/releases/tag/4.1.2.0"},
        {"title": "Microsoft: Pwd-Last-Set attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-pwdlastset"},
        {"title": "Microsoft: msDS-ReplAttributeMetaData attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-replattributemetadata"},
    ],
    "description": (
        "The account's password age was reset (pwdLastSet refreshed, for example by ticking and "
        "unticking \"User must change password at next logon\") without the password being "
        "changed: the directory's replication metadata shows pwdLastSet written more than a day "
        "after the password itself (unicodePwd). The password is older than it looks, so expiry "
        "and password-age checks are fooled. High for an enabled privileged account."
    ),
    "remediation": (
        "Change the password of each account listed (for a service account, to a new long random "
        "value, updating the services that use it), then find out who reset the password age and "
        "why: the domain controllers' event 4738 (pwdLastSet changed) without a matching 4723 / "
        "4724 (password change / reset) around the time in the detail. Tell administrators not to "
        "use the \"must change password\" toggle to extend passwords. Plan service accounts as "
        "gMSAs, whose passwords rotate automatically."
    ),
    "base_severity": "high",
    "query": r"""
        WITH
        meta AS (
            SELECT v.object_guid,
                   max(CASE WHEN e.value ->> 'attributeName' = 'pwdLastSet'
                            THEN (e.value ->> 'lastOriginatingChangeTime')::timestamptz END) AS pls_change,
                   max(CASE WHEN e.value ->> 'attributeName' = 'pwdLastSet'
                            THEN e.value ->> 'version' END) AS pls_version,
                   max(CASE WHEN e.value ->> 'attributeName' = 'unicodePwd'
                            THEN (e.value ->> 'lastOriginatingChangeTime')::timestamptz END) AS pwd_change,
                   max(CASE WHEN e.value ->> 'attributeName' = 'unicodePwd'
                            THEN e.value ->> 'version' END) AS pwd_version
              FROM directory_object_version v
              CROSS JOIN LATERAL jsonb_array_elements(v.attributes_full -> 'msDS-ReplAttributeMetaData') AS e
             WHERE v.client_id = %(client_id)s
               AND v.valid_to IS NULL
               AND jsonb_typeof(v.attributes_full -> 'msDS-ReplAttributeMetaData') = 'array'
               AND e.value ->> 'attributeName' IN ('pwdLastSet', 'unicodePwd')
               AND e.value ->> 'lastOriginatingChangeTime' ~ '^[0-9]{4}-'
             GROUP BY v.object_guid
        ),
        cand AS (
            SELECT o.object_guid, o.sam_account_name, o.dn_current, u.is_enabled, u.pwd_last_set,
                   m.pls_change, m.pls_version, m.pwd_change, m.pwd_version,
                   EXISTS (SELECT 1 FROM v_privileged_principal vp
                            WHERE vp.client_id = o.client_id AND vp.object_guid = o.object_guid) AS privileged
              FROM meta m
              JOIN directory_object o
                ON o.object_guid = m.object_guid AND o.client_id = %(client_id)s AND NOT o.is_deleted
              JOIN ad_user u
                ON u.object_guid = o.object_guid AND u.client_id = o.client_id AND u.valid_to IS NULL
             WHERE o.object_class = 'user'
               AND COALESCE(o.sam_account_name, '') NOT LIKE '%%$'
               AND m.pls_change IS NOT NULL AND m.pwd_change IS NOT NULL
               AND m.pls_change > m.pwd_change + interval '1 day'
               -- pwdLastSet 0 = must change at next logon: the next logon changes it
               AND u.pwd_last_set IS NOT NULL
               AND u.pwd_last_set > timestamptz '1601-01-02 00:00:00+00'
        ),
        cls AS (
            SELECT c.*,
                   CASE WHEN c.privileged AND COALESCE(c.is_enabled, true) THEN 'high'
                        WHEN c.privileged THEN 'medium'
                        WHEN COALESCE(c.is_enabled, true) THEN 'low' END AS sev
              FROM cand c
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            c.sev AS fd_severity,
            CASE WHEN c.privileged THEN 'Privileged account "' ELSE 'Account "' END
                || COALESCE(c.sam_account_name, c.dn_current)
                || '": password age reset on ' || to_char(c.pls_change AT TIME ZONE 'UTC', 'YYYY-MM-DD')
                || ' without a password change -- the password was last changed on '
                || to_char(c.pwd_change AT TIME ZONE 'UTC', 'YYYY-MM-DD') || ' ('
                || (current_date - (c.pwd_change AT TIME ZONE 'UTC')::date) || ' days ago)'
                || CASE WHEN COALESCE(c.is_enabled, true) THEN '' ELSE ' (account disabled)' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'distinguished_name', c.dn_current,
                'enabled', c.is_enabled,
                'privileged', c.privileged,
                'pwd_last_set', c.pwd_last_set,
                'pwd_last_set_written_at', c.pls_change,
                'pwd_last_set_metadata_version', c.pls_version,
                'password_changed_at', c.pwd_change,
                'password_metadata_version', c.pwd_version,
                'real_password_age_days', current_date - (c.pwd_change AT TIME ZONE 'UTC')::date,
                'source', 'msDS-ReplAttributeMetaData (pwdLastSet vs unicodePwd)'
            ) AS detail
        FROM cls c
        WHERE c.sev IS NOT NULL
    """,
}
