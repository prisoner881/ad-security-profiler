"""
Plugin 1049: Shared or Generic Account in Use

Flags enabled user accounts whose sAMAccountName is a generic, role- or
function-style name rather than a person's or a specific service's
identity: admin, administrator2, admin1, test, test1, testuser, temp,
guest2, scan, scanner, svc, service, backup, kiosk, shared, training,
demo, user1, helpdesk, reception, frontdesk, conference, sql, oracle, ftp,
web, www, print and similar.

The match is anchored on the whole name (case-insensitive):

    ^(admin|administrator|test|testuser|temp|guest|scan|scanner|svc|service|
      backup|kiosk|shared|training|demo|user|helpdesk|reception|frontdesk|
      conference|sql|oracle|ftp|web|www|print|printer)
     ([-_.]?(user|account|acct|[0-9]+))?$

so "test", "test1", "test_user", "admin-01", "user1" and "print2" match,
while ordinary personal names that merely contain a keyword ("jtest",
"webbj", "printz") and named service accounts ("svc_sql", "sqlsvc_crm") do
not. It is a heuristic: a match is a prompt to confirm who owns and uses
the account.

Why: a generic account cannot be tied to one person, so its actions are
not attributable and its password is typically known to several people
and rarely changed when one of them leaves. PCI DSS 4.0 requirement 8.2.2
forbids group, shared or generic IDs except where strictly necessary and
controlled; NIST SP 800-53 IA-2 / IA-4 require unique identification.
Accounts named "test" or "temp" are also the first guesses in password
spraying (MITRE ATT&CK T1078.002 / T1110.003).

Excluded: the built-in Administrator (RID 500) and Guest (RID 501), which
are covered by plugins 1004/1005/1033; disabled accounts (not "in use").

Severity: high if the account is a current Tier 0 principal
(v_privileged_principal) -- a shared domain-admin credential; medium if
its password never expires (a shared password that is never forced to
change); low otherwise. One row per account.
"""

PLUGIN = {
    "plugin_id": 1049,
    "category": "User Accounts",
    "name": "Shared or Generic Account in Use",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "HYGIENE-1049",
    "framework_tags": [
        "NIST-800-53-IA-2", "NIST-800-53-IA-4", "NIST-800-53-AC-2(9)",
        "PCI-DSS-4.0-8.2.1", "PCI-DSS-4.0-8.2.2", "CIS-CSC-8-4.7",
        "ISO-27001-2022-A.5.16", "SOC2-CC6.1", "HIPAA-164.312(a)(2)(i)",
        "MITRE-ATTCK-T1078.002",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1078.002: Valid Accounts - Domain Accounts",
         "url": "https://attack.mitre.org/techniques/T1078/002/"},
        {"title": "MITRE ATT&CK T1110.003: Password Spraying",
         "url": "https://attack.mitre.org/techniques/T1110/003/"},
    ],
    "description": (
        "An enabled account has a generic or function-style name (admin, "
        "test, temp, scan, svc, backup, kiosk, shared, helpdesk, ...), which "
        "usually means several people share it. Its activity cannot be "
        "attributed to an individual and its password tends to be widely "
        "known and rarely rotated. PCI DSS 4.0 requirement 8.2.2 prohibits "
        "shared and generic IDs except under strict, documented control."
    ),
    "remediation": (
        "Identify who uses the account (lastLogonTimestamp, logon events "
        "4624/4768 by source host). Replace interactive shared use with "
        "named individual accounts (and separate named admin accounts for "
        "privileged work); replace service use with a gMSA or a named, "
        "documented service account. Then disable the generic account "
        "(Disable-ADAccount <sam>) and delete it after a grace period. "
        "Where a shared account is genuinely unavoidable (e.g. a kiosk), "
        "document the business justification, restrict where it can log on "
        "(logonWorkstations / authentication policy), remove "
        "PasswordNeverExpires, and rotate its password whenever a user with "
        "knowledge of it leaves (PCI DSS 8.2.2)."
    ),
    "base_severity": "low",
    "query": """
        WITH tier0 AS (
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
            CASE WHEN t.object_guid IS NOT NULL THEN 'high'
                 WHEN u.pwd_never_expires THEN 'medium'
                 ELSE 'low' END AS fd_severity,
            (CASE WHEN t.object_guid IS NOT NULL THEN 'Tier 0 ' ELSE '' END)
                || 'Generic/shared-style account '
                || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' is enabled'
                || CASE WHEN u.pwd_never_expires THEN ' and its password never expires'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'description', u.description,
                'pwd_never_expires', u.pwd_never_expires,
                'pwd_last_set', u.pwd_last_set,
                'last_logon_timestamp', u.last_logon_timestamp,
                'tier0', t.object_guid IS NOT NULL,
                'privilege_sources', t.privilege_sources
            ) AS detail
        FROM ad_user u
        JOIN directory_object o
          ON o.object_guid = u.object_guid AND o.client_id = u.client_id
         AND NOT o.is_deleted
        LEFT JOIN tier0 t ON t.object_guid = u.object_guid
        WHERE u.client_id = %(client_id)s
          AND u.valid_to IS NULL
          AND u.is_enabled
          AND (o.object_sid IS NULL
               OR (o.object_sid NOT LIKE '%%-500' AND o.object_sid NOT LIKE '%%-501'))
          AND lower(u.sam_account_name) ~ '^(admin|administrator|test|testuser|temp|guest|scan|scanner|svc|service|backup|kiosk|shared|training|demo|user|helpdesk|reception|frontdesk|conference|sql|oracle|ftp|web|www|print|printer)([-_.]?(user|account|acct|[0-9]+))?$'
    """,
}
