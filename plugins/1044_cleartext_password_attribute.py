"""
Plugin 1044: Cleartext Password Stored in a Readable Attribute

Detects user and computer accounts on which one or more of the legacy
password-carrying attributes is populated: userPassword, unixUserPassword,
msSFU30Password (Services for UNIX / Identity Management for UNIX) or
os400Password (IBM i integration). None of these is the account's real
Windows credential (that lives in unicodePwd, which is never readable), but
whatever was written into them is stored as plain or trivially reversible
text, and in a default forest they are readable by any authenticated user
(userPassword is readable by Authenticated Users unless dSHeuristics
fUserPwdSupport changes its semantics; the SFU/UNIX attributes inherit the
broad default read of the user object). The value is very often the
account's actual password, copied in by a provisioning script, a UNIX/NIS
synchronisation tool or a help-desk procedure -- so any domain user can
recover it with a single LDAP query (MITRE ATT&CK T1552 Unsecured
Credentials; PingCastle's userPassword rule; NIST IA-5(1) and PCI DSS
8.3.2 require passwords to be unreadable in storage).

Data: schema v38 column cleartext_password_attributes on ad_user and
ad_computer -- the sorted NAMES of the populated attributes. The collector
never stores the values (attributes_full holds a redaction marker), so this
plugin reports names only. NULL means the row was collected before v38
(not collected) and is skipped; an empty array means none populated.

Severity: critical if the account is a current Tier 0 principal
(v_privileged_principal), high otherwise, and medium if the account is
disabled (the password cannot be used against this account while it stays
disabled, but it is still exposed and is frequently reused elsewhere).
Disabled takes precedence over Tier 0. One row per account.
"""

PLUGIN = {
    "plugin_id": 1044,
    "category": "User Accounts",
    "name": "Cleartext Password Stored in a Readable Attribute",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CRED-1044",
    "framework_tags": [
        "NIST-800-53-IA-5(1)", "NIST-800-53-SC-28", "NIST-CSF-2.0-PR.DS-01",
        "PCI-DSS-4.0-8.3.2", "CIS-CSC-8-3.11", "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1", "HIPAA-164.312(a)(2)(iv)", "MITRE-ATTCK-T1552",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1552: Unsecured Credentials",
         "url": "https://attack.mitre.org/techniques/T1552/"},
        {"title": "Microsoft: User-Password attribute (userPassword)",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-userpassword"},
        {"title": "PingCastle health check rules (userPassword / cleartext password attributes)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "One or more of userPassword, unixUserPassword, msSFU30Password or "
        "os400Password is populated on this account. These attributes hold "
        "plain or reversibly encoded text and are readable by ordinary "
        "authenticated users in a default forest, and the value is commonly "
        "the account's real password written there by a provisioning, "
        "UNIX/NIS synchronisation or help-desk process. Any domain user can "
        "read it with one LDAP query."
    ),
    "remediation": (
        "Treat the password as disclosed: reset the account's password (and "
        "any other account known to share it) and review the account's recent "
        "logons. Then clear the attribute(s) named in the finding, e.g. "
        "Set-ADUser <sam> -Clear userPassword,unixUserPassword,msSFU30Password,"
        "os400Password (Set-ADComputer for computer objects). Find every "
        "affected object with Get-ADObject -LDAPFilter '(|(userPassword=*)"
        "(unixUserPassword=*)(msSFU30Password=*)(os400Password=*))'. Identify "
        "and fix the process that wrote the value (provisioning scripts, "
        "Identity Management for UNIX / NIS sync, legacy IBM i integration) so "
        "it does not come back, and if UNIX attributes are still needed, "
        "restrict read access to them with a confidential-attribute flag or an "
        "explicit deny for Authenticated Users."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0 AS (
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        ),
        accts AS (
            SELECT u.object_guid, 'User'::text AS kind,
                   COALESCE(u.user_principal_name, u.sam_account_name, u.object_guid::text) AS name,
                   u.sam_account_name, u.is_enabled, u.cleartext_password_attributes AS attrs
            FROM ad_user u
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
              AND cardinality(u.cleartext_password_attributes) > 0
            UNION ALL
            SELECT c.object_guid, 'Computer'::text,
                   COALESCE(c.sam_account_name, c.dns_hostname, c.object_guid::text),
                   c.sam_account_name, c.is_enabled, c.cleartext_password_attributes
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
              AND cardinality(c.cleartext_password_attributes) > 0
        ),
        agg AS (
            SELECT a.object_guid, a.kind, a.name, a.sam_account_name, a.is_enabled,
                   (SELECT array_agg(DISTINCT x ORDER BY x) FROM unnest(a.attrs) x
                     WHERE x IS NOT NULL AND x <> '') AS attrs
            FROM accts a
            JOIN directory_object o
              ON o.object_guid = a.object_guid AND o.client_id = %(client_id)s
             AND NOT o.is_deleted
        )
        SELECT
            'fail' AS status,
            a.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN a.is_enabled IS FALSE THEN 'medium'
                 WHEN t.object_guid IS NOT NULL THEN 'critical'
                 ELSE 'high' END AS fd_severity,
            (CASE WHEN a.is_enabled IS FALSE THEN 'Disabled '
                  WHEN t.object_guid IS NOT NULL THEN 'Tier 0 '
                  ELSE '' END)
                || a.kind || ' account ' || a.name
                || ' has a password stored in readable attribute(s): '
                || array_to_string(a.attrs, ', ') AS summary,
            jsonb_build_object(
                'object_type', lower(a.kind),
                'sam_account_name', a.sam_account_name,
                'is_enabled', a.is_enabled,
                'populated_attributes', to_jsonb(a.attrs),
                'tier0', t.object_guid IS NOT NULL,
                'privilege_sources', t.privilege_sources
            ) AS detail
        FROM agg a
        LEFT JOIN tier0 t ON t.object_guid = a.object_guid
        WHERE cardinality(a.attrs) > 0
    """,
}
