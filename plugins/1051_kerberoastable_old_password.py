"""
Plugin 1051: Kerberoastable Service Account With a Password Older Than One Year

Flags enabled user accounts (not krbtgt, not computer/gMSA/dMSA accounts,
which live in ad_computer and rotate automatically) that have at least one
servicePrincipalName and whose password was last set more than 365 days
ago, or never (pwdLastSet NULL / 0).

Distinct from plugin 1009, which reports every user account with an SPN
regardless of password age. This plugin reports the crackability-window
condition: any authenticated user can request a service ticket for the
account and crack it offline (Kerberoasting, MITRE ATT&CK T1558.003), and
a password that has not changed for over a year has had at least that
long to be cracked -- a cracked password stays valid until it changes.
Human-chosen service-account passwords that are never rotated are the
classic Kerberoasting win. The Five Eyes "Detecting and Mitigating Active
Directory Compromises" guidance (2024) and Microsoft both recommend
replacing such accounts with group Managed Service Accounts (gMSA) or, on
Windows Server 2025, delegated Managed Service Accounts (dMSA), whose
240-byte random passwords rotate automatically (every 30 days by
default); PingCastle scores Kerberoastable accounts by password age for
the same reason.

pwd_last_set NULL or the FILETIME epoch (pwdLastSet = 0) is reported as
"never set": the account has an SPN but no known password-set time, so
its current key may be arbitrarily old.

Severity: high; critical if the account is a current Tier 0 principal
(v_privileged_principal). Disabled accounts are excluded (no tickets are
issued for a disabled service account). The summary uses the one-year
threshold and the password date, never a day count.
"""

PLUGIN = {
    "plugin_id": 1051,
    "category": "User Accounts",
    "name": "Kerberoastable Service Account With a Password Older Than One Year",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "KERB-1051",
    "framework_tags": [
        "NIST-800-53-IA-5", "NIST-800-53-IA-5(1)", "NIST-CSF-2.0-PR.DS-01",
        "PCI-DSS-4.0-8.6.3", "PCI-DSS-4.0-8.3.9", "CIS-CSC-8-5.5",
        "ISO-27001-2022-A.5.17", "SOC2-CC6.1", "MITRE-ATTCK-T1558.003",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1558.003: Kerberoasting",
         "url": "https://attack.mitre.org/techniques/T1558/003/"},
        {"title": "PingCastle health check rules (Kerberoasting / service account password age)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "A user account with a servicePrincipalName (Kerberoastable by any "
        "domain user) has not changed its password in over a year, or never. "
        "An attacker who captured a service ticket at any point in that "
        "window has had all that time to crack it offline, and the cracked "
        "password is still valid. Unlike plugin 1009 (any SPN on a user), "
        "this reports the long crackability window; the fix is a gMSA/dMSA."
    ),
    "remediation": (
        "Migrate the service to a group Managed Service Account "
        "(New-ADServiceAccount -Name <name> -DNSHostName <fqdn> "
        "-PrincipalsAllowedToRetrieveManagedPassword <hosts group>; then "
        "Install-ADServiceAccount on the hosts and move the SPNs) or, on "
        "Windows Server 2025, to a delegated MSA (Start-ADServiceAccountMigration). "
        "Where that is not possible, reset the password now to a random value "
        "of 25+ characters, set msDS-SupportedEncryptionTypes to AES only "
        "(0x18) so roasted tickets are AES, rotate it at least annually, and "
        "remove SPNs that are no longer used (setspn -D). For Tier 0 service "
        "accounts, also reduce the account's privileges."
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
        cand AS (
            SELECT u.object_guid, u.sam_account_name, u.user_principal_name,
                   u.service_principal_names, u.supported_encryption_types,
                   CASE WHEN u.pwd_last_set > TIMESTAMPTZ '1601-01-02 00:00:00+00'
                        THEN u.pwd_last_set END AS pwd_last_set
            FROM ad_user u
            JOIN directory_object o
              ON o.object_guid = u.object_guid AND o.client_id = u.client_id
             AND NOT o.is_deleted
            WHERE u.client_id = %(client_id)s
              AND u.valid_to IS NULL
              AND u.is_enabled
              AND cardinality(u.service_principal_names) > 0
              AND (o.object_sid IS NULL OR o.object_sid NOT LIKE '%%-502')
              AND lower(COALESCE(u.sam_account_name, '')) <> 'krbtgt'
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN t.object_guid IS NOT NULL THEN 'critical' ELSE 'high' END AS fd_severity,
            (CASE WHEN t.object_guid IS NOT NULL THEN 'Tier 0 ' ELSE '' END)
                || 'Kerberoastable user account '
                || COALESCE(c.user_principal_name, c.sam_account_name, c.object_guid::text)
                || CASE WHEN c.pwd_last_set IS NULL
                        THEN ' has no recorded password-set time (password never set)'
                        ELSE ' has a password older than one year (last set '
                             || to_char(c.pwd_last_set AT TIME ZONE 'UTC', 'YYYY-MM-DD') || ')'
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'user_principal_name', c.user_principal_name,
                'service_principal_names', to_jsonb(c.service_principal_names),
                'pwd_last_set', c.pwd_last_set,
                'password_age_days', EXTRACT(DAY FROM now() - c.pwd_last_set)::int,
                'supported_encryption_types', c.supported_encryption_types,
                'tier0', t.object_guid IS NOT NULL,
                'privilege_sources', t.privilege_sources
            ) AS detail
        FROM cand c
        LEFT JOIN tier0 t ON t.object_guid = c.object_guid
        WHERE c.pwd_last_set IS NULL
           OR c.pwd_last_set < now() - INTERVAL '365 days'
    """,
}
