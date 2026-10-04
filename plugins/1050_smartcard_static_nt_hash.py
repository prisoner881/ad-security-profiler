"""
Plugin 1050: Smart-Card-Required Account With a Static NT Hash

When "Smart card is required for interactive logon" (SCRIL,
userAccountControl 0x40000 SMARTCARD_REQUIRED) is set, the domain
controller replaces the account's password with a random value. Users
never know it, but the account still has an NT hash: it is returned to the
client in the PAC (PKINIT "NTLM supplemental credential") so NTLM keeps
working, it is what NTLM authentication and RC4 Kerberos use, and it can
be dumped from LSASS or the DC like any other hash. Without rotation that
random hash never changes -- it is set once, when SCRIL is enabled -- so a
hash stolen years ago still works for pass-the-hash (MITRE ATT&CK
T1550.002) today, and the smart-card requirement gives a false sense that
the account has "no password".

Windows Server 2016 added automatic rolling: with the domain at the 2016
functional level and msDS-ExpirePasswordsOnSmartCardOnlyAccounts set to
TRUE on the domain object, domain controllers regenerate the random hash
of SCRIL accounts whenever it reaches the maximum password age. Toggling
SCRIL off and on also regenerates it manually.

Flags enabled users with smartcard_required whose pwd_last_set (when the
current hash was generated) is older than the domain's maximum password
age (ad_domain.max_pwd_age_seconds; 365 days when that is NULL or 0,
i.e. passwords never expire domain-wide), in a domain where
ad_domain.smartcard_hash_rolling_enabled IS NOT TRUE. NULL there means
the attribute is unset or absent from the schema (pre-2016 schema), and
either way rolling is not happening, so NULL counts as "not enabled".
The user's domain is the ad_domain whose DN is the longest suffix of the
user's DN (single-domain collections have exactly one).

Skipped: pwd_last_set NULL or the FILETIME epoch (pwdLastSet = 0, must
change at next logon); disabled accounts (the hash cannot be used while
the account is disabled). Fine-grained password policies are not taken
into account: SCRIL rolling uses the domain policy's maximum age.

Severity: medium; high if the account is a current Tier 0 principal
(v_privileged_principal). The summary states the hash date (deterministic).
"""

PLUGIN = {
    "plugin_id": 1050,
    "category": "User Accounts",
    "name": "Smart-Card-Required Account With a Static NT Hash",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CRED-1050",
    "framework_tags": [
        "NIST-800-53-IA-5", "NIST-800-53-IA-5(1)", "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-8.3.9", "CIS-CSC-8-5.2", "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1", "MITRE-ATTCK-T1550.002",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1550.002: Use Alternate Authentication Material - Pass the Hash",
         "url": "https://attack.mitre.org/techniques/T1550/002/"},
        {"title": "PingCastle health check rules (smart card required / hash rotation)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "The account requires a smart card, so the DC gave it a random "
        "password -- but its NT hash still exists, is usable for NTLM and "
        "pass-the-hash, and has not changed for longer than the maximum "
        "password age because SCRIL hash rolling "
        "(msDS-ExpirePasswordsOnSmartCardOnlyAccounts, domain functional "
        "level 2016+) is not enabled. A hash stolen at any point since then "
        "is still valid."
    ),
    "remediation": (
        "Enable automatic rolling: raise the domain functional level to "
        "Windows Server 2016 or later, then set the attribute on the domain "
        "object: Set-ADObject (Get-ADDomain).DistinguishedName -Replace "
        "@{'msDS-ExpirePasswordsOnSmartCardOnlyAccounts'=$true} (or tick "
        "'Enable rolling of expiring NTLM secrets during sign on' in Active "
        "Directory Administrative Center). Rolled hashes are then renewed at "
        "the domain maximum password age. Until then, and immediately for "
        "privileged accounts, regenerate the hash by clearing and re-setting "
        "'Smart card is required for interactive logon' "
        "(Set-ADUser <sam> -SmartcardLogonRequired $false; then $true), "
        "or by scripting that toggle on a schedule."
    ),
    "base_severity": "medium",
    "query": """
        WITH tier0 AS (
            SELECT object_guid,
                   array_agg(DISTINCT privilege_source ORDER BY privilege_source) AS privilege_sources
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        ),
        doms AS (
            SELECT d.object_guid, lower(o.dn_current) AS dn,
                   d.max_pwd_age_seconds, d.smartcard_hash_rolling_enabled
            FROM ad_domain d
            JOIN directory_object o
              ON o.object_guid = d.object_guid AND o.client_id = d.client_id
             AND NOT o.is_deleted
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
        ),
        cand AS (
            SELECT u.object_guid, u.sam_account_name, u.user_principal_name,
                   u.pwd_last_set, dm.object_guid AS domain_guid,
                   dm.max_pwd_age_seconds, dm.smartcard_hash_rolling_enabled,
                   CASE WHEN COALESCE(dm.max_pwd_age_seconds, 0) > 0
                        THEN dm.max_pwd_age_seconds
                        ELSE 365 * 86400 END AS threshold_seconds
            FROM ad_user u
            JOIN directory_object o
              ON o.object_guid = u.object_guid AND o.client_id = u.client_id
             AND NOT o.is_deleted
            LEFT JOIN LATERAL (
                SELECT * FROM doms
                WHERE right(lower(o.dn_current), length(doms.dn) + 1) = ',' || doms.dn
                ORDER BY length(doms.dn) DESC
                LIMIT 1
            ) dm ON true
            WHERE u.client_id = %(client_id)s
              AND u.valid_to IS NULL
              AND u.is_enabled
              AND u.smartcard_required
              AND u.pwd_last_set IS NOT NULL
              AND u.pwd_last_set > TIMESTAMPTZ '1601-01-02 00:00:00+00'
              AND dm.smartcard_hash_rolling_enabled IS NOT TRUE
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN t.object_guid IS NOT NULL THEN 'high' ELSE 'medium' END AS fd_severity,
            (CASE WHEN t.object_guid IS NOT NULL THEN 'Tier 0 ' ELSE '' END)
                || 'Smart-card-required account '
                || COALESCE(c.user_principal_name, c.sam_account_name, c.object_guid::text)
                || ' has had the same NT hash since '
                || to_char(c.pwd_last_set AT TIME ZONE 'UTC', 'YYYY-MM-DD')
                || ' (older than the maximum password age; SCRIL hash rolling is not enabled)'
                AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'user_principal_name', c.user_principal_name,
                'pwd_last_set', c.pwd_last_set,
                'hash_age_days', EXTRACT(DAY FROM now() - c.pwd_last_set)::int,
                'threshold_days', c.threshold_seconds / 86400,
                'domain_max_pwd_age_seconds', c.max_pwd_age_seconds,
                'smartcard_hash_rolling_enabled', c.smartcard_hash_rolling_enabled,
                'domain_guid', c.domain_guid,
                'tier0', t.object_guid IS NOT NULL,
                'privilege_sources', t.privilege_sources
            ) AS detail
        FROM cand c
        LEFT JOIN tier0 t ON t.object_guid = c.object_guid
        WHERE c.pwd_last_set < now() - make_interval(secs => c.threshold_seconds)
    """,
}
