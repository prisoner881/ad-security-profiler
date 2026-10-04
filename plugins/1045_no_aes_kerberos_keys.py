"""
Plugin 1045: Account Has No AES Kerberos Keys (Password Predates AES Key Generation)

Domain controllers only derive AES128/AES256 Kerberos keys for an account
when its password is set in a domain running at the Windows Server 2008
domain functional level or later. An account whose password was last set
before that point has only the RC4-HMAC (NT hash) key -- and DES keys, if
any -- no matter what msDS-SupportedEncryptionTypes says. Such accounts:

  * can only be issued RC4 tickets, so their service tickets are the cheap
    RC4 kind to crack offline (Kerberoasting, T1558.003) and their TGTs
    use the NT hash as key (overpass-the-hash);
  * break when RC4 is removed. The November 2022 Kerberos hardening for
    CVE-2022-37966 (KB5021131) made AES the default session-key type for
    accounts without msDS-SupportedEncryptionTypes, and Microsoft's
    deprecation of RC4 in Windows Kerberos (domain controllers defaulting
    to AES-only during 2026) means RC4-only accounts stop authenticating
    unless RC4 is re-enabled for them.

Detection uses PingCastle's proxy for "when the domain started generating
AES keys" (rule S-AesNotEnabled): the whenCreated of the domain's
"Read-only Domain Controllers" group (RID 521), which is created when the
domain is first prepared for / operated by Windows Server 2008 domain
controllers. It is a proxy: the group appears when the PDC emulator first
runs on 2008 (adprep /rodcprep era), which can precede the DFL raise; an
account whose password was set in between is a real finding the proxy
misses, not a false positive. If the domain has no RID 521 group at all,
it never reached 2008 and every enabled account qualifies.

Flags enabled ad_user accounts (krbtgt is included even though it is
always disabled, because its keys sign every TGT; service and trust
accounts are included) whose pwd_last_set is earlier than the RID 521
group's creation time minus one hour. The hour of grace absorbs the
domain's own creation: dcpromo of a new 2008+ domain creates krbtgt and
the default groups in the same operation, seconds apart. The group's
creation time comes from ad_group.when_created, falling back to
whenCreated in the current directory_object_version.attributes_full.

Excluded / skipped:
  * computer accounts -- their passwords rotate automatically (30 days by
    default), so they acquire AES keys on their own;
  * accounts with pwd_last_set NULL or the FILETIME epoch (pwdLastSet = 0,
    "must change password at next logon") -- the old password is unusable;
  * a domain (by SID) for which neither the RID 521 group nor the Domain
    Users group (RID 513) was collected -- group data is missing, so
    "never reached 2008" cannot be concluded; also a domain whose RID 521
    group exists but whose creation time is unknown.

Severity: medium; high if the account has an SPN (service tickets for it
are RC4 and roastable; krbtgt carries kadmin/changepw) or is a current
Tier 0 principal (v_privileged_principal).
"""

PLUGIN = {
    "plugin_id": 1045,
    "category": "User Accounts",
    "name": "Account Has No AES Kerberos Keys (Password Predates AES Key Generation)",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "KERB-1045",
    "framework_tags": [
        "NIST-800-53-SC-13", "NIST-CSF-2.0-PR.DS-02", "PCI-DSS-4.0-12.3.3",
        "CIS-CSC-8-3.10", "ISO-27001-2022-A.8.24", "SOC2-CC6.1",
        "CVE-2022-37966", "MITRE-ATTCK-T1558.003",
    ],
    "references": [
        {"title": "KB5021131: How to manage the Kerberos protocol changes related to CVE-2022-37966",
         "url": "https://support.microsoft.com/en-us/topic/kb5021131-how-to-manage-the-kerberos-protocol-changes-related-to-cve-2022-37966-fd837ac3-cdec-4e76-a6ec-86e67501407d"},
        {"title": "MSRC: CVE-2022-37966 Windows Kerberos RC4-HMAC Elevation of Privilege Vulnerability",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-37966"},
        {"title": "NVD: CVE-2022-37966",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-37966"},
        {"title": "Microsoft: Network security - Configure encryption types allowed for Kerberos",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"},
        {"title": "PingCastle health check rules (S-AesNotEnabled)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1558.003: Kerberoasting",
         "url": "https://attack.mitre.org/techniques/T1558/003/"},
    ],
    "description": (
        "The account's password was last set before the domain began "
        "generating AES Kerberos keys (approximated, as PingCastle does, by "
        "the creation of the Read-only Domain Controllers group, or the "
        "domain never reached the 2008 functional level). The account has "
        "only an RC4 (NT hash) key: its tickets are RC4 and cheap to crack "
        "offline, and it will fail to authenticate once RC4 is disabled, as "
        "Microsoft's RC4 deprecation and the CVE-2022-37966 (KB5021131) "
        "hardening move domain controllers to AES-only."
    ),
    "remediation": (
        "Reset the password of each listed account (for krbtgt, use the "
        "documented two-reset procedure with full replication in between, "
        "e.g. Microsoft's New-KrbtgtKeys.ps1). A reset in a domain at DFL "
        "2008 or later generates AES keys. If the domain is still below DFL "
        "2008, raise it first (Set-ADDomainMode). For service accounts, "
        "prefer migrating to a gMSA/dMSA; otherwise reset the password, then "
        "set msDS-SupportedEncryptionTypes to AES only (0x18) once the "
        "service is confirmed to work with AES. Check with "
        "Get-ADUser <sam> -Properties pwdLastSet,msDS-SupportedEncryptionTypes, "
        "and monitor event 4769 (Ticket Encryption Type 0x17) for remaining "
        "RC4 use before disabling RC4."
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
        wk_group AS (
            -- Domain Users (513) and Read-only Domain Controllers (521),
            -- by SID, per domain SID.
            SELECT regexp_replace(o.object_sid, '-[0-9]+$', '') AS domain_sid,
                   substring(o.object_sid FROM '-([0-9]+)$')::int AS rid,
                   COALESCE(g.when_created,
                            CASE WHEN v.attributes_full ->> 'whenCreated'
                                      ~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}[ T][0-9]{2}:[0-9]{2}'
                                 THEN (v.attributes_full ->> 'whenCreated')::timestamptz
                            END) AS when_created
            FROM directory_object o
            JOIN ad_group g
              ON g.object_guid = o.object_guid AND g.client_id = o.client_id
             AND g.valid_to IS NULL
            LEFT JOIN directory_object_version v
              ON v.object_guid = o.object_guid AND v.client_id = o.client_id
             AND v.valid_to IS NULL
            WHERE o.client_id = %(client_id)s
              AND NOT o.is_deleted
              AND o.object_sid ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(513|521)$'
        ),
        dom AS (
            SELECT domain_sid,
                   bool_or(rid = 521) AS has_rodc_group,
                   min(when_created) FILTER (WHERE rid = 521) AS aes_since
            FROM wk_group
            GROUP BY domain_sid
        ),
        cand AS (
            SELECT u.object_guid, u.sam_account_name, u.user_principal_name,
                   u.is_enabled, u.pwd_last_set, u.supported_encryption_types,
                   u.service_principal_names,
                   o.object_sid LIKE '%%-502' AS is_krbtgt,
                   d.has_rodc_group, d.aes_since
            FROM ad_user u
            JOIN directory_object o
              ON o.object_guid = u.object_guid AND o.client_id = u.client_id
             AND NOT o.is_deleted
            JOIN dom d
              ON d.domain_sid = regexp_replace(o.object_sid, '-[0-9]+$', '')
            WHERE u.client_id = %(client_id)s
              AND u.valid_to IS NULL
              AND (u.is_enabled OR o.object_sid LIKE '%%-502')
              AND u.pwd_last_set IS NOT NULL
              -- pwdLastSet = 0 (must change at next logon) arrives as 1601-01-01
              AND u.pwd_last_set > TIMESTAMPTZ '1601-01-02 00:00:00+00'
              AND (NOT d.has_rodc_group
                   OR (d.aes_since IS NOT NULL
                       AND u.pwd_last_set < d.aes_since - INTERVAL '1 hour'))
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN t.object_guid IS NOT NULL
                      OR cardinality(c.service_principal_names) > 0
                 THEN 'high' ELSE 'medium' END AS fd_severity,
            (CASE WHEN t.object_guid IS NOT NULL THEN 'Tier 0 ' ELSE '' END)
                || 'User account '
                || COALESCE(c.user_principal_name, c.sam_account_name, c.object_guid::text)
                || ' has no AES Kerberos keys (RC4 only): '
                || CASE WHEN c.has_rodc_group
                        THEN 'password last set '
                             || to_char(c.pwd_last_set AT TIME ZONE 'UTC', 'YYYY-MM-DD')
                             || ', before the domain began generating AES keys ('
                             || to_char(c.aes_since AT TIME ZONE 'UTC', 'YYYY-MM-DD') || ')'
                        ELSE 'the domain has never reached the Windows Server 2008 '
                             || 'functional level (no Read-only Domain Controllers group)'
                   END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'user_principal_name', c.user_principal_name,
                'is_enabled', c.is_enabled,
                'is_krbtgt', c.is_krbtgt,
                'pwd_last_set', c.pwd_last_set,
                'aes_keys_since', c.aes_since,
                'rodc_group_present', c.has_rodc_group,
                'supported_encryption_types', c.supported_encryption_types,
                'service_principal_names', to_jsonb(c.service_principal_names),
                'tier0', t.object_guid IS NOT NULL,
                'privilege_sources', t.privilege_sources
            ) AS detail
        FROM cand c
        LEFT JOIN tier0 t ON t.object_guid = c.object_guid
    """,
}
