"""
Plugin 2018: Computer Account Does Not Support AES Kerberos Encryption

Distinct from the existing DES checks (2005/2016): flags a computer
account whose msDS-SupportedEncryptionTypes lacks both AES bits
(0x8/0x10), so its service tickets fall back to RC4 (whether or not DES
is also enabled -- DES is covered by those other plugins). Lower
severity than the equivalent user-account check (1024) for a specific,
important reason: every computer account inherently has default SPNs
(HOST/, RestrictedKrbHost/) as a normal consequence of domain join, so
unlike the user check this isn't scoped to "has an SPN, which is
unusual" -- and a machine account's password is a 120-character
auto-generated random value, not realistically crackable via offline
Kerberoasting regardless of which encryption type is used. Still worth
flagging: RC4 usage is visible on the wire and contributes to a domain's
overall RC4 exposure, which some environments are actively working to
eliminate ahead of Microsoft's own RC4 deprecation timeline.

[v1.3] Rows are now labelled by account type: Domain Controller /
Read-only Domain Controller (RODCs are included in is_domain_controller
since schema v36, so they now get the DC escalation to medium), Group
Managed Service Account (ad_computer also holds gMSAs, recognised by a
msDS-GroupMSAMembership value in the current attributes_full) or
Computer Account. An account where msDS-SupportedEncryptionTypes is not
set at all is still reported (the KDC then applies
DefaultDomainSupportedEncTypes, which since the November 2022 updates
still issues RC4 tickets for such accounts), but the summary and detail
now say so explicitly (attribute_set = false) instead of presenting it
as an explicit RC4-only configuration -- typical for Linux/Samba hosts,
NAS appliances and cluster objects that never write the attribute.

[v1.4] The v1.3 note above is out of date: from the April 2026 update
(CVE-2026-20833; the July 2026 update removed the rollback) domain
controllers treat an account whose msDS-SupportedEncryptionTypes is not
set (or 0) as AES only (DefaultDomainSupportedEncTypes 0x18). Such
accounts are therefore no longer reported, unless the domain controllers'
Group Policy sets DefaultDomainSupportedEncTypes with RC4 (plugin 9043),
which brings RC4 back for all of them (then as before: medium for a DC,
low otherwise). Accounts explicitly set without AES are reported as
before. Without SYSVOL read by the evaluated run the Group Policy check is
skipped (sysvol_optional: the plugin still runs) and unset accounts are not
reported. A device whose keytab has no AES key now fails Kerberos instead
of falling back to RC4; it shows in the DC's System log (KDCSVC events
201-209), not in the directory. detail adds kdc_default_rc4_gpos.
"""

PLUGIN = {
    "plugin_id": 2018,
    "category": "Computer Accounts",
    "name": "Computer Account Does Not Support AES Kerberos Encryption",
    "version": "1.4",
    "revision_date": "2026-11-01",
    "remediation": (
        "Set msDS-SupportedEncryptionTypes to include AES128/AES256 "
        "(bits 0x8/0x10) -- typically automatic for modern, "
        "domain-joined Windows computers, so a computer missing this is "
        "usually either very old or has an unusual join/provisioning "
        "history worth understanding. Can be set directly via "
        "`Set-ADComputer -KerberosEncryptionType AES128,AES256` if not "
        "already resolved by the OS itself on next password rotation. "
        "Where the attribute is not set at all (non-Windows joins, NAS "
        "appliances), the KDC default applies: AES only since the "
        "CVE-2026-20833 enforcement, unless Group Policy sets "
        "DefaultDomainSupportedEncTypes with RC4 (plugin 9043) -- remove "
        "that setting once the devices' keytabs have AES keys."
    ),
    "control_id": "KERB-202",
    "framework_tags": [
        "NIST-800-53-SC-13",
        "NIST-CSF-2.0-PR.DS-02",
        "PCI-DSS-4.0-12.3.3",
        "CIS-CSC-8-3.10",
        "ISO-27001-2022-A.8.24",
        "SOC2-CC6.1",
        "HIPAA-164.312(e)(1)",
        "MITRE-ATTCK-T1558",
        "CVE-2026-20833",
    ],
    "references": [
        {"title": "Microsoft: Network security -- Configure encryption types allowed for Kerberos",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"},
        {"title": "Microsoft: How to manage Kerberos KDC usage of RC4 for service account ticket issuance changes related to CVE-2026-20833",
         "url": "https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc"},
    ],
    "description": (
        "msDS-SupportedEncryptionTypes bits 0x8/0x10, same citation "
        "basis as plugin 1024. Lower severity than that plugin "
        "deliberately: a machine account's password is a 120-character "
        "auto-generated random value, not realistically crackable via "
        "offline Kerberoasting regardless of encryption type, so the "
        "primary risk here is RC4's visibility on the wire and its "
        "contribution to a domain's overall RC4 exposure -- relevant "
        "for environments working toward eliminating RC4 ahead of "
        "Microsoft's own deprecation timeline, not an immediate "
        "crackable-credential concern the way the user-account version "
        "of this check is. Since the CVE-2026-20833 enforcement (April "
        "2026) the KDC uses AES for accounts where the attribute is not "
        "set, so those are reported only when Group Policy puts RC4 back "
        "into the KDC default."
    ),
    "base_severity": "low",
    "sysvol_optional": True,
    "query": r"""
        WITH
        -- [v1.4] Since the CVE-2026-20833 enforcement (April 2026, rollback
        -- removed July 2026) the KDC issues AES-only service tickets for an
        -- account without msDS-SupportedEncryptionTypes -- unless Group
        -- Policy sets DefaultDomainSupportedEncTypes with RC4 on the DCs
        -- (plugin 9043). Read only when the evaluated run read SYSVOL.
        sysvol AS (
            SELECT EXISTS (SELECT 1 FROM sysvol_collection_status s
                           WHERE s.client_id = %(client_id)s AND s.run_id = %(run_id)s
                             AND (s.status = 'ok' OR (s.status = 'partial' AND s.gpos_read > 0)))
                   AS collected
        ),
        kdc_rc4 AS (
            SELECT string_agg(DISTINCT COALESCE(g.display_name, e.winning_gpo_guid::text), ', ') AS gpos
            FROM v_dc_effective_gpo_setting e
            CROSS JOIN sysvol sv
            LEFT JOIN ad_gpo g
              ON g.client_id = e.client_id AND g.object_guid = e.winning_gpo_guid AND g.valid_to IS NULL
            WHERE sv.collected
              AND e.client_id = %(client_id)s AND e.source = 'registry' AND e.section = 'HKLM'
              AND lower(e.setting_key) = lower('System\CurrentControlSet\Services\KDC\DefaultDomainSupportedEncTypes')
              AND e.value_type IS DISTINCT FROM 'DELETE'
              AND (CASE WHEN e.setting_value ~ '^\s*[0-9]{1,10}\s*$' THEN trim(e.setting_value)::bigint
                        WHEN e.setting_value ~* '^\s*0x[0-9a-f]{1,8}\s*$'
                             THEN ('x' || lpad(substr(trim(e.setting_value), 3), 8, '0'))::bit(32)::bigint
                   END & 4) <> 0
        )
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_domain_controller THEN 'medium' ELSE 'low' END AS fd_severity,
            (CASE WHEN c.is_read_only_dc THEN 'Read-only Domain Controller '
                  WHEN c.is_domain_controller THEN 'Domain Controller '
                  WHEN gm.is_gmsa THEN 'Group Managed Service Account '
                  ELSE 'Computer Account ' END)
                || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' does not support AES Kerberos encryption'
                || CASE WHEN COALESCE(c.supported_encryption_types, 0) = 0
                        THEN ' (msDS-SupportedEncryptionTypes not set, and Group Policy puts RC4 back into the '
                             || 'KDC default: DefaultDomainSupportedEncTypes, GPO ' || k.gpos || ')'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'supported_encryption_types', c.supported_encryption_types,
                'attribute_set', COALESCE(c.supported_encryption_types, 0) <> 0,
                'kdc_default_rc4_gpos', k.gpos,
                'is_domain_controller', c.is_domain_controller,
                'is_read_only_dc', c.is_read_only_dc,
                'is_gmsa', gm.is_gmsa,
                'operating_system', c.operating_system
            ) AS detail
        FROM ad_computer c
        CROSS JOIN kdc_rc4 k
        LEFT JOIN LATERAL (
            SELECT bool_or(dov.attributes_full->>'msDS-GroupMSAMembership' IS NOT NULL) IS TRUE AS is_gmsa
            FROM directory_object_version dov
            WHERE dov.object_guid = c.object_guid
              AND dov.client_id = c.client_id
              AND dov.valid_to IS NULL
        ) gm ON TRUE
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.is_enabled
          AND (COALESCE(c.supported_encryption_types, 0) & 24) = 0
          -- [v1.4] unset (or 0) uses AES since the RC4 enforcement, unless
          -- Group Policy re-enables RC4 in the KDC default
          AND (COALESCE(c.supported_encryption_types, 0) <> 0 OR k.gpos IS NOT NULL)
    """,
}
