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
"""

PLUGIN = {
    "plugin_id": 2018,
    "category": "Computer Accounts",
    "name": "Computer Account Does Not Support AES Kerberos Encryption",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Set msDS-SupportedEncryptionTypes to include AES128/AES256 "
        "(bits 0x8/0x10) -- typically automatic for modern, "
        "domain-joined Windows computers, so a computer missing this is "
        "usually either very old or has an unusual join/provisioning "
        "history worth understanding. Can be set directly via "
        "`Set-ADComputer -KerberosEncryptionType AES128,AES256` if not "
        "already resolved by the OS itself on next password rotation. "
        "Where the attribute is not set at all (non-Windows joins, NAS "
        "appliances), set it explicitly once the device's keytab has AES "
        "keys, or the KDC default (DefaultDomainSupportedEncTypes) applies."
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
    ],
    "references": [
        {"title": "Microsoft: Network security -- Configure encryption types allowed for Kerberos",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"},
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
        "of this check is."
    ),
    "base_severity": "low",
    "query": """
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
                || CASE WHEN c.supported_encryption_types IS NULL
                        THEN ' (msDS-SupportedEncryptionTypes not set; KDC default applies)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'supported_encryption_types', c.supported_encryption_types,
                'attribute_set', c.supported_encryption_types IS NOT NULL,
                'is_domain_controller', c.is_domain_controller,
                'is_read_only_dc', c.is_read_only_dc,
                'is_gmsa', gm.is_gmsa,
                'operating_system', c.operating_system
            ) AS detail
        FROM ad_computer c
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
    """,
}
