"""
Plugin 2018: Computer Account Does Not Support AES Kerberos Encryption

Distinct from the existing DES checks (2005/2016): flags a computer
account that supports neither DES nor AES, falling back to RC4. Lower
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
"""

PLUGIN = {
    "plugin_id": 2018,
    "category": "Computer Accounts",
    "name": "Computer Account Does Not Support AES Kerberos Encryption",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Set msDS-SupportedEncryptionTypes to include AES128/AES256 "
        "(bits 0x8/0x10) -- typically automatic for modern, "
        "domain-joined Windows computers, so a computer missing this is "
        "usually either very old or has an unusual join/provisioning "
        "history worth understanding. Can be set directly via "
        "`Set-ADComputer -KerberosEncryptionType AES128,AES256` if not "
        "already resolved by the OS itself on next password rotation."
    ),
    "control_id": "KERB-202",
    "framework_tags": [],
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
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE 'Computer Account ' END)
                || c.sam_account_name
                || ' does not support AES Kerberos encryption' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'supported_encryption_types', c.supported_encryption_types,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.is_enabled
          AND (COALESCE(c.supported_encryption_types, 0) & 24) = 0
    """,
}
