"""
Plugin 1024: SPN-Bearing User Account Does Not Support AES Kerberos Encryption

Distinct from the existing DES checks (1011/1019): this flags an account
that supports NEITHER DES NOR AES for Kerberos, meaning it falls back to
RC4 -- weaker than AES and directly tied to the NTLM hash, making a
Kerberoasted ticket for this account crackable using NTLM-hash-cracking
techniques and tooling. Bit values (0x8 AES128, 0x10 AES256) confirmed
directly against Microsoft's own MS-KILE protocol specification. Scoped
to SPN-bearing accounts specifically -- msDS-SupportedEncryptionTypes is
only consulted by the KDC for the target of a TGS-REQ, meaning a
non-SPN user's value has no effect on Kerberos behavior at all.
"""

PLUGIN = {
    "plugin_id": 1024,
    "category": "User Accounts",
    "name": "SPN-Bearing User Account Does Not Support AES Kerberos Encryption",
    "version": "1.3",
    "revision_date": "2026-07-15",
    "remediation": (
        "Enable AES128 and/or AES256 support on this account (Account "
        "tab in ADUC: \"This account supports Kerberos AES 128/256 bit "
        "encryption\", or set msDS-SupportedEncryptionTypes to include "
        "bits 0x8/0x10 directly via LDAP/PowerShell: "
        "`Set-ADUser -KerberosEncryptionType AES128,AES256`). Test "
        "thoroughly before removing RC4 support entirely -- some older "
        "clients may depend on it -- but enabling AES alongside RC4 is "
        "a safe first step with no compatibility risk, and is a "
        "prerequisite for eventually disabling RC4 domain-wide."
    ),
    "control_id": "KERB-201",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "Microsoft: Network security -- Configure encryption types allowed for Kerberos",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"},
    ],
    "description": (
        "msDS-SupportedEncryptionTypes bits 0x8 (AES128-CTS-HMAC-SHA1-96) "
        "and 0x10 (AES256-CTS-HMAC-SHA1-96), confirmed directly against "
        "Microsoft's own MS-KILE protocol specification. An SPN-bearing "
        "account with neither bit set falls back to RC4 -- weaker than "
        "AES and directly derived from the account's NTLM hash, meaning "
        "a Kerberoasted service ticket for this account is crackable "
        "using the same tooling and techniques as NTLM hash cracking. "
        "Scoped to SPN-bearing accounts specifically: per Microsoft's "
        "own documentation, the KDC only consults "
        "msDS-SupportedEncryptionTypes for the target of a TGS-REQ, so "
        "a regular user account without an SPN is never the target of "
        "that operation and its encryption-type setting has no effect "
        "on Kerberos behavior at all."
    ),
    "base_severity": "medium",
    "query": """
        WITH privileged_check AS (
            -- [v1.x, ACL-aware] "Privileged" now means group-membership-based
            -- privilege (the original, sole definition) OR ACL-derived
            -- privilege: directly holding a dangerous right or DCSync rights
            -- on the domain root/AdminSDHolder, or owning either object.
            -- A user with none of the classic admin-group memberships but
            -- who directly holds GenericAll on the domain root is privileged
            -- in every meaningful sense -- arguably more concerning than a
            -- managed Domain Admin, since this kind of privilege is often
            -- unmanaged/accidental rather than deliberately delegated.
            SELECT DISTINCT vem.member_guid AS object_guid
            FROM v_effective_group_membership vem
            JOIN directory_object pgo
                ON pgo.object_guid = vem.group_guid AND pgo.client_id = vem.client_id
            JOIN ad_group pg
                ON pg.object_guid = pgo.object_guid AND pg.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
              AND pg.is_protected_group
            UNION
            SELECT do_acl.object_guid
            FROM acl_edge a
            JOIN directory_object do_acl ON do_acl.object_sid = a.trustee_sid AND do_acl.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                               '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                  )
            UNION
            SELECT do_owner.object_guid
            FROM directory_object owned_target
            JOIN directory_object do_owner
                ON do_owner.object_sid = owned_target.owner_sid AND do_owner.client_id = owned_target.client_id
            WHERE owned_target.client_id = %(client_id)s
              AND owned_target.owner_sid IS NOT NULL
        )
        SELECT
            'warn' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 'high' ELSE 'medium' END AS fd_severity,
            (CASE WHEN u.admin_count = 1 OR pc.object_guid IS NOT NULL THEN 'Privileged ' ELSE '' END)
                || 'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' has an SPN but does not support AES Kerberos encryption' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'supported_encryption_types', u.supported_encryption_types,
                'service_principal_names', u.service_principal_names
            ) AS detail
        FROM ad_user u
        LEFT JOIN privileged_check pc ON pc.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND u.service_principal_names IS NOT NULL
          AND array_length(u.service_principal_names, 1) > 0
          AND (COALESCE(u.supported_encryption_types, 0) & 24) = 0
    """,
}
