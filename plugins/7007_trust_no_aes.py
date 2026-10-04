"""
Plugin 7007: Windows Trust Without AES Kerberos Encryption

Reports Windows (uplevel, trustType = 2) trusts whose trusted domain object
does not enable AES in msDS-SupportedEncryptionTypes (bits 0x08 AES128 /
0x10 AES256). Cross-domain Kerberos referral tickets are encrypted with the
inter-realm trust key; when the trust does not advertise AES, DCs fall back
to RC4-HMAC, whose key is the unsalted MD4 of the trust password and which
Microsoft is removing (CVE-2022-37966 / KB5021131 hardening, RC4 deprecation).
RC4 referral tickets can also be cracked offline or forged with a stolen
trust key more easily. PingCastle T-AlgsAES flags the same condition.

Two cases, one row per trust:
  * attribute set (non-zero) but without AES, e.g. RC4 and/or DES only ->
    'fail', medium;
  * attribute not set (NULL or 0) -> 'warn', low: the encryption types then
    depend on the DCs' defaults (DefaultDomainSupportedEncTypes and the
    patch level on both sides) and RC4 may still be negotiated; set AES
    explicitly. This case does not claim RC4 definitively.
Unset types on a trust inside the forest (TRUST_ATTRIBUTE_WITHIN_FOREST,
0x20 -- parent-child and tree-root trusts) are not reported: intra-forest
referrals use AES by default whenever both domains' DCs support it, and the
attribute is normally left unset there, so every such trust would otherwise
produce a low warning that needs no action. An explicit non-AES value is
still reported for them.
MIT realm trusts (trustType 3) are plugin 7003's; downlevel trusts (1) are
plugin 7008's; disabled trusts (trust_direction 0) are plugin 7004's.

Data: ad_trust.supported_encryption_types (schema v38, from the TDO's
msDS-SupportedEncryptionTypes).
"""

PLUGIN = {
    "plugin_id": 7007,
    "category": "Trusts",
    "name": "Windows Trust Without AES Kerberos Encryption",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "TRUST-7007",
    "framework_tags": [
        "NIST-800-53-SC-13", "NIST-CSF-2.0-PR.DS-02", "CIS-CSC-8-3.10",
        "ISO-27001-2022-A.8.24", "SOC2-CC6.1", "HIPAA-164.312(e)(1)",
        "NIST-800-53-AC-20", "MITRE-ATTCK-T1558", "CVE-2022-37966",
    ],
    "references": [
        {"title": "NVD: CVE-2022-37966 (Kerberos RC4-HMAC elevation of privilege)",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2022-37966"},
        {"title": "Microsoft: Network security - Configure encryption types allowed for Kerberos",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"},
        {"title": "PingCastle health check rules (T-AlgsAES)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets",
         "url": "https://attack.mitre.org/techniques/T1558/"},
    ],
    "description": (
        "A Windows trust's msDS-SupportedEncryptionTypes does not include "
        "AES. When explicitly set to RC4/DES only (medium), cross-domain "
        "Kerberos referral tickets use the weak RC4/DES trust key; when not "
        "set at all (low), the encryption type depends on DC defaults and "
        "RC4 may still be used -- AES should be set explicitly."
    ),
    "remediation": (
        "Confirm both sides support AES (Windows Server 2008 or later DCs), "
        "then enable it on the trust on BOTH sides: Active Directory "
        "Domains and Trusts -> domain -> Properties -> Trusts -> <trust> -> "
        "Properties -> 'The other domain supports Kerberos AES Encryption', "
        "or ksetup /setenctypeattr <trusted domain DNS name> "
        "AES128-CTS-HMAC-SHA1-96 AES256-CTS-HMAC-SHA1-96 (Set-ADObject "
        "on the TDO's msDS-SupportedEncryptionTypes = 0x18 is equivalent). "
        "Reset the trust password afterwards (netdom trust /resetOneSide or "
        "the GUI 'Validate'/'Reset') so AES keys are derived, and test "
        "cross-domain authentication before removing RC4."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            CASE WHEN COALESCE(t.supported_encryption_types, 0) = 0 THEN 'warn' ELSE 'fail' END AS status,
            t.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN COALESCE(t.supported_encryption_types, 0) = 0 THEN 'low' ELSE 'medium' END AS fd_severity,
            CASE WHEN COALESCE(t.supported_encryption_types, 0) = 0 THEN
                     'Trust with "' || COALESCE(t.trust_partner, '(unknown)')
                     || '" does not set Kerberos encryption types: AES use depends on DC defaults; set AES explicitly'
                 ELSE
                     'Trust with "' || COALESCE(t.trust_partner, '(unknown)')
                     || '" allows only '
                     || COALESCE(NULLIF(array_to_string(ARRAY_REMOVE(ARRAY[
                            CASE WHEN (t.supported_encryption_types & 3) <> 0 THEN 'DES' END,
                            CASE WHEN (t.supported_encryption_types & 4) <> 0 THEN 'RC4' END
                        ], NULL), '/'), ''), 'non-AES')
                     || ' Kerberos encryption, not AES'
            END AS summary,
            jsonb_build_object(
                'trust_partner', t.trust_partner,
                'trust_type', t.trust_type,
                'trust_direction', t.trust_direction,
                'trust_attributes', t.trust_attributes,
                'within_forest', (COALESCE(t.trust_attributes, 0) & 32) <> 0,
                'forest_trust', (COALESCE(t.trust_attributes, 0) & 8) <> 0,
                'msds_supported_encryption_types', t.supported_encryption_types
            ) AS detail
        FROM ad_trust t
        JOIN directory_object o
          ON o.object_guid = t.object_guid AND o.client_id = t.client_id AND NOT o.is_deleted
        WHERE t.client_id = %(client_id)s
          AND t.valid_to IS NULL
          AND t.trust_type = 2
          AND COALESCE(t.trust_direction, -1) <> 0
          AND (COALESCE(t.supported_encryption_types, 0) & 24) = 0
          AND NOT (COALESCE(t.supported_encryption_types, 0) = 0
                   AND (COALESCE(t.trust_attributes, 0) & 32) <> 0)
    """,
}
