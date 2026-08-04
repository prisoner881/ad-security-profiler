"""
Plugin 7003: MIT Kerberos Realm Trust Uses RC4 Encryption

TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION (trustAttributes bit 0x00000080,
confirmed against Microsoft's own [MS-ADTS] specification) is set on
trusts to a non-Windows, RFC4120-compliant Kerberos realm (trustType=3,
"MIT") that are configured to use RC4 for cross-realm ticket
encryption. Consistent with this project's existing position on RC4
and DES within a single domain (plugins 1011/1019/2005/2016/2018):
RC4 directly derives from an NTLM-equivalent key and is considered
weak by current standards. Historically, older MIT Kerberos
distributions supported only DES/3DES until MIT 1.4.1 added RC4-HMAC
for Windows interoperability -- if the trusted realm is running a
sufficiently current MIT Kerberos version, RC4 may no longer be needed
at all.
"""

PLUGIN = {
    "plugin_id": 7003,
    "category": "Trusts",
    "name": "MIT Kerberos Realm Trust Uses RC4 Encryption",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Confirm the MIT Kerberos realm on the other side of this trust "
        "supports AES for cross-realm authentication (MIT krb5 1.7 and "
        "later). If it does, reconfigure the trust to use AES instead of "
        "RC4 (`netdom trust` / `ksetup` depending on tooling, or by "
        "editing the trust's supported encryption types via Active "
        "Directory Domains and Trusts). If the realm genuinely cannot "
        "support AES, treat this as accepted risk tied to that "
        "dependency and prioritize upgrading the realm."
    ),
    "control_id": "TRUST-103",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: [MS-ADTS] trustAttributes",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c"},
    ],
    "description": (
        "TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION (trustAttributes bit "
        "0x00000080, confirmed against Microsoft's own [MS-ADTS] "
        "specification) is set on trusts to a non-Windows MIT Kerberos "
        "realm configured to use RC4 for cross-realm ticket encryption. "
        "Consistent with this project's existing RC4/DES findings "
        "within a single domain, RC4 directly derives from an NTLM-"
        "equivalent key and is considered weak by current standards. "
        "Older MIT Kerberos distributions required RC4 for Windows "
        "interoperability before MIT 1.4.1 added support for it "
        "natively; sufficiently current MIT realms can typically use "
        "AES instead."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            t.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'MIT Kerberos realm trust with "' || COALESCE(t.trust_partner, '(unknown)')
                || '" is configured to use RC4 encryption' AS summary,
            jsonb_build_object(
                'trust_partner', t.trust_partner,
                'trust_direction', t.trust_direction,
                'trust_attributes', t.trust_attributes,
                'uses_aes', (COALESCE(t.trust_attributes, 0) & 256) != 0
            ) AS detail
        FROM ad_trust t
        WHERE t.valid_to IS NULL
          AND t.client_id = %(client_id)s
          AND t.trust_type = 3
          AND (COALESCE(t.trust_attributes, 0) & 128) != 0
    """,
}
