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

[v1.1] Also reports an MIT realm trust with neither USES_RC4_ENCRYPTION
(0x80) nor USES_AES_KEYS (0x100) set: per [MS-KILE] such a trust falls
back to DES unless AES is configured in the trust object's
msDS-SupportedEncryptionTypes (e.g. `ksetup /setenctypeattr`). That
attribute is not in the collector's TRUST_ATTRS today, so it is read from
attributes_full when present (an AES bit 0x08/0x10 there clears the
finding) and otherwise the finding is raised at low severity with that
caveat in its summary, since a working trust without either bit is most
often AES-configured through that attribute. Description wording fixed
(MIT krb5 originally offered only DES/3DES; RC4-HMAC came in 1.4.1 for
Windows interoperability, AES later).
"""

PLUGIN = {
    "plugin_id": 7003,
    "category": "Trusts",
    "name": "MIT Kerberos Realm Trust Uses RC4 or DES Encryption",
    "version": "1.1",
    "revision_date": "2026-10-04",
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
        "Older MIT Kerberos distributions offered only DES/3DES; MIT "
        "1.4.1 added RC4-HMAC for Windows interoperability, and current "
        "MIT realms can use AES instead. An MIT realm trust with neither "
        "the RC4 (0x80) nor the AES (0x100) trust attribute set falls "
        "back to DES unless AES is configured in the trust object's "
        "msDS-SupportedEncryptionTypes; that case is reported at low "
        "severity (the attribute is honoured when collected, otherwise "
        "the summary says it could not be checked)."
    ),
    "base_severity": "medium",
    "query": """
        WITH mit AS (
            SELECT t.*,
                   -- [v1.1] msDS-SupportedEncryptionTypes, if ever collected
                   CASE WHEN set_txt ~ '^-?[0-9]+$' THEN set_txt::bigint END AS set_value,
                   (COALESCE(t.trust_attributes, 0) & 128) != 0 AS uses_rc4,
                   (COALESCE(t.trust_attributes, 0) & 256) != 0 AS uses_aes
            FROM ad_trust t
            LEFT JOIN directory_object_version v
                   ON v.version_id = t.version_id
                  AND v.object_guid = t.object_guid
                  AND v.client_id = t.client_id
            LEFT JOIN LATERAL (
                SELECT CASE jsonb_typeof(v.attributes_full -> 'msDS-SupportedEncryptionTypes')
                           WHEN 'array' THEN v.attributes_full -> 'msDS-SupportedEncryptionTypes' ->> 0
                           ELSE v.attributes_full ->> 'msDS-SupportedEncryptionTypes'
                       END AS set_txt
            ) e ON TRUE
            WHERE t.valid_to IS NULL
              AND t.client_id = %(client_id)s
              AND t.trust_type = 3
        )
        SELECT
            'warn' AS status,
            m.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN m.uses_rc4 THEN 'medium' ELSE 'low' END AS fd_severity,
            CASE
                WHEN m.uses_rc4 THEN
                    'MIT Kerberos realm trust with "' || COALESCE(m.trust_partner, '(unknown)')
                    || '" is configured to use RC4 encryption'
                WHEN m.set_value IS NULL THEN
                    'MIT Kerberos realm trust with "' || COALESCE(m.trust_partner, '(unknown)')
                    || '" has neither the RC4 nor the AES trust attribute set and defaults to DES'
                    || ' unless AES is set in msDS-SupportedEncryptionTypes (not collected)'
                ELSE
                    'MIT Kerberos realm trust with "' || COALESCE(m.trust_partner, '(unknown)')
                    || '" has no AES encryption type configured and defaults to DES'
            END AS summary,
            jsonb_build_object(
                'trust_partner', m.trust_partner,
                'trust_direction', m.trust_direction,
                'trust_attributes', m.trust_attributes,
                'uses_rc4', m.uses_rc4,
                'uses_aes', m.uses_aes,
                'msds_supported_encryption_types', m.set_value
            ) AS detail
        FROM mit m
        WHERE m.uses_rc4
           OR (NOT m.uses_aes
               AND (m.set_value IS NULL OR (m.set_value & 24) = 0))
    """,
}
