"""
Plugin 6003: Certificate Template Omits the Security Identifier Extension (ESC9)

ESC9: a published certificate template with CT_FLAG_NO_SECURITY_EXTENSION
set (msPKI-Enrollment-Flag bit 0x80000, confirmed against Microsoft's own
[MS-CRTD] specification). Certificates issued from such a template omit
the szOID_NTDS_CA_SECURITY_EXT extension that Microsoft introduced in the
May 2022 update (the fix for CVE-2022-26923, "Certifried") specifically
to bind a certificate to the AD object that requested it. Without that
extension, domain controllers fall back to weaker, legacy identity-
mapping methods (typically the UPN or a SAN value) when validating the
certificate for authentication -- unless the domain has been moved to
Full Enforcement mode for strong certificate binding, which most have
not, since it is not the default and can break legitimate certificate-
based authentication that predates the patch.

[v1.2] Applies the canonical ESC9 preconditions: the template must be
client-authentication capable and need no CA manager approval
(msPKI-Enrollment-Flag & 0x2) or authorized signatures
(msPKI-RA-Signature), and its enrollment ACL is evaluated (medium when a
low-privileged principal can enroll -- Domain Users, Domain Computers,
Authenticated Users, Everyone or any principal not in
v_privileged_principal -- low otherwise). Lowered to warn: the
enforcement statement above is out of date. Microsoft's February 2025
update made Full Enforcement the DC default, and the September 2025
update removed Compatibility mode, so on patched DCs the Kerberos weak
mapping path is closed; the Schannel path (CertificateMappingMethods)
can remain.
"""

PLUGIN = {
    "plugin_id": 6003,
    "category": "Certificate Services",
    "name": "Certificate Template Omits the Security Identifier Extension (ESC9)",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Remove the CT_FLAG_NO_SECURITY_EXTENSION flag from this "
        "template's msPKI-Enrollment-Flag unless there is a specific, "
        "documented reason it must remain set (`certutil -dstemplate "
        "<name> msPKI-Enrollment-Flag -0x00080000`), and restrict who "
        "can enroll (the evidence lists low-privileged enrollers). "
        "Confirm every domain controller has the February 2025 or later "
        "update, which makes Full Enforcement of strong certificate "
        "binding the default (September 2025 and later updates remove "
        "Compatibility mode, so StrongCertificateBindingEnforcement can "
        "no longer weaken it), and that Schannel certificate mapping "
        "(SCHANNEL CertificateMappingMethods) does not enable weak "
        "UPN-based mapping."
    ),
    "control_id": "ADCS-103",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1649"],
    "references": [
        {"title": "Certipy Wiki: Privilege Escalation -- ESC9 (No Security Extension)",
         "url": "https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation"},
    ],
    "description": (
        "CT_FLAG_NO_SECURITY_EXTENSION (msPKI-Enrollment-Flag bit "
        "0x00080000, confirmed against Microsoft's own [MS-CRTD] "
        "specification) instructs the CA to omit the "
        "szOID_NTDS_CA_SECURITY_EXT extension from certificates issued "
        "by this template. That extension was introduced in the May "
        "2022 Windows update as the fix for CVE-2022-26923 ('Certifried') "
        "specifically to strongly bind an issued certificate to the AD "
        "object that requested it. Without it, domain controllers fall "
        "back to weaker, legacy certificate-to-identity mapping (SAN or "
        "UPN based) during Kerberos PKINIT or Schannel authentication -- "
        "on DCs still in Compatibility mode (patched DCs default to Full "
        "Enforcement since February 2025, which closes the Kerberos "
        "path; Schannel mapping can still be weak). "
        "Combined with any means of writing to an account attribute that "
        "affects that weaker mapping, this can enable authenticating as "
        "another principal. Only checked against enabled (published) "
        "templates, for the same reason as plugins 6001/6002: an "
        "unpublished template cannot be requested by anyone. Only "
        "client-auth-capable templates without manager approval or "
        "authorized signatures are reported: warn / medium when a "
        "low-privileged principal can enroll, warn / low otherwise."
    ),
    "base_severity": "medium",
    "query": """
        WITH
        -- Who can enroll: allow ACEs on the template that apply to it
        -- (inherit_only IS NOT TRUE) granting CONTROL_ACCESS (0x100) for
        -- Certificate-Enrollment (0e10c968-...) or AutoEnroll (a05b8cc2-...),
        -- or All Extended Rights (no object type -- GenericAll included).
        -- Low-privileged = Everyone, Authenticated Users, Anonymous,
        -- builtin Users/Guests, Domain Users/Guests/Computers, or any
        -- collected principal that is not a well-known admin SID, not an
        -- AdminSDHolder-protected group and not in v_privileged_principal.
        template_enrollers AS (
            SELECT a.object_guid AS template_guid,
                   COALESCE(tr.sam_account_name,
                            CASE WHEN a.trustee_sid = 'S-1-1-0' THEN 'Everyone'
                                 WHEN a.trustee_sid = 'S-1-5-11' THEN 'Authenticated Users'
                                 WHEN a.trustee_sid = 'S-1-5-7' THEN 'Anonymous Logon'
                                 WHEN a.trustee_sid = 'S-1-5-32-545' THEN 'Users'
                                 WHEN a.trustee_sid = 'S-1-5-32-546' THEN 'Guests'
                                 WHEN a.trustee_sid LIKE 'S-1-5-21-%%-513' THEN 'Domain Users'
                                 WHEN a.trustee_sid LIKE 'S-1-5-21-%%-514' THEN 'Domain Guests'
                                 WHEN a.trustee_sid LIKE 'S-1-5-21-%%-515' THEN 'Domain Computers'
                            END,
                            a.trustee_sid) AS trustee_name,
                   (a.trustee_sid IN ('S-1-1-0', 'S-1-5-11', 'S-1-5-7',
                                      'S-1-5-32-545', 'S-1-5-32-546')
                    OR a.trustee_sid LIKE 'S-1-5-21-%%-513'
                    OR a.trustee_sid LIKE 'S-1-5-21-%%-514'
                    OR a.trustee_sid LIKE 'S-1-5-21-%%-515'
                    OR (tr.object_guid IS NOT NULL
                        AND NOT (a.trustee_sid LIKE '%%-500' OR a.trustee_sid LIKE '%%-512'
                                 OR a.trustee_sid LIKE '%%-516' OR a.trustee_sid LIKE '%%-518'
                                 OR a.trustee_sid LIKE '%%-519' OR a.trustee_sid LIKE '%%-521'
                                 OR a.trustee_sid LIKE '%%-498'
                                 OR a.trustee_sid IN ('S-1-5-32-544', 'S-1-5-18', 'S-1-5-9'))
                        AND NOT EXISTS (SELECT 1 FROM ad_group pg
                                        WHERE pg.object_guid = tr.object_guid
                                          AND pg.client_id = tr.client_id
                                          AND pg.valid_to IS NULL AND pg.is_protected_group)
                        AND NOT EXISTS (SELECT 1 FROM v_privileged_principal vp
                                        WHERE vp.client_id = tr.client_id
                                          AND vp.object_guid = tr.object_guid))
                   ) AS is_low_privileged
            FROM acl_edge a
            LEFT JOIN directory_object tr
                ON tr.object_sid = a.trustee_sid AND tr.client_id = a.client_id
               AND NOT tr.is_deleted
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE
              AND (((a.access_mask & 256) <> 0
                    AND (a.object_type_guid IS NULL
                         OR a.object_type_guid IN ('0e10c968-78fb-11d2-90d4-00c04f79dc55',
                                                   'a05b8cc2-17bc-4802-a710-e7c15ab866a2')))
                   OR (a.access_mask & 268435456) <> 0)
        ),
        low_priv_enrollment AS (
            SELECT te.template_guid,
                   array_agg(DISTINCT te.trustee_name ORDER BY te.trustee_name) AS low_priv_enrollers
            FROM template_enrollers te
            WHERE te.is_low_privileged
            GROUP BY te.template_guid
        )
        SELECT
            'warn' AS status,
            ct.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN lpe.template_guid IS NOT NULL THEN 'medium' ELSE 'low' END AS fd_severity,
            'Certificate template "' || COALESCE(ct.display_name, ct.template_name, ct.object_guid::text)
                || '" has CT_FLAG_NO_SECURITY_EXTENSION set, omitting the certificate '
                'security identifier extension (ESC9 pattern)'
                || CASE WHEN lpe.template_guid IS NOT NULL
                        THEN '; low-privileged principals can enroll: '
                             || array_to_string(lpe.low_priv_enrollers, ', ')
                        ELSE '; no low-privileged principal can enroll'
                   END AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'enrollment_flags', ct.enrollment_flags,
                'extended_key_usage', ct.extended_key_usage,
                'low_privileged_enrollers', to_jsonb(lpe.low_priv_enrollers),
                'published_on_cas', (
                    SELECT array_agg(es.ca_name ORDER BY es.ca_name)
                    FROM cert_template_enabled_edge ctee
                    JOIN ad_enrollment_service es ON es.object_guid = ctee.ca_guid AND es.client_id = ctee.client_id AND es.valid_to IS NULL
                    WHERE ctee.template_guid = ct.object_guid AND ctee.client_id = ct.client_id AND ctee.valid_to IS NULL
                )
            ) AS detail
        FROM ad_cert_template ct
        LEFT JOIN low_priv_enrollment lpe ON lpe.template_guid = ct.object_guid
        WHERE ct.valid_to IS NULL
          AND ct.client_id = %(client_id)s
          AND ct.is_enabled
          AND (COALESCE(ct.enrollment_flags, 0) & 524288) != 0
          -- [v1.2] canonical ESC9: the certificate must be usable for
          -- client authentication, and issuance must not need CA manager
          -- approval or authorized signatures.
          AND ct.client_authentication_capable
          AND (COALESCE(ct.enrollment_flags, 0) & 2) = 0
          AND COALESCE(ct.ra_signature_count, 0) = 0
    """,
}
