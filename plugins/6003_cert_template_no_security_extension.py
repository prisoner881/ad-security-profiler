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
"""

PLUGIN = {
    "plugin_id": 6003,
    "category": "Certificate Services",
    "name": "Certificate Template Omits the Security Identifier Extension (ESC9)",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Remove the CT_FLAG_NO_SECURITY_EXTENSION flag from this "
        "template's msPKI-Enrollment-Flag unless there is a specific, "
        "documented reason it must remain unset (`certutil -dstemplate "
        "<name> msPKI-Enrollment-Flag -0x00080000`). Separately, confirm "
        "the domain's StrongCertificateBindingEnforcement registry value "
        "on domain controllers -- Microsoft's default since the May 2022 "
        "update is Compatibility mode (value 1), not Full Enforcement "
        "(value 2); moving to Full Enforcement closes the gap this flag "
        "otherwise opens, though it requires validating that no "
        "legitimate certificate-based authentication currently depends "
        "on the weaker mapping first."
    ),
    "control_id": "ADCS-103",
    "framework_tags": [],
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
        "unless the domain has been moved to Full Enforcement mode for "
        "strong certificate binding, which is not Microsoft's default. "
        "Combined with any means of writing to an account attribute that "
        "affects that weaker mapping, this can enable authenticating as "
        "another principal. Only checked against enabled (published) "
        "templates, for the same reason as plugins 6001/6002: an "
        "unpublished template cannot be requested by anyone."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            ct.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Certificate template "' || COALESCE(ct.display_name, ct.template_name)
                || '" has CT_FLAG_NO_SECURITY_EXTENSION set, omitting the certificate '
                'security identifier extension (ESC9 pattern)' AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'enrollment_flags', ct.enrollment_flags,
                'published_on_cas', (
                    SELECT array_agg(es.ca_name ORDER BY es.ca_name)
                    FROM cert_template_enabled_edge ctee
                    JOIN ad_enrollment_service es ON es.object_guid = ctee.ca_guid AND es.client_id = ctee.client_id AND es.valid_to IS NULL
                    WHERE ctee.template_guid = ct.object_guid AND ctee.client_id = ct.client_id AND ctee.valid_to IS NULL
                )
            ) AS detail
        FROM ad_cert_template ct
        WHERE ct.valid_to IS NULL
          AND ct.client_id = %(client_id)s
          AND ct.is_enabled
          AND (COALESCE(ct.enrollment_flags, 0) & 524288) != 0
    """,
}
