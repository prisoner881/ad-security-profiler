"""
Plugin 6010: Certificate Template Vulnerable to ESC15 ("EKUwu" EKU Injection)

ESC15/"EKUwu", disclosed by Justin Bollinger (TrustedSec) in late 2024
and assigned CVE-2024-49019 (patched by Microsoft in November 2024):
a Schema Version 1 certificate template that also allows the enrollee
to supply an arbitrary subject (the same CT_FLAG_ENROLLEE_SUPPLIES_
SUBJECT flag plugin 6001 already checks for ESC1) lets an attacker
inject an arbitrary Application Policy / Extended Key Usage extension
directly into the certificate request -- V1 templates, unlike V2+,
don't populate msPKI-Certificate-Application-Policy, and AD CS's
handling of that gap doesn't reject a requester-supplied one the way
it should. This means a V1 template can be exploited exactly like
ESC1 even if it currently has NO client-authentication-capable EKU at
all -- the attacker adds Client Authentication themselves at request
time. Confirmed against multiple independent sources (TrustedSec,
SpecterOps/Certify wiki, Certipy's own PR implementing detection)
before building this.

Deliberately a distinct plugin from 6001 (ESC1) rather than folding
schema_version into that query: an unpatched CA is vulnerable via THIS
mechanism regardless of the template's current EKU configuration --
flagging it as "ESC1" specifically would understate why it's
exploitable and could suggest EKU remediation alone is sufficient,
when the schema version itself (or the November 2024 patch) is what
actually matters here.
"""

PLUGIN = {
    "plugin_id": 6010,
    "category": "Certificate Services",
    "name": "Certificate Template Vulnerable to ESC15 (\"EKUwu\" EKU Injection)",
    "version": "1.0",
    "revision_date": "2026-07-31",
    "remediation": (
        "First, confirm the November 2024 patch for CVE-2024-49019 is "
        "installed on every Certificate Authority server -- this "
        "closes the underlying vulnerability regardless of template "
        "configuration. Independently, this template's schema version "
        "cannot be changed in place (V1 templates cannot be upgraded "
        "via the GUI) -- duplicate it, which automatically creates a "
        "V2+ template, then unpublish and remove the original V1 "
        "template from this CA once the duplicate is in use."
    ),
    "control_id": "PKI-1501",
    "framework_tags": [],
    "references": [
        {"title": "SpecterOps/Certify Wiki: ESC15 -- EKUwu (Application Policy Injection)",
         "url": "https://docs.specterops.io/ghostpack-docs/Certify.wik-mdx/esc15-ekuwu-application-policy-injection"},
        {"title": "Microsoft Security Response Center: CVE-2024-49019",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-49019"},
    ],
    "description": (
        "A Schema Version 1 certificate template also allows the "
        "enrollee to supply an arbitrary subject -- exploitable via "
        "ESC15/\"EKUwu\" (CVE-2024-49019, patched November 2024) to "
        "inject an arbitrary Extended Key Usage (e.g. Client "
        "Authentication) directly into the certificate request, even "
        "if the template currently has no client-auth-capable EKU "
        "configured at all."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            ct.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Certificate template "' || ct.display_name
                || '" is Schema Version 1 and allows enrollee-supplied subject -- '
                || 'vulnerable to ESC15/EKUwu (CVE-2024-49019) unless the CA is patched' AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'schema_version', ct.schema_version,
                'enrollee_supplies_subject', ct.enrollee_supplies_subject
            ) AS detail
        FROM ad_cert_template ct
        WHERE ct.client_id = %(client_id)s
          AND ct.valid_to IS NULL
          AND ct.schema_version = 1
          AND ct.enrollee_supplies_subject
    """,
}
