"""
Plugin 6004: Certificate Template Grants the Certificate Request Agent EKU (ESC3)

ESC3 (SpecterOps' "Certified Pre-Owned" research, technique name
"Misconfigured Certificate Request Agent"): a published certificate
template whose Extended Key Usage includes the Certificate Request
Agent OID (1.3.6.1.4.1.311.20.2.1, confirmed against multiple
independent technical sources including SpecterOps' own Certify
documentation). A certificate issued from such a template lets its
holder sign certificate requests "on behalf of" other users -- acting
as an enrollment agent. Full exploitation additionally requires a
second, separate template that accepts enrollment-agent-signed
requests without adequately restricting who the agent can request on
behalf of, which this finding does not confirm; what's flagged here
is the structural precondition -- a template that can mint enrollment
agent certificates at all -- the same "identify the pattern, not the
full attack chain" scope already used for this project's other ADCS
findings (plugins 6001-6003).
"""

PLUGIN = {
    "plugin_id": 6004,
    "category": "Certificate Services",
    "name": "Certificate Template Grants the Certificate Request Agent EKU (ESC3)",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Confirm who can enroll against this template (its own "
        "security tab, or `certutil -v -template <name>`) -- if this "
        "is broader than a small, trusted set of principals who "
        "genuinely need to issue certificates on behalf of others "
        "(e.g. a smart card provisioning team), restrict it. Separately, "
        "audit every OTHER published template for whether it restricts "
        "enrollment-agent-signed requests via msPKI-RA-Signature and "
        "the Application Policy Issuance Requirement -- ESC3 requires "
        "both this template AND a second, insufficiently-restricted "
        "target template to be exploitable, so closing either half "
        "breaks the chain."
    ),
    "control_id": "ADCS-104",
    "framework_tags": [],
    "references": [
        {"title": "SpecterOps Certify Documentation: ESC3 -- Misconfigured Certificate Request Agent",
         "url": "https://docs.specterops.io/ghostpack-docs/Certify.wik-mdx/esc3-misconfigured-certificate-request-agent"},
    ],
    "description": (
        "ESC3 (SpecterOps' 'Certified Pre-Owned' research): a "
        "published certificate template whose Extended Key Usage "
        "includes the Certificate Request Agent OID "
        "(1.3.6.1.4.1.311.20.2.1). A certificate issued from such a "
        "template lets its holder sign certificate requests 'on "
        "behalf of' other users -- acting as an enrollment agent. "
        "Full exploitation additionally requires a second, separate "
        "template that accepts enrollment-agent-signed requests "
        "without adequately restricting who the agent can act for, "
        "which this finding does not confirm -- it identifies the "
        "structural precondition only, the same scope already used "
        "for this project's other ADCS findings (plugins 6001-6003)."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            ct.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Certificate template "' || COALESCE(ct.display_name, ct.template_name)
                || '" grants the Certificate Request Agent EKU (ESC3 pattern)' AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'extended_key_usage', ct.extended_key_usage,
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
          AND ct.extended_key_usage @> ARRAY['1.3.6.1.4.1.311.20.2.1']
    """,
}
