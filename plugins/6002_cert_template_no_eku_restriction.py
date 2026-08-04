"""
Plugin 6002: Certificate Template Has No Extended Key Usage Restriction

ESC2, from SpecterOps' "Certified Pre-Owned" research: a published
certificate template whose Extended Key Usage (EKU) is either
explicitly set to "Any Purpose" or left completely unrestricted --
Windows treats an empty EKU list the same way it treats an explicit
Any Purpose OID. A certificate issued from such a template can be used
for anything the underlying key supports, including client
authentication, regardless of what the template was actually intended
for. Deliberately excludes templates already flagged by plugin 6001
(ESC1): a template that also permits enrollee-supplied subject names
is the more severe, more specific ESC1 pattern, and flagging the same
template twice under two findings would be noise rather than signal.
This finding is what's left after that exclusion -- unrestricted EKU
on its own, without subject-name control, still meaningfully widens
what a certificate from this template can be used for.
"""

PLUGIN = {
    "plugin_id": 6002,
    "category": "Certificate Services",
    "name": "Certificate Template Has No Extended Key Usage Restriction",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Restrict the template's Extended Key Usage to only the "
        "specific purpose(s) it's actually intended for (Certificate "
        "Template console -> Extensions tab -> Application Policies / "
        "Extended Key Usage), rather than leaving it unrestricted. If "
        "this template genuinely needs to remain general-purpose, "
        "confirm who can enroll against it is tightly scoped -- the "
        "combination of broad enrollment rights and unrestricted EKU is "
        "what makes this pattern exploitable, not the EKU setting alone."
    ),
    "control_id": "ADCS-102",
    "framework_tags": [],
    "references": [
        {"title": "SpecterOps: Certified Pre-Owned -- Abusing Active Directory Certificate Services",
         "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2"},
    ],
    "description": (
        "ESC2 (SpecterOps' 'Certified Pre-Owned' research): a published "
        "certificate template with no Extended Key Usage restriction at "
        "all -- an empty EKU list is treated identically to an explicit "
        "Any Purpose OID by Windows' certificate validation. A "
        "certificate issued from such a template can be used for any "
        "purpose the key supports, including client authentication, "
        "regardless of the template's intended use. Excludes templates "
        "also matching plugin 6001's ESC1 pattern (enrollee-supplied "
        "subject name), since that combination is the more specific, "
        "more severe finding already covered there -- this finding is "
        "the remainder: unrestricted EKU without subject-name control. "
        "As with plugin 6001, this identifies the structural pattern "
        "only; actual exploitability additionally depends on who can "
        "enroll against the template, which this project does not yet "
        "collect."
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
                || '" is published with no Extended Key Usage restriction (functionally '
                'Any Purpose)' AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'requires_manager_approval', (COALESCE(ct.enrollment_flags, 0) & 2) != 0,
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
          AND ct.extended_key_usage IS NULL
          AND NOT (ct.enrollee_supplies_subject AND ct.client_authentication_capable)
    """,
}
