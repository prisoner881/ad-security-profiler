"""
Plugin 11006: Certificate Template Newly Published to an Enterprise CA

Change Detection companion to the 6xxx Certificate Services plugins.
Those evaluate the standing configuration of every published template;
this reports the act of publishing, which is the moment a template
stops being inert configuration and becomes something anyone can
request against.

Derived from CISA advisory AA26-237A (2026-08-25), in which
misconfigured certificate templates matching the ESC1 pattern provided
the escalation path in the Government Services and Facilities
assessment, and a machine account created via MachineAccountQuota was
fed into a misconfigured template in the Water and Wastewater Systems
assessment.

Publishing is the right event to watch because of the asymmetry
plugin 6001 documents: a template's flags can be dangerous for years
without consequence as long as it is not published to a CA, since an
unpublished template cannot be requested by anyone. The publish
operation converts latent misconfiguration into live attack surface in
a single step, and it is a small, reviewable population -- most
environments publish templates rarely.

Severity is critical where the newly published template also matches
the ESC1 structural pattern (enrollee-supplied subject plus
client-authentication capability), since that combination is a
low-effort path to impersonating any domain principal.
"""

PLUGIN = {
    "plugin_id": 11006,
    "category": "Change Detection",
    "name": "Certificate Template Newly Published to an Enterprise CA",
    "version": "1.0",
    "revision_date": "2026-09-02",
    "remediation": (
        "Confirm the publication was intentional and that the "
        "template was reviewed before it went live. Where this "
        "finding's evidence shows the template also matches the ESC1 "
        "pattern, treat it as urgent: unpublish it immediately "
        "(Certification Authority console -> Certificate Templates -> "
        "right-click the template -> Delete, which removes it from "
        "the CA without deleting the template definition), then fix "
        "the underlying configuration before republishing. The fixes "
        "are to stop the enrollee supplying the subject name "
        "(Subject Name tab -> 'Build from Active Directory "
        "information'), to restrict the extended key usage so the "
        "certificate cannot be used for client authentication, to "
        "require manager approval, or to narrow enrollment rights to "
        "a small trusted group -- see plugin 6001 for the full "
        "treatment. Review who holds the rights to publish templates "
        "on the CA: publishing is a CA administrator operation, and "
        "if this action was not performed by a known CA "
        "administrator, treat it as an incident and review CA "
        "officer and ManageCA assignments (plugin 6008). Because a "
        "certificate issued from a dangerous template survives "
        "unpublishing and password resets, check the CA's issued "
        "certificate log for anything requested against this "
        "template during the exposure window, and revoke what you "
        "cannot account for."
    ),
    "control_id": "CHANGE-506",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1649", "MITRE-ATTCK-T1098"],
    "references": [
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
        {"title": "SpecterOps: Certified Pre-Owned -- Abusing Active Directory Certificate Services",
         "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2"},
    ],
    "description": (
        "Reports certificate templates that were published to an "
        "Enterprise CA between the previous collection run and this "
        "one. An unpublished template cannot be requested regardless "
        "of how dangerously it is configured, so publication is the "
        "point at which its configuration starts to matter -- and it "
        "is a rare, reviewable event in most environments. "
        "Misconfigured certificate templates were the escalation path "
        "in CISA's AA26-237A red team assessment. Severity is "
        "critical when the newly published template also matches the "
        "ESC1 structural pattern reported by plugin 6001, meaning it "
        "permits an enrollee-supplied subject name and issues "
        "certificates usable for client authentication. Suppressed on "
        "a client's first collection run."
    ),
    "base_severity": "high",
    "query": """
        WITH prior_run AS (
            SELECT EXISTS (
                SELECT 1 FROM sync_run sr
                WHERE sr.client_id = %(client_id)s
                  AND sr.run_id < %(run_id)s
                  AND sr.status = 'succeeded'
            ) AS have_prior
        ),
        newly_published AS (
            SELECT ctee.template_guid,
                   array_agg(DISTINCT es.ca_name ORDER BY es.ca_name) AS published_on_cas,
                   min(ctee.valid_from) AS change_observed_at
            FROM cert_template_enabled_edge ctee
            JOIN ad_enrollment_service es
                ON es.object_guid = ctee.ca_guid
               AND es.client_id = ctee.client_id
               AND es.valid_to IS NULL
            WHERE ctee.client_id = %(client_id)s
              AND ctee.valid_to IS NULL
              AND ctee.run_id_valid_from = %(run_id)s
            GROUP BY ctee.template_guid
        )
        SELECT
            'warn' AS status,
            ct.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN ct.enrollee_supplies_subject AND ct.client_authentication_capable
                    THEN 'critical'
                ELSE 'high'
            END AS fd_severity,
            'Certificate template "'
                || COALESCE(ct.display_name, ct.template_name)
                || '" was newly published on '
                || array_to_string(np.published_on_cas, ', ')
                || CASE
                       WHEN ct.enrollee_supplies_subject AND ct.client_authentication_capable
                           THEN ' and matches the ESC1 attack pattern (enrollee-supplied '
                                'subject name, client-auth capable) -- it is now '
                                'requestable and is a path to impersonating any domain '
                                'principal'
                       ELSE ' and is now requestable by anyone holding enrollment rights'
                   END AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'published_on_cas', np.published_on_cas,
                'change_observed_at', np.change_observed_at,
                'enrollee_supplies_subject', ct.enrollee_supplies_subject,
                'client_authentication_capable', ct.client_authentication_capable,
                'matches_esc1_pattern',
                    ct.enrollee_supplies_subject AND ct.client_authentication_capable,
                'requires_manager_approval',
                    (COALESCE(ct.enrollment_flags, 0) & 2) != 0,
                'extended_key_usage', ct.extended_key_usage
            ) AS detail
        FROM newly_published np
        JOIN ad_cert_template ct
            ON ct.object_guid = np.template_guid
           AND ct.client_id = %(client_id)s
           AND ct.valid_to IS NULL
        CROSS JOIN prior_run pr
        WHERE pr.have_prior
    """,
}
