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

[v1.1] 'critical' and the ESC1 wording now require the full ESC1
preconditions used by plugin 6001: enrollee-supplied subject,
client-auth capability, no CA manager approval (enrollment_flags 0x2), no
authorized signatures (msPKI-RA-Signature) and Enroll/AutoEnroll (or All
Extended Rights / GenericAll) held by a low-privileged principal
(Everyone, Authenticated Users, Domain Users/Computers, ... or any
principal outside the privileged set). A template with the ESC1 flags
that is gated by approval/signatures or enrollable only by privileged
principals is high, with wording that says so. The low-privileged
enrollers and whether the publishing CA itself first appeared in this run
(a new CA publishing its default set, a one-off legitimate burst) are in
the detail. Summary is NULL-safe.
"""

PLUGIN = {
    "plugin_id": 11006,
    "category": "Change Detection",
    "name": "Certificate Template Newly Published to an Enterprise CA",
    "version": "1.1",
    "revision_date": "2026-10-04",
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
        "critical when the newly published template is exploitable via "
        "ESC1 as defined by plugin 6001: it permits an enrollee-supplied "
        "subject name, issues certificates usable for client "
        "authentication, requires neither CA manager approval nor "
        "authorized signatures, and a low-privileged principal holds "
        "enrollment rights on it. Otherwise high. Suppressed on a "
        "client's first collection run."
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
                   bool_and(cado.first_seen_run_id = %(run_id)s) AS ca_newly_installed,
                   min(ctee.valid_from) AS change_observed_at
            FROM cert_template_enabled_edge ctee
            JOIN ad_enrollment_service es
                ON es.object_guid = ctee.ca_guid
               AND es.client_id = ctee.client_id
               AND es.valid_to IS NULL
            LEFT JOIN directory_object cado
                ON cado.object_guid = ctee.ca_guid AND cado.client_id = ctee.client_id
            WHERE ctee.client_id = %(client_id)s
              AND ctee.valid_to IS NULL
              AND ctee.run_id_valid_from = %(run_id)s
            GROUP BY ctee.template_guid
        ),
        -- [v1.1] Low-privileged enrollers, mirroring plugin 6001: allow ACEs
        -- that apply to the template granting CONTROL_ACCESS for
        -- Certificate-Enrollment / AutoEnroll or All Extended Rights
        -- (GenericAll included), or GENERIC_ALL, held by a well-known
        -- broad principal or any collected principal outside the
        -- privileged set.
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
            JOIN newly_published np ON np.template_guid = a.object_guid
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
        ),
        classified AS (
            SELECT np.*, ct.object_guid, ct.template_name, ct.display_name,
                   ct.enrollee_supplies_subject, ct.client_authentication_capable,
                   ct.enrollment_flags, ct.ra_signature_count, ct.extended_key_usage,
                   lpe.low_priv_enrollers,
                   COALESCE(ct.enrollee_supplies_subject AND ct.client_authentication_capable,
                            false) AS esc1_flags,
                   (COALESCE(ct.enrollment_flags, 0) & 2) <> 0 AS requires_manager_approval,
                   COALESCE(ct.ra_signature_count, 0) > 0 AS requires_ra_signature
            FROM newly_published np
            JOIN ad_cert_template ct
                ON ct.object_guid = np.template_guid
               AND ct.client_id = %(client_id)s
               AND ct.valid_to IS NULL
            LEFT JOIN low_priv_enrollment lpe ON lpe.template_guid = np.template_guid
        )
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN c.esc1_flags AND NOT c.requires_manager_approval
                     AND NOT c.requires_ra_signature
                     AND c.low_priv_enrollers IS NOT NULL
                    THEN 'critical'
                ELSE 'high'
            END AS fd_severity,
            'Certificate template "'
                || COALESCE(c.display_name, c.template_name, c.object_guid::text)
                || '" was newly published on '
                || array_to_string(c.published_on_cas, ', ')
                || CASE
                       WHEN c.esc1_flags AND NOT c.requires_manager_approval
                            AND NOT c.requires_ra_signature
                            AND c.low_priv_enrollers IS NOT NULL
                           THEN ' and matches the ESC1 attack pattern (enrollee-supplied '
                                'subject name, client-auth capable, no approval, enrollable '
                                'by low-privileged principals: '
                                || array_to_string(c.low_priv_enrollers, ', ')
                                || ') -- it is now requestable and is a path to '
                                   'impersonating any domain principal'
                       WHEN c.esc1_flags
                           THEN ' and has the ESC1 template flags (enrollee-supplied '
                                'subject name, client-auth capable), gated by '
                                || CASE WHEN c.requires_manager_approval
                                             OR c.requires_ra_signature
                                        THEN 'manager approval or authorized signatures'
                                        ELSE 'enrollment rights held only by '
                                             'privileged principals' END
                       ELSE ' and is now requestable by anyone holding enrollment rights'
                   END AS summary,
            jsonb_build_object(
                'template_name', c.template_name,
                'display_name', c.display_name,
                'published_on_cas', c.published_on_cas,
                'ca_newly_installed', c.ca_newly_installed,
                'change_observed_at', c.change_observed_at,
                'enrollee_supplies_subject', c.enrollee_supplies_subject,
                'client_authentication_capable', c.client_authentication_capable,
                'matches_esc1_pattern',
                    c.esc1_flags AND NOT c.requires_manager_approval
                    AND NOT c.requires_ra_signature AND c.low_priv_enrollers IS NOT NULL,
                'requires_manager_approval', c.requires_manager_approval,
                'ra_signature_count', c.ra_signature_count,
                'low_privileged_enrollers', to_jsonb(c.low_priv_enrollers),
                'extended_key_usage', c.extended_key_usage
            ) AS detail
        FROM classified c
        CROSS JOIN prior_run pr
        WHERE pr.have_prior
    """,
}
