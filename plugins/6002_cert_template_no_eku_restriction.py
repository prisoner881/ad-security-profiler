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

[v1.2] Now also matches an explicit Any Purpose EKU (2.5.29.37.0), which
the query used to miss although the definition above includes it.
Applies the canonical ESC2 conditions: templates requiring CA manager
approval (msPKI-Enrollment-Flag & 0x2) or authorized signatures
(msPKI-RA-Signature > 0, collected since schema v36) are not reported,
and the template's enrollment ACL (in acl_edge since adprofiler v0.5.4)
is evaluated: fail / high when a low-privileged principal can enroll
(Enroll / AutoEnroll, All Extended Rights or GenericAll held by
Everyone, Authenticated Users, Domain Users, Domain Computers, or any
principal not privileged per v_privileged_principal), warn / low
otherwise. The summary names the low-privileged enrollers.
"""

PLUGIN = {
    "plugin_id": 6002,
    "category": "Certificate Services",
    "name": "Certificate Template Has No Extended Key Usage Restriction",
    "version": "1.2",
    "revision_date": "2026-10-04",
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
    "framework_tags": [
        "NIST-800-53-SC-17",
        "NIST-800-53-IA-5(2)",
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-CSF-2.0-PR.DS-02",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-4.2.1.1",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.24",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.1",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1649",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "SpecterOps: Certified Pre-Owned -- Abusing Active Directory Certificate Services",
         "url": "https://posts.specterops.io/certified-pre-owned-d95910965cd2"},
    ],
    "description": (
        "ESC2 (SpecterOps' 'Certified Pre-Owned' research): a published "
        "certificate template with an explicit Any Purpose EKU or no "
        "Extended Key Usage restriction at all -- an empty EKU list is treated identically to an explicit "
        "Any Purpose OID by Windows' certificate validation. A "
        "certificate issued from such a template can be used for any "
        "purpose the key supports, including client authentication, "
        "regardless of the template's intended use. Excludes templates "
        "also matching plugin 6001's ESC1 pattern (enrollee-supplied "
        "subject name), since that combination is the more specific, "
        "more severe finding already covered there -- this finding is "
        "the remainder: unrestricted EKU without subject-name control. "
        "Templates requiring CA manager approval or authorized "
        "signatures are not reported. The finding is fail / high when a "
        "low-privileged principal (Domain Users, Domain Computers, "
        "Authenticated Users, Everyone, or any non-privileged principal) "
        "can enroll, and warn / low when none can."
    ),
    "base_severity": "high",
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
            CASE WHEN lpe.template_guid IS NOT NULL THEN 'fail' ELSE 'warn' END AS status,
            ct.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN lpe.template_guid IS NOT NULL THEN 'high' ELSE 'low' END AS fd_severity,
            'Certificate template "' || COALESCE(ct.display_name, ct.template_name, ct.object_guid::text)
                || CASE WHEN ct.extended_key_usage IS NULL
                        THEN '" is published with no Extended Key Usage restriction (functionally '
                             'Any Purpose)'
                        ELSE '" is published with the Any Purpose Extended Key Usage (2.5.29.37.0)'
                   END
                || CASE WHEN lpe.template_guid IS NOT NULL
                        THEN ' and low-privileged principals can enroll: '
                             || array_to_string(lpe.low_priv_enrollers, ', ')
                        ELSE '; no low-privileged principal can enroll'
                   END AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'extended_key_usage', ct.extended_key_usage,
                'requires_manager_approval', false,
                'ra_signature_count', ct.ra_signature_count,
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
          -- [v1.2] no EKU, or an explicit Any Purpose EKU
          AND (ct.extended_key_usage IS NULL
               OR ct.extended_key_usage @> ARRAY['2.5.29.37.0'])
          -- [v1.2] canonical ESC2: no CA manager approval, no authorized signatures
          AND (COALESCE(ct.enrollment_flags, 0) & 2) = 0
          AND COALESCE(ct.ra_signature_count, 0) = 0
          -- ESS templates are reported by 6001 (ESC1) instead.
          AND NOT (ct.enrollee_supplies_subject AND ct.client_authentication_capable)
    """,
}
