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

[v1.2] Templates requiring CA manager approval (msPKI-Enrollment-Flag &
0x2) or authorized signatures (msPKI-RA-Signature, schema v36) are no
longer reported, and the template's enrollment ACL (collected in
acl_edge since adprofiler v0.5.4) is evaluated: medium when a
low-privileged principal (Domain Users, Domain Computers, Authenticated
Users, Everyone, or any principal not in v_privileged_principal) holds
Enroll / AutoEnroll, All Extended Rights or GenericAll; low otherwise.
The summary names the low-privileged enrollers.
"""

PLUGIN = {
    "plugin_id": 6004,
    "category": "Certificate Services",
    "name": "Certificate Template Grants the Certificate Request Agent EKU (ESC3)",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Review who can enroll against this template (the evidence "
        "lists low-privileged enrollers; see its security tab, or "
        "`certutil -v -template <name>`) -- if this "
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
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1649"],
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
        "structural precondition only. Templates requiring CA manager "
        "approval or authorized signatures are not reported; the "
        "severity is medium when a low-privileged principal can enroll "
        "and low otherwise."
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
                || '" grants the Certificate Request Agent EKU (ESC3 pattern)'
                || CASE WHEN lpe.template_guid IS NOT NULL
                        THEN '; low-privileged principals can enroll: '
                             || array_to_string(lpe.low_priv_enrollers, ', ')
                        ELSE '; no low-privileged principal can enroll'
                   END AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
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
          AND ct.extended_key_usage @> ARRAY['1.3.6.1.4.1.311.20.2.1']
          -- [v1.2] canonical ESC3 condition 1: no CA manager approval,
          -- no authorized signatures.
          AND (COALESCE(ct.enrollment_flags, 0) & 2) = 0
          AND COALESCE(ct.ra_signature_count, 0) = 0
    """,
}
