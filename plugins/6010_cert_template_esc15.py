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

[v1.2] Canonical ESC15 preconditions are now applied. Unpublished
templates are skipped (ct.is_enabled): several built-in V1 templates
carry enrollee-supplies-subject (SubCA, CA, WebServer, OfflineRouter,
CEPEncryption, IPSECIntermediateOffline, EnrollmentAgentOffline) and
were reported critical on every AD CS install even when no CA publishes
them. Templates requiring CA manager approval (msPKI-Enrollment-Flag &
0x2) or authorized signatures are skipped too. Enrollment rights are
evaluated from the template DACL with the same logic as 6001/6002/6009
(Certificate-Enrollment / AutoEnroll CONTROL_ACCESS, All Extended Rights
or GenericAll, not inherit-only): fail/high when a low-privileged
principal (Domain Users, Domain Computers, Authenticated Users,
Everyone, ... or anyone not privileged per v_privileged_principal) can
enroll, warn/low when only privileged principals can (e.g. the default
WebServer / SubCA ACL: Domain Admins / Enterprise Admins). Severity
lowered from critical to high because exploitation also requires a CA
missing the November 2024 CVE-2024-49019 update, which cannot be seen
over LDAP. The summary falls back to the template cn when there is no
displayName.
"""

PLUGIN = {
    "plugin_id": 6010,
    "category": "Certificate Services",
    "name": "Certificate Template Vulnerable to ESC15 (\"EKUwu\" EKU Injection)",
    "version": "1.2",
    "revision_date": "2026-10-04",
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
    "framework_tags": [
        "NIST-800-53-SC-17",
        "NIST-800-53-IA-5(2)",
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-CSF-2.0-PR.DS-02",
        "NIST-CSF-2.0-ID.RA-01",
        "PCI-DSS-4.0-4.2.1.1",
        "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.8.24",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC6.1",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1649",
        "CVE-2024-49019",
        "CISA-AA26-237A",
    ],
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
        "configured at all. Only published templates without manager "
        "approval or authorized-signature requirements are reported; "
        "fail when low-privileged principals can enroll, otherwise warn. "
        "Exploitable only on a CA missing the November 2024 update, "
        "which LDAP cannot show."
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
                || '" is Schema Version 1 and allows enrollee-supplied subject -- '
                || 'vulnerable to ESC15/EKUwu (CVE-2024-49019) unless the CA is patched'
                || CASE WHEN lpe.template_guid IS NOT NULL
                        THEN '; enrollable by low-privileged principals: '
                             || array_to_string(lpe.low_priv_enrollers, ', ')
                        ELSE '; only privileged principals can enroll'
                   END AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'schema_version', ct.schema_version,
                'enrollee_supplies_subject', ct.enrollee_supplies_subject,
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
        WHERE ct.client_id = %(client_id)s
          AND ct.valid_to IS NULL
          AND ct.schema_version = 1
          AND ct.enrollee_supplies_subject
          -- [v1.2] canonical ESC15: published, no manager approval, no RA signatures
          AND ct.is_enabled
          AND (COALESCE(ct.enrollment_flags, 0) & 2) = 0
          AND COALESCE(ct.ra_signature_count, 0) = 0
    """,
}
