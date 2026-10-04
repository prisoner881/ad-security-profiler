"""
Plugin 6001: Certificate Template Matches ESC1 Attack Pattern

ESC1, from SpecterOps' "Certified Pre-Owned" research: a certificate
template that (a) is actually published on at least one Enterprise CA,
(b) lets the enrollee supply an arbitrary subject name in the request
(CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT, msPKI-Certificate-Name-Flag bit
0x1), and (c) issues certificates usable for client authentication
(an explicit client-auth-capable EKU, or no EKU restriction at all,
which is equivalent to "Any Purpose"). Anyone who can enroll against
such a template can request a certificate claiming to be an arbitrary
domain principal -- including Domain Admin -- and authenticate as them.

Deliberately does NOT determine actual exploitability: that requires
knowing who can enroll against the template (the template's own
enrollment ACL), which this project does not yet collect -- the same
binary security-descriptor parsing limitation already documented for
acl_edge (domain root/AdminSDHolder only). What's flagged here is the
structural precondition, exactly as the underlying schema was designed
to support (see ad_cert_template's own column comments and the
pre-built idx_cert_template_esc1_flag partial index this query uses).

[v1.1] The built-in SubCA template matches this exact structural
pattern in every ADCS installation by default (Client Authentication
EKU, CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT set) and is a real, actively-
referenced ESC1 vector, confirmed against multiple independent sources
-- NOT a false positive to be excluded, despite its "CA infrastructure"
name suggesting otherwise. What differs about it is the exploitation
mechanics: direct enrollment is normally denied (only Domain Admins
can enroll by default), but a principal holding ManageCA or
ManageCertificates rights on the issuing CA can approve their own
denied request anyway. Flagging that distinction explicitly in
evidence and remediation now, rather than treating every match
identically, since the actionable next step genuinely differs.

[v1.3] Applies the full canonical ESC1 definition (Certified Pre-Owned /
Certipy). The "enrollment ACL not collected" limitation above is stale:
since adprofiler v0.5.4 every template's DACL is in acl_edge, and
msPKI-RA-Signature is collected since v0.5.15 (schema v36). A template
is now reported only when it also requires no CA manager approval
(msPKI-Enrollment-Flag & 0x2 = 0) and no authorized signatures
(ra_signature_count 0 or NULL). It is fail / critical when a
low-privileged principal can enroll -- an allow ACE (not inherit-only)
granting Certificate-Enrollment or AutoEnroll (CONTROL_ACCESS with
0e10c968-... / a05b8cc2-...), All Extended Rights or GenericAll to
Everyone, Authenticated Users, Domain Users, Domain Computers, or any
principal that is not a well-known admin SID, a protected group or in
v_privileged_principal. When only privileged principals can enroll (e.g.
the default SubCA template: DA/EA) it is warn / medium. The summary
lists the low-privileged enrollers. EKUs come from pKIExtendedKeyUsage
only (msPKI-Certificate-Application-Policy is not collected).
"""

PLUGIN = {
    "plugin_id": 6001,
    "category": "Certificate Services",
    "name": "Certificate Template Matches ESC1 Attack Pattern",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm who can actually enroll against this template (its own "
        "security tab in the Certificate Templates console, or "
        "`certutil -v -template <name>`). If Domain Users, Authenticated "
        "Users, or any broad, low-privileged group has Enroll rights, "
        "this is a complete, low-effort path to domain compromise -- "
        "prioritize immediately. Remediate by either disabling the "
        "CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT flag (Subject Name tab -> "
        "'Supply in the request' -> switch to 'Build from Active "
        "Directory information'), restricting the template's EKU to "
        "something that cannot be used for client authentication, or "
        "restricting enrollment rights to a small, trusted set of "
        "principals. The evidence lists the low-privileged principals "
        "that can enroll (low_privileged_enrollers); a warn finding "
        "means only privileged principals can enroll today. Requiring "
        "CA manager approval (Issuance Requirements tab) also blocks "
        "ESC1 and is a valid interim mitigation. If this finding's "
        "evidence shows is_builtin_ca_infrastructure_template=true "
        "(SubCA/CrossCA), the exploitation path is different: normal "
        "enrollment is denied by default (only Domain Admins can "
        "enroll), but anyone holding ManageCA or ManageCertificates "
        "rights on the issuing CA can approve their own denied request. "
        "Review CA officer assignments (`certutil -config <CA> "
        "-getreg CA\\OfficerRights`, or the CA console's Security tab) "
        "with the same scrutiny as enrollment rights -- restricting "
        "enrollment alone does not fully close this specific template."
    ),
    "control_id": "ADCS-101",
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
        "ESC1 (SpecterOps' 'Certified Pre-Owned' research): a certificate "
        "template that is (a) actually published on at least one "
        "Enterprise CA -- an unpublished template cannot be requested by "
        "anyone regardless of its flags -- (b) permits the enrollee to "
        "supply an arbitrary subject name in the certificate request "
        "(CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT), and (c) issues certificates "
        "usable for client authentication, either via an explicit "
        "client-auth-capable EKU (Client Authentication, PKINIT Client "
        "Authentication, Smart Card Logon, Any Purpose) or no EKU "
        "restriction at all "
        "(functionally equivalent to Any Purpose). Combined, these three "
        "conditions mean anyone permitted to enroll against the template "
        "can request a certificate claiming to be any domain principal "
        "of their choosing, including Domain Admin, and authenticate as "
        "them. Following the canonical ESC1 definition, templates that "
        "require CA manager approval or authorized signatures are not "
        "reported. The finding is fail / critical when a low-privileged "
        "principal (Domain Users, Domain Computers, Authenticated Users, "
        "Everyone, or any non-privileged account or group) holds "
        "Enroll / AutoEnroll, All Extended Rights or GenericAll on the "
        "template, and warn / medium when only privileged principals can "
        "enroll (e.g. the built-in SubCA template, still reachable "
        "through CA officer rights)."
    ),
    "base_severity": "critical",
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
            CASE WHEN lpe.template_guid IS NOT NULL THEN 'critical' ELSE 'medium' END AS fd_severity,
            'Certificate template "' || COALESCE(ct.display_name, ct.template_name, ct.object_guid::text)
                || CASE WHEN lpe.template_guid IS NOT NULL
                        THEN '" matches the ESC1 attack pattern (published, enrollee-supplied '
                             'subject name, client-auth-capable, no approval, enrollable by '
                             'low-privileged principals: '
                             || array_to_string(lpe.low_priv_enrollers, ', ') || ')'
                        ELSE '" matches the ESC1 template pattern (published, enrollee-supplied '
                             'subject name, client-auth-capable, no approval) but no '
                             'low-privileged principal can enroll'
                   END AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'extended_key_usage', ct.extended_key_usage,
                'requires_manager_approval', false,
                'ra_signature_count', ct.ra_signature_count,
                'low_privileged_enrollers', to_jsonb(lpe.low_priv_enrollers),
                'is_builtin_ca_infrastructure_template', COALESCE(ct.template_name IN ('SubCA', 'CrossCA'), false),
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
          AND ct.enrollee_supplies_subject
          AND ct.client_authentication_capable
          -- [v1.3] canonical ESC1: no CA manager approval
          -- (CT_FLAG_PEND_ALL_REQUESTS 0x2) and no authorized signatures.
          AND (COALESCE(ct.enrollment_flags, 0) & 2) = 0
          AND COALESCE(ct.ra_signature_count, 0) = 0
    """,
}
