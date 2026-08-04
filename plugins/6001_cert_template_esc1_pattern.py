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
"""

PLUGIN = {
    "plugin_id": 6001,
    "category": "Certificate Services",
    "name": "Certificate Template Matches ESC1 Attack Pattern",
    "version": "1.1",
    "revision_date": "2026-07-18",
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
        "principals. If manager approval is enabled on this template "
        "(see this finding's evidence), exploitation additionally "
        "requires a CA manager to approve an enrollee-supplied identity "
        "claim -- a real mitigating control, but not a substitute for "
        "fixing the underlying template configuration. If this finding's "
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
    "framework_tags": [],
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
        "Authentication, Smart Card Logon) or no EKU restriction at all "
        "(functionally equivalent to Any Purpose). Combined, these three "
        "conditions mean anyone permitted to enroll against the template "
        "can request a certificate claiming to be any domain principal "
        "of their choosing, including Domain Admin, and authenticate as "
        "them. This finding identifies the structural pattern only -- it "
        "does not confirm who can actually enroll, since template "
        "enrollment ACLs are not yet collected by this project. Includes "
        "the built-in SubCA/CrossCA templates deliberately: despite the "
        "name, SubCA is a confirmed, actively-referenced ESC1 vector in "
        "its own right, exploitable via CA officer rights rather than "
        "ordinary enrollment."
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
            'Certificate template "' || COALESCE(ct.display_name, ct.template_name)
                || '" matches the ESC1 attack pattern (published, enrollee-supplied '
                'subject name, client-auth-capable)' AS summary,
            jsonb_build_object(
                'template_name', ct.template_name,
                'display_name', ct.display_name,
                'extended_key_usage', ct.extended_key_usage,
                'requires_manager_approval', (COALESCE(ct.enrollment_flags, 0) & 2) != 0,
                'is_builtin_ca_infrastructure_template', ct.template_name IN ('SubCA', 'CrossCA'),
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
          AND ct.enrollee_supplies_subject
          AND ct.client_authentication_capable
    """,
}
