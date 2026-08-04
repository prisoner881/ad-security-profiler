"""
Plugin 6009: Certificate Template Issuance Policy Links to a Group (ESC13)

Confirmed against Certipy's own documentation (the reference
implementation that first added ESC13 detection) before building:
a certificate template's msPKI-Certificate-Policy attribute can
reference an OID object (Configuration partition,
CN=OID,CN=Public Key Services,CN=Services,...) whose own
msDS-OIDToGroupLink attribute points to a security group. When set,
any certificate issued from that template implicitly grants the
holder that group's membership for authorization purposes -- a
certificate-based path to group membership that bypasses normal
group-membership management entirely (adding/removing members,
expiring access, auditing who's in the group).

This is a template-plus-OID combination, not a template misconfiguration
on its own -- a template referencing a certificate policy is completely
normal (issuance policies are a standard PKI concept); what makes it
ESC13 is specifically that the referenced OID has an OIDToGroupLink set
at all. Certipy's own project notes this is one of the vaguer,
harder-to-fully-automate ESC techniques (whether it's actually
exploitable further depends on who can enroll against the template,
data this project does not yet collect -- the same limitation already
documented on plugin 6001).
"""

PLUGIN = {
    "plugin_id": 6009,
    "category": "Certificate Services",
    "name": "Certificate Template Issuance Policy Links to a Group (ESC13)",
    "version": "1.0",
    "revision_date": "2026-07-31",
    "remediation": (
        "Confirm this OID-to-group link is an intentional, understood "
        "part of an Authentication Mechanism Assurance (AMA) design, "
        "not a leftover or accidental configuration. If intentional, "
        "make sure the template's own enrollment rights are scoped "
        "tightly -- anyone who can enroll against this template "
        "effectively gains the linked group's membership for "
        "authorization purposes, bypassing normal group-membership "
        "management (auditing, expiration, removal) entirely. Review "
        "via `Get-ADObject -SearchBase \"CN=OID,CN=Public Key "
        "Services,CN=Services,CN=Configuration,<domain>\" -Filter * "
        "-Properties msDS-OIDToGroupLink`."
    ),
    "control_id": "PKI-1301",
    "framework_tags": [],
    "references": [
        {"title": "Certipy Wiki: Privilege Escalation -- ESC13",
         "url": "https://github.com/ly4k/Certipy/wiki/06-%E2%80%90-Privilege-Escalation"},
    ],
    "description": (
        "A certificate template's issuance policy (msPKI-Certificate-"
        "Policy) references an OID whose own msDS-OIDToGroupLink "
        "points to a security group -- any certificate issued from "
        "this template implicitly grants the holder that group's "
        "membership for authorization purposes, a path that bypasses "
        "normal group-membership management entirely."
    ),
    "base_severity": "high",
    "query": """
        WITH template_oids AS (
            SELECT ct.object_guid AS template_guid, ct.display_name, ct.template_name,
                   trim(both '"' from oid_elem::text) AS policy_oid
            FROM ad_cert_template ct, jsonb_array_elements(ct.certificate_policy_oids) AS oid_elem
            WHERE ct.client_id = %(client_id)s AND ct.valid_to IS NULL
        ),
        linked AS (
            SELECT t.template_guid, t.display_name, t.template_name,
                   o.schema_cn AS oid, o.oid_to_group_link AS linked_group
            FROM template_oids t
            JOIN ad_cert_oid o
                ON o.client_id = %(client_id)s AND o.valid_to IS NULL AND o.schema_cn = t.policy_oid
            WHERE o.oid_to_group_link IS NOT NULL
        ),
        -- [fix, caught via a real production crash on plugin 4023 --
        -- same root cause, checked and fixed here proactively] A
        -- template can reference multiple certificate-policy OIDs, and
        -- more than one could independently link to a group. The
        -- original version produced one row per (template, OID) pair,
        -- all sharing the same template's object_guid -- a second
        -- match on the same template would collide on identity_guid
        -- exactly like 4023's crash did. Aggregated here instead.
        aggregated AS (
            SELECT template_guid, display_name, template_name,
                   array_agg(oid || ' -> ' || linked_group ORDER BY oid) AS links,
                   count(*) AS link_count
            FROM linked
            GROUP BY template_guid, display_name, template_name
        )
        SELECT
            'fail' AS status,
            a.template_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Certificate template "' || a.display_name || '" issuance policy has '
                || a.link_count || ' OID-to-group link(s) (ESC13): '
                || array_to_string(a.links, '; ') AS summary,
            jsonb_build_object(
                'template_name', a.template_name,
                'display_name', a.display_name,
                'links', to_jsonb(a.links)
            ) AS detail
        FROM aggregated a
    """,
}
