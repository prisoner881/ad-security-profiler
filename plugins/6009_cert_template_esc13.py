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

[v1.2] Never matched real data before: the join compared the template's
dotted policy OID with the OID object's cn, which is a generated name
(e.g. 402.<32 hex>), not the OID. It now joins on ad_cert_oid.policy_oid
(msPKI-Cert-Template-OID, collected since adprofiler 0.5.15 / schema
v36). The canonical Certipy ESC13 preconditions are applied: the
template is published (is_enabled), client-authentication-capable, has
no CA manager approval (msPKI-Enrollment-Flag & 0x2) and needs no
authorized signatures (msPKI-RA-Signature = 0/NULL). Enrollment rights
are now evaluated from the template DACL with the same logic as 6001/
6002/6010 (Certificate-Enrollment / AutoEnroll CONTROL_ACCESS, All
Extended Rights or GenericAll, not inherit-only): fail/high when a
low-privileged principal (Domain Users, Domain Computers, Authenticated
Users, Everyone, ... or anyone not privileged per v_privileged_principal)
can enroll; warn/low when only privileged principals can. The linked
group is resolved to its sAMAccountName when collected, and the summary
falls back to the template cn when there is no displayName.
"""

PLUGIN = {
    "plugin_id": 6009,
    "category": "Certificate Services",
    "name": "Certificate Template Issuance Policy Links to a Group (ESC13)",
    "version": "1.2",
    "revision_date": "2026-10-04",
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
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1649"],
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
        "normal group-membership management entirely. Only published, "
        "client-authentication-capable templates without manager "
        "approval or authorized-signature requirements are reported; "
        "fail when low-privileged principals can enroll, otherwise warn."
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
        ),
        template_oids AS (
            SELECT ct.object_guid AS template_guid, ct.display_name, ct.template_name,
                   trim(both '"' from oid_elem::text) AS policy_oid
            FROM ad_cert_template ct, jsonb_array_elements(ct.certificate_policy_oids) AS oid_elem
            WHERE ct.client_id = %(client_id)s AND ct.valid_to IS NULL
              AND jsonb_typeof(ct.certificate_policy_oids) = 'array'
              -- [v1.2] canonical ESC13 preconditions
              AND ct.is_enabled
              AND ct.client_authentication_capable
              AND (COALESCE(ct.enrollment_flags, 0) & 2) = 0
              AND COALESCE(ct.ra_signature_count, 0) = 0
        ),
        linked AS (
            SELECT DISTINCT t.template_guid, t.display_name, t.template_name,
                   t.policy_oid AS oid,
                   COALESCE(o.display_name, o.schema_cn) AS oid_name,
                   o.oid_to_group_link AS linked_group_dn,
                   COALESCE(g.sam_account_name, o.oid_to_group_link) AS linked_group,
                   (g.object_guid IS NOT NULL AND EXISTS (
                        SELECT 1 FROM v_privileged_principal vp
                        WHERE vp.client_id = g.client_id AND vp.object_guid = g.object_guid)) AS linked_group_privileged
            FROM template_oids t
            JOIN ad_cert_oid o
                ON o.client_id = %(client_id)s AND o.valid_to IS NULL
               AND o.policy_oid = t.policy_oid        -- [v1.2] the dotted OID, not the cn
            LEFT JOIN directory_object g
                ON g.client_id = o.client_id AND lower(g.dn_current) = lower(o.oid_to_group_link)
               AND NOT g.is_deleted
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
                   array_agg(oid || ' -> ' || linked_group ORDER BY oid, linked_group) AS links,
                   jsonb_agg(jsonb_build_object(
                       'policy_oid', oid, 'oid_name', oid_name,
                       'linked_group', linked_group, 'linked_group_dn', linked_group_dn,
                       'linked_group_privileged', linked_group_privileged
                   ) ORDER BY oid, linked_group) AS link_details,
                   count(*) AS link_count
            FROM linked
            GROUP BY template_guid, display_name, template_name
        )
        SELECT
            CASE WHEN lpe.template_guid IS NOT NULL THEN 'fail' ELSE 'warn' END AS status,
            a.template_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN lpe.template_guid IS NOT NULL THEN 'high' ELSE 'low' END AS fd_severity,
            'Certificate template "' || COALESCE(a.display_name, a.template_name, a.template_guid::text)
                || '" issuance policy has '
                || a.link_count || ' OID-to-group link(s) (ESC13): '
                || array_to_string(a.links, '; ')
                || CASE WHEN lpe.template_guid IS NOT NULL
                        THEN '; enrollable by low-privileged principals: '
                             || array_to_string(lpe.low_priv_enrollers, ', ')
                        ELSE '; only privileged principals can enroll'
                   END AS summary,
            jsonb_build_object(
                'template_name', a.template_name,
                'display_name', a.display_name,
                'links', to_jsonb(a.links),
                'link_details', a.link_details,
                'low_privileged_enrollers', to_jsonb(lpe.low_priv_enrollers)
            ) AS detail
        FROM aggregated a
        LEFT JOIN low_priv_enrollment lpe ON lpe.template_guid = a.template_guid
    """,
}
