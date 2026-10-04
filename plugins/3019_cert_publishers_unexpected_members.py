"""
Plugin 3019: Cert Publishers Group Has Unexpected Members

The built-in Cert Publishers group exists so Enterprise/Standalone CA
computer accounts can publish issued certificates and certificate
revocation lists to Active Directory. Its only expected members are
CA server computer accounts themselves -- Microsoft's own
provisioning process adds the CA's computer account automatically
when the CA role is installed. Any OTHER kind of member (a regular
user or a computer that is not actually running a CA role) is
unexpected. Members of Cert Publishers can write to
certificateRevocationList and cACertificate-related attributes,
which -- depending on the exact object being written to -- can be a
step toward introducing a rogue, domain-trusted Certificate Authority.

[v1.2] Identified by domain RID 517 instead of the English name (which
never matched on localized/renamed domains). Membership is now evaluated
transitively (nested groups, primaryGroupID) and covers every member
type the docstring promised: users, groups, foreign principals (medium)
and computers that are not the host of a current Enterprise CA
(ad_enrollment_service.dns_hostname) -- low when computers are the only
unexpected members, since a standalone or recently decommissioned CA is
the usual explanation. Summary wording changed to "unexpected member(s)".
"""

PLUGIN = {
    "plugin_id": 3019,
    "category": "Groups",
    "name": "Cert Publishers Group Has Unexpected Members",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Review every member listed in this finding's evidence. If a "
        "member is a computer account that IS actually running an "
        "Enterprise or Standalone CA role, this is expected and no "
        "action is needed. If a member is a user account, a computer "
        "that is not running a CA role, or a CA that has since been "
        "decommissioned, remove it -- there is no legitimate reason "
        "for anything other than an active CA server's own computer "
        "account to be here."
    ),
    "control_id": "PRIV-307",
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-800-53-SC-17",
        "NIST-800-53-IA-5(2)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "ISO-27001-2022-A.8.24",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1078.002",
        "CISA-AA26-237A",
    ],
    "references": [],
    "description": (
        "The built-in Cert Publishers group exists so CA computer "
        "accounts can publish issued certificates and revocation lists "
        "to Active Directory. Its only expected members are CA server "
        "computer accounts, added automatically when the CA role is "
        "installed. Identified by RID 517. Flags every effective member "
        "(direct, nested or primaryGroupID) that is not the computer "
        "account of a current Enterprise CA host: user accounts, "
        "nested groups and foreign principals are never an automatic "
        "provisioning outcome (medium); computers that are not an "
        "Enterprise CA host are rated low, since a standalone CA (not "
        "published in AD) or a decommissioned CA is the usual cause."
    ),
    "base_severity": "medium",
    "query": """
        WITH ca_hosts AS (
            SELECT DISTINCT lower(es.dns_hostname) AS h
            FROM ad_enrollment_service es
            WHERE es.client_id = %(client_id)s AND es.valid_to IS NULL
              AND es.dns_hostname IS NOT NULL
        ),
        cp AS (
            SELECT g.object_guid, g.client_id, g.member_count_direct
            FROM ad_group g
            JOIN directory_object do2
                ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              AND do2.object_sid LIKE 'S-1-5-21-%%-517'
        ),
        unexpected AS (
            SELECT cp.object_guid AS group_guid,
                   COALESCE(mdo.sam_account_name, mdo.object_sid, mdo.object_guid::text) AS n,
                   mdo.object_class::text AS cls
            FROM cp
            JOIN v_effective_group_membership vem
                ON vem.group_guid = cp.object_guid AND vem.client_id = cp.client_id
            JOIN directory_object mdo
                ON mdo.object_guid = vem.member_guid AND mdo.client_id = vem.client_id
            LEFT JOIN ad_computer c
                ON c.object_guid = vem.member_guid AND c.client_id = vem.client_id AND c.valid_to IS NULL
            WHERE NOT mdo.is_deleted
              AND NOT (mdo.object_class = 'computer'
                       AND lower(c.dns_hostname) IN (SELECT h FROM ca_hosts))
        )
        SELECT
            'warn' AS status,
            cp.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_and(u.cls = 'computer') THEN 'low' ELSE 'medium' END AS fd_severity,
            'Cert Publishers group has ' || count(*)
                || ' unexpected member(s) (anything other than an Enterprise CA host computer)' AS summary,
            jsonb_build_object(
                'member_count_direct', cp.member_count_direct,
                'user_members', COALESCE(jsonb_agg(u.n ORDER BY u.n) FILTER (WHERE u.cls = 'user'), '[]'::jsonb),
                'group_members', COALESCE(jsonb_agg(u.n ORDER BY u.n) FILTER (WHERE u.cls = 'group'), '[]'::jsonb),
                'non_ca_computer_members', COALESCE(jsonb_agg(u.n ORDER BY u.n) FILTER (WHERE u.cls = 'computer'), '[]'::jsonb),
                'other_members', COALESCE(jsonb_agg(u.n ORDER BY u.n)
                                          FILTER (WHERE u.cls NOT IN ('user', 'group', 'computer')), '[]'::jsonb),
                'enterprise_ca_hosts', (SELECT jsonb_agg(h ORDER BY h) FROM ca_hosts)
            ) AS detail
        FROM cp
        JOIN unexpected u ON u.group_guid = cp.object_guid
        GROUP BY cp.object_guid, cp.member_count_direct
    """,
}
