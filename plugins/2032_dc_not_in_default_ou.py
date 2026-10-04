"""
Plugin 2032: Domain Controller Computer Object Not in the Default Domain Controllers OU

Every AD domain automatically creates a dedicated "Domain Controllers"
OU during promotion, and every domain controller's computer object is
placed there by default. That placement isn't cosmetic: the Default
Domain Controllers Policy GPO is linked specifically to that OU, and
DC-specific security hardening (audit policy, user rights assignments
like "Log on as a service" restrictions, and everything else in that
baseline GPO) only applies to computer objects actually inside it. A
DC computer object living somewhere else either doesn't receive that
policy at all, or receives whatever policy applies at its actual
location instead -- neither of which is the hardening a domain
controller is expected to have. A classic, well-established AD
hygiene/security check (present in essentially every serious AD
security assessment methodology), only became derivable here once OU
data existed to check placement against.

[v1.1] The location test is now anchored to the domain's own Domain
Controllers OU instead of matching ",OU=Domain Controllers," anywhere in
the DN, which let a DC in an unrelated OU of that name (e.g.
OU=Domain Controllers,OU=Legacy,...) pass. The expected OU is taken from
the domain's wellKnownObjects entry for the Domain Controllers container
(GUID A361B2FFFFD211D1AA4B00C04FD7D83A), falling back to
"OU=Domain Controllers,<domain DN>"; a DC directly in it or in a sub-OU
of it passes (sub-OUs inherit the Default Domain Controllers Policy
unless inheritance is blocked). The old substring test is kept only when
no domain object was collected. RODCs, which also belong in this OU, are
checked since schema v36. Severity lowered from high to medium, in line
with comparable tools: the real impact depends on which GPOs apply at
the DC's actual location. detail adds expected_ou_dn.
"""

PLUGIN = {
    "plugin_id": 2032,
    "category": "Computer Accounts",
    "name": "Domain Controller Computer Object Not in the Default Domain Controllers OU",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Move the computer object back into the default Domain "
        "Controllers OU (Active Directory Users and Computers -> "
        "drag-and-drop, or `Move-ADObject`). If it was moved "
        "deliberately for some specific reason, confirm the Default "
        "Domain Controllers Policy (and any other DC-specific security "
        "GPOs) are still being applied at wherever it currently sits -- "
        "either via an equivalent link at that location, or by moving "
        "it back, since replicating DC-specific GPO scope correctly "
        "outside the default container is easy to get subtly wrong."
    ),
    "control_id": "HYGIENE-202",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-800-53-CM-2",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "PCI-DSS-4.0-2.2.6",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "HIPAA-164.312(c)(1)",
    ],
    "references": [],
    "description": (
        "Every AD domain automatically creates a dedicated Domain "
        "Controllers OU during promotion, with every DC's computer "
        "object placed there by default. The Default Domain "
        "Controllers Policy GPO is linked specifically to that OU -- a "
        "DC computer object living elsewhere either doesn't receive "
        "that policy at all, or receives whatever applies at its "
        "actual location instead, neither of which is the DC-specific "
        "hardening (audit policy, restricted logon rights, and more) a "
        "domain controller is expected to have. A classic AD hygiene/"
        "security check present in essentially every serious "
        "assessment methodology, only derivable here once OU "
        "collection existed to check placement against."
    ),
    "base_severity": "medium",
    "query": """
        WITH dom AS (
            SELECT o.dn_current AS domain_dn,
                   COALESCE(
                       (SELECT substring(elem from '^B:32:[0-9A-Fa-f]{32}:(.*)$')
                        FROM jsonb_array_elements_text(d.well_known_objects) AS elem
                        WHERE upper(substring(elem from '^B:32:([0-9A-Fa-f]{32}):'))
                              = 'A361B2FFFFD211D1AA4B00C04FD7D83A'
                        LIMIT 1),
                       'OU=Domain Controllers,' || o.dn_current) AS dc_ou_dn
            FROM ad_domain d
            JOIN directory_object o ON o.object_guid = d.object_guid AND o.client_id = d.client_id
            WHERE d.client_id = %(client_id)s
              AND d.valid_to IS NULL
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain Controller ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' is not in the default Domain Controllers OU' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'current_dn', cdo.dn_current,
                'expected_ou_dn', dm.dc_ou_dn,
                'is_read_only_dc', c.is_read_only_dc
            ) AS detail
        FROM ad_computer c
        JOIN directory_object cdo ON cdo.object_guid = c.object_guid AND cdo.client_id = c.client_id
                                 AND NOT cdo.is_deleted
        LEFT JOIN LATERAL (
            SELECT dom.dc_ou_dn
            FROM dom
            WHERE lower(right(cdo.dn_current, length(dom.domain_dn) + 1)) = ',' || lower(dom.domain_dn)
            ORDER BY length(dom.domain_dn) DESC
            LIMIT 1
        ) dm ON true
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.is_domain_controller
          AND CASE WHEN dm.dc_ou_dn IS NOT NULL
                   THEN lower(right(cdo.dn_current, length(dm.dc_ou_dn) + 1))
                        IS DISTINCT FROM ',' || lower(dm.dc_ou_dn)
                   ELSE cdo.dn_current NOT ILIKE '%%,OU=Domain Controllers,%%'
              END
    """,
}
