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
"""

PLUGIN = {
    "plugin_id": 2032,
    "category": "Computer Accounts",
    "name": "Domain Controller Computer Object Not in the Default Domain Controllers OU",
    "version": "1.0",
    "revision_date": "2026-07-19",
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
    "framework_tags": [],
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
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Domain Controller ' || c.sam_account_name || ' is not in the default Domain Controllers OU' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'current_dn', cdo.dn_current
            ) AS detail
        FROM ad_computer c
        JOIN directory_object cdo ON cdo.object_guid = c.object_guid AND cdo.client_id = %(client_id)s
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.is_domain_controller
          AND cdo.dn_current NOT ILIKE '%%,OU=Domain Controllers,%%'
    """,
}
