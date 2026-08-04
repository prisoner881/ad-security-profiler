"""
Plugin 2030: Domain Controller Computer Object Owned by a Non-Administrator

Distinct from plugins 5006 and 2028 (which check ownership of the
domain root/AdminSDHolder, and ownership combined with an independent
weakness on the computer, respectively): this checks the owner of
every Domain Controller's own computer object directly, regardless of
any other condition. An owner can always rewrite an object's ACL
outright, no matter what the object's current explicit permissions
say -- gaining control of a DC's own computer account object is a
direct, uncomplicated path to compromising that DC and, from there,
the domain. Expected owners are Domain Admins, Enterprise Admins, or
the built-in Administrator account; anything else is worth
investigating. Confirmed against Purple Knight's own equivalent check.
"""

PLUGIN = {
    "plugin_id": 2030,
    "category": "Computer Accounts",
    "name": "Domain Controller Computer Object Owned by a Non-Administrator",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Determine why this Domain Controller's computer object is not "
        "owned by a Domain Admins, Enterprise Admins, or the built-in "
        "Administrator account -- this is not a default outcome and "
        "usually indicates either historical migration residue or a "
        "genuine misconfiguration. Reassign ownership to Domain Admins "
        "(`Set-ADObject <DC-DN> -Cmdlet takeownership` via a tool that "
        "supports it, or via the Advanced Security Settings dialog in "
        "Active Directory Users and Computers -> Owner tab), then "
        "review the object's full ACL for anything the previous owner "
        "may have granted."
    ),
    "control_id": "PRIV-205",
    "framework_tags": [],
    "references": [],
    "description": (
        "Distinct from plugins 5006/2028 (domain root/AdminSDHolder "
        "ownership, and ownership combined with an independent "
        "weakness): checks the owner of every Domain Controller's own "
        "computer object directly. An owner can always rewrite an "
        "object's ACL regardless of its current explicit permissions, "
        "so gaining control of a DC's own computer account object is a "
        "direct path to compromising that DC and, from there, the "
        "domain. Expected owners are Domain Admins, Enterprise Admins, "
        "or the built-in Administrator account."
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
            'Domain Controller ' || c.sam_account_name || ' is owned by '
                || COALESCE(owner.sam_account_name, cdo.owner_sid) AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'owner_sid', cdo.owner_sid,
                'owner_sam_account_name', owner.sam_account_name,
                'owner_object_class', owner.object_class
            ) AS detail
        FROM ad_computer c
        JOIN directory_object cdo ON cdo.object_guid = c.object_guid AND cdo.client_id = c.client_id
        LEFT JOIN directory_object owner ON owner.object_sid = cdo.owner_sid AND owner.client_id = cdo.client_id
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.is_domain_controller
          AND cdo.owner_sid IS NOT NULL
          AND NOT (
                cdo.owner_sid LIKE '%%-512'   -- Domain Admins
                OR cdo.owner_sid LIKE '%%-519' -- Enterprise Admins
                OR cdo.owner_sid LIKE '%%-500'  -- built-in Administrator
                OR cdo.owner_sid = 'S-1-5-32-544'  -- BUILTIN\\Administrators
              )
    """,
}
