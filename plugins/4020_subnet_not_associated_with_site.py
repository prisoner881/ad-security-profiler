"""
Plugin 4020: AD Subnet Not Associated With Any Site

PingCastle's own S-DC-SubnetMissing rule checks whether every domain
controller's IP address falls within a declared AD subnet -- caught
partway through implementing that exact check here that it
fundamentally requires resolving each DC's hostname to an IP address,
which is a DNS lookup, not an LDAP query. That's outside this
project's LDAP-only mission (the same reasoning that already ruled out
ESC6/ESC8/ESC11 and protocol-probe-based checks like MS17-010/SMBv1)
-- corrected before shipping rather than building something that
silently depended on a data source this project doesn't have.

This plugin instead checks something closely related and fully
LDAP-derivable: a subnet object declared in AD Sites and Services but
not actually associated with any site (siteObject empty, or pointing
to a site that no longer exists). A subnet with no site association
is inert for site-aware referral purposes -- functionally the same
practical consequence as the DC-coverage gap PingCastle's check
targets, just detected from the configuration data itself rather than
requiring DNS resolution to determine which subnet a DC's IP falls
into.
"""

PLUGIN = {
    "plugin_id": 4020,
    "category": "Domain",
    "name": "AD Subnet Not Associated With Any Site",
    "version": "1.0",
    "revision_date": "2026-07-31",
    "remediation": (
        "Associate this subnet with the correct AD site in AD Sites "
        "and Services (right-click the subnet -> Properties -> Site). "
        "A subnet with no site association is inert for site-aware "
        "referral -- clients on that network segment can't be reliably "
        "directed to the nearest DC or DFS target. This is usually a "
        "sign the subnet was declared but never finished being "
        "configured, or the site it referenced was later deleted "
        "without updating the subnet."
    ),
    "control_id": "DOM-421",
    "framework_tags": [],
    "references": [
        {"title": "PingCastle: Stale Objects rules -- S-DC-SubnetMissing",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "An AD subnet object exists but is not associated with any "
        "site -- either siteObject is empty, or it references a site "
        "that no longer exists. Functionally inert for site-aware "
        "service referral, the same practical consequence PingCastle's "
        "own DC-subnet-coverage check targets, detected here from the "
        "configuration data directly rather than requiring DNS "
        "resolution."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'fail' AS status,
            sub.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Subnet ' || sub.subnet_name ||
                CASE
                    WHEN sub.site_dn IS NULL THEN ' has no associated AD site'
                    ELSE ' references AD site "' || sub.site_dn || '", which no longer exists'
                END AS summary,
            jsonb_build_object(
                'subnet_name', sub.subnet_name,
                'site_dn', sub.site_dn
            ) AS detail
        FROM ad_subnet sub
        WHERE sub.client_id = %(client_id)s
          AND sub.valid_to IS NULL
          AND (
              sub.site_dn IS NULL
              OR NOT EXISTS (
                  SELECT 1 FROM directory_object do2
                  WHERE do2.client_id = %(client_id)s
                    AND lower(do2.dn_current) = lower(sub.site_dn)
              )
          )
    """,
}
