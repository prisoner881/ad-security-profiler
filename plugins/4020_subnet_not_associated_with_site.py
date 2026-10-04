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

[v1.1] The "references a site that no longer exists" branch now looks
the siteObject DN up among current, non-deleted ad_site rows (not any
directory_object, deleted ones included) and is skipped entirely when
no current ad_site rows exist for the client. siteObject is a forward
link, so AD itself clears it when a site is deleted: a dangling value
in practice means site collection failed (it is non-fatal in the
collector) while subnet collection succeeded, which v1.0 reported as a
configuration problem on every subnet. The PingCastle reference is
kept as a related (not equivalent) rule.
"""

PLUGIN = {
    "plugin_id": 4020,
    "category": "Domain",
    "name": "AD Subnet Not Associated With Any Site",
    "version": "1.1",
    "revision_date": "2026-10-04",
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
    "framework_tags": [
        "NIST-800-53-CM-8",
        "NIST-CSF-2.0-ID.AM-01",
        "PCI-DSS-4.0-12.5.1",
        "CIS-CSC-8-1.1",
        "ISO-27001-2022-A.5.9",
        "SOC2-CC6.1",
    ],
    "references": [
        {"title": "PingCastle (related rule, DC IP coverage): S-DC-SubnetMissing",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "An AD subnet object exists but is not associated with any "
        "site -- either siteObject is empty, or it references a site "
        "that is not among the collected sites. Functionally inert for site-aware "
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
              -- [v1.1] dangling-site branch: match current, non-deleted
              -- ad_site rows only, and only when sites were collected
              -- at all (otherwise it is a collection gap, not config).
              OR (
                  EXISTS (
                      SELECT 1 FROM ad_site s0
                      WHERE s0.client_id = %(client_id)s
                        AND s0.valid_to IS NULL
                  )
                  AND NOT EXISTS (
                      SELECT 1
                      FROM ad_site s
                      JOIN directory_object do2
                        ON do2.object_guid = s.object_guid
                       AND do2.client_id = s.client_id
                       AND NOT do2.is_deleted
                      WHERE s.client_id = %(client_id)s
                        AND s.valid_to IS NULL
                        AND lower(do2.dn_current) = lower(sub.site_dn)
                  )
              )
          )
    """,
}
