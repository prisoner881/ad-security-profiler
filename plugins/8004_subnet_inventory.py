"""
Plugin 8004: AD Subnet Inventory

A utility plugin, not a finding plugin: see plugin 8001's docstring
for the full design rationale of this second, parallel plugin type.
Runs fresh every invocation, no persistence, no change tracking.

Deliberately purely informational -- AD's own declared subnet list
(CN=Subnets,CN=Sites,CN=Configuration,...) is administrator-maintained
and entirely disconnected from any DHCP server's actual scope
configuration (confirmed: no technical link exists between the two in
either direction). This plugin cannot verify whether AD's declared
subnets are accurate or complete against what's actually in use on the
network -- only DHCP itself, a data source outside this project's
LDAP-only model, could confirm that. What it CAN do is hand a client a
clean, complete list of everything AD currently has declared, in a
form that's easy to eyeball against DHCP's own scope list by hand.
Plugin 4020 (subnet not linked to any site) already covers the
FAIL-worthy structural gap on the finding-plugin side; this is the
complementary "just show me everything" counterpart, not a
replacement for it.
"""

PLUGIN = {
    "plugin_id": 8004,
    "plugin_type": "inventory",
    "category": "Inventory",
    "name": "AD Subnet Inventory",
    "version": "1.0",
    "revision_date": "2026-08-05",
    "description": (
        "Snapshot listing of every AD subnet object currently declared "
        "in AD Sites and Services: the subnet itself (CIDR notation), "
        "and the site it's associated with (if any). Purely "
        "informational -- intended to be compared by hand against a "
        "DHCP server's own scope configuration, which this project has "
        "no visibility into and cannot verify against."
    ),
    "query": """
        SELECT
            sub.subnet_name,
            site.site_name,
            sub.site_dn
        FROM ad_subnet sub
        LEFT JOIN ad_site site
            ON site.object_guid = (
                SELECT do2.object_guid FROM directory_object do2
                WHERE do2.client_id = sub.client_id
                  AND lower(do2.dn_current) = lower(sub.site_dn)
            )
            AND site.valid_to IS NULL
        WHERE sub.client_id = %(client_id)s
          AND sub.valid_to IS NULL
        ORDER BY sub.subnet_name
    """,
}
