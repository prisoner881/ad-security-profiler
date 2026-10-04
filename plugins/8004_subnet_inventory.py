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

[v1.1] The site is resolved by joining the subnet's siteObject DN to the
DNs of current, non-deleted site objects (ad_site joined to
directory_object) instead of a scalar subquery over every
directory_object row. Deleted objects keep their dn_current, so a site
deleted and recreated under the same name made that subquery return two
rows and the whole inventory failed; it also scanned the entire
directory once per subnet. One site row per DN is kept (DISTINCT ON), so
the join can never multiply subnet rows.
"""

PLUGIN = {
    "plugin_id": 8004,
    "plugin_type": "inventory",
    "category": "Inventory",
    "name": "AD Subnet Inventory",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "description": (
        "Snapshot listing of every AD subnet object currently declared "
        "in AD Sites and Services: the subnet itself (CIDR notation), "
        "and the site it's associated with (if any). Purely "
        "informational -- intended to be compared by hand against a "
        "DHCP server's own scope configuration, which this project has "
        "no visibility into and cannot verify against."
    ),
    "query": """
        WITH site_dn AS (
            -- [v1.1] current, non-deleted sites only; one row per DN
            SELECT DISTINCT ON (lower(d.dn_current))
                   lower(d.dn_current) AS dn_lower, st.site_name
            FROM ad_site st
            JOIN directory_object d
              ON d.object_guid = st.object_guid
             AND d.client_id = st.client_id
             AND NOT d.is_deleted
            WHERE st.client_id = %(client_id)s
              AND st.valid_to IS NULL
            ORDER BY lower(d.dn_current), st.site_name
        )
        SELECT
            sub.subnet_name,
            site.site_name,
            sub.site_dn
        FROM ad_subnet sub
        LEFT JOIN site_dn site
            ON site.dn_lower = lower(sub.site_dn)
        WHERE sub.client_id = %(client_id)s
          AND sub.valid_to IS NULL
        ORDER BY sub.subnet_name
    """,
}
