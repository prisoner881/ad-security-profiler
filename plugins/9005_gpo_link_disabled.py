"""
Plugin 9005: Disabled Group Policy Link Still Present

gPLink's per-link options bit 0 (LINK_DISABLED). A disabled link means
this specific GPO-to-container association exists but is not currently
being processed -- distinct from plugin 9004 (a GPO with no links at
all): this GPO IS linked here, just switched off, at this specific
location, while potentially still active elsewhere. Same "worth
knowing about, unmanaged configuration surface" reasoning as plugin
7004 (disabled trust relationships) and 9004 (unlinked GPOs) -- a
disabled link left in place indefinitely is easy to forget existed,
and is one accidental checkbox away from silently re-applying a GPO
nobody currently expects to be active at this location.

[v1.1] One finding per GPO. The identity is the GPO's object_guid, but
the query returned one row per disabled (container, GPO) link, so a GPO
with disabled links on two or more containers (common in staged
rollouts) produced duplicate identities and the whole plugin errored.
Links are now aggregated per GPO: the summary lists every container with
a disabled link, sorted (unchanged wording when there is only one), and
the detail carries one entry per link. The redundant directory_object
join for the GPO is dropped (ad_gpo carries object_guid). Site links are
not collected (see plugin 9004).

[v1.2] Site links are collected since collector 0.5.16 (gpo_link_edge
now includes links whose container is an AD site), so disabled site
links are reported too. Each container in the summary is labelled by
kind -- Site "<name>", Domain "<dns name>", OU "<DN>" -- instead of a
bare quoted DN (summary text changed once); detail.links entries gain
container_type (site/domain/ou/other) and container_dn.
"""

PLUGIN = {
    "plugin_id": 9005,
    "category": "Organizational Units",
    "name": "Disabled Group Policy Link Still Present",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "If this link is genuinely no longer needed at this location, "
        "remove it entirely (Group Policy Management Console -> select "
        "the OU, the domain, or the site under Sites (use Show Sites if it "
        "is not listed) -> right-click the disabled link -> Delete "
        "Link) rather than leaving it disabled indefinitely. If it's "
        "intentionally disabled for a specific, temporary reason, "
        "document why and by whom, since a disabled link with no "
        "explanation is one accidental re-enable away from silently "
        "applying a GPO nobody currently expects active here."
    ),
    "control_id": "GPO-903",
    "framework_tags": [],
    "references": [],
    "description": (
        "gPLink's per-link options bit 0 (LINK_DISABLED). A disabled "
        "link means this specific GPO-to-container association exists "
        "but isn't currently processed -- distinct from plugin 9004 (a "
        "GPO with no links at all): this GPO IS linked here, just "
        "switched off, while potentially still active elsewhere. Same "
        "reasoning as plugin 7004 (disabled trusts): unmanaged "
        "configuration surface, easy to forget, one accidental "
        "re-enable away from silently applying again. One finding per "
        "GPO, listing every container -- AD site, domain or OU -- where its "
        "link is disabled (site links since collector 0.5.16)."
    ),
    "base_severity": "low",
    "query": """
        WITH disabled_links AS (
            SELECT g.object_guid AS gpo_object_guid,
                   g.display_name,
                   -- [v1.2] containers are labelled by kind: AD sites (since
                   -- collector 0.5.16), the domain, or an OU (by DN, since OU
                   -- names are not unique)
                   CASE WHEN st.object_guid IS NOT NULL THEN 'site'
                        WHEN dm.object_guid IS NOT NULL OR cdo.object_class = 'domain' THEN 'domain'
                        WHEN ou.object_guid IS NOT NULL OR cdo.object_class = 'ou' THEN 'ou'
                        ELSE 'other' END AS container_type,
                   CASE WHEN st.object_guid IS NOT NULL
                            THEN 'Site "' || COALESCE(st.site_name, cdo.dn_current) || '"'
                        WHEN dm.object_guid IS NOT NULL OR cdo.object_class = 'domain'
                            THEN 'Domain "' || COALESCE(dm.dns_root, cdo.dn_current) || '"'
                        WHEN ou.object_guid IS NOT NULL OR cdo.object_class = 'ou'
                            THEN 'OU "' || cdo.dn_current || '"'
                        ELSE '"' || COALESCE(cdo.sam_account_name, cdo.dn_current) || '"'
                   END AS container_label,
                   cdo.dn_current AS container_dn,
                   cdo.object_class AS container_object_class,
                   gle.link_order
            FROM gpo_link_edge gle
            JOIN ad_gpo g ON g.object_guid = gle.gpo_guid AND g.client_id = gle.client_id AND g.valid_to IS NULL
            JOIN directory_object cdo ON cdo.object_guid = gle.container_guid AND cdo.client_id = gle.client_id
            LEFT JOIN ad_site st
                ON st.object_guid = gle.container_guid AND st.client_id = gle.client_id AND st.valid_to IS NULL
            LEFT JOIN ad_domain dm
                ON dm.object_guid = gle.container_guid AND dm.client_id = gle.client_id AND dm.valid_to IS NULL
            LEFT JOIN ad_ou ou
                ON ou.object_guid = gle.container_guid AND ou.client_id = gle.client_id AND ou.valid_to IS NULL
            WHERE gle.client_id = %(client_id)s
              AND gle.valid_to IS NULL
              AND NOT gle.link_enabled
        )
        -- [v1.1] one row per GPO: several disabled links of the same GPO
        -- used to produce duplicate finding identities
        SELECT
            'warn' AS status,
            dl.gpo_object_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'GPO "' || COALESCE(min(dl.display_name), 'unnamed') || '" has '
                || CASE WHEN count(*) = 1 THEN 'a disabled link on '
                        ELSE 'disabled links on ' END
                || string_agg(dl.container_label, ', '
                              ORDER BY dl.container_label, dl.container_dn) AS summary,
            jsonb_build_object(
                'gpo', min(dl.display_name),
                'container', CASE WHEN count(*) = 1 THEN min(dl.container_label) END,
                'links', jsonb_agg(jsonb_build_object(
                    'container', dl.container_label,
                    'container_type', dl.container_type,
                    'container_dn', dl.container_dn,
                    'container_object_class', dl.container_object_class,
                    'link_order', dl.link_order
                ) ORDER BY dl.container_label, dl.container_dn)
            ) AS detail
        FROM disabled_links dl
        GROUP BY dl.gpo_object_guid
    """,
}
