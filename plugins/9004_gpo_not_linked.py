"""
Plugin 9004: Group Policy Object Is Not Linked Anywhere

A GPO with zero links -- not to the domain, not to any OU -- exists in
Active Directory but is never actually applied to anything. This
project collected GPO objects (ad_gpo) since early on, but had no
visibility into GPO LINKS at all until gpo_link_edge existed alongside
Organizational Unit collection -- meaning this specific, common
hygiene issue (a GPO created for a project that ended, a test GPO
never cleaned up, a GPO unlinked during troubleshooting and never
relinked or removed) was previously invisible to this project
entirely.

Not a vulnerability in itself -- an unlinked GPO grants no access to
anyone and enforces nothing -- but it is unmanaged configuration
surface: unclear to anyone reviewing Group Policy Management why it
exists, a candidate for being accidentally relinked without review
later, and clutter that makes genuinely-applied GPOs harder to find
during an audit.

[v1.1] Wording narrowed to what is actually checked: gpo_link_edge is
built from the gPLink of the domain object and every OU only. Site
gPLinks are not collected, and links from other domains of the forest
are not visible, so a GPO linked only at a site or from another domain
is reported here too; the summary now says "not linked to the domain or
any OU" (summary text changed) and the description states the gap. Also
suppressed entirely when the client has no current GPO link at all --
the Default Domain Policy is always linked to the domain, so zero links
means link resolution failed for that run, not that every GPO is
unlinked.

[v1.2] Site links are now part of gpo_link_edge: collector 0.5.16
collects AD sites before resolving gPLink and includes their gPLink, so a
GPO linked only to a site counts as linked and is no longer reported.
The summary reads "is not linked to any site, the domain or any OU"
(summary text changed). If no current ad_site row exists -- site
collection failed, which the collector treats as non-fatal, or the data
predates 0.5.16 -- site links are unknown: the summary then keeps the
old wording plus "(site links not collected)", and
detail.site_links_collected records which case applies. Links made from
another domain of the forest remain invisible.
"""

PLUGIN = {
    "plugin_id": 9004,
    "category": "Organizational Units",
    "name": "Group Policy Object Is Not Linked Anywhere",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "If this GPO is genuinely no longer needed, delete it (Group "
        "Policy Management Console -> Group Policy Objects -> right-"
        "click -> Delete) rather than leaving it unlinked indefinitely. "
        "If it's intentionally staged for future use, document why and "
        "by whom, since an unlinked GPO with no explanation is easy to "
        "either forget entirely or accidentally relink without review."
    ),
    "control_id": "GPO-902",
    "framework_tags": [
        "NIST-800-53-CM-2",
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "PCI-DSS-4.0-2.2.6",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "HIPAA-164.312(c)(1)",
        "MITRE-ATTCK-T1484.001",
    ],
    "references": [],
    "description": (
        "A GPO with zero links on any AD site, the domain or any OU "
        "exists but is never actually applied to anything. This "
        "project had no visibility into GPO links at all until "
        "gpo_link_edge existed alongside Organizational Unit "
        "collection, so this common hygiene issue -- a GPO from a "
        "finished project, a test GPO, one unlinked during "
        "troubleshooting and never relinked or removed -- was "
        "previously invisible entirely. Not a vulnerability by itself; "
        "an unlinked GPO grants no access and enforces nothing. "
        "Unmanaged configuration surface worth cleaning up. Site links "
        "are collected since collector 0.5.16 (when site collection fails "
        "the summary says \"site links not collected\" and a GPO linked "
        "only at a site may be reported). Limitation: links made from "
        "another domain in the forest are not visible; confirm in Group "
        "Policy Management before deleting."
    ),
    "base_severity": "low",
    "query": """
        WITH site_collection AS (
            -- [v1.2] Every forest has at least one site, so no current
            -- ad_site row means site collection failed (non-fatal in the
            -- collector) or the data predates collector 0.5.16 -- site links
            -- are then unknown and the summary says so.
            SELECT EXISTS (SELECT 1 FROM ad_site s
                           WHERE s.client_id = %(client_id)s AND s.valid_to IS NULL)
                       AS sites_collected
        )
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'GPO "' || COALESCE(g.display_name, 'unnamed') || '" is not linked to '
                || CASE WHEN sc.sites_collected THEN 'any site, the domain or any OU'
                        ELSE 'the domain or any OU (site links not collected)' END AS summary,
            jsonb_build_object(
                'display_name', g.display_name,
                'gpo_guid', g.gpo_guid,
                'version_number', g.version_number,
                'site_links_collected', sc.sites_collected
            ) AS detail
        FROM ad_gpo g
        CROSS JOIN site_collection sc
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          -- [v1.2] a link on a site, the domain or an OU (enabled or not)
          AND NOT EXISTS (
                SELECT 1 FROM gpo_link_edge gle
                WHERE gle.gpo_guid = g.object_guid AND gle.client_id = g.client_id AND gle.valid_to IS NULL
              )
          -- [v1.1] no link at all for the client = link resolution failed
          AND EXISTS (
                SELECT 1 FROM gpo_link_edge any_link
                WHERE any_link.client_id = g.client_id AND any_link.valid_to IS NULL
              )
    """,
}
