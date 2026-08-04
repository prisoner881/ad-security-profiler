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
"""

PLUGIN = {
    "plugin_id": 9004,
    "category": "Organizational Units",
    "name": "Group Policy Object Is Not Linked Anywhere",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "If this GPO is genuinely no longer needed, delete it (Group "
        "Policy Management Console -> Group Policy Objects -> right-"
        "click -> Delete) rather than leaving it unlinked indefinitely. "
        "If it's intentionally staged for future use, document why and "
        "by whom, since an unlinked GPO with no explanation is easy to "
        "either forget entirely or accidentally relink without review."
    ),
    "control_id": "GPO-902",
    "framework_tags": [],
    "references": [],
    "description": (
        "A GPO with zero links anywhere (not the domain, not any OU) "
        "exists but is never actually applied to anything. This "
        "project had no visibility into GPO links at all until "
        "gpo_link_edge existed alongside Organizational Unit "
        "collection, so this common hygiene issue -- a GPO from a "
        "finished project, a test GPO, one unlinked during "
        "troubleshooting and never relinked or removed -- was "
        "previously invisible entirely. Not a vulnerability by itself; "
        "an unlinked GPO grants no access and enforces nothing. "
        "Unmanaged configuration surface worth cleaning up."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'GPO "' || COALESCE(g.display_name, 'unnamed') || '" is not linked anywhere' AS summary,
            jsonb_build_object(
                'display_name', g.display_name,
                'gpo_guid', g.gpo_guid,
                'version_number', g.version_number
            ) AS detail
        FROM ad_gpo g
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND NOT EXISTS (
                SELECT 1 FROM gpo_link_edge gle
                WHERE gle.gpo_guid = g.object_guid AND gle.client_id = g.client_id AND gle.valid_to IS NULL
              )
    """,
}
