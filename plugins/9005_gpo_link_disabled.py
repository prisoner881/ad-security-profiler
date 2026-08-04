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
"""

PLUGIN = {
    "plugin_id": 9005,
    "category": "Organizational Units",
    "name": "Disabled Group Policy Link Still Present",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "If this link is genuinely no longer needed at this location, "
        "remove it entirely (Group Policy Management Console -> select "
        "the OU or domain -> right-click the disabled link -> Delete "
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
        "re-enable away from silently applying again."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            gdo.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'GPO "' || COALESCE(g.display_name, 'unnamed') || '" has a disabled link on "'
                || COALESCE(cdo.sam_account_name, cdo.dn_current) || '"' AS summary,
            jsonb_build_object(
                'gpo', g.display_name,
                'container', COALESCE(cdo.sam_account_name, cdo.dn_current),
                'container_object_class', cdo.object_class,
                'link_order', gle.link_order
            ) AS detail
        FROM gpo_link_edge gle
        JOIN directory_object gdo ON gdo.object_guid = gle.gpo_guid AND gdo.client_id = gle.client_id
        JOIN ad_gpo g ON g.object_guid = gle.gpo_guid AND g.client_id = gle.client_id AND g.valid_to IS NULL
        JOIN directory_object cdo ON cdo.object_guid = gle.container_guid AND cdo.client_id = gle.client_id
        WHERE gle.client_id = %(client_id)s
          AND gle.valid_to IS NULL
          AND NOT gle.link_enabled
    """,
}
