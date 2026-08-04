"""
Plugin 3010: Group Membership Nested Unusually Deep

Deep nesting chains make "who actually has access to this" a genuinely
harder question to answer correctly -- widely discussed across AD
security literature (nested-group audit guides, Trimarc's writing on
nested-group risk, general PingCastle-adjacent commentary), though
without one crisp, universally-cited numeric threshold the way some
other findings in this project have. The threshold used here (deeper
than 4 levels) is this project's own reasoned heuristic, stated as such,
not an externally cited standard.
"""

PLUGIN = {
    "plugin_id": 3010,
    "category": "Groups",
    "name": "Group Membership Nested Unusually Deep",
    "version": "1.1",
    "revision_date": "2026-07-15",
    "remediation": (
        "Review the full nesting chain (available in this finding's "
        "detail) and consider flattening it -- add the ultimately-"
        "affected principals more directly, or consolidate intermediate "
        "groups that don't serve a distinct purpose of their own. Deep "
        "nesting isn't inherently a vulnerability, but it does make "
        "\"who actually has access to this\" measurably harder to "
        "answer correctly during a review, which is itself a real cost "
        "worth weighing against whatever convenience the nesting "
        "provides."
    ),
    "control_id": "HYGIENE-304",
    "framework_tags": [],
    "references": [],
    "description": (
        "Deep group nesting chains make permission auditing measurably "
        "harder -- widely discussed across AD security literature "
        "(nested-group audit guidance, general commentary on nested-"
        "group risk), though without one crisp, universally-cited "
        "numeric threshold the way some other findings in this plugin "
        "set have. The threshold used here (a membership relationship "
        "spanning more than 4 levels -- direct membership plus at "
        "least 4 intermediate nested groups) is this "
        "project's own reasoned heuristic, stated as such rather than "
        "dressed up as an external standard. Computed directly off this "
        "project's existing recursive membership view "
        "(v_effective_group_membership.min_depth) -- no new collection "
        "or logic needed beyond what circular-nesting detection (plugin "
        "3006) already relies on."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            deep.group_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN g.is_protected_group THEN 'medium' ELSE 'low' END AS fd_severity,
            (CASE WHEN g.is_protected_group THEN 'Privileged ' ELSE '' END)
                || 'Group ' || g.sam_account_name || ' has a membership chain nested '
                || deep.min_depth || ' levels deep' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'max_nesting_depth', deep.min_depth,
                'is_protected_group', g.is_protected_group
            ) AS detail
        FROM (
            SELECT group_guid, max(min_depth) AS min_depth
            FROM v_effective_group_membership
            WHERE client_id = %(client_id)s
            GROUP BY group_guid
            HAVING max(min_depth) > 4
        ) deep
        JOIN ad_group g ON g.object_guid = deep.group_guid AND g.valid_to IS NULL
        WHERE g.client_id = %(client_id)s
    """,
}
