"""
Plugin 3018: Print Operators Group Has Members

Print Operators is a built-in group that, historically, could load
printer drivers (kernel-mode code) on domain controllers -- a
documented privilege escalation path when combined with a malicious
driver, and part of the same family of risk as DnsAdmins, Account
Operators, Server Operators, and Backup Operators (plugins 3013-3015,
3017): a group whose name suggests a narrow, mundane administrative
task, but whose actual default rights on domain controllers are far
broader than most organizations intend to grant. Completes this
project's coverage of the four classic "operator" groups Microsoft
and independent AD security research consistently name as commonly-
overlooked privilege escalation vectors.
"""

PLUGIN = {
    "plugin_id": 3018,
    "category": "Groups",
    "name": "Print Operators Group Has Members",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Review every member listed in this finding's evidence and "
        "confirm each one genuinely needs domain-wide print "
        "administration rights. For most environments, this group "
        "should remain empty -- print server administration can "
        "typically be delegated at the individual server level instead "
        "of granting a group with default rights on every domain "
        "controller. If members must remain, treat them with the same "
        "scrutiny applied to Domain Admins."
    ),
    "control_id": "PRIV-306",
    "framework_tags": [],
    "references": [],
    "description": (
        "Print Operators is a built-in group that, historically, could "
        "load printer drivers (kernel-mode code) on domain controllers "
        "-- a documented privilege escalation path when combined with "
        "a malicious driver. Part of the same family of risk as "
        "DnsAdmins, Account Operators, Server Operators, and Backup "
        "Operators: a group whose name suggests a narrow administrative "
        "task, but whose actual default rights on domain controllers "
        "are broader than most organizations intend to grant."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Print Operators group has ' || g.member_count_direct || ' direct member(s)' AS summary,
            jsonb_build_object(
                'member_count_direct', g.member_count_direct,
                'members', (
                    SELECT array_agg(mdo.sam_account_name ORDER BY mdo.sam_account_name)
                    FROM group_member_edge gme
                    JOIN directory_object mdo ON mdo.object_guid = gme.member_guid AND mdo.client_id = gme.client_id
                    WHERE gme.group_guid = g.object_guid AND gme.client_id = g.client_id AND gme.valid_to IS NULL
                )
            ) AS detail
        FROM ad_group g
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND g.sam_account_name = 'Print Operators'
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
