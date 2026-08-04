"""
Plugin 2015: Computer Primary Group ID Set to a Privileged Group

Same technique as user-account plugin 1016, applied to computer objects.
The default for a computer object is 515 (Domain Computers); a
privileged-group RID here means membership that won't appear in that
group's own member list.
"""

PLUGIN = {
    "plugin_id": 2015,
    "category": "Computer Accounts",
    "name": "Computer Primary Group ID Set to a Privileged Group",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Investigate immediately -- this is a known attacker persistence "
        "technique, not a benign misconfiguration in most cases. "
        "Determine who or what set this value and when before simply "
        "correcting it. Once confirmed benign or after investigation "
        "concludes, reset primaryGroupID back to the standard default for "
        "a computer object (515, Domain Computers) via "
        "`Set-ADComputer -Replace @{primaryGroupID=515}`."
    ),
    "control_id": "PRIV-203",
    "framework_tags": ["ANSSI"],
    "references": [],
    "description": (
        "Same technique as user-account plugin 1016, applied to computer "
        "objects: group membership via primaryGroupID does not appear in "
        "the target group's own member list, so reviewing membership the "
        "normal way (via the group) would miss it entirely. The default "
        "for a computer object is 515 (Domain Computers); this checks "
        "the same commonly-abused sensitive RIDs as the user-account "
        "equivalent (512 Domain Admins, 518 Schema Admins, 519 Enterprise "
        "Admins, 520 Group Policy Creator Owners, 544 Administrators). "
        "NOT downgraded when disabled -- this is persistent configuration "
        "that survives disablement."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            'high' AS tool_severity,
            'PingCastle / ANSSI: "Accounts with modified PrimaryGroupID" '
                '(vuln3_primary_group_id_nochange) -- same rule already cited for '
                'the user-account equivalent, applies identically to computer objects' AS tool_reference,
            CASE WHEN c.is_domain_controller THEN 'critical' ELSE 'high' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || c.sam_account_name
                || ' has primaryGroupID set to a privileged group (RID '
                || c.primary_group_id || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'primary_group_id', c.primary_group_id,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.primary_group_id IN (512, 518, 519, 520, 544)
    """,
}
