"""
Plugin 3017: Server Operators Group Has Members

Server Operators is a built-in group that, on domain controllers,
commonly inherits enough rights via the Default Domain Controllers
Policy to start/stop and reconfigure services and typically also
receives SeBackupPrivilege/SeRestorePrivilege -- the same privileges
that make Backup Operators membership dangerous (see plugin 3015).
In practice this makes Server Operators a bridge between two attack
paths: pointing a service's binary path at an arbitrary command and
restarting it as LocalSystem if a service's own ACL allows it, or
falling back to direct NTDS.dit extraction the same way a Backup
Operators member would. Like DnsAdmins and Account Operators, its
name does not obviously signal how much trust it carries.
"""

PLUGIN = {
    "plugin_id": 3017,
    "category": "Groups",
    "name": "Server Operators Group Has Members",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Review every member listed in this finding's evidence. Server "
        "Operators on a domain controller carries risk comparable to "
        "Backup Operators -- treat membership with the same scrutiny "
        "applied to Domain Admins. If the actual need is narrower (e.g. "
        "managing one specific service), delegate that specific right "
        "rather than adding accounts to this built-in group."
    ),
    "control_id": "PRIV-315",
    "framework_tags": [],
    "references": [
        {"title": "HackTricks: Privileged Groups and Token Privileges",
         "url": "https://book.hacktricks.xyz/windows-hardening/active-directory-methodology/privileged-groups-and-token-privileges"},
    ],
    "description": (
        "Server Operators is a built-in group that, on domain "
        "controllers, commonly inherits rights via the Default Domain "
        "Controllers Policy to start/stop and reconfigure services, "
        "and typically also receives SeBackupPrivilege/SeRestorePrivilege "
        "-- the same privileges that make Backup Operators membership "
        "dangerous. This creates two paths: retargeting a poorly-ACL'd "
        "service's binary and restarting it as LocalSystem, or falling "
        "back to direct NTDS.dit extraction the same way a Backup "
        "Operators member would. Like DnsAdmins and Account Operators, "
        "its name doesn't obviously signal how much trust it carries."
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
            'Server Operators group has ' || g.member_count_direct || ' direct member(s)' AS summary,
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
          AND g.sam_account_name = 'Server Operators'
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
