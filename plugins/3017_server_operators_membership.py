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

[v1.2] The group is identified by its well-known SID (S-1-5-32-549) instead
of the English sAMAccountName 'Server Operators', which never matched on localized
(non-English) or renamed domains. detail.effective_member_accounts lists
the enabled users/computers holding the membership directly, through
nested groups or through primaryGroupID; direct members fall back to SID.
"""

PLUGIN = {
    "plugin_id": 3017,
    "category": "Groups",
    "name": "Server Operators Group Has Members",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Review every member listed in this finding's evidence. Server "
        "Operators on a domain controller carries risk comparable to "
        "Backup Operators -- treat membership with the same scrutiny "
        "applied to Domain Admins. If the actual need is narrower (e.g. "
        "managing one specific service), delegate that specific right "
        "rather than adding accounts to this built-in group."
    ),
    "control_id": "PRIV-315",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1078.002"],
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
                'sam_account_name', g.sam_account_name,
                'object_sid', do2.object_sid,
                'member_count_direct', g.member_count_direct,
                'members', (
                    SELECT array_agg(COALESCE(mdo.sam_account_name, mdo.object_sid, mdo.object_guid::text)
                                     ORDER BY COALESCE(mdo.sam_account_name, mdo.object_sid, mdo.object_guid::text))
                    FROM group_member_edge gme
                    JOIN directory_object mdo ON mdo.object_guid = gme.member_guid AND mdo.client_id = gme.client_id
                    WHERE gme.group_guid = g.object_guid AND gme.client_id = g.client_id AND gme.valid_to IS NULL
                ),
                'effective_member_accounts', (
                    SELECT array_agg(n ORDER BY n) FROM (
                        SELECT DISTINCT COALESCE(mdo.sam_account_name, mdo.object_sid, mdo.object_guid::text) AS n
                        FROM v_effective_group_membership vem
                        JOIN directory_object mdo
                            ON mdo.object_guid = vem.member_guid AND mdo.client_id = vem.client_id
                        LEFT JOIN ad_user u
                            ON u.object_guid = vem.member_guid AND u.client_id = vem.client_id AND u.valid_to IS NULL
                        LEFT JOIN ad_computer c
                            ON c.object_guid = vem.member_guid AND c.client_id = vem.client_id AND c.valid_to IS NULL
                        WHERE vem.group_guid = g.object_guid AND vem.client_id = g.client_id
                          AND NOT mdo.is_deleted
                          AND (u.is_enabled IS TRUE OR c.is_enabled IS TRUE)
                    ) em
                )
            ) AS detail
        FROM ad_group g
        JOIN directory_object do2
            ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND do2.object_sid = 'S-1-5-32-549'
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
