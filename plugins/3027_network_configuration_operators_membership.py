"""
Plugin 3027: Network Configuration Operators Group Has Members

Network Configuration Operators (S-1-5-32-556) is a built-in group meant
to let members change TCP/IP settings. On domain controllers it is a
domain-wide built-in group, so its members hold those rights on every
DC. CVE-2025-21293 (January 2025) showed that the group's registry
rights -- CreateSubKey on the Dnscache and NetBT service keys -- let a
member register a Performance Counter DLL under those keys and have it
loaded as SYSTEM: local privilege escalation to SYSTEM, which on a
domain controller is full domain compromise. Microsoft patched the
specific path, but the group remains an operator group that ANSSI and
others recommend keeping empty, and it is not AdminSDHolder-protected,
so its membership is rarely watched.

Mirrors plugin 3014 (Account Operators). The group is identified by its
well-known SID, never by name. It is reported when it has members --
member_count_direct > 0 or a current direct membership edge.
detail.effective_member_accounts lists the enabled users/computers
holding the membership directly, through nested groups or through
primaryGroupID; disabled accounts are left out of that list but a group
whose only members are disabled is still reported (it is not empty).
If the group was not collected there is nothing to report.
"""

PLUGIN = {
    "plugin_id": 3027,
    "category": "Groups",
    "name": "Network Configuration Operators Group Has Members",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "remediation": (
        "Remove every member of Network Configuration Operators unless a "
        "documented need exists, and grant network configuration rights on the "
        "specific servers that need them through local groups or a scoped GPO "
        "instead. Make sure all domain controllers have the January 2025 "
        "security updates (CVE-2025-21293). Monitor the group's membership "
        "(Security events 4732/4733 on the DCs) the same way as other privileged "
        "groups."
    ),
    "control_id": "PRIV-3027",
    "framework_tags": [
        "CVE-2025-21293", "MITRE-ATTCK-T1068", "MITRE-ATTCK-T1078.002",
        "NIST-800-53-AC-2(7)", "NIST-800-53-AC-6(5)", "NIST-CSF-2.0-PR.AA-05", "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4", "ISO-27001-2022-A.8.2", "SOC2-CC6.3",
        "NIST-800-53-SI-2", "ISO-27001-2022-A.8.8",
    ],
    "references": [
        {"title": "MSRC: CVE-2025-21293 Active Directory Domain Services Elevation of Privilege",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-21293"},
        {"title": "NVD: CVE-2025-21293", "url": "https://nvd.nist.gov/vuln/detail/CVE-2025-21293"},
        {"title": "Microsoft: Active Directory security groups (Network Configuration Operators)",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups"},
    ],
    "description": (
        "Network Configuration Operators is a built-in group with registry rights "
        "on every domain controller that CVE-2025-21293 turned into SYSTEM-level "
        "code execution -- domain compromise from a group few organizations "
        "monitor. It should be empty; any member is reported."
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
            'Network Configuration Operators group has '
                || COALESCE(g.member_count_direct, dm.cnt) || ' direct member(s)' AS summary,
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
        CROSS JOIN LATERAL (
            SELECT count(*) AS cnt FROM group_member_edge gme
            WHERE gme.group_guid = g.object_guid AND gme.client_id = g.client_id AND gme.valid_to IS NULL
        ) dm
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND NOT do2.is_deleted
          AND do2.object_sid = 'S-1-5-32-556'
          AND (COALESCE(g.member_count_direct, 0) > 0 OR dm.cnt > 0)
    """,
}
