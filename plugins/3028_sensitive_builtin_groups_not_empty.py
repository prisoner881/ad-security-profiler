"""
Plugin 3028: Sensitive Built-in Groups Are Not Empty

Reports members of built-in (BUILTIN domain, S-1-5-32-*) groups that
are not AdminSDHolder-protected and are rarely monitored, but give
their members significant power on every domain controller:
  - Hyper-V Administrators (S-1-5-32-578), high: full control of
    Hyper-V on the DCs; anyone who controls a virtualised DC's host or
    VM can copy its disk and extract NTDS.dit.
  - Storage Replica Administrators (S-1-5-32-582), medium: full control
    of Storage Replica, i.e. the ability to replicate volumes (including
    the NTDS volume) elsewhere.
  - Remote Management Users (S-1-5-32-580), medium: WinRM / PowerShell
    remoting access to the DCs, an entry point for local privilege
    escalation.
  - Event Log Readers (S-1-5-32-573), medium: read the DCs' Security log,
    which reveals account names, logon patterns and sometimes secrets on
    command lines.
  - Distributed COM Users (S-1-5-32-562), medium: launch and activate
    DCOM objects on the DCs (remote code execution primitives).
  - Cryptographic Operators (S-1-5-32-569), medium: perform
    cryptographic operations / change crypto settings on the DCs.
On a domain controller these built-ins are domain-wide groups, so a
member holds the right on every DC. ANSSI and Microsoft's privileged
groups guidance recommend keeping them empty unless a documented need
exists.

Groups are matched by SID, never by name. A group not collected into
directory_object (built-ins only exist there if collected) has nothing
to report. A group is reported when it has members
(member_count_direct > 0 or a current direct membership edge).
detail.effective_member_accounts lists the enabled users/computers
holding the membership directly, through nesting or primaryGroupID;
disabled accounts are left out of that list, but a group whose only
members are disabled is still reported (it is not empty).

One row per non-empty group.
"""

PLUGIN = {
    "plugin_id": 3028,
    "category": "Groups",
    "name": "Sensitive Built-in Groups Are Not Empty",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "PRIV-3028",
    "framework_tags": [
        "MITRE-ATTCK-T1078.002",
        "NIST-800-53-AC-2(7)", "NIST-800-53-AC-6(5)", "NIST-CSF-2.0-PR.AA-05", "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4", "ISO-27001-2022-A.8.2", "SOC2-CC6.3",
    ],
    "references": [
        {"title": "Microsoft: Active Directory security groups",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups"},
        {"title": "Microsoft: Appendix B - Privileged Accounts and Groups in Active Directory",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-b--privileged-accounts-and-groups-in-active-directory"},
    ],
    "description": (
        "Flags members of sensitive built-in groups that act on every domain "
        "controller but are not AdminSDHolder-protected: Hyper-V Administrators "
        "(high), Storage Replica Administrators, Remote Management Users, Event Log "
        "Readers, Distributed COM Users and Cryptographic Operators (medium). These "
        "groups should normally be empty."
    ),
    "remediation": (
        "Review each member listed in the evidence and remove those without a "
        "documented need (`Remove-ADGroupMember -Identity '<group SID>' -Members "
        "<member>`). Grant the right on the specific servers that need it through "
        "their local groups or a scoped GPO instead of the domain-wide built-in "
        "group. Treat Hyper-V Administrators like Domain Admins when DCs are "
        "virtualised. Monitor membership changes (Security events 4732/4733)."
    ),
    "base_severity": "high",
    "query": """
        WITH target AS (
            SELECT * FROM (VALUES
                ('S-1-5-32-578', 'Hyper-V Administrators', 'high'),
                ('S-1-5-32-582', 'Storage Replica Administrators', 'medium'),
                ('S-1-5-32-580', 'Remote Management Users', 'medium'),
                ('S-1-5-32-573', 'Event Log Readers', 'medium'),
                ('S-1-5-32-562', 'Distributed COM Users', 'medium'),
                ('S-1-5-32-569', 'Cryptographic Operators', 'medium')
            ) v(sid, label, sev)
        )
        SELECT
            CASE WHEN t.sev = 'high' THEN 'fail' ELSE 'warn' END AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            t.sev AS fd_severity,
            t.label || ' group has ' || COALESCE(NULLIF(g.member_count_direct, 0), dm.cnt)
                || ' direct member(s)' AS summary,
            jsonb_build_object(
                'group', t.label,
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
        JOIN target t ON t.sid = do2.object_sid
        CROSS JOIN LATERAL (
            SELECT count(*) AS cnt FROM group_member_edge gme
            WHERE gme.group_guid = g.object_guid AND gme.client_id = g.client_id AND gme.valid_to IS NULL
        ) dm
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND NOT do2.is_deleted
          AND (COALESCE(g.member_count_direct, 0) > 0 OR dm.cnt > 0)
        ORDER BY g.object_guid
    """,
}
