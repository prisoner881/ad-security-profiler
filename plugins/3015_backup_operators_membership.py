"""
Plugin 3015: Backup Operators Group Has Members

Members of the built-in Backup Operators group hold SeBackupPrivilege
and SeRestorePrivilege on domain controllers via the Default Domain
Controllers Policy -- rights specifically designed to read or write
any file regardless of its ACL, for legitimate backup/restore
purposes. Those same rights allow a Backup Operators member to copy
the Active Directory database (ntds.dit) and the registry SAM/SYSTEM/
SECURITY hives directly off a domain controller (e.g. via
`robocopy /b`, DiskShadow, or a raw volume shadow copy), extract every
password hash in the domain offline, and authenticate as any account
via pass-the-hash -- a well-documented, complete path to domain
compromise from a group whose name doesn't sound like a Domain Admin-
tier risk. Unlike some other operator-tier groups, Backup Operators IS
covered by AdminSDHolder/SDProp, but that alone does not limit what
its members can already do with existing membership -- it only
protects the group's own ACL from casual tampering.

Given the severity of what a single inappropriate member enables here,
this fires on any membership at all rather than the higher bloat
threshold used by plugin 3004 for privileged groups generally.

[v1.2] The group is identified by its well-known SID (S-1-5-32-551) instead
of the English sAMAccountName 'Backup Operators', which never matched on localized
(non-English) or renamed domains. detail.effective_member_accounts lists
the enabled users/computers holding the membership directly, through
nested groups or through primaryGroupID; direct members fall back to SID.
"""

PLUGIN = {
    "plugin_id": 3015,
    "category": "Groups",
    "name": "Backup Operators Group Has Members",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Review every member listed in this finding's evidence. Backup "
        "Operators is effectively equivalent to Domain Admin from a "
        "data-confidentiality standpoint (any member can extract every "
        "password hash in the domain via NTDS.dit), even though its "
        "name doesn't suggest that. If backup software genuinely needs "
        "these rights, prefer a dedicated managed service account used "
        "only by the backup product, not a human administrator account, "
        "and confirm the backup software actually requires domain-level "
        "membership rather than local Backup Operators rights on "
        "individual servers. Monitor Event ID 4672/4673 (privileged "
        "use) and 4732 (group membership change) for this group with "
        "the same rigor applied to Domain Admins."
    ),
    "control_id": "PRIV-312",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1078.002"],
    "references": [
        {"title": "Hacking Articles: Windows Privilege Escalation -- SeBackupPrivilege",
         "url": "https://www.hackingarticles.in/windows-privilege-escalation-sebackupprivilege/"},
    ],
    "description": (
        "Members of the built-in Backup Operators group hold "
        "SeBackupPrivilege and SeRestorePrivilege on domain controllers "
        "via the Default Domain Controllers Policy -- rights that read "
        "or write any file regardless of its ACL. This allows copying "
        "the Active Directory database (ntds.dit) and registry hives "
        "directly off a domain controller, extracting every password "
        "hash in the domain offline -- a complete, well-documented path "
        "to domain compromise. Fires on any membership at all, rather "
        "than plugin 3004's higher bloat threshold, since a single "
        "inappropriate member here is already a significant finding."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Backup Operators group has ' || g.member_count_direct || ' direct member(s)' AS summary,
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
          AND do2.object_sid = 'S-1-5-32-551'
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
