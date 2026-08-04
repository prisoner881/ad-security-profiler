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
"""

PLUGIN = {
    "plugin_id": 3015,
    "category": "Groups",
    "name": "Backup Operators Group Has Members",
    "version": "1.0",
    "revision_date": "2026-07-18",
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
    "framework_tags": [],
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
          AND g.sam_account_name = 'Backup Operators'
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
