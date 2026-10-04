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

[v1.2] The group is identified by its well-known SID (S-1-5-32-550) instead
of the English sAMAccountName 'Print Operators', which never matched on localized
(non-English) or renamed domains. detail.effective_member_accounts lists
the enabled users/computers holding the membership directly, through
nested groups or through primaryGroupID; direct members fall back to SID.
"""

PLUGIN = {
    "plugin_id": 3018,
    "category": "Groups",
    "name": "Print Operators Group Has Members",
    "version": "1.2",
    "revision_date": "2026-10-04",
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
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1078.002",
        "CISA-AA26-237A",
    ],
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
          AND do2.object_sid = 'S-1-5-32-550'
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
