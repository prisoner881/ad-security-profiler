"""
Plugin 3030: SID History Migration Auditing Group (DOMAIN$$$) Present

Reports a domain-local group whose sAMAccountName ends in "$$$" -- the
"<NetBIOS domain name>$$$" group that the Active Directory Migration Tool
(ADMT) and DsAddSidHistory require on the SOURCE domain of a migration.

Why it matters: the group exists only to enable sIDHistory-based migration.
Together with "Audit account management" auditing and the
TcpipClientSupport registry value on the PDC, it lets an administrator of a
trusting domain copy SIDs from this domain into sIDHistory -- the mechanism
of SID-history injection (MITRE ATT&CK T1134.005). Left behind after a
migration, it signals that SID-history writes may still be possible
(PingCastle S-Domain$$$).

Severity: medium ('warn'); high when the group has members (it should
always be empty). One row per group (object_guid = the group).

Data: ad_group (sAMAccountName, current version), member edges.
"""

PLUGIN = {
    "plugin_id": 3030,
    "category": "Groups",
    "name": "SID History Migration Auditing Group (DOMAIN$$$) Present",
    "version": "1.0",
    "revision_date": "2026-10-20",
    "control_id": "GROUP-3030",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.3",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC6.3",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1134.005",
    ],
    "references": [
        {"title": "Microsoft: DsAddSidHistory function (requirements, including the <SrcDomainFlatName>$$$ group)",
         "url": "https://learn.microsoft.com/en-us/windows/win32/api/ntdsapi/nf-ntdsapi-dsaddsidhistorya"},
        {"title": "PingCastle health check rules (S-Domain$$$)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1134.005: Access Token Manipulation: SID-History Injection",
         "url": "https://attack.mitre.org/techniques/T1134/005/"},
    ],
    "description": (
        "A group named <DOMAIN>$$$ exists. It is created only to allow "
        "sIDHistory migration (ADMT / DsAddSidHistory) from this domain; left "
        "in place it keeps SID-history writes possible. Medium; high when "
        "the group has members."
    ),
    "remediation": (
        "If no domain migration is in progress, delete the group (and remove "
        "the TcpipClientSupport registry value from the PDC emulator if it "
        "was set for the migration). If a migration is running, remove the "
        "group as soon as it ends, and keep it empty in the meantime."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN COALESCE(m.members, 0) > 0 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Group ' || g.sam_account_name || ' exists: it enables sIDHistory migration from this domain'
                || CASE WHEN COALESCE(m.members, 0) > 0
                        THEN ' and has ' || m.members || ' member(s)' ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
                'group_type', g.group_type,
                'when_created', g.when_created,
                'direct_member_count', COALESCE(m.members, 0)
            ) AS detail
        FROM ad_group g
        JOIN directory_object o
          ON o.object_guid = g.object_guid AND o.client_id = g.client_id AND NOT o.is_deleted
        LEFT JOIN (
            SELECT e.group_guid, count(*) AS members
            FROM group_member_edge e
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL AND e.is_direct
            GROUP BY e.group_guid
        ) m ON m.group_guid = g.object_guid
        WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL
          AND g.sam_account_name LIKE '%%$$$'
    """,
}
