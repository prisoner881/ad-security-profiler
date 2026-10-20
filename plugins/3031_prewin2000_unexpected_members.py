"""
Plugin 3031: Pre-Windows 2000 Compatible Access Has Authenticated Users or Other Members

Reports the members of the builtin group Pre-Windows 2000 Compatible Access
(S-1-5-32-554) other than Everyone and Anonymous Logon, which plugin 3012
already reports. One row for the group (object_guid = the group), listing
every member found.

Why it matters: the group's members can read user and group attributes
that are otherwise restricted (default ACEs on the domain grant it read
access through the legacy "list contents" and "read all properties"
permissions), and it is what makes anonymous and null-session enumeration
possible when Everyone/Anonymous are added. With Authenticated Users in it
-- the default when a domain was created in "compatible with pre-Windows
2000" mode -- every account, including any computer account an attacker
creates through MachineAccountQuota, gets that extra read access
(PingCastle A-PreWin2000AuthenticatedUsers, informative). Any other member
(a user, a computer, Domain Users, ...) is a deliberate widening that
Microsoft's guidance never requires today (PingCastle A-PreWin2000Other).

Severity ('warn'):
- low: members other than Authenticated Users, Everyone and Anonymous Logon;
- info: Authenticated Users is the only extra member.

Data: group_member_edge (direct members), directory_object,
ad_foreign_security_principal for well-known SIDs.
"""

PLUGIN = {
    "plugin_id": 3031,
    "category": "Groups",
    "name": "Pre-Windows 2000 Compatible Access Has Authenticated Users or Other Members",
    "version": "1.0",
    "revision_date": "2026-10-20",
    "control_id": "GROUP-3031",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "CIS-CSC-8-3.3",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1087.002",
    ],
    "references": [
        {"title": "Microsoft: Active Directory security groups -- Pre-Windows 2000 Compatible Access",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-groups#pre-windows-2000-compatible-access"},
        {"title": "PingCastle health check rules (A-PreWin2000AuthenticatedUsers, A-PreWin2000Other)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1087.002: Account Discovery: Domain Account",
         "url": "https://attack.mitre.org/techniques/T1087/002/"},
    ],
    "description": (
        "The Pre-Windows 2000 Compatible Access group contains Authenticated "
        "Users or other principals beyond Everyone and Anonymous Logon "
        "(plugin 3012). Its members get legacy read access to user and group "
        "data. Low when principals other than Authenticated Users are "
        "members, info when Authenticated Users is the only one."
    ),
    "remediation": (
        "Remove the extra members: Remove-ADGroupMember 'Pre-Windows 2000 "
        "Compatible Access' -Members <member>. Before removing Authenticated "
        "Users, check for applications that enumerate group memberships "
        "with non-administrative accounts (old NAS appliances, Exchange 2003, "
        "RAS servers on NT4); test in a pilot first."
    ),
    "base_severity": "low",
    "query": """
        WITH grp AS (
            SELECT o.object_guid
            FROM directory_object o
            WHERE o.client_id = %(client_id)s AND NOT o.is_deleted
              AND o.object_sid = 'S-1-5-32-554'
        ),
        mem AS (
            SELECT g.object_guid AS group_guid, m.object_guid AS member_guid,
                   COALESCE(f.well_known_name, m.sam_account_name, m.dn_current, m.object_sid::text,
                            m.object_guid::text) AS member_name,
                   m.object_sid::text AS member_sid,
                   m.object_class::text AS member_class,
                   (m.object_sid = 'S-1-5-11') AS is_authenticated_users
            FROM grp g
            JOIN group_member_edge e
              ON e.client_id = %(client_id)s AND e.group_guid = g.object_guid
             AND e.valid_to IS NULL AND e.is_direct
            JOIN directory_object m
              ON m.object_guid = e.member_guid AND m.client_id = e.client_id AND NOT m.is_deleted
            LEFT JOIN ad_foreign_security_principal f
              ON f.object_guid = m.object_guid AND f.client_id = m.client_id AND f.valid_to IS NULL
            WHERE COALESCE(m.object_sid::text, '') NOT IN ('S-1-1-0', 'S-1-5-7')
        )
        SELECT
            'warn' AS status,
            m.group_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_and(m.is_authenticated_users) THEN 'info' ELSE 'low' END AS fd_severity,
            'Pre-Windows 2000 Compatible Access has '
                || CASE WHEN bool_and(m.is_authenticated_users)
                        THEN 'Authenticated Users as a member (every account gets legacy read access)'
                        ELSE count(*) || ' member(s) beyond Everyone/Anonymous: '
                             || string_agg(m.member_name, ', ' ORDER BY lower(m.member_name), m.member_guid)
                   END AS summary,
            jsonb_build_object(
                'members', jsonb_agg(jsonb_build_object('name', m.member_name, 'sid', m.member_sid,
                                                        'object_class', m.member_class)
                                     ORDER BY lower(m.member_name), m.member_guid),
                'authenticated_users_member', bool_or(m.is_authenticated_users),
                'other_member_count', count(*) FILTER (WHERE NOT m.is_authenticated_users)
            ) AS detail
        FROM mem m
        GROUP BY m.group_guid
    """,
}
