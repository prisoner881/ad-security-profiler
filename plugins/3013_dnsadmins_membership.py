"""
Plugin 3013: DnsAdmins Group Has Members

Members of the built-in DnsAdmins group can configure the domain's DNS
server (typically running directly on a domain controller, since AD-
integrated DNS is the overwhelmingly common deployment) to load an
arbitrary DLL via the ServerLevelPluginDll registry parameter. That
DLL executes in the context of the dns.exe service -- SYSTEM, on
whatever machine is running it. On a domain controller, that's a
direct, well-documented path from "member of DnsAdmins" to full domain
compromise, requiring only a service restart (which DnsAdmins members
can typically trigger themselves) to trigger execution.

Unlike Domain Admins, Enterprise Admins, and the other RID-500-series
groups, DnsAdmins is NOT protected by AdminSDHolder/SDProp -- its ACL
is not automatically reset to the protected-object template, so
control over the group itself, not just membership in it, is a
separate and equally real path worth investigating (though confirming
that requires the group object's own ACL, which is not collected by this
project -- see this finding's description).

[v1.2] DnsAdmins has no fixed RID, so it is still found by name, but now
case-insensitively or by its default description ("DNS Administrators
Group"), which survives a rename. detail.effective_member_accounts lists
the enabled users/computers holding the membership directly, through
nested groups or through primaryGroupID; direct members fall back to SID.
Corrected the "enrollment ACL" wording (an AD CS term).
"""

PLUGIN = {
    "plugin_id": 3013,
    "category": "Groups",
    "name": "DnsAdmins Group Has Members",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Review every member listed in this finding's evidence and "
        "confirm each one genuinely needs DNS administration rights. "
        "For most environments, DNS administration doesn't need broad "
        "group membership at all -- delegate specific, narrower rights "
        "on the DNS zone objects instead of adding accounts to "
        "DnsAdmins. If members must remain, treat every one of them as "
        "tier-0 equivalent (they are one DLL load and a service "
        "restart away from SYSTEM on whatever runs DNS) and apply the "
        "same protections you'd apply to Domain Admins -- MFA, "
        "dedicated admin workstations, and no use for day-to-day "
        "logons. Also review who holds modify rights on the DnsAdmins "
        "group object itself: unlike Domain Admins/Enterprise Admins, "
        "it is not covered by AdminSDHolder, so a broad ACL grant on "
        "the group is a separate path to the same outcome."
    ),
    "control_id": "PRIV-310",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1078.002"],
    "references": [
        {"title": "Tenable: DnsAdmins Exploitation",
         "url": "https://www.tenable.com/indicators/ioa/I-DnsAdmins"},
    ],
    "description": (
        "Members of the built-in DnsAdmins group can configure the DNS "
        "server (typically running on a domain controller under AD-"
        "integrated DNS) to load an arbitrary DLL via the "
        "ServerLevelPluginDll parameter, executing as SYSTEM on the "
        "next service restart -- a well-documented, direct path to "
        "domain compromise. DnsAdmins is not covered by AdminSDHolder/"
        "SDProp the way Domain Admins and Enterprise Admins are, so "
        "control over the group object itself (not just membership) is "
        "a separate risk this finding cannot directly assess, since it "
        "would require the group object's own ACL -- not collected by "
        "this project. DnsAdmins has no well-known RID; it is matched by "
        "name (case-insensitive) or by its default description."
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
            'DnsAdmins group has ' || g.member_count_direct || ' direct member(s)' AS summary,
            jsonb_build_object(
                'sam_account_name', g.sam_account_name,
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
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND (lower(g.sam_account_name) = 'dnsadmins'
               OR g.description = 'DNS Administrators Group')
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
