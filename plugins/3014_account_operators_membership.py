"""
Plugin 3014: Account Operators Group Has Members

Account Operators is a built-in group granted broad rights to create,
modify, and delete most user, group, and computer objects domain-wide
by default -- without being one of the classic Domain Admins-tier
groups an organization is likely to be watching closely. It cannot
directly modify accounts protected by AdminSDHolder (Domain Admins,
Enterprise Admins, and the other protected-group membership), but it
can create new computer accounts, modify most other accounts'
attributes (including, on many builds, enabling delegation or
resetting passwords on non-protected accounts), and -- as documented
in recent research -- can be chained with other primitives such as
DnsAdmins and incoming forest trust creation into a full domain
compromise path. Membership in this group is worth the same scrutiny
as membership in a more obviously named privileged group.
"""

PLUGIN = {
    "plugin_id": 3014,
    "category": "Groups",
    "name": "Account Operators Group Has Members",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Review every member listed in this finding's evidence and "
        "confirm each one genuinely needs domain-wide account "
        "management rights. Account Operators is broader than most "
        "organizations intend to grant -- if the actual need is "
        "narrower (e.g. managing accounts within one OU, or resetting "
        "passwords for one department), delegate that specific, "
        "scoped right instead of adding accounts to this built-in "
        "group. If members must remain, monitor them with the same "
        "rigor as more obviously privileged groups, since Account "
        "Operators membership is a documented component of several "
        "chained domain-compromise paths."
    ),
    "control_id": "PRIV-311",
    "framework_tags": [],
    "references": [
        {"title": "SpecterOps: Untrustworthy Trust Builders -- Account Operators Replicating Trust Attack (AORTA)",
         "url": "https://specterops.io/blog/2025/06/25/untrustworthy-trust-builders-account-operators-replicating-trust-attack-aorta/"},
    ],
    "description": (
        "Account Operators is a built-in group granted broad default "
        "rights to create, modify, and delete most user, group, and "
        "computer objects domain-wide -- without carrying an obviously "
        "privileged name the way Domain Admins does. It cannot directly "
        "modify AdminSDHolder-protected accounts, but recent research "
        "(see reference) documents it being chained with other "
        "primitives, including DnsAdmins and forest trust creation, "
        "into full domain compromise. Membership here deserves the "
        "same scrutiny as membership in a more obviously named "
        "privileged group."
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
            'Account Operators group has ' || g.member_count_direct || ' direct member(s)' AS summary,
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
          AND g.sam_account_name = 'Account Operators'
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
