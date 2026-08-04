"""
Plugin 3016: Allowed RODC Password Replication Group Is Not Empty

The built-in "Allowed RODC Password Replication Group" is, by design,
meant to remain empty. Any account added to it has its password hash
cached and revealed on every Read-Only Domain Controller in the
domain -- not just one specific RODC. A Read-Only Domain Controller is
inherently a lower-trust asset, typically deployed at a branch office
or other location with weaker physical security, precisely because it
is expected NOT to hold the credentials of sensitive accounts.
Membership in this group defeats that entire design assumption:
compromise of any RODC in the domain becomes equivalent to compromise
of every account whose hash it has been allowed to cache. Microsoft's
intended pattern is to create dedicated Allowed/Denied password
replication groups scoped to each individual RODC's actual use case,
not to add accounts to this shared, domain-wide group.
"""

PLUGIN = {
    "plugin_id": 3016,
    "category": "Groups",
    "name": "Allowed RODC Password Replication Group Is Not Empty",
    "version": "1.0",
    "revision_date": "2026-07-18",
    "remediation": (
        "Remove every member from the Allowed RODC Password Replication "
        "Group -- it is designed to remain empty. If specific accounts "
        "genuinely need their passwords cached on a specific RODC (for "
        "a legitimate branch-office use case), configure that on the "
        "individual RODC's own Password Replication Policy (Active "
        "Directory Users and Computers -> Domain Controllers -> the "
        "RODC's Properties -> Password Replication Policy tab) rather "
        "than through this shared, domain-wide group, which applies to "
        "every RODC at once."
    ),
    "control_id": "PRIV-314",
    "framework_tags": [],
    "references": [],
    "description": (
        "The built-in Allowed RODC Password Replication Group is, by "
        "design, meant to remain empty. Any account added to it has "
        "its password hash cached and revealed on every Read-Only "
        "Domain Controller in the domain -- not just one. An RODC is "
        "inherently a lower-trust asset, typically deployed somewhere "
        "with weaker physical security, precisely because it isn't "
        "expected to hold sensitive credentials. Membership here "
        "defeats that assumption: compromise of any RODC becomes "
        "equivalent to compromising every account whose hash it was "
        "allowed to cache. Microsoft's intended pattern is a dedicated "
        "Password Replication Policy scoped to each individual RODC, "
        "not this shared group."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Allowed RODC Password Replication Group has ' || g.member_count_direct || ' member(s), but should be empty' AS summary,
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
          AND g.sam_account_name = 'Allowed RODC Password Replication Group'
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
