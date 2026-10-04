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

[v1.1] The group is identified by its well-known domain RID 571 instead
of its English name (which never matched on localized or renamed
domains). Severity drops to medium when the domain has no read-only DC
(ad_computer.is_read_only_dc, schema v36) -- the exposure is then
latent. detail lists the effective enabled member accounts (nested and
primaryGroupID membership included) and which of them are also in the
Denied RODC Password Replication Group (RID 572), since Deny wins and
those are not actually cached.
"""

PLUGIN = {
    "plugin_id": 3016,
    "category": "Groups",
    "name": "Allowed RODC Password Replication Group Is Not Empty",
    "version": "1.1",
    "revision_date": "2026-10-04",
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
        "not this shared group. Identified by RID 571; rated medium "
        "when the domain has no read-only DC yet (latent exposure)."
    ),
    "base_severity": "high",
    "query": """
        WITH eff AS (
            SELECT vem.group_guid, vem.member_guid,
                   COALESCE(mdo.sam_account_name, mdo.object_sid, mdo.object_guid::text) AS n
            FROM v_effective_group_membership vem
            JOIN directory_object mdo
                ON mdo.object_guid = vem.member_guid AND mdo.client_id = vem.client_id
            LEFT JOIN ad_user u
                ON u.object_guid = vem.member_guid AND u.client_id = vem.client_id AND u.valid_to IS NULL
            LEFT JOIN ad_computer c
                ON c.object_guid = vem.member_guid AND c.client_id = vem.client_id AND c.valid_to IS NULL
            WHERE vem.client_id = %(client_id)s
              AND NOT mdo.is_deleted
              AND (u.is_enabled IS TRUE OR c.is_enabled IS TRUE)
        ),
        denied AS (
            SELECT e.member_guid
            FROM eff e
            JOIN directory_object ddo
                ON ddo.object_guid = e.group_guid AND ddo.client_id = %(client_id)s
            WHERE ddo.object_sid LIKE 'S-1-5-21-%%-572'
        )
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN EXISTS (SELECT 1 FROM ad_computer rc
                               WHERE rc.client_id = g.client_id AND rc.valid_to IS NULL
                                 AND rc.is_read_only_dc)
                 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Allowed RODC Password Replication Group has ' || g.member_count_direct || ' member(s), but should be empty' AS summary,
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
                    SELECT array_agg(DISTINCT e.n ORDER BY e.n) FROM eff e WHERE e.group_guid = g.object_guid
                ),
                'effective_members_also_denied', (
                    SELECT array_agg(DISTINCT e.n ORDER BY e.n) FROM eff e
                    WHERE e.group_guid = g.object_guid
                      AND e.member_guid IN (SELECT member_guid FROM denied)
                ),
                'read_only_dc_present', EXISTS (
                    SELECT 1 FROM ad_computer rc
                    WHERE rc.client_id = g.client_id AND rc.valid_to IS NULL AND rc.is_read_only_dc
                )
            ) AS detail
        FROM ad_group g
        JOIN directory_object do2
            ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND do2.object_sid LIKE 'S-1-5-21-%%-571'
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
