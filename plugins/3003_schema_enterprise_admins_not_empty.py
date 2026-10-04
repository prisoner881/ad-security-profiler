"""
Plugin 3003: Schema Admins or Enterprise Admins Group Has Members

Both groups should remain empty except during the specific, rare window
of actively making a schema change or forest-wide operation -- direct,
current guidance from Microsoft's own AD health-check remediation
documentation, not a general inference. Detected by RID (518 Schema
Admins, 519 Enterprise Admins), not name, for the same rename-resistance
reason as the built-in Administrator/Guest account checks (plugins
1004/1005): these groups can be renamed, but their RID cannot change.

[v1.3] Populates stig_severity/stig_reference (CAT_I, DISA AD Forest STIG
V-243502) for the Schema Admins finding; detail.members now falls back
to the member's SID (foreign security principals have no
sAMAccountName and previously appeared as null) and the summary is
NULL-safe.
"""

PLUGIN = {
    "plugin_id": 3003,
    "category": "Groups",
    "name": "Schema Admins or Enterprise Admins Group Has Members",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Remove all members. Per Microsoft's own guidance: membership in "
        "Schema Admins is not required for any purpose beyond actively "
        "making a schema change, and the group should remain empty the "
        "rest of the time -- anyone who needs to make a change should "
        "add themselves temporarily, make the change, and remove "
        "themselves again. The same reasoning applies to Enterprise "
        "Admins for forest-wide operations. Standing membership in "
        "either group is unnecessary attack surface for a capability "
        "that's rarely exercised."
    ),
    "control_id": "PRIV-302",
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
        "DISA-STIG",
        "DISA-STIG-V-243502",
        "MITRE-ATTCK-T1078.002",
    ],
    "references": [
        {"title": "DISA STIG V-243502: Membership to the Schema Admins group must be limited",
         "url": "https://www.stigviewer.com/stigs/active_directory_forest/2025-05-15/finding/V-243502"},
    ],
    "description": (
        "Directly quoted from Microsoft's own AD health-check "
        "remediation documentation: \"we recommend that the Schema "
        "Admins group remain empty except when actively making changes. "
        "This approach helps reduce the possibility of accidental "
        "schema changes.\" The same standing-empty-except-when-needed "
        "principle is documented for Enterprise Admins given its "
        "forest-wide reach. Detected by RID (518 Schema Admins, 519 "
        "Enterprise Admins), not by name, since both groups can be "
        "renamed but their RID cannot change -- the same rename-"
        "resistant detection already used for the built-in Administrator "
        "and Guest accounts."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            g.object_guid,
            CASE WHEN do2.object_sid LIKE '%%-518' THEN 'CAT_I' END AS stig_severity,
            CASE WHEN do2.object_sid LIKE '%%-518'
                 THEN 'DISA Active Directory Forest STIG V-243502' END AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Group "' || COALESCE(g.sam_account_name, do2.object_sid, g.object_guid::text) || '" (RID '
                || right(do2.object_sid, 3) || ') has ' || g.member_count_direct
                || ' member(s)' AS summary,
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
                )
            ) AS detail
        FROM ad_group g
        JOIN directory_object do2
            ON do2.object_guid = g.object_guid AND do2.client_id = g.client_id
        WHERE g.valid_to IS NULL
          AND g.client_id = %(client_id)s
          AND (do2.object_sid LIKE '%%-518' OR do2.object_sid LIKE '%%-519')
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
