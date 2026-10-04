"""
Plugin 3022: Key Admins or Enterprise Key Admins Group Has Members

Members of Key Admins (RID 526, domain-scoped) or Enterprise Key
Admins (RID 527, forest-wide -- exists only in the forest root domain,
but its grant covers every domain in the forest) hold the built-in,
sanctioned ability to write msDS-KeyCredentialLink on user and
computer objects within their scope. That's the exact attribute this
project's Shadow Credentials findings (plugins 1022, 2013, 2029)
already treat as a serious, direct impersonation primitive when found
registered on an individual account -- membership in these two groups
is the same capability granted broadly, by design, as a standing
right rather than a one-off registration.

These groups exist specifically to support Windows Hello for Business
key-trust deployments and hybrid Entra Connect writeback scenarios
(confirmed via Microsoft's own documentation and support forum
threads describing exactly this use case) -- legitimate uses exist,
but they're narrow and specific, not something that calls for standing
membership by more than the automation account actually performing
that sync. Detected by RID, not name, for the same rename-resistance
reason as plugin 3003 (Schema/Enterprise Admins): the RID cannot
change even if the group is renamed.

[v1.2] detail.members falls back to the member's SID (foreign security
principals have no sAMAccountName and appeared as null); NULL-safe
summary.
"""

PLUGIN = {
    "plugin_id": 3022,
    "category": "Groups",
    "name": "Key Admins or Enterprise Key Admins Group Has Members",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "Review every member listed in this finding's evidence. The "
        "only common legitimate reason for standing membership is a "
        "hybrid identity sync account (e.g. Entra Connect) performing "
        "Windows Hello for Business key-trust writeback -- confirm "
        "that's genuinely what each member is for, and that no human "
        "account or unrelated service account is included. A member of "
        "either group can write msDS-KeyCredentialLink (register a "
        "Shadow Credential -- see plugins 1022/2013/2029) on any user "
        "or computer object within scope, without needing any other "
        "standing right on that specific account first."
    ),
    "control_id": "PRIV-313",
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
    "references": [
        {"title": "MITRE ATT&CK T1556: Modify Authentication Process",
         "url": "https://attack.mitre.org/techniques/T1556/"},
    ],
    "description": (
        "Key Admins (RID 526, domain-scoped) and Enterprise Key Admins "
        "(RID 527, forest-wide) hold built-in, sanctioned write access "
        "to msDS-KeyCredentialLink on user/computer objects within "
        "their scope -- the same attribute this project's Shadow "
        "Credentials findings (1022/2013/2029) treat as a serious "
        "impersonation primitive when registered on an individual "
        "account. These groups exist to support Windows Hello for "
        "Business key-trust and hybrid identity sync writeback "
        "scenarios; legitimate uses exist but are narrow, typically "
        "limited to a specific automation account. Detected by RID, "
        "not name, since the RID cannot change even if the group is "
        "renamed."
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
          AND (do2.object_sid LIKE '%%-526' OR do2.object_sid LIKE '%%-527')
          AND COALESCE(g.member_count_direct, 0) > 0
    """,
}
