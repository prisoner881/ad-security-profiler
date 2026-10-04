"""
Plugin 3025: Group Policy Creator Owners or Incoming Forest Trust Builders Has Members

Directly cited against DISA Active Directory Domain STIG V-243487
(CAT II): "If any accounts [in either group] are not documented as
necessary with the ISSO, this is a finding." Confirmed against the
current STIG text (V3R7) directly.

The STIG's actual requirement is documentation-backed authorization,
not an absolute prohibition on membership -- something no LDAP-only
tool can verify (we can't see the ISSO's records). What IS objectively
checkable is membership itself: matches the established pattern
already used for plugins 3013-3019 (DnsAdmins, Account Operators,
Backup Operators, etc.) -- report who's actually in these two
specific, genuinely powerful groups, so a reviewer can check that
population against their own documentation, rather than this plugin
guessing at whether documentation exists.

Group Policy Creator Owners members can create and edit GPOs, a
meaningful lateral-movement and persistence vector. Incoming Forest
Trust Builders members can create one-way incoming forest trusts,
directly relevant to this STIG's own broader trust-relationship
concerns (V-243481 through V-243501).

Confirmed the two groups' well-known identifiers precisely rather than
assuming both work the same way: Group Policy Creator Owners is a
domain-relative RID (RID 520, S-1-5-21-<domain>-520), while Incoming
Forest Trust Builders is a BUILTIN alias (S-1-5-32-557) -- a different
SID structure entirely, verified against Microsoft's own documentation
before writing this query, not guessed at.

[v1.1] One finding per member: a principal in both groups (or reaching
both through nesting) produced two rows with the same identity, which
made the evidence write fail for the whole plugin. Rows are now
aggregated per member, the summary lists the sorted group names
(unchanged wording for single-group members apart from the class label)
and detail.privileged_groups is a sorted array. The summary labels the
member by object class and falls back to its SID. SIDs are matched
exactly (S-1-5-21-*-520, S-1-5-32-557).
"""

PLUGIN = {
    "plugin_id": 3025,
    "category": "Groups",
    "name": "Group Policy Creator Owners or Incoming Forest Trust Builders Has Members",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Confirm each member is documented with the ISSO as requiring "
        "this specific privilege. Remove any account whose need isn't "
        "documented or no longer applies. Group Policy Creator Owners "
        "members can create and edit Group Policy Objects across the "
        "domain; Incoming Forest Trust Builders members can establish "
        "new incoming forest trusts -- both are meaningful standing "
        "privileges that should be actively justified, not left over "
        "from historical delegation."
    ),
    "control_id": "STIG-V-243487",
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-800-53-AC-4",
        "NIST-800-53-AC-20",
        "NIST-800-53-SC-7",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-12.2",
        "ISO-27001-2022-A.8.2",
        "ISO-27001-2022-A.8.20",
        "ISO-27001-2022-A.8.22",
        "SOC2-CC6.3",
        "SOC2-CC6.6",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "DISA-STIG",
        "DISA-STIG-V-243487",
        "MITRE-ATTCK-T1484.001",
    ],
    "references": [
        {"title": "DISA Active Directory Domain STIG V3R7: V-243487",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243487"},
    ],
    "description": (
        "DISA Active Directory Domain STIG V-243487 (CAT II): "
        "membership in Group Policy Creator Owners and Incoming "
        "Forest Trust Builders must be documented as necessary with "
        "the ISSO. This plugin reports current membership as evidence "
        "for that documentation review -- it cannot verify whether "
        "documentation actually exists, only who currently holds the "
        "privilege."
    ),
    "base_severity": "medium",
    "query": """
        WITH matches AS (
            SELECT mdo.object_guid, mdo.sam_account_name, mdo.object_sid, mdo.object_class,
                   COALESCE(gdo.sam_account_name, gdo.object_sid) AS group_name
            FROM v_effective_group_membership vem
            JOIN directory_object gdo ON gdo.object_guid = vem.group_guid AND gdo.client_id = vem.client_id
            JOIN directory_object mdo ON mdo.object_guid = vem.member_guid AND mdo.client_id = vem.client_id
            WHERE vem.client_id = %(client_id)s
              AND NOT mdo.is_deleted
              AND (gdo.object_sid LIKE 'S-1-5-21-%%-520' OR gdo.object_sid = 'S-1-5-32-557')
        ),
        -- [v1.1] one row per member (identity = member's object_guid)
        aggregated AS (
            SELECT object_guid, sam_account_name, object_sid, object_class,
                   array_agg(DISTINCT group_name ORDER BY group_name) AS group_names
            FROM matches
            GROUP BY object_guid, sam_account_name, object_sid, object_class
        )
        SELECT
            'warn' AS status,
            a.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Active Directory Domain STIG V-243487' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            (CASE a.object_class::text
                  WHEN 'group' THEN 'Group '
                  WHEN 'computer' THEN 'Computer '
                  WHEN 'foreign_security_principal' THEN 'Foreign principal '
                  ELSE 'Account ' END)
                || COALESCE(a.sam_account_name, a.object_sid, a.object_guid::text)
                || ' is a member of "' || array_to_string(a.group_names, '", "') || '"' AS summary,
            jsonb_build_object(
                'sam_account_name', a.sam_account_name,
                'object_sid', a.object_sid,
                'object_class', a.object_class,
                'privileged_groups', to_jsonb(a.group_names)
            ) AS detail
        FROM aggregated a
    """,
}
