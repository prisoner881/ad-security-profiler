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
"""

PLUGIN = {
    "plugin_id": 3025,
    "category": "Groups",
    "name": "Group Policy Creator Owners or Incoming Forest Trust Builders Has Members",
    "version": "1.0",
    "revision_date": "2026-08-12",
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
    "framework_tags": ["DISA-STIG"],
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
        SELECT
            'warn' AS status,
            mdo.object_guid,
            'CAT_II' AS stig_severity,
            'DISA Active Directory Domain STIG V-243487' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Account ' || COALESCE(mdo.sam_account_name, mdo.object_guid::text)
                || ' is a member of "' || gdo.sam_account_name || '"' AS summary,
            jsonb_build_object(
                'sam_account_name', mdo.sam_account_name,
                'object_class', mdo.object_class,
                'privileged_group', gdo.sam_account_name
            ) AS detail
        FROM v_effective_group_membership vem
        JOIN directory_object gdo ON gdo.object_guid = vem.group_guid AND gdo.client_id = vem.client_id
        JOIN directory_object mdo ON mdo.object_guid = vem.member_guid AND mdo.client_id = vem.client_id
        WHERE vem.client_id = %(client_id)s
          AND (gdo.object_sid LIKE '%%-520' OR gdo.object_sid LIKE '%%-557')
    """,
}
