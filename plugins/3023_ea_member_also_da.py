"""
Plugin 3023: Enterprise Admins Member Also Holds Domain Admins Membership

Directly cited against DISA Active Directory Domain STIG V-243466 (CAT I /
High): "If any account listed in the Enterprise Admins group is a member
of other administrator groups including the Domain Admins group,
[...], this is a finding." Confirmed against the current STIG text
(V3R7) directly, not paraphrased from memory.

Deliberately scoped to the one part of V-243466's check that's
objectively LDAP-verifiable: cross-membership with Domain Admins
specifically. The STIG's check also names "domain member server
administrators groups" and "domain workstation administrators groups"
-- but these are site-defined, arbitrarily-named custom groups with no
fixed RID or naming convention, so nothing in AD identifies which
group(s), if any, serve that role at a given organization. Checking
those would require the client to tell us their names first; silently
guessing at group names would produce unreliable results, so that part
of the STIG's intent is left to the client to verify manually rather
than approximated here.

[v1.1] The summary labels the member by object class (User / Group /
Computer / Foreign principal) and falls back to its SID rather than its
GUID (foreign security principals have no sAMAccountName). Coverage
note: Enterprise Admins exists only in the forest root domain, so this
check can only fire on a forest-root collection; child-domain admins
placed in the root's Enterprise Admins are visible only there. Plugin
3024 reports the same intersection under STIG V-243467.
"""

PLUGIN = {
    "plugin_id": 3023,
    "category": "Groups",
    "name": "Enterprise Admins Member Also Holds Domain Admins Membership",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Remove this account from either Enterprise Admins or Domain "
        "Admins so that no single account holds both simultaneously. "
        "Each administrator should have a separate, dedicated account "
        "for each distinct level of authority -- an account managing "
        "the Active Directory forest (Enterprise Admins) should not "
        "also be the same account managing an individual domain "
        "(Domain Admins), since that collapses the separation of "
        "responsibilities the two tiers exist to enforce."
    ),
    "control_id": "STIG-V-243466",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "DISA Active Directory Domain STIG V3R7: V-243466",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243466"},
    ],
    "description": (
        "DISA Active Directory Domain STIG V-243466 (CAT I): membership "
        "in Enterprise Admins must be restricted to accounts used "
        "exclusively to manage the AD forest. An account that is a "
        "member of both Enterprise Admins and Domain Admins collapses "
        "the separation those two tiers are meant to enforce -- a "
        "single compromised credential now carries both forest-wide "
        "and domain-wide privilege at once. Enterprise Admins exists only in the forest root domain, "
        "so this can only fire on a forest-root collection."
    ),
    "base_severity": "critical",
    "query": """
        WITH ea_members AS (
            SELECT DISTINCT vem.member_guid
            FROM v_effective_group_membership vem
            JOIN directory_object gdo ON gdo.object_guid = vem.group_guid AND gdo.client_id = vem.client_id
            WHERE vem.client_id = %(client_id)s AND gdo.object_sid LIKE 'S-1-5-21-%%-519'
        ),
        da_members AS (
            SELECT DISTINCT vem.member_guid
            FROM v_effective_group_membership vem
            JOIN directory_object gdo ON gdo.object_guid = vem.group_guid AND gdo.client_id = vem.client_id
            WHERE vem.client_id = %(client_id)s AND gdo.object_sid LIKE 'S-1-5-21-%%-512'
        )
        SELECT
            'fail' AS status,
            m.member_guid AS object_guid,
            'CAT_I' AS stig_severity,
            'DISA Active Directory Domain STIG V-243466' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            (CASE mdo.object_class::text
                  WHEN 'group' THEN 'Group '
                  WHEN 'computer' THEN 'Computer '
                  WHEN 'foreign_security_principal' THEN 'Foreign principal '
                  ELSE 'Account ' END)
                || COALESCE(mdo.sam_account_name, mdo.object_sid, mdo.object_guid::text)
                || ' is a member of both Enterprise Admins and Domain Admins' AS summary,
            jsonb_build_object(
                'sam_account_name', mdo.sam_account_name,
                'object_sid', mdo.object_sid,
                'object_class', mdo.object_class
            ) AS detail
        FROM ea_members m
        JOIN da_members d ON d.member_guid = m.member_guid
        JOIN directory_object mdo ON mdo.object_guid = m.member_guid AND mdo.client_id = %(client_id)s
    """,
}
