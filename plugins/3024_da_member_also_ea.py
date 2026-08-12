"""
Plugin 3024: Domain Admins Member Also Holds Enterprise Admins Membership

Directly cited against DISA Active Directory Domain STIG V-243467 (CAT I /
High): "If any account listed in the Domain Admins group is a member of
other administrator groups including the Enterprise Admins group,
[...], this is a finding." Confirmed against the current STIG text
(V3R7) directly.

Structurally the mirror of plugin 3023 -- kept as a distinct plugin
rather than merged with it because the STIG itself treats these as two
separate, independently-numbered findings (V-243466 vs V-243467), and
because the two checks aren't quite symmetric in practice: a domain
with a single-domain forest may have deliberately identical EA/DA
membership as a matter of course, while the STIG's actual concern --
recorded here for reference, not re-litigated -- is about tier
separation regardless of forest topology. Same scoping limitation as
3023: only the objectively LDAP-verifiable cross-membership with
Enterprise Admins is checked here, not the site-specific "domain
member server administrators" / "domain workstation administrators"
custom groups the STIG's check text also names but that have no fixed
identity in AD to check against.
"""

PLUGIN = {
    "plugin_id": 3024,
    "category": "Groups",
    "name": "Domain Admins Member Also Holds Enterprise Admins Membership",
    "version": "1.0",
    "revision_date": "2026-08-12",
    "remediation": (
        "Remove this account from either Domain Admins or Enterprise "
        "Admins so that no single account holds both simultaneously. "
        "Each administrator should have a separate, dedicated account "
        "for each distinct level of authority."
    ),
    "control_id": "STIG-V-243467",
    "framework_tags": ["DISA-STIG"],
    "references": [
        {"title": "DISA Active Directory Domain STIG V3R7: V-243467",
         "url": "https://cyber.trackr.live/stig/Active_Directory_Domain/3/7#V-243467"},
    ],
    "description": (
        "DISA Active Directory Domain STIG V-243467 (CAT I): membership "
        "in Domain Admins must be restricted to accounts used "
        "exclusively to manage this domain and its domain controllers. "
        "An account that is a member of both Domain Admins and "
        "Enterprise Admins collapses the separation those two tiers "
        "are meant to enforce."
    ),
    "base_severity": "critical",
    "query": """
        WITH ea_members AS (
            SELECT DISTINCT vem.member_guid
            FROM v_effective_group_membership vem
            JOIN directory_object gdo ON gdo.object_guid = vem.group_guid AND gdo.client_id = vem.client_id
            WHERE vem.client_id = %(client_id)s AND gdo.object_sid LIKE '%%-519'
        ),
        da_members AS (
            SELECT DISTINCT vem.member_guid
            FROM v_effective_group_membership vem
            JOIN directory_object gdo ON gdo.object_guid = vem.group_guid AND gdo.client_id = vem.client_id
            WHERE vem.client_id = %(client_id)s AND gdo.object_sid LIKE '%%-512'
        )
        SELECT
            'fail' AS status,
            m.member_guid AS object_guid,
            'CAT_I' AS stig_severity,
            'DISA Active Directory Domain STIG V-243467' AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Account ' || COALESCE(mdo.sam_account_name, mdo.object_guid::text)
                || ' is a member of both Domain Admins and Enterprise Admins' AS summary,
            jsonb_build_object(
                'sam_account_name', mdo.sam_account_name,
                'object_class', mdo.object_class
            ) AS detail
        FROM da_members m
        JOIN ea_members e ON e.member_guid = m.member_guid
        JOIN directory_object mdo ON mdo.object_guid = m.member_guid AND mdo.client_id = %(client_id)s
    """,
}
