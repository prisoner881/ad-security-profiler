"""
Plugin 1037: Privileged User Account Resides in a Delegated Organizational Unit

A genuinely new category of finding, only possible once OU data and
OU-level ACL scanning both existed (plugins 9001's underlying
collection). Every ACL-based finding in this project up to now checks
rights held DIRECTLY on an object -- but an object's effective control
surface isn't just its own ACL. Anyone with GenericAll/GenericWrite/
WriteDacl/WriteOwner on the OU CONTAINING an object can reset that
object's password, modify its attributes, or otherwise compromise it,
even with zero rights explicitly granted on the object itself.

This chains two independently-collected facts that were previously
invisible together: which OU an object's DN places it in (parsed from
directory_object.dn_current -- no new collection needed, this
information has always been sitting in the DN), and plugin 9001's
dangerous-rights-on-an-OU detection. A Domain Admin whose account
happens to sit in a general-purpose OU delegated to a help desk team
is protected on paper by admin_count=1's ACL template, but is
genuinely reachable through the OU the moment SDProp's protection
lapses or is bypassed -- and more directly, anyone who can reset the
account's password via OU delegation doesn't need to touch the
account's own ACL at all to compromise it.
"""

PLUGIN = {
    "plugin_id": 1037,
    "category": "User Accounts",
    "name": "Privileged User Account Resides in a Delegated Organizational Unit",
    "version": "1.1",
    "revision_date": "2026-08-04",
    "remediation": (
        "Move this account to a dedicated, tightly-controlled OU "
        "reserved for privileged accounts (a common Tier-0 hardening "
        "pattern), where delegation is limited to a small, trusted set "
        "of principals -- not the same OU structure used for everyday "
        "user accounts. If moving the account isn't immediately "
        "practical, review plugin 9001's finding for this specific OU "
        "and determine whether the delegated principal's rights should "
        "be scoped down or removed. Either fix addresses the same "
        "underlying exposure: standing rights over an OU are standing "
        "rights over everyone currently placed inside it, including "
        "privileged accounts that landed there for organizational "
        "convenience rather than deliberate placement."
    ),
    "control_id": "CHAIN-107",
    "framework_tags": [],
    "references": [
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
    ],
    "description": (
        "Chains two facts previously invisible together: which OU an "
        "object's DN places it in, and plugin 9001's detection of "
        "dangerous ACL rights on that OU held by an unexpected "
        "principal. A privileged account (admin_count=1) sitting in a "
        "delegated OU is reachable by anyone with GenericAll/"
        "GenericWrite/WriteDacl/WriteOwner on that OU -- a password "
        "reset or attribute change requires no rights on the account "
        "itself when the containing OU already grants them. Most "
        "commonly the result of organizational convenience (a "
        "privileged account simply never moved out of the OU it was "
        "originally created in) rather than deliberate placement."
    ),
    "base_severity": "high",
    "query": """
        WITH expected_holders AS (
            SELECT do2.object_guid
            FROM directory_object do2
            WHERE do2.client_id = %(client_id)s
              AND (do2.object_sid LIKE '%%-512' OR do2.object_sid LIKE '%%-519'
                   OR do2.object_sid LIKE '%%-544')
            UNION
            SELECT fsp.object_guid
            FROM ad_foreign_security_principal fsp
            WHERE fsp.client_id = %(client_id)s AND fsp.valid_to IS NULL
              AND fsp.well_known_name = 'Local System'
        ),
        ou_dangerous_holders AS (
            SELECT DISTINCT a.object_guid AS ou_guid, o.ou_name,
                   ou_do.dn_current AS ou_dn,
                   trustee_do.sam_account_name AS trustee_name
            FROM acl_edge a
            JOIN ad_ou o ON o.object_guid = a.object_guid AND o.valid_to IS NULL
            JOIN directory_object ou_do ON ou_do.object_guid = a.object_guid AND ou_do.client_id = %(client_id)s
            JOIN directory_object trustee_do
                ON trustee_do.object_sid = a.trustee_sid AND trustee_do.client_id = %(client_id)s
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
              AND NOT EXISTS (SELECT 1 FROM expected_holders eh WHERE eh.object_guid = trustee_do.object_guid)
        ),
        -- [fix, caught via a real production crash at large scale (525
        -- OUs) that this project's own small test lab never exposed]
        -- ou_dangerous_holders has one row per (OU, trustee) pair --
        -- fine for plugin 9001 (now itself fixed to aggregate before
        -- reporting), but here it was joined directly against users,
        -- so a privileged user sitting in an OU with 2+ unexpected
        -- trustees produced 2+ rows sharing that user's object_guid.
        -- Aggregated to one row per OU here too, before the join.
        ou_holders_agg AS (
            SELECT ou_dn, ou_name,
                   array_agg(DISTINCT trustee_name ORDER BY trustee_name) AS trustee_names
            FROM ou_dangerous_holders
            GROUP BY ou_dn, ou_name
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Privileged User Account ' || COALESCE(udo.sam_account_name, u.user_principal_name)
                || ' resides in OU "' || odh.ou_name || '", where '
                || array_to_string(odh.trustee_names, ', ')
                || ' hold(s) dangerous rights (see plugin 9001)' AS summary,
            jsonb_build_object(
                'sam_account_name', udo.sam_account_name,
                'ou_name', odh.ou_name,
                'trustees_with_ou_rights', odh.trustee_names
            ) AS detail
        FROM ad_user u
        JOIN directory_object udo ON udo.object_guid = u.object_guid AND udo.client_id = %(client_id)s
        JOIN ou_holders_agg odh
            ON odh.ou_dn = substring(udo.dn_current FROM position(',' IN udo.dn_current) + 1)
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.admin_count = 1
    """,
}
