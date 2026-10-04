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

[v1.2] GenericAll/GenericWrite are now recognised in the form AD stores
them. ACE masks are stored already mapped: GenericAll as 0xF01FF and
GenericWrite as 0x20028 (WRITE_PROP with no object type, i.e. write
every property), so the raw GENERIC_ALL (0x10000000) / GENERIC_WRITE
(0x40000000) bits tested before essentially never matched; GenericWrite-
only OU delegation was missed entirely (raw bits are still matched too).
Inherit-only ACEs are deliberately still counted: rights an OU's ACL
grants over its descendant objects are exactly how the privileged user
in it is reachable.

[v1.3] Reworked OU association and ACE applicability:
- Every ancestor OU is checked (DN-suffix match), not just the parent
  found by splitting the DN at its first comma -- which also broke on
  escaped commas ("CN=Smith\\, John,...") so such accounts never matched.
- An inherit-only ACE counts only when it is inherited by user objects
  (inherited_object_type_guid NULL or the user class). "Descendant
  Computer/Group objects" delegations no longer count. Rights on the OU
  itself (GenericAll/GenericWrite/WriteDacl/WriteOwner) still count:
  they let the holder add an inheritable ACE or link a GPO (gPLink).
  The password-reset extended right and All Extended Rights inherited by
  users (the typical help-desk delegation) now count as well.
- Well-known trustees without a directory object (Everyone,
  Authenticated Users, Anonymous Logon) are kept instead of dropped by
  the SID join; expected holders are excluded by SID.
- "Privileged" is v_privileged_principal (adminCount=1 alone is sticky
  and stale). SDProp disables ACL inheritance on adminCount=1 accounts,
  so OU rights only reach them if inheritance is re-enabled: 'medium';
  a privileged account without adminCount=1 inherits them: 'high'.
  Disabled accounts one step lower. Limitation: the ACE's
  CONTAINER_INHERIT flag and the user's own inheritance setting are not
  collected.
- One row per user: summary lists every matching OU and trustee, sorted.
"""

PLUGIN = {
    "plugin_id": 1037,
    "category": "User Accounts",
    "name": "Privileged User Account Resides in a Delegated Organizational Unit",
    "version": "1.3",
    "revision_date": "2026-10-04",
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
        "principal. A privileged account sitting below a delegated OU "
        "(at any level) is reachable by anyone with GenericAll/"
        "GenericWrite/WriteDacl/WriteOwner on that OU, or with the "
        "password-reset right inherited by user objects -- a password "
        "reset or attribute change requires no rights on the account "
        "itself when the containing OU already grants them. Accounts "
        "protected by AdminSDHolder (adminCount=1) have ACL inheritance "
        "turned off by SDProp, so for them the exposure applies only if "
        "inheritance is re-enabled (rated medium); privileged accounts "
        "without that protection are rated high. Most "
        "commonly the result of organizational convenience (a "
        "privileged account simply never moved out of the OU it was "
        "originally created in) rather than deliberate placement."
    ),
    "base_severity": "high",
    "query": """
        WITH ou_rights AS (
            -- [v1.3] Rights on an OU that reach the user objects below it.
            SELECT a.object_guid AS ou_guid, a.trustee_sid
            FROM acl_edge a
            JOIN ad_ou o
                ON o.object_guid = a.object_guid AND o.client_id = a.client_id AND o.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (
                    -- Control of the OU itself (GenericAll, GenericWrite,
                    -- WriteDacl, WriteOwner): the holder can add an
                    -- inheritable ACE (or link a GPO via gPLink) and so reach
                    -- every descendant that inherits. An inherit-only ACE
                    -- grants nothing on the OU and counts only when it
                    -- flows to user objects (all classes, or the user class).
                    (
                      (   (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                       OR (a.access_mask & 983551) = 983551                    -- GenericAll, as stored
                       OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)  -- GenericWrite, as stored
                      )
                      AND (a.inherit_only IS NOT TRUE
                           OR a.inherited_object_type_guid IS NULL
                           OR a.inherited_object_type_guid = 'bf967aba-0de6-11d0-a285-00aa003049e2')
                    )
                    -- Password reset (User-Force-Change-Password) or All
                    -- Extended Rights inherited by user objects -- the usual
                    -- help-desk delegation. Only meaningful on descendants.
                 OR (
                      (a.access_mask & 256) <> 0
                      AND (a.object_type_guid IS NULL
                           OR a.object_type_guid = '00299570-246d-11d0-a768-00aa006e0529')
                      AND (a.inherited_object_type_guid IS NULL
                           OR a.inherited_object_type_guid = 'bf967aba-0de6-11d0-a285-00aa003049e2')
                    )
                  )
              -- Expected holders, by SID: SYSTEM, Administrators, Domain
              -- Admins, Enterprise Admins; plus Principal Self and Creator
              -- Owner, which name no attacker-controlled principal.
              AND a.trustee_sid NOT IN ('S-1-5-18', 'S-1-5-32-544', 'S-1-5-10', 'S-1-3-0')
              AND a.trustee_sid !~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(512|519)$'
        ),
        ou_holders AS (
            SELECT DISTINCT r.ou_guid, lower(ou_do.dn_current) AS ou_dn_lc,
                   COALESCE(o.ou_name, ou_do.dn_current) AS ou_name,
                   -- [v1.3] Unresolved well-known trustees (Everyone,
                   -- Authenticated Users, ...) are kept, not dropped.
                   COALESCE(tdo.sam_account_name, wk.name, r.trustee_sid) AS trustee_name
            FROM ou_rights r
            JOIN ad_ou o
                ON o.object_guid = r.ou_guid AND o.client_id = %(client_id)s AND o.valid_to IS NULL
            JOIN directory_object ou_do
                ON ou_do.object_guid = r.ou_guid AND ou_do.client_id = %(client_id)s
               AND NOT ou_do.is_deleted
            LEFT JOIN LATERAL (
                SELECT d.sam_account_name
                FROM directory_object d
                WHERE d.client_id = %(client_id)s AND d.object_sid = r.trustee_sid
                ORDER BY d.is_deleted, d.object_guid
                LIMIT 1
            ) tdo ON TRUE
            LEFT JOIN (VALUES
                ('S-1-1-0', 'Everyone'),
                ('S-1-5-7', 'Anonymous Logon'),
                ('S-1-5-11', 'Authenticated Users')
            ) AS wk(sid, name) ON wk.sid = r.trustee_sid
        ),
        privileged AS (
            SELECT object_guid
            FROM v_privileged_principal
            WHERE client_id = %(client_id)s
            GROUP BY object_guid
        ),
        user_ou AS (
            -- [v1.3] Every ancestor OU, matched as a DN suffix. The old
            -- split at the first comma broke on escaped commas
            -- (CN=Smith\\, John,...) and only ever looked at the parent OU.
            SELECT u.object_guid, u.sam_account_name, u.user_principal_name, u.is_enabled,
                   u.admin_count, oh.ou_name, oh.ou_dn_lc, oh.trustee_name
            FROM ad_user u
            JOIN privileged p ON p.object_guid = u.object_guid
            JOIN directory_object udo
                ON udo.object_guid = u.object_guid AND udo.client_id = u.client_id
               AND NOT udo.is_deleted
            JOIN ou_holders oh
                ON right(lower(udo.dn_current), length(oh.ou_dn_lc) + 1) = ',' || oh.ou_dn_lc
            WHERE u.valid_to IS NULL
              AND u.client_id = %(client_id)s
        )
        SELECT
            'fail' AS status,
            uo.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            -- [v1.3] adminCount=1 means SDProp has turned ACL inheritance
            -- off on the account, so OU rights reach it only if inheritance
            -- is re-enabled or protection lapses: 'medium'. A privileged
            -- account without it inherits the OU's ACEs: 'high'. Disabled
            -- accounts one step lower.
            CASE WHEN uo.admin_count IS DISTINCT FROM 1 AND uo.is_enabled IS NOT FALSE THEN 'high'
                 WHEN uo.admin_count IS DISTINCT FROM 1 OR uo.is_enabled IS NOT FALSE THEN 'medium'
                 ELSE 'low' END AS fd_severity,
            'Privileged User Account ' || COALESCE(uo.sam_account_name, uo.user_principal_name, uo.object_guid::text)
                || CASE WHEN count(DISTINCT uo.ou_dn_lc) = 1 THEN ' resides in OU ' ELSE ' resides under OUs ' END
                || string_agg(DISTINCT '"' || uo.ou_name || '"', ', ' ORDER BY '"' || uo.ou_name || '"')
                || ', where '
                || string_agg(DISTINCT uo.trustee_name, ', ' ORDER BY uo.trustee_name)
                || ' hold(s) dangerous rights (see plugin 9001)' AS summary,
            jsonb_build_object(
                'sam_account_name', uo.sam_account_name,
                'admin_count', uo.admin_count,
                'is_enabled', uo.is_enabled,
                'ou_names', jsonb_agg(DISTINCT uo.ou_name ORDER BY uo.ou_name),
                'trustees_with_ou_rights', jsonb_agg(DISTINCT uo.trustee_name ORDER BY uo.trustee_name)
            ) AS detail
        FROM user_ou uo
        GROUP BY uo.object_guid, uo.sam_account_name, uo.user_principal_name, uo.is_enabled, uo.admin_count
    """,
}
