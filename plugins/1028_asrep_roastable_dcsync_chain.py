"""
Plugin 1028: AS-REP Roastable User Account Holds DCSync Rights

Same chain as plugin 1026, using AS-REP roasting instead of Kerberoasting
as the initial-access primitive. Arguably more severe: AS-REP roasting
requires no valid credentials or prior authentication at all (any
network access to a DC is sufficient to request the crackable
AS-REP), whereas Kerberoasting at least requires a valid, authenticated
domain account first. Kept as a distinct finding from 1026 for that
reason -- the attack complexity is meaningfully lower here.

[v1.4] DCSync now means what v_privileged_principal means by it: allow
ACEs on the domain root, not inherit-only, with CONTROL_ACCESS, granting
BOTH Get-Changes and Get-Changes-All, or All Extended Rights (which
GenericAll includes). v1.3 accepted either replication right alone, so a
Get-Changes-only holder (DirSync-style sync accounts) was reported as
DCSync-capable, while All Extended Rights / GenericAll holders were
missed. Also follows DCSync held through a group (nested), except via
the groups that hold it by default (Domain Controllers, Enterprise
Domain Controllers, Administrators, Domain Admins, Enterprise Admins);
such findings say "through group(s) <names>" instead of "directly".
"""

PLUGIN = {
    "plugin_id": 1028,
    "category": "User Accounts",
    "name": "AS-REP Roastable User Account Holds DCSync Rights",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Treat as an active, complete attack path requiring NO prior "
        "authentication: anyone with network access to a domain "
        "controller can request and crack this account's AS-REP "
        "offline, then use the recovered password for DCSync directly. "
        "Prioritize above plugin 1026 -- this requires even less "
        "attacker capability. Remove the DONT_REQ_PREAUTH flag "
        "immediately (see plugin 1013's remediation) and separately "
        "review why this account holds DCSync rights at all."
    ),
    "control_id": "CHAIN-103",
    "framework_tags": ["MITRE-ATTCK-T1558.004", "MITRE-ATTCK-T1003.006",
                       "CISA-AA26-237A"],
    "references": [
        {"title": "MITRE ATT&CK T1558.004: Steal or Forge Kerberos Tickets -- AS-REP Roasting",
         "url": "https://attack.mitre.org/techniques/T1558/004/"},
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping -- DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
    ],
    "description": (
        "Chains two independently-true findings: this account is "
        "AS-REP roastable (plugin 1013 -- Kerberos pre-authentication "
        "disabled) AND holds DCSync replication rights on the domain "
        "root (plugin 5001), directly or through a group that does not "
        "hold them by default. Unlike Kerberoasting, AS-REP "
        "roasting requires no valid domain credentials at all -- any "
        "network path to a domain controller is sufficient to request "
        "the crackable response. Combined with direct DCSync rights, "
        "this is one of the lowest-effort complete paths to full domain "
        "compromise this project can detect."
    ),
    "base_severity": "critical",
    "query": """
        WITH dcsync_trustee AS (
            -- [v1.4] Same DCSync test as v_privileged_principal's dcsync
            -- CTE: allow ACEs on the domain root that are not inherit-only
            -- and carry CONTROL_ACCESS (0x100), with BOTH Get-Changes and
            -- Get-Changes-All, or All Extended Rights (null object type --
            -- GenericAll 0xF01FF includes it). Either replication right on
            -- its own is not DCSync.
            SELECT a.trustee_sid,
                   COALESCE(bool_or(a.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'), false) AS has_get_changes,
                   COALESCE(bool_or(a.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'), false) AS has_get_changes_all,
                   bool_or(a.object_type_guid IS NULL) AS has_all_extended_rights
            FROM acl_edge a
            JOIN ad_domain d
                ON d.object_guid = a.object_guid AND d.client_id = a.client_id AND d.valid_to IS NULL
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE
              AND (a.access_mask & 256) <> 0
              AND (a.object_type_guid IS NULL
                   OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                             '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'))
            GROUP BY a.trustee_sid
            HAVING bool_or(a.object_type_guid IS NULL)
                OR (bool_or(a.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')
                    AND bool_or(a.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'))
        ),
        dcsync_principal AS (
            SELECT p.object_guid, p.sam_account_name, p.object_sid, t.has_get_changes,
                   t.has_get_changes_all, t.has_all_extended_rights
            FROM dcsync_trustee t
            JOIN directory_object p
                ON p.object_sid = t.trustee_sid AND p.client_id = %(client_id)s AND NOT p.is_deleted
        ),
        dcsync_holders AS (
            -- [v1.4] Direct trustee, or effective (nested) member of a group
            -- that holds DCSync. Groups that hold it by default (Domain
            -- Controllers 516, Enterprise Domain Controllers S-1-5-9,
            -- Administrators S-1-5-32-544, Domain Admins 512, Enterprise
            -- Admins 519) are not followed: their members are privileged
            -- by design and reported by the privileged-account plugins.
            SELECT h.object_guid,
                   bool_or(h.via_group IS NULL) AS is_direct,
                   bool_or(h.has_get_changes) AS has_get_changes,
                   bool_or(h.has_get_changes_all) AS has_get_changes_all,
                   bool_or(h.has_all_extended_rights) AS has_all_extended_rights,
                   string_agg(DISTINCT h.via_group, ', ' ORDER BY h.via_group) AS via_groups
            FROM (
                SELECT dp.object_guid, NULL::text AS via_group, dp.has_get_changes,
                       dp.has_get_changes_all, dp.has_all_extended_rights
                FROM dcsync_principal dp
                UNION ALL
                SELECT vem.member_guid, COALESCE(dp.sam_account_name, dp.object_sid),
                       dp.has_get_changes, dp.has_get_changes_all, dp.has_all_extended_rights
                FROM dcsync_principal dp
                JOIN v_effective_group_membership vem
                    ON vem.group_guid = dp.object_guid AND vem.client_id = %(client_id)s
                WHERE dp.object_sid NOT IN ('S-1-5-9', 'S-1-5-32-544')
                  AND dp.object_sid !~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-(512|516|519)$'
            ) h
            GROUP BY h.object_guid
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' is AS-REP roastable (no Kerberos pre-authentication required) AND '
                || CASE WHEN dh.is_direct THEN 'directly holds DCSync replication rights on the domain root'
                        ELSE 'holds DCSync replication rights on the domain root through group(s) '
                             || dh.via_groups END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'has_get_changes', dh.has_get_changes,
                'has_get_changes_all', dh.has_get_changes_all,
                'has_all_extended_rights', dh.has_all_extended_rights,
                'is_direct', dh.is_direct,
                'via_groups', dh.via_groups
            ) AS detail
        FROM ad_user u
        JOIN dcsync_holders dh ON dh.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND (u.user_account_control & 4194304) != 0
    """,
}
