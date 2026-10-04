"""
Plugin 1026: Kerberoastable User Account Holds DCSync Rights

The canonical BloodHound-style attack-path insight, made possible for
the first time by this project's ACL collection work: a Kerberoastable
account (crackable offline, no privileged access needed to attempt) that
is ALSO, independently, a direct DCSync-rights holder is a complete,
low-effort path to full domain compromise -- crack the Kerberoast hash
(plugin 1009 already flags the account as roastable), authenticate as
that account, and DCSync every credential in the domain (plugin 5001
already flags the account as an unexpected DCSync holder). This plugin
exists specifically to call out the CHAIN, not just the two
individually-true facts -- a report reader scanning 1009 and 5001
separately could easily miss that they're the same account.

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
    "plugin_id": 1026,
    "category": "User Accounts",
    "name": "Kerberoastable User Account Holds DCSync Rights",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Treat as an active, complete attack path, not a theoretical "
        "risk: anyone who can request a service ticket for this "
        "account (any authenticated domain user, by default) can crack "
        "it offline and, if successful, has DCSync rights with no "
        "further steps. Prioritize over an ordinary Kerberoastable or "
        "DCSync finding alone. Remediate both ends: remove the SPN if "
        "it isn't genuinely needed, enable AES-only Kerberos encryption "
        "(see plugin 1024) if it is, use a long/randomly-generated "
        "password if this is a service account, and separately review "
        "why this account holds DCSync rights at all (see plugin "
        "5001's remediation)."
    ),
    "control_id": "CHAIN-101",
    "framework_tags": ["MITRE-ATTCK-T1558.003", "MITRE-ATTCK-T1003.006",
                       "CISA-AA26-237A"],
    "references": [
        {"title": "MITRE ATT&CK T1558.003: Steal or Forge Kerberos Tickets -- Kerberoasting",
         "url": "https://attack.mitre.org/techniques/T1558/003/"},
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping -- DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
    ],
    "description": (
        "Chains two independently-true findings into a single complete "
        "attack path: this account is Kerberoastable (plugin 1009 --any "
        "authenticated user can request a crackable service ticket for "
        "it) AND holds DCSync replication rights on the domain root "
        "(plugin 5001), either as an explicit ACE naming this account "
        "or through a group that does not hold them by default. An "
        "attacker who "
        "cracks the Kerberoast hash gets DCSync with no further "
        "privilege escalation required. This is the kind of "
        "multi-primitive path BloodHound-style analysis is specifically "
        "built to surface -- scanning 1009 and 5001 as separate lists "
        "makes it easy to miss that they describe the same account."
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
                || ' is Kerberoastable (has an SPN) AND '
                || CASE WHEN dh.is_direct THEN 'directly holds DCSync replication rights on the domain root'
                        ELSE 'holds DCSync replication rights on the domain root through group(s) '
                             || dh.via_groups END AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'service_principal_names', u.service_principal_names,
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
          AND u.service_principal_names IS NOT NULL
          AND array_length(u.service_principal_names, 1) > 0
    """,
}
