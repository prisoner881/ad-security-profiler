"""
Plugin 1042: Disabled Account Still Holding Privilege

Derived from CISA advisory AA26-237A (2026-08-25), the joint red team
assessment retrospective covering a Government Services and Facilities
organization and a Water and Wastewater Systems organization. In that
assessment the team's final pivot into the cloud tenant used an
AD-synced account that was *disabled* in Active Directory: they simply
re-enabled it, DCSynced its hash, and authenticated as it.

The premise this plugin encodes is that disabling an account is not a
security control. A disabled account retains its group memberships,
its admin_count marker, its SPNs, its SID history, and its position in
every ACL that references it. Anyone who can flip userAccountControl --
a right delegated far more freely than "membership in Domain Admins,"
because it reads as a helpdesk function -- converts all of that back
into live privilege in one write. Disabled privileged accounts also
tend to escape the review processes that cover enabled ones, precisely
because they look inert on an access report.

Deliberately excludes the accounts that are disabled *by design* and
would otherwise fire on every domain in existence: krbtgt (RID 502),
the per-RODC krbtgt_<n> accounts, the built-in Guest (RID 501), and
DefaultAccount (RID 503). All four are disabled-and-privileged as
shipped, and flagging them would train the reader to ignore this
finding.

Scope note: this identifies accounts that are privileged *today* by
membership or admin_count. It does not attempt to determine who can
re-enable them -- that requires per-object ACL collection, which this
project currently performs only for the domain root and AdminSDHolder
(see acl_edge's own scope documentation).
"""

PLUGIN = {
    "plugin_id": 1042,
    "category": "User Accounts",
    "name": "Disabled Account Still Holding Privilege",
    "version": "1.0",
    "revision_date": "2026-09-02",
    "remediation": (
        "Treat a disabled privileged account as an account that still "
        "needs decommissioning, not one that has been decommissioned. "
        "For each finding, decide which of two states it should be in: "
        "if the account is genuinely retired, strip its privileged "
        "group memberships and SPNs first, then delete it (or move it "
        "to a staging OU with a documented deletion date) -- deleting "
        "an account still carrying Domain Admin membership leaves "
        "orphaned ACEs behind, so order matters. If the account is "
        "dormant but expected to return (extended leave, seasonal "
        "role, break-glass), remove the privileged membership now and "
        "re-grant it at reactivation; standing privilege on an account "
        "nobody is watching is the exact condition an attacker wants. "
        "Separately, audit who can write userAccountControl on these "
        "objects: the ability to re-enable an account is functionally "
        "the ability to assume whatever privilege it holds, and it is "
        "commonly delegated to helpdesk tiers that were never intended "
        "to have a path to Domain Admin. Where accounts must remain "
        "disabled and privileged, add them to a monitored watchlist "
        "and alert on any change to their enabled state (see plugin "
        "11002, which detects that transition between collection runs)."
    ),
    "control_id": "LIFECYCLE-142",
    "framework_tags": ["CISA-AA26-237A", "MITRE-ATTCK-T1078.002", "MITRE-ATTCK-T1098"],
    "references": [
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Identifies accounts that are disabled in Active Directory but "
        "still hold privilege -- either an effective membership "
        "(including nested) in a well-known privileged group, or the "
        "AdminSDHolder admin_count marker. Disabling an account "
        "suspends authentication; it does not remove group membership, "
        "SPNs, SID history, or any ACE granting the account rights "
        "elsewhere in the directory. A single write to "
        "userAccountControl restores all of it. CISA's AA26-237A red "
        "team assessment used exactly this path, re-enabling a "
        "disabled AD-synced account to pivot into the organization's "
        "cloud tenant. Accounts that are disabled by design (krbtgt "
        "and its per-RODC variants, Guest, DefaultAccount) are "
        "excluded."
    ),
    "base_severity": "high",
    "query": """
        WITH privileged_roots AS (
            SELECT g.object_guid, g.sam_account_name
            FROM ad_group g
            JOIN directory_object gdo
                ON gdo.object_guid = g.object_guid AND gdo.client_id = g.client_id
            WHERE g.valid_to IS NULL
              AND g.client_id = %(client_id)s
              -- 512 Domain Admins, 516 Domain Controllers, 517 Cert Publishers,
              -- 518 Schema Admins, 519 Enterprise Admins, 520 Group Policy
              -- Creator Owners, 521 Read-only Domain Controllers, 526 Key
              -- Admins, 527 Enterprise Key Admins, 544 Administrators,
              -- 548 Account Operators, 549 Server Operators, 550 Print
              -- Operators, 551 Backup Operators, 552 Replicator.
              AND (gdo.object_sid LIKE '%%-512' OR gdo.object_sid LIKE '%%-516'
                   OR gdo.object_sid LIKE '%%-517' OR gdo.object_sid LIKE '%%-518'
                   OR gdo.object_sid LIKE '%%-519' OR gdo.object_sid LIKE '%%-520'
                   OR gdo.object_sid LIKE '%%-521' OR gdo.object_sid LIKE '%%-526'
                   OR gdo.object_sid LIKE '%%-527' OR gdo.object_sid LIKE '%%-544'
                   OR gdo.object_sid LIKE '%%-548' OR gdo.object_sid LIKE '%%-549'
                   OR gdo.object_sid LIKE '%%-550' OR gdo.object_sid LIKE '%%-551'
                   OR gdo.object_sid LIKE '%%-552')
        ),
        privileged_members AS (
            SELECT vem.member_guid,
                   array_agg(DISTINCT pr.sam_account_name ORDER BY pr.sam_account_name)
                       AS via_groups
            FROM v_effective_group_membership vem
            JOIN privileged_roots pr ON pr.object_guid = vem.group_guid
            WHERE vem.client_id = %(client_id)s
            GROUP BY vem.member_guid
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE
                WHEN pm.via_groups IS NOT NULL THEN 'high'
                ELSE 'medium'
            END AS fd_severity,
            'Disabled account "' || COALESCE(u.sam_account_name, do2.dn_current)
                || '" still holds privilege ('
                || CASE
                       WHEN pm.via_groups IS NOT NULL
                           THEN 'effective member of ' || array_to_string(pm.via_groups, ', ')
                       ELSE 'admin_count marker set'
                   END
                || ') -- re-enabling it restores that privilege in a single write'
                AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'user_principal_name', u.user_principal_name,
                'distinguished_name', do2.dn_current,
                'admin_count', u.admin_count,
                'privileged_via_groups', pm.via_groups,
                'has_service_principal_names',
                    COALESCE(array_length(u.service_principal_names, 1), 0) > 0,
                'service_principal_names', u.service_principal_names,
                'has_sid_history', COALESCE(array_length(u.sid_history, 1), 0) > 0,
                'sid_history', u.sid_history,
                'pwd_last_set', u.pwd_last_set,
                'password_age_days',
                    CASE WHEN u.pwd_last_set IS NULL THEN NULL
                         ELSE EXTRACT(DAY FROM now() - u.pwd_last_set)::int END,
                'last_logon_timestamp', u.last_logon_timestamp,
                'when_created', u.when_created
            ) AS detail
        FROM ad_user u
        JOIN directory_object do2
            ON do2.object_guid = u.object_guid AND do2.client_id = u.client_id
        LEFT JOIN privileged_members pm ON pm.member_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled IS FALSE
          AND (u.admin_count = 1 OR pm.member_guid IS NOT NULL)
          -- Disabled by design in every domain; excluding these keeps the
          -- finding actionable rather than perpetually noisy.
          AND COALESCE(do2.object_sid, '') NOT LIKE '%%-501'
          AND COALESCE(do2.object_sid, '') NOT LIKE '%%-502'
          AND COALESCE(do2.object_sid, '') NOT LIKE '%%-503'
          AND COALESCE(u.sam_account_name, '') NOT LIKE 'krbtgt%%'
    """,
}
