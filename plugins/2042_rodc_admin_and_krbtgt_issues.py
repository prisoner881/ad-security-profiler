"""
Plugin 2042: RODC Delegated Administration and krbtgt Account Issues

Per read-only domain controller (ad_computer.is_read_only_dc), checks:
  - managedBy is not set (low): no delegated RODC administrator. Local
    administration then needs a domain admin to log on to the RODC,
    which is exactly what an RODC deployment is meant to avoid.
  - managedBy resolves (directory_object.dn_current, case-insensitive)
    to a Tier 0 principal (v_privileged_principal or an
    AdminSDHolder-protected group) or to a group whose effective members
    include one (high): the delegated admins log on to the RODC
    interactively, so Tier 0 credentials end up cached/exposed on a
    server that is by design less trusted. Delegated RODC admins should
    be ordinary branch accounts.
  - msDS-KrbTgtLink is NULL or does not resolve to a collected user
    (medium): the RODC's own krbtgt_NNNNN account is missing or the link
    is orphaned, so tickets it issues cannot be managed (rotated,
    revoked) as intended -- PingCastle P-RODCKrbtgtOrphan.
  - The linked krbtgt_NNNNN account's password is older than 180 days
    (medium): RODC-issued TGTs are signed with this key; like the main
    krbtgt it should be rotated regularly and immediately after any
    suspected RODC compromise.

Why it matters: PingCastle's RODC rules and Microsoft's RODC
administration guidance (Admin Role Separation, per-RODC krbtgt).
managedBy values that do not resolve to any collected object are not
rated (detail.managed_by_resolved = false). A NULL pwd_last_set on the
krbtgt account is treated as unknown, not old.

One row per RODC; severity = worst issue; the summary lists the issue
types only (exact ages are in detail).
"""

PLUGIN = {
    "plugin_id": 2042,
    "category": "Computer Accounts",
    "name": "RODC Delegated Administration and krbtgt Account Issues",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "HYGIENE-2042",
    "framework_tags": [
        "MITRE-ATTCK-T1558.001",
        "NIST-800-53-AC-6(5)", "NIST-800-53-AC-6(2)", "NIST-CSF-2.0-PR.AA-05", "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.8.2", "SOC2-CC6.3",
        "NIST-800-53-IA-5", "PCI-DSS-4.0-8.6.3", "CIS-CSC-8-5.5",
        "NIST-800-53-AC-2", "CIS-CSC-8-5.3",
    ],
    "references": [
        {"title": "Microsoft: ms-DS-KrbTgt-Link attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-krbtgtlink"},
        {"title": "PingCastle health check rules",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1558.001: Golden Ticket",
         "url": "https://attack.mitre.org/techniques/T1558/001/"},
    ],
    "description": (
        "Per read-only domain controller, reports: no delegated administrator "
        "(managedBy unset, low); a delegated administrator that is or contains a "
        "Tier 0 principal (high, Tier 0 credentials get cached on the RODC); a "
        "missing or orphaned RODC krbtgt_NNNNN account (msDS-KrbTgtLink, medium); "
        "and an RODC krbtgt password older than 180 days (medium)."
    ),
    "remediation": (
        "Set managedBy to a dedicated, non-privileged branch admin group "
        "(`Set-ADComputer <RODC> -ManagedBy <group>`) and make sure no Tier 0 "
        "account is in it; add that group to the RODC's local administrators via "
        "Admin Role Separation (`dsmgmt \"local roles\" \"add <group> "
        "administrators\"`). If the RODC krbtgt account is missing or the link is "
        "orphaned, demote and re-promote the RODC (or delete the stale RODC "
        "account and its krbtgt_NNNNN). Rotate the RODC krbtgt key regularly, e.g. "
        "with Microsoft's New-KrbtgtKeys.ps1 (which supports RODC krbtgt "
        "accounts), and immediately after any suspected RODC compromise."
    ),
    "base_severity": "high",
    "query": """
        WITH tier0 AS (
            SELECT p.object_guid FROM v_privileged_principal p WHERE p.client_id = %(client_id)s
            UNION
            SELECT g.object_guid FROM ad_group g
             WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL AND g.is_protected_group
        ),
        rodc AS (
            SELECT c.object_guid, c.sam_account_name, c.managed_by, c.krbtgt_link,
                   mb.object_guid AS mb_guid,
                   COALESCE(mb.sam_account_name, mb.object_sid) AS mb_name,
                   ku.object_guid AS krbtgt_guid, ku.sam_account_name AS krbtgt_name,
                   ku.pwd_last_set AS krbtgt_pwd_last_set
            FROM ad_computer c
            JOIN directory_object d
              ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
            LEFT JOIN LATERAL (
                SELECT o.object_guid, o.sam_account_name, o.object_sid
                FROM directory_object o
                WHERE o.client_id = c.client_id AND NOT o.is_deleted
                  AND lower(o.dn_current) = lower(c.managed_by)
                ORDER BY o.object_guid LIMIT 1
            ) mb ON true
            LEFT JOIN LATERAL (
                SELECT u.object_guid, u.sam_account_name, u.pwd_last_set
                FROM directory_object o
                JOIN ad_user u
                  ON u.object_guid = o.object_guid AND u.client_id = o.client_id AND u.valid_to IS NULL
                WHERE o.client_id = c.client_id AND NOT o.is_deleted
                  AND lower(o.dn_current) = lower(c.krbtgt_link)
                ORDER BY o.object_guid LIMIT 1
            ) ku ON true
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_read_only_dc
        ),
        assessed AS (
            SELECT r.*,
                   (r.mb_guid IS NOT NULL AND (
                        r.mb_guid IN (SELECT object_guid FROM tier0)
                     OR EXISTS (SELECT 1 FROM v_effective_group_membership vem
                                 JOIN tier0 t ON t.object_guid = vem.member_guid
                                WHERE vem.client_id = %(client_id)s AND vem.group_guid = r.mb_guid)
                   )) AS mb_tier0,
                   (SELECT jsonb_agg(DISTINCT COALESCE(md.sam_account_name, md.object_sid, md.object_guid::text))
                      FROM v_effective_group_membership vem
                      JOIN tier0 t ON t.object_guid = vem.member_guid
                      JOIN directory_object md
                        ON md.object_guid = vem.member_guid AND md.client_id = vem.client_id
                     WHERE vem.client_id = %(client_id)s AND vem.group_guid = r.mb_guid) AS mb_tier0_members
            FROM rodc r
        ),
        issues AS (
            SELECT a.*, i.issue, i.sev, i.ord
            FROM assessed a
            CROSS JOIN LATERAL (VALUES
                (CASE WHEN NULLIF(btrim(a.managed_by), '') IS NULL
                      THEN 'no delegated administrator (managedBy) set' END, 1, 3),
                (CASE WHEN a.mb_tier0
                      THEN 'delegated administrator (managedBy) is or contains a Tier 0 principal' END, 3, 1),
                (CASE WHEN a.krbtgt_guid IS NULL
                      THEN 'RODC krbtgt account (msDS-KrbTgtLink) missing or orphaned' END, 2, 2),
                (CASE WHEN a.krbtgt_pwd_last_set < now() - interval '180 days'
                      THEN 'RODC krbtgt password older than 180 days' END, 2, 2)
            ) i(issue, sev, ord)
            WHERE i.issue IS NOT NULL
        )
        SELECT
            CASE WHEN max(x.sev) >= 3 THEN 'fail' ELSE 'warn' END AS status,
            x.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE max(x.sev) WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'RODC ' || COALESCE(x.sam_account_name, x.object_guid::text) || ': '
                || string_agg(x.issue, '; ' ORDER BY x.ord, x.issue) AS summary,
            jsonb_build_object(
                'rodc', x.sam_account_name,
                'issues', jsonb_agg(x.issue ORDER BY x.ord, x.issue),
                'managed_by', x.managed_by,
                'managed_by_resolved', x.mb_guid IS NOT NULL,
                'managed_by_name', x.mb_name,
                'managed_by_tier0_members', x.mb_tier0_members,
                'krbtgt_link', x.krbtgt_link,
                'krbtgt_account', x.krbtgt_name,
                'krbtgt_pwd_last_set', x.krbtgt_pwd_last_set,
                'krbtgt_pwd_age_days', floor(extract(epoch FROM now() - x.krbtgt_pwd_last_set) / 86400)
            ) AS detail
        FROM issues x
        GROUP BY x.object_guid, x.sam_account_name, x.managed_by, x.mb_guid, x.mb_name,
                 x.mb_tier0_members, x.krbtgt_link, x.krbtgt_name, x.krbtgt_pwd_last_set
        ORDER BY x.object_guid
    """,
}
