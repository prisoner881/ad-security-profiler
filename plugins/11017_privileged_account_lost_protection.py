"""
Plugin 11017: Tier 0 Account Lost Protected Users Membership or Delegation Protection

Change Detection companion to plugins 1040 (privileged account not in
Protected Users) and 1041 (privileged account missing "Account is
sensitive and cannot be delegated"). Those report the standing gap;
this one reports the regression: a current Tier 0 account that, since
the previous successful collection run,
- was removed from Protected Users (RID 525): its direct membership edge
  closed in this window and it is no longer an effective member
  (directly, nested or by primary group); or
- had NOT_DELEGATED (0x100000, "Account is sensitive and cannot be
  delegated") cleared from userAccountControl.

Why: both controls stop the account's credentials being reused through
Kerberos delegation (an unconstrained-delegation host capturing its TGT,
S4U2Proxy impersonation via constrained or resource-based delegation);
Protected Users additionally blocks NTLM, DES/RC4 and credential caching.
Removing them is a quiet preparation step before a delegation-based
attack on an administrator (MITRE ATT&CK T1098 Account Manipulation,
T1558 Steal or Forge Kerberos Tickets) and is recommended in Microsoft's
privileged-access guidance.

Comparison: group_member_edge rows into Protected Users closed after the
previous succeeded sync_run (run_id_valid_to), and the userAccountControl
of the current ad_user / ad_computer version against the version current
at the previous run (11002's lookup) -- only that bit, so the schema v38
rescan cannot produce findings. "Tier 0" is v_privileged_principal or
v_tier0_object as of now; an account that lost its privilege in the same
run is not reported.

Severity: medium (low if the account is disabled). One row per account,
listing both regressions when both happened. Suppressed on a client's
first collection run.
"""

PLUGIN = {
    "plugin_id": 11017,
    "category": "Change Detection",
    "name": "Tier 0 Account Lost Protected Users Membership or Delegation Protection",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "CHANGE-11017",
    "framework_tags": [
        "NIST-800-53-CM-3", "NIST-800-53-SI-4", "NIST-800-53-AU-6", "NIST-800-53-AC-2(4)",
        "NIST-800-53-AC-6(5)", "NIST-800-53-IA-2(8)",
        "NIST-CSF-2.0-DE.CM-03", "NIST-CSF-2.0-DE.CM-09", "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-10.2.1.2", "PCI-DSS-4.0-10.2.1.5",
        "CIS-CSC-8-8.11", "CIS-CSC-8-5.4",
        "ISO-27001-2022-A.8.16", "ISO-27001-2022-A.8.2",
        "SOC2-CC7.2", "SOC2-CC6.3",
        "HIPAA-164.308(a)(1)(ii)(D)",
        "MITRE-ATTCK-T1098", "MITRE-ATTCK-T1558",
        "CISA-AA26-237A",
    ],
    "references": [
        {"title": "Microsoft: Protected Users security group",
         "url": "https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group"},
        {"title": "MITRE ATT&CK T1558: Steal or Forge Kerberos Tickets",
         "url": "https://attack.mitre.org/techniques/T1558/"},
        {"title": "CISA AA26-237A: Joint Red Team Assessment Findings",
         "url": "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-237a"},
    ],
    "description": (
        "Reports current Tier 0 accounts that, since the previous successful "
        "collection run, were removed from Protected Users (and are no longer an "
        "effective member) or had 'Account is sensitive and cannot be delegated' "
        "(NOT_DELEGATED) cleared. Both stop an administrator's credentials being "
        "reused through Kerberos delegation; removing them is a quiet preparation "
        "step for a delegation-based attack. Severity is medium, low for disabled "
        "accounts. Only the membership edge and the NOT_DELEGATED bit are compared, so "
        "re-collection by a newer collector does not produce findings. Suppressed on "
        "a client's first collection run."
    ),
    "remediation": (
        "Confirm the change against a change record (events 4729/4733/4757 member "
        "removed from a group, 4738 user account changed). Unless an application "
        "incompatibility was documented, restore the protection: Add-ADGroupMember "
        "-Identity 'Protected Users' -Members <account>; Set-ADAccountControl "
        "<account> -AccountNotDelegated $true. If it was not approved, review the "
        "account's authentication activity since the change for delegation use "
        "(event 4769 with a delegation ticket for the account) and rotate its "
        "credentials."
    ),
    "base_severity": "medium",
    "query": """
        WITH prior_run AS (
            SELECT max(sr.run_id) AS prev_run_id
            FROM sync_run sr
            WHERE sr.client_id = %(client_id)s
              AND sr.run_id < %(run_id)s
              AND sr.status = 'succeeded'
        ),
        tier0 AS (
            SELECT pp.object_guid FROM v_privileged_principal pp WHERE pp.client_id = %(client_id)s
            UNION
            SELECT t.object_guid FROM v_tier0_object t WHERE t.client_id = %(client_id)s
        ),
        acct AS (
            SELECT 'user' AS kind, u.object_guid, u.sam_account_name, u.user_account_control,
                   u.is_enabled, u.version_id, u.valid_from
            FROM ad_user u
            JOIN tier0 t ON t.object_guid = u.object_guid
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL
            UNION ALL
            SELECT 'computer', c.object_guid, c.sam_account_name, c.user_account_control,
                   c.is_enabled, c.version_id, c.valid_from
            FROM ad_computer c
            JOIN tier0 t ON t.object_guid = c.object_guid
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
        ),
        protected_users AS (
            SELECT o.object_guid
            FROM directory_object o
            WHERE o.client_id = %(client_id)s
              AND o.object_class = 'group'
              AND NOT o.is_deleted
              AND o.object_sid ~ '^S-1-5-21-[0-9]+-[0-9]+-[0-9]+-525$'
        ),
        left_pu AS (
            SELECT a.object_guid, min(e.valid_to) AS removed_at
            FROM acct a
            CROSS JOIN prior_run pr
            JOIN group_member_edge e
              ON e.client_id = %(client_id)s
             AND e.member_guid = a.object_guid
             AND e.group_guid IN (SELECT object_guid FROM protected_users)
            WHERE pr.prev_run_id IS NOT NULL
              AND e.run_id_valid_from <= pr.prev_run_id
              AND e.run_id_valid_to > pr.prev_run_id
              AND e.run_id_valid_to <= %(run_id)s
              AND NOT EXISTS (SELECT 1 FROM v_effective_group_membership vem
                              WHERE vem.client_id = %(client_id)s
                                AND vem.member_guid = a.object_guid
                                AND vem.group_guid IN (SELECT object_guid FROM protected_users))
            GROUP BY a.object_guid
        ),
        lost_not_delegated AS (
            SELECT a.object_guid, a.valid_from AS changed_at, prev.prev_uac
            FROM acct a
            CROSS JOIN prior_run pr
            JOIN directory_object_version cv
              ON cv.version_id = a.version_id AND cv.object_guid = a.object_guid
             AND cv.client_id = %(client_id)s AND cv.valid_from = a.valid_from
            JOIN LATERAL (
                SELECT p.user_account_control AS prev_uac
                FROM (SELECT u.version_id, u.object_guid, u.valid_from, u.user_account_control
                        FROM ad_user u
                       WHERE a.kind = 'user' AND u.object_guid = a.object_guid
                         AND u.client_id = %(client_id)s
                      UNION ALL
                      SELECT k.version_id, k.object_guid, k.valid_from, k.user_account_control
                        FROM ad_computer k
                       WHERE a.kind = 'computer' AND k.object_guid = a.object_guid
                         AND k.client_id = %(client_id)s) p
                JOIN directory_object_version pv
                  ON pv.version_id = p.version_id AND pv.object_guid = p.object_guid
                 AND pv.client_id = %(client_id)s AND pv.valid_from = p.valid_from
                WHERE p.valid_from < a.valid_from
                  AND pv.run_id_valid_from <= pr.prev_run_id
                  AND (pv.run_id_valid_to IS NULL OR pv.run_id_valid_to > pr.prev_run_id)
                ORDER BY p.valid_from DESC
                LIMIT 1
            ) prev ON TRUE
            WHERE pr.prev_run_id IS NOT NULL
              AND cv.run_id_valid_from > pr.prev_run_id
              AND cv.run_id_valid_from <= %(run_id)s
              AND (prev.prev_uac & 1048576) <> 0
              AND (COALESCE(a.user_account_control, 0) & 1048576) = 0
        )
        SELECT
            'warn' AS status,
            a.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN a.is_enabled IS FALSE THEN 'low' ELSE 'medium' END AS fd_severity,
            'Tier 0 ' || CASE WHEN a.kind = 'computer' THEN 'computer account "' ELSE 'account "' END
                || COALESCE(a.sam_account_name, do2.dn_current) || '" '
                || array_to_string(array_remove(ARRAY[
                       CASE WHEN lp.object_guid IS NOT NULL
                            THEN 'was removed from Protected Users' END,
                       CASE WHEN ln.object_guid IS NOT NULL
                            THEN 'had "Account is sensitive and cannot be delegated" (NOT_DELEGATED) cleared' END
                   ], NULL), ' and ')
                || ' since the previous collection run'
                || CASE WHEN a.is_enabled IS FALSE THEN ' (account is disabled)' ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', a.sam_account_name,
                'distinguished_name', do2.dn_current,
                'account_kind', a.kind,
                'removed_from_protected_users', lp.object_guid IS NOT NULL,
                'protected_users_removal_observed_at', lp.removed_at,
                'not_delegated_cleared', ln.object_guid IS NOT NULL,
                'user_account_control', a.user_account_control,
                'previous_user_account_control', ln.prev_uac,
                'is_enabled', a.is_enabled,
                'privilege_sources', (SELECT jsonb_agg(DISTINCT pp.privilege_source ORDER BY pp.privilege_source)
                                        FROM v_privileged_principal pp
                                       WHERE pp.client_id = %(client_id)s
                                         AND pp.object_guid = a.object_guid),
                'baseline_run_id', (SELECT prev_run_id FROM prior_run),
                'corroborating_event_ids', jsonb_build_array(4729, 4733, 4757, 4738)
            ) AS detail
        FROM acct a
        JOIN directory_object do2
          ON do2.object_guid = a.object_guid AND do2.client_id = %(client_id)s
         AND NOT do2.is_deleted
        LEFT JOIN left_pu lp ON lp.object_guid = a.object_guid
        LEFT JOIN lost_not_delegated ln ON ln.object_guid = a.object_guid
        WHERE lp.object_guid IS NOT NULL OR ln.object_guid IS NOT NULL
    """,
}
