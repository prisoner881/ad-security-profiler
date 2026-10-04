"""
Plugin 4017: Forest Contains an Excessive Number of Privileged Accounts

A simple count of every user and group carrying the AdminSDHolder
protection marker (admin_count=1) -- the same population every other
admin_count-based plugin in this project already reasons about
individually. Considered in aggregate rather than one object at a
time: the more privileged accounts and groups exist domain-wide, the
larger the attack surface for privilege escalation, since each one is
an independent path an attacker could compromise to reach Tier-0
access. Confirmed against Purple Knight's own equivalent check and
threshold (50).

[v1.1] Counts enabled privileged *user accounts* rather than every
admin_count=1 user and group. v1.0 included ~12 built-in protected
groups (which are not accounts), krbtgt, disabled accounts and orphaned
ex-admins whose sticky adminCount was never cleared, while missing users
privileged by other means. The population is now enabled users found in
v_privileged_principal (effective, nested and primary-group members of
protected groups, plus Tier-0 ACL control, ownership and DCSync holders,
directly or via a group), excluding krbtgt (RID 502) -- the same
"enabled admin users" basis PingCastle uses for P-AdminNum. Each
collected domain is evaluated on its own, so the wording now says
"Domain" instead of "Forest".
"""

PLUGIN = {
    "plugin_id": 4017,
    "category": "Domain",
    "name": "Domain Contains an Excessive Number of Privileged Accounts",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "Review the list of enabled privileged user accounts (listed in "
        "the finding detail) and identify which ones genuinely "
        "need standing privileged access versus which could move to a "
        "just-in-time or time-limited privileged access model instead. "
        "A large, flat population of always-on privileged accounts is "
        "harder to monitor effectively than a smaller, well-understood "
        "set -- reducing the count is itself a meaningful hardening "
        "step, independent of any individual account's own "
        "configuration."
    ),
    "control_id": "PRIV-401",
    "framework_tags": [
        "NIST-800-53-AC-2(7)",
        "NIST-800-53-AC-6(5)",
        "NIST-800-53-AC-6(2)",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-5.4",
        "CIS-CSC-8-6.8",
        "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "HIPAA-164.308(a)(4)(ii)(B)",
        "MITRE-ATTCK-T1078.002",
    ],
    "references": [
        {"title": "PingCastle: Privileged accounts -- P-AdminNum",
         "url": "https://pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "Microsoft: Reducing the Active Directory attack surface",
         "url": "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/reducing-the-active-directory-attack-surface"},
    ],
    "description": (
        "Counts enabled user accounts that hold privilege in the domain "
        "-- effective (nested or primary-group) members of protected "
        "groups, or holders of Tier-0 ACL control, ownership or DCSync "
        "rights, directly or via a group -- excluding krbtgt. "
        "Considered in aggregate: the more privileged accounts exist, the "
        "larger the attack surface for privilege escalation, since "
        "each one is an independent path to Tier-0 access. Confirmed "
        "against Purple Knight's own equivalent check and threshold "
        "(50)."
    ),
    "base_severity": "medium",
    "query": """
        WITH priv_user AS (
            -- [v1.1] Enabled users with effective privilege (not the
            -- sticky admin_count marker); groups and krbtgt excluded.
            SELECT DISTINCT u.object_guid,
                   COALESCE(u.sam_account_name, o.dn_current) AS name
            FROM v_privileged_principal pp
            JOIN ad_user u
              ON u.object_guid = pp.object_guid
             AND u.client_id = pp.client_id
             AND u.valid_to IS NULL
            JOIN directory_object o
              ON o.object_guid = u.object_guid
             AND o.client_id = u.client_id
             AND NOT o.is_deleted
            WHERE pp.client_id = %(client_id)s
              AND u.is_enabled IS NOT FALSE
              AND COALESCE(o.object_sid, '') NOT LIKE '%%-502'
        ),
        agg AS (
            SELECT count(*) AS n,
                   jsonb_agg(name ORDER BY lower(name), name) AS names
            FROM priv_user
        )
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, d.object_guid::text) || ' has '
                || agg.n || ' enabled privileged user account(s), exceeding the 50-account threshold' AS summary,
            jsonb_build_object(
                'enabled_privileged_user_count', agg.n,
                'threshold', 50,
                'privileged_users', agg.names
            ) AS detail
        FROM ad_domain d
        CROSS JOIN agg
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND agg.n > 50
    """,
}
