"""
Plugin 4019: Default Computers or Users Container Has Been Redirected

Confirmed as a genuine, if low-severity, gap via PingCastle's own
S-DefaultOUChanged rule (an informative-only check in PingCastle too --
adopted the same severity treatment here rather than inventing a
different one without reason). Redirecting the default Computers/Users
containers (via redircmp.exe/redirusr.exe) to a proper OU is itself a
widely-recommended hardening practice -- OUs support Group Policy
linking and delegated ACLs, the default CN=Computers/CN=Users
containers do not -- so this plugin is NOT flagging redirection as bad;
it is informational, surfacing the CURRENT location either way so a
reviewer can confirm it matches what they expect. An unexpected
redirection (one nobody on the current team remembers configuring)
is the actual case worth a second look.

Format and both well-known GUIDs confirmed against multiple
independent Microsoft/community sources (including [MS-ADTS] itself)
before writing this query: wellKnownObjects values are
"B:32:<32-hex-char GUID>:<current DN>"; AA312825768811D1ADED00C04FD8D5CD
is the Computers container, A9D1CA15768811D1ADED00C04FD8D5CD is the
Users container.

[v1.1] The default DN is now built from the domain object's own
distinguishedName (directory_object.dn_current). v1.0 used
ad_domain.dns_root, which only worked while that column wrongly held
the DN; now that it holds the DNS name (corp.local) every domain would
have been reported as redirected. The target DN is parsed with a regex
(everything after "B:32:<guid>:"), so a DN containing ':' (e.g. a
CNF:-renamed OU) is no longer truncated. The detail now also records,
per redirection, the target's object class (an OU, a plain container,
or not found) and the explicit (non-inherited) allow-ACE trustees on
the target, so the reviewer can judge the delegation on the place new
accounts land -- the real risk behind a redirection.
"""

PLUGIN = {
    "plugin_id": 4019,
    "category": "Domain",
    "name": "Default Computers or Users Container Has Been Redirected",
    "version": "1.1",
    "revision_date": "2026-10-04",
    "remediation": (
        "No remediation implied by this finding alone -- confirm the "
        "current location shown in evidence is expected and understood "
        "by the current team. Redirection to a proper OU (via "
        "redircmp.exe/redirusr.exe) is itself a common, recommended "
        "practice, since only OUs support Group Policy linking and "
        "delegated ACLs, unlike the default CN=Computers/CN=Users "
        "containers. This is worth investigating only if nobody "
        "currently on the team can account for why or when it was "
        "redirected."
    ),
    "control_id": "DOM-419",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-800-53-CM-2",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "PCI-DSS-4.0-2.2.6",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "HIPAA-164.312(c)(1)",
    ],
    "references": [
        {"title": "PingCastle: Stale Objects rules -- S-DefaultOUChanged",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "Microsoft: Redirecting the Users and Computers containers",
         "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/redirect-users-computers-containers"},
    ],
    "description": (
        "The domain's default Computers and/or Users container has "
        "been redirected away from Microsoft's default location "
        "(CN=Computers/CN=Users) to a different container, per the "
        "domain object's own wellKnownObjects attribute. Informational "
        "only -- redirection to a proper OU is itself a common, "
        "recommended practice -- surfaced so a reviewer can confirm "
        "the current location is expected. The evidence records the "
        "target's object class and the trustees of its explicit "
        "allow ACEs (who controls where new accounts are created)."
    ),
    "base_severity": "info",
    "query": """
        WITH wko AS (
            -- [v1.1] default DNs are built from the domain object's DN,
            -- not ad_domain.dns_root (which now holds the DNS name).
            SELECT d.object_guid, o.dn_current AS domain_dn,
                   upper(substring(elem from '^B:32:([0-9A-Fa-f]{32}):')) AS wk_guid,
                   substring(elem from '^B:32:[0-9A-Fa-f]{32}:(.*)$') AS target_dn
            FROM ad_domain d
            JOIN directory_object o
              ON o.object_guid = d.object_guid
             AND o.client_id = d.client_id,
                 jsonb_array_elements_text(d.well_known_objects) AS elem
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
        ),
        redirections AS (
            SELECT object_guid,
                   CASE wk_guid WHEN 'AA312825768811D1ADED00C04FD8D5CD' THEN 'Computers'
                                ELSE 'Users' END AS container_type,
                   target_dn AS current_dn,
                   CASE wk_guid WHEN 'AA312825768811D1ADED00C04FD8D5CD' THEN 'CN=Computers,'
                                ELSE 'CN=Users,' END || domain_dn AS default_dn
            FROM wko
            WHERE wk_guid IN ('AA312825768811D1ADED00C04FD8D5CD',
                              'A9D1CA15768811D1ADED00C04FD8D5CD')
              AND target_dn IS NOT NULL
        ),
        actually_redirected AS (
            SELECT r.object_guid, r.container_type, r.current_dn, r.default_dn,
                   COALESCE(t.object_class::text, 'not_found') AS target_object_class,
                   (SELECT COALESCE(jsonb_agg(DISTINCT a.trustee_sid::text), '[]'::jsonb)
                    FROM acl_edge a
                    WHERE a.client_id = %(client_id)s
                      AND a.object_guid = t.object_guid
                      AND a.valid_to IS NULL
                      AND a.ace_type = 'allow'
                      AND NOT a.inherited) AS target_explicit_allow_trustees
            FROM redirections r
            LEFT JOIN directory_object t
              ON t.client_id = %(client_id)s
             AND lower(t.dn_current) = lower(r.current_dn)
             AND NOT t.is_deleted
            WHERE lower(r.current_dn) != lower(r.default_dn)
        ),
        -- [fix, caught via a real production crash on plugin 4023 --
        -- same root cause, checked and fixed here proactively] There
        -- is exactly one domain object, but BOTH the Computers and
        -- Users containers can be redirected simultaneously -- the
        -- original version produced one row per redirected container,
        -- both sharing the same domain object_guid, colliding on
        -- identity_guid exactly like 4023's crash did if both were
        -- ever redirected in the same domain. Aggregated here instead.
        aggregated AS (
            SELECT object_guid,
                   array_agg(container_type || ': "' || current_dn || '" (default "' || default_dn || '")'
                             ORDER BY container_type) AS redirections_list,
                   count(*) AS redirection_count,
                   jsonb_agg(jsonb_build_object(
                       'container_type', container_type,
                       'current_dn', current_dn,
                       'default_dn', default_dn,
                       'target_object_class', target_object_class,
                       'target_explicit_allow_trustees', target_explicit_allow_trustees)
                       ORDER BY container_type) AS redirection_detail
            FROM actually_redirected
            GROUP BY object_guid
        )
        SELECT
            'warn' AS status,
            a.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'info' AS fd_severity,
            a.redirection_count || ' default container(s) redirected: '
                || array_to_string(a.redirections_list, '; ') AS summary,
            jsonb_build_object(
                'redirections', to_jsonb(a.redirections_list),
                'redirection_targets', a.redirection_detail
            ) AS detail
        FROM aggregated a
    """,
}
