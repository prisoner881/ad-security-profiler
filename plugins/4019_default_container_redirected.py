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
"""

PLUGIN = {
    "plugin_id": 4019,
    "category": "Domain",
    "name": "Default Computers or Users Container Has Been Redirected",
    "version": "1.0",
    "revision_date": "2026-07-31",
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
    "framework_tags": [],
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
        "the current location is expected."
    ),
    "base_severity": "info",
    "query": """
        WITH wko AS (
            SELECT d.object_guid, d.dns_root, elem
            FROM ad_domain d, jsonb_array_elements_text(d.well_known_objects) AS elem
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
        ),
        redirections AS (
            SELECT object_guid, dns_root,
                   'Computers' AS container_type,
                   split_part(elem, ':', 4) AS current_dn,
                   'CN=Computers,' || dns_root AS default_dn
            FROM wko
            WHERE upper(split_part(elem, ':', 3)) = 'AA312825768811D1ADED00C04FD8D5CD'
            UNION ALL
            SELECT object_guid, dns_root,
                   'Users' AS container_type,
                   split_part(elem, ':', 4) AS current_dn,
                   'CN=Users,' || dns_root AS default_dn
            FROM wko
            WHERE upper(split_part(elem, ':', 3)) = 'A9D1CA15768811D1ADED00C04FD8D5CD'
        ),
        actually_redirected AS (
            SELECT object_guid, container_type, current_dn, default_dn
            FROM redirections
            WHERE lower(current_dn) != lower(default_dn)
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
                   count(*) AS redirection_count
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
                'redirections', to_jsonb(a.redirections_list)
            ) AS detail
        FROM aggregated a
    """,
}
