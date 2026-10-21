"""
Plugin 1052: User Logon Script Runs From Outside the Domain

Reports enabled user accounts whose logon script (scriptPath,
ad_user.script_path) is a UNC path on a host that is not part of this
domain. A bare name or relative path ("logon.bat") runs from the domain's
own NETLOGON share and is never reported.

How the host of \\\\host\\share\\... is classified:
  * the domain itself: its DNS name or any name under it (corp.local,
    dfs.corp.local), its NetBIOS name (ad_domain.netbios_name), or the
    short or DNS name of a computer in this domain -- not reported;
  * a DNS name outside the domain's namespace (another domain or forest,
    a partner) -- medium: whoever controls that host or share runs code
    in these users' sessions at every logon, so a compromise of the other
    domain spreads into this one (PingCastle T-ScriptOutOfDomain);
  * an IP address, or a short name that is no computer of this domain
    (a DFS namespace, another domain's NetBIOS name) -- low: it cannot be
    placed, so it is listed for review.

One row per domain (object_guid = the domain) listing each script path, its
host's classification and the accounts using it. Status 'fail' at medium.
The share's own permissions are not visible; a script inside the domain on a
share writable by ordinary users is just as dangerous (PingCastle
P-DelegationLoginScript) and is not judged here.
"""

PLUGIN = {
    "plugin_id": 1052,
    "category": "User Accounts",
    "name": "User Logon Script Runs From Outside the Domain",
    "version": "1.0",
    "revision_date": "2026-10-21",
    "control_id": "HYGIENE-1052",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "HIPAA-164.312(c)(1)",
        "MITRE-ATTCK-T1037.003",
        "MITRE-ATTCK-T1199",
    ],
    "references": [
        {"title": "PingCastle health check rules (T-ScriptOutOfDomain)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1037.003: Boot or Logon Initialization Scripts: Network Logon Script",
         "url": "https://attack.mitre.org/techniques/T1037/003/"},
    ],
    "description": (
        "Enabled accounts run a logon script (scriptPath) from a UNC path on a "
        "host outside this domain (medium), or on a host that cannot be placed "
        "-- an IP address or an unknown short name (low). Whoever controls that "
        "share runs code at these users' logon."
    ),
    "remediation": (
        "Copy the script to the domain's NETLOGON share (or a share in this "
        "domain whose permissions only Tier 0 can change) and set scriptPath "
        "to it: Set-ADUser <user> -ScriptPath <name relative to NETLOGON>. "
        "Remove scriptPath from accounts that no longer need a logon script."
    ),
    "base_severity": "medium",
    "query": """
        WITH dom AS (
            SELECT m.object_guid, m.dns_root, m.netbios_name, lower(m.dns_root) AS dns_lc, lower(m.netbios_name) AS nb
            FROM ad_domain m
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL
            ORDER BY m.object_guid LIMIT 1
        ),
        known_host AS (
            SELECT lower(rtrim(c.sam_account_name, '$')) AS h
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.sam_account_name IS NOT NULL
            UNION
            SELECT lower(c.dns_hostname)
            FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.dns_hostname IS NOT NULL
        ),
        script AS (
            SELECT u.object_guid, u.sam_account_name, btrim(u.script_path, ' "') AS path
            FROM ad_user u
            JOIN directory_object o
              ON o.object_guid = u.object_guid AND o.client_id = u.client_id AND NOT o.is_deleted
            WHERE u.client_id = %(client_id)s AND u.valid_to IS NULL AND u.is_enabled
              AND btrim(COALESCE(u.script_path, ''), ' "') <> ''
        ),
        placed AS (
            SELECT s.*, h.host,
                   CASE WHEN h.host IS NULL THEN 'local'
                        WHEN h.host = d.dns_lc OR h.host LIKE ('%%.' || d.dns_lc) OR h.host = d.nb
                             OR h.host IN (SELECT kh.h FROM known_host kh) THEN 'domain'
                        WHEN h.host ~ '^[0-9.]+$' OR strpos(h.host, ':') > 0 THEN 'ip'
                        WHEN strpos(h.host, '.') = 0 THEN 'unresolved'
                        ELSE 'outside' END AS place
            FROM script s
            CROSS JOIN dom d
            CROSS JOIN LATERAL (
                SELECT CASE WHEN left(s.path, 2) = repeat(chr(92), 2)
                            THEN NULLIF(lower(split_part(substr(s.path, 3), chr(92), 1)), '') END AS host
            ) h
        ),
        per_path AS (
            SELECT p.path, p.host, p.place, count(*) AS accounts,
                   to_jsonb((array_agg(p.sam_account_name ORDER BY lower(p.sam_account_name)))[1:50])
                       AS account_names
            FROM placed p
            WHERE p.place IN ('outside', 'ip', 'unresolved')
            GROUP BY p.path, p.host, p.place
        )
        SELECT
            CASE WHEN bool_or(pp.place = 'outside') THEN 'fail' ELSE 'warn' END AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_or(pp.place = 'outside') THEN 'medium' ELSE 'low' END AS fd_severity,
            sum(pp.accounts) || ' enabled account(s) run a logon script from '
                || CASE WHEN bool_or(pp.place = 'outside') THEN 'outside the domain'
                        ELSE 'a host that is not a known part of the domain' END
                || ': '
                || string_agg(pp.path || ' (' || pp.accounts || ' account(s), '
                              || CASE pp.place WHEN 'outside' THEN 'host outside the domain'
                                               WHEN 'ip' THEN 'IP address'
                                               ELSE 'unknown short name' END || ')',
                              '; ' ORDER BY (pp.place = 'outside') DESC, lower(pp.path)) AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'netbios_name', d.netbios_name,
                'scripts', jsonb_agg(jsonb_build_object('script_path', pp.path, 'host', pp.host,
                                                        'host_placement', pp.place,
                                                        'account_count', pp.accounts,
                                                        'accounts_first_50', pp.account_names)
                                     ORDER BY (pp.place = 'outside') DESC, lower(pp.path)),
                'note', 'Hosts are placed by name only; the share''s permissions are not visible.'
            ) AS detail
        FROM per_path pp
        CROSS JOIN dom d
        GROUP BY d.object_guid, d.dns_root, d.netbios_name
    """,
}
