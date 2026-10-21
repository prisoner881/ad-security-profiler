"""
Plugin 9040: Group Policy Script Runs From Outside the Domain or a User-Writable Location

Reports GPOs whose startup, shutdown, logon or logoff scripts (scripts.ini
and psscripts.ini in the GPO's Machine|User\\Scripts folder,
gpo_setting_edge source 'scripts', sysvol_collector 1.1) run a command from a
location the domain does not control. A bare name runs from the GPO's own
Scripts folder in SYSVOL and is never reported.

UNC paths -- hosts are placed as in plugin 1052: the domain's DNS name or any
name under it, its NetBIOS name, or a computer of this domain = the domain
(not reported); another DNS name = outside the domain -- medium: startup
scripts run as SYSTEM on every computer the GPO applies to, logon scripts in
every user's session, so whoever controls that host or share controls them
(PingCastle T-ScriptOutOfDomain); an IP address or an unknown short name =
cannot be placed -- low.

Local paths -- [1.1] a path under a user profile (X:\\Users\\..., %USERPROFILE%,
%APPDATA%, %TEMP%, ...), in a OneDrive folder, or on a drive other than C:
runs whatever sits at that path on each computer, and such folders are
typically writable by (or synced from the cloud for) an ordinary user. A
typical cause is a script picked with Browse from an administrator's own
desktop. Medium when the GPO applies to a domain controller (that user then
runs code as SYSTEM on the DCs), low otherwise. Other local paths
(C:\\Windows\\..., C:\\Program Files\\...) are not reported.

A GPO that is not linked anywhere (no enabled link) is low at most: its
scripts don't run until it is linked. One row per GPO (object_guid = the
GPO) listing each such script. Status 'fail' at medium. Requires SYSVOL
collection (adprofiler.py --sysvol); a GPO collected by sysvol_collector
before 1.1 has no script rows.
"""

PLUGIN = {
    "plugin_id": 9040,
    "category": "Organizational Units",
    "name": "Group Policy Script Runs From Outside the Domain or a User-Writable Location",
    "version": "1.1",
    "revision_date": "2026-10-21",
    "control_id": "GPO-9040",
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
        "MITRE-ATTCK-T1484.001",
        "MITRE-ATTCK-T1199",
    ],
    "references": [
        {"title": "PingCastle health check rules (T-ScriptOutOfDomain)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1037.003: Boot or Logon Initialization Scripts: Network Logon Script",
         "url": "https://attack.mitre.org/techniques/T1037/003/"},
        {"title": "MITRE ATT&CK T1484.001: Domain or Tenant Policy Modification: Group Policy Modification",
         "url": "https://attack.mitre.org/techniques/T1484/001/"},
    ],
    "description": (
        "A GPO's startup, shutdown, logon or logoff script runs from a UNC path "
        "on a host outside this domain (medium), from a host that cannot be "
        "placed (low), or from a local path in a user profile, OneDrive folder "
        "or non-system drive (medium when the GPO applies to domain controllers, "
        "low otherwise). Unlinked GPOs are low at most."
    ),
    "remediation": (
        "Copy the script into the GPO's own Scripts folder (Group Policy "
        "Management Editor > Scripts > Show Files) or the domain's NETLOGON "
        "share and point the script entry at it by name. Remove script entries "
        "that are no longer used, and check whether the old location was "
        "writable by anyone other than Tier 0 while the entry pointed at it."
    ),
    "base_severity": "medium",
    "query": """
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS ok
        ),
        dom AS (
            SELECT lower(m.dns_root) AS dns_lc, lower(m.netbios_name) AS nb
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
        linked AS (
            SELECT DISTINCT l.gpo_guid
            FROM gpo_link_edge l
            WHERE l.client_id = %(client_id)s AND l.valid_to IS NULL AND l.link_enabled
        ),
        dc_gpo AS (
            SELECT DISTINCT a.gpo_guid
            FROM v_gpo_dc_application a
            WHERE a.client_id = %(client_id)s AND a.precedence IS NOT NULL
        ),
        script AS (
            SELECT e.gpo_guid, e.scope, e.section, e.setting_key, e.value_type,
                   btrim(e.setting_value, ' "') AS path
            FROM gpo_setting_edge e
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL AND e.source = 'scripts'
              AND (SELECT ok FROM sysvol)
              AND btrim(COALESCE(e.setting_value, ''), ' "') <> ''
        ),
        placed AS (
            SELECT s.*, h.host,
                   CASE WHEN h.host IS NOT NULL THEN
                            CASE WHEN h.host = d.dns_lc OR h.host LIKE ('%%.' || d.dns_lc) OR h.host = d.nb
                                      OR h.host IN (SELECT kh.h FROM known_host kh) THEN 'domain'
                                 WHEN h.host ~ '^[0-9.]+$' OR strpos(h.host, ':') > 0 THEN 'ip'
                                 WHEN strpos(h.host, '.') = 0 THEN 'unresolved'
                                 ELSE 'outside' END
                        -- local paths, compared with forward slashes
                        WHEN h.np ~ '^%%(userprofile|appdata|localappdata|temp|tmp|onedrive[a-z]*|homepath|homedrive|public)%%'
                          OR h.np ~ '^[a-z]:/users/'
                          OR strpos(h.np, 'onedrive') > 0
                          OR (h.np ~ '^[a-z]:/' AND h.np !~ '^c:/')
                            THEN 'local_user'
                        ELSE 'local' END AS place
            FROM script s
            CROSS JOIN dom d
            CROSS JOIN LATERAL (
                SELECT CASE WHEN left(s.path, 2) = repeat(chr(92), 2)
                            THEN NULLIF(lower(split_part(substr(s.path, 3), chr(92), 1)), '') END AS host,
                       lower(replace(s.path, chr(92), '/')) AS np
            ) h
        ),
        bad AS (
            SELECT p.*, (lk.gpo_guid IS NOT NULL) AS is_linked, (dg.gpo_guid IS NOT NULL) AS applies_to_dc,
                   CASE WHEN lk.gpo_guid IS NOT NULL
                             AND (p.place = 'outside' OR (p.place = 'local_user' AND dg.gpo_guid IS NOT NULL))
                        THEN 2 ELSE 1 END AS sev
            FROM placed p
            LEFT JOIN linked lk ON lk.gpo_guid = p.gpo_guid
            LEFT JOIN dc_gpo dg ON dg.gpo_guid = p.gpo_guid
            WHERE p.place IN ('outside', 'ip', 'unresolved', 'local_user')
        )
        SELECT
            CASE WHEN max(b.sev) = 2 THEN 'fail' ELSE 'warn' END AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN max(b.sev) = 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'GPO ''' || COALESCE(g.display_name, g.object_guid::text) || ''' runs scripts from locations '
                || 'the domain does not control'
                || CASE WHEN bool_or(b.applies_to_dc) THEN ' (the GPO applies to domain controllers)'
                        WHEN NOT bool_or(b.is_linked) THEN ' (the GPO is not linked)' ELSE '' END || ': '
                || string_agg(b.section || ' ' || b.path || ' ('
                              || CASE b.place WHEN 'outside' THEN 'host outside the domain'
                                              WHEN 'ip' THEN 'IP address'
                                              WHEN 'unresolved' THEN 'unknown short name'
                                              ELSE 'local path in a user profile, OneDrive folder or '
                                                   || 'non-system drive' END || ')',
                              '; ' ORDER BY b.sev DESC, b.scope, b.section, b.setting_key) AS summary,
            jsonb_build_object(
                'gpo_name', g.display_name,
                'gpo_guid', upper(g.gpo_guid::text),
                'gpo_linked', bool_or(b.is_linked),
                'applies_to_domain_controllers', bool_or(b.applies_to_dc),
                'scripts', jsonb_agg(jsonb_build_object('scope', b.scope, 'event', b.section,
                                                        'entry', b.setting_key, 'kind', b.value_type,
                                                        'command', b.path, 'host', b.host,
                                                        'placement', b.place)
                                     ORDER BY b.sev DESC, b.scope, b.section, b.setting_key),
                'note', 'Hosts are placed by name and local paths by location only; the permissions '
                        || 'of the share or folder are not visible.'
            ) AS detail
        FROM bad b
        JOIN ad_gpo g ON g.object_guid = b.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
        GROUP BY g.object_guid, g.display_name, g.gpo_guid
    """,
}
