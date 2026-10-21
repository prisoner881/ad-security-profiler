"""
Plugin 9042: Script File Types Still Run When Opened (Not Redirected to Notepad)

Reports, once per domain, the Windows Script Host file types that no linked
GPO redirects to Notepad: .js, .jse, .vbs, .vbe, .vb, .wsh and .wsf. Double-
clicking one of these files -- an e-mail attachment, a download, a file in
a ZIP -- runs it with the script engine rather than showing it. Making
Notepad the default program for them with Group Policy Preferences (Folder
Options: a File Type or Open With item) stops that without affecting
anything else (PingCastle S-FolderOptions, informative). PowerShell files
(.ps1) already open in Notepad by default.

A file type counts as redirected when a GPO with at least one enabled link
has a FolderOptions preference item (gpo_preference_item_edge,
sysvol_collector 1.1) for that extension whose settings name notepad.exe,
and the item is not a Delete. Which computers the GPO reaches is not
evaluated; the detail lists the GPOs found.

One row per domain (object_guid = the domain), info ('warn'). Requires
SYSVOL collection (adprofiler.py --sysvol) by sysvol_collector 1.1 or later.
"""

PLUGIN = {
    "plugin_id": 9042,
    "category": "Organizational Units",
    "name": "Script File Types Still Run When Opened (Not Redirected to Notepad)",
    "version": "1.0",
    "revision_date": "2026-10-21",
    "control_id": "GPO-9042",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "HIPAA-164.312(c)(1)",
        "NIST-800-53-SI-3",
        "CIS-CSC-8-10.1",
        "MITRE-ATTCK-T1059.005",
        "MITRE-ATTCK-T1059.007",
        "MITRE-ATTCK-T1204.002",
    ],
    "references": [
        {"title": "PingCastle health check rules (S-FolderOptions)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1204.002: User Execution: Malicious File",
         "url": "https://attack.mitre.org/techniques/T1204/002/"},
    ],
    "description": (
        "No linked GPO makes Notepad the default program for some Windows "
        "Script Host file types (.js, .jse, .vbs, .vbe, .vb, .wsh, .wsf), so "
        "opening one runs it (info)."
    ),
    "remediation": (
        "In a GPO linked to the computers' OUs: Computer Configuration > "
        "Preferences > Control Panel Settings > Folder Options > New > File "
        "Type, action Replace, one item per extension (js, jse, vbs, vbe, vb, "
        "wsh, wsf); under Configure class settings add an 'open' action using "
        "C:\\Windows\\System32\\notepad.exe and make it the default. Check "
        "first that no business process double-clicks these files."
    ),
    "base_severity": "info",
    "query": """
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS ok
        ),
        dom AS (
            SELECT m.object_guid, m.dns_root
            FROM ad_domain m
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL
            ORDER BY m.object_guid LIMIT 1
        ),
        wanted (ext) AS (
            VALUES ('js'), ('jse'), ('vbs'), ('vbe'), ('vb'), ('wsh'), ('wsf')
        ),
        linked AS (
            SELECT DISTINCT l.gpo_guid
            FROM gpo_link_edge l
            WHERE l.client_id = %(client_id)s AND l.valid_to IS NULL AND l.link_enabled
        ),
        item AS (
            SELECT p.gpo_guid,
                   lower(ltrim(btrim(COALESCE(j.d -> 'properties' ->> 'fileExt',
                                              j.d -> 'properties' ->> 'fileExtension',
                                              p.item_name, '')), '.')) AS ext,
                   strpos(lower(p.details_json), 'notepad') > 0 AS uses_notepad
            FROM gpo_preference_item_edge p
            CROSS JOIN LATERAL (SELECT p.details_json::jsonb AS d) j
            WHERE p.client_id = %(client_id)s AND p.valid_to IS NULL
              AND p.preference_type = 'FolderOptions'
              AND upper(COALESCE(p.action, '')) <> 'D'
        ),
        covered AS (
            SELECT i.ext, string_agg(DISTINCT COALESCE(g.display_name, g.object_guid::text), ', ') AS gpos
            FROM item i
            JOIN linked lk ON lk.gpo_guid = i.gpo_guid
            JOIN ad_gpo g ON g.object_guid = i.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
            WHERE i.uses_notepad
            GROUP BY i.ext
        ),
        result AS (
            SELECT w.ext, c.gpos
            FROM wanted w
            LEFT JOIN covered c ON c.ext = w.ext
        )
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'info' AS fd_severity,
            'Script file types that still run when opened (no linked GPO makes Notepad their default '
                || 'program): ' || string_agg('.' || r.ext, ', ' ORDER BY r.ext) FILTER (WHERE r.gpos IS NULL)
                AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'not_redirected', jsonb_agg('.' || r.ext ORDER BY r.ext) FILTER (WHERE r.gpos IS NULL),
                'redirected', COALESCE(jsonb_object_agg('.' || r.ext, r.gpos) FILTER (WHERE r.gpos IS NOT NULL),
                                       '{}'::jsonb)
            ) AS detail
        FROM result r
        CROSS JOIN dom d
        WHERE (SELECT ok FROM sysvol)
        GROUP BY d.object_guid, d.dns_root
        HAVING count(*) FILTER (WHERE r.gpos IS NULL) > 0
    """,
}
