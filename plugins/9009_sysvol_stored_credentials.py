"""
Plugin 9009: Credentials Stored in SYSVOL or NETLOGON

Reports credentials left in files every domain user can read:

(a) Scripts and text files in a GPO's Scripts folder (SYSVOL) or on the
    NETLOGON share whose content matches a credential pattern -- "net use
    ... /user:x <password>", ConvertTo-SecureString -AsPlainText, a
    PSCredential built from a literal, "$password = '...'" assignments,
    connection strings with Password=, cpassword attributes, runas
    /savecred, DefaultPassword (AutoAdminLogon). One row per file;
    object_guid = md5('9009:' || share || ':' || lower(file_path))::uuid,
    a stable identity for a file that is not a directory object.
(b) Registry values a GPO writes whose name marks them as a secret
    (Winlogon DefaultPassword for AutoAdminLogon, any *Password*, *Pwd*,
    *Secret* string value) -- the collector stores those values as
    '<redacted>'. A GPO-deployed DefaultPassword is plaintext in
    Registry.pol / GptTmpl.inf on SYSVOL and in the registry of every
    computer the GPO applies to. One row per GPO (object_guid = GPO).

Why: SYSVOL and NETLOGON are readable by every authenticated user and
computer by design; credentials there are disclosed to the whole domain
(MITRE ATT&CK T1552.001, Credentials In Files; PingCastle and DISA STIG
both flag them). Service and admin passwords found this way are a common
first step to privilege escalation.

Data and caveats: sysvol_script_edge holds only the pattern names and
line numbers, never the matched text, so a hit can be a placeholder or a
commented-out line -- review the file. The scanner only reads script-like
files (.bat .cmd .ps1 .vbs .js .kix .wsf .txt .ini .config .xml ...) up to
1 MB, at most four folders deep. Part (b): a redacted value may also be an
empty string (the collector redacts by value name only). Unlinked GPOs are
reported too -- their files are equally readable. Zero rows unless SYSVOL
has been collected (adprofiler.py --sysvol). cpassword in Group Policy
Preferences XML is plugin 9008.
"""

PLUGIN = {
    "plugin_id": 9009,
    "category": "Organizational Units",
    "name": "Credentials Stored in SYSVOL or NETLOGON",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-9009",
    "framework_tags": [
        "NIST-800-53-IA-5(1)", "NIST-800-53-SC-28", "NIST-CSF-2.0-PR.DS-01",
        "PCI-DSS-4.0-8.3.2", "PCI-DSS-4.0-8.6.2", "CIS-CSC-8-3.11",
        "ISO-27001-2022-A.5.17", "SOC2-CC6.1", "HIPAA-164.312(a)(2)(iv)",
        "MITRE-ATTCK-T1552.001",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1552.001: Unsecured Credentials: Credentials In Files",
         "url": "https://attack.mitre.org/techniques/T1552/001/"},
        {"title": "Microsoft Learn: Turn on automatic logon in Windows (DefaultPassword is stored in clear text)",
         "url": "https://learn.microsoft.com/en-us/troubleshoot/windows-server/user-profiles-and-logon/turn-on-automatic-logon"},
    ],
    "description": (
        "Reports credentials readable by every domain user: scripts or text files in "
        "GPO script folders (SYSVOL) or on the NETLOGON share that match credential "
        "patterns (net use with a password, ConvertTo-SecureString -AsPlainText, "
        "literal PSCredential, password assignments, connection-string passwords, "
        "runas /savecred, DefaultPassword) -- one row per file -- and GPOs that "
        "deploy a credential-like registry value such as Winlogon DefaultPassword for "
        "AutoAdminLogon -- one row per GPO. Only pattern names and line numbers are "
        "collected, never the text, so review each file. Requires SYSVOL collection "
        "(adprofiler.py --sysvol)."
    ),
    "remediation": (
        "Treat each exposed password as compromised and reset it. Remove the secret "
        "from the file: map drives with the user's own credentials (or GPP Drive items "
        "without a password), run scheduled work as SYSTEM or a group Managed Service "
        "Account, and fetch secrets at run time from a vault rather than embedding "
        "them. For AutoAdminLogon remove the DefaultPassword setting from the GPO "
        "(and the value from affected computers) and use a kiosk / assigned-access "
        "configuration or LSA-secret based autologon (Sysinternals Autologon) only "
        "where truly required. Check older copies: search \\\\<domain>\\SYSVOL and "
        "\\\\<domain>\\NETLOGON (e.g. findstr /S /I /M password) and restrict write "
        "access to both shares to Tier 0 administrators."
    ),
    "base_severity": "high",
    "query": r"""
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS collected
        ),
        script AS (
            SELECT e.share, e.file_path, e.gpo_guid, e.size_bytes, e.credential_indicators,
                   (SELECT string_agg(DISTINCT split_part(x, ':', 1), ', '
                                      ORDER BY split_part(x, ':', 1))
                      FROM unnest(e.credential_indicators) AS x) AS patterns
            FROM sysvol_script_edge e
            CROSS JOIN sysvol sv
            WHERE sv.collected
              AND e.client_id = %(client_id)s
              AND e.valid_to IS NULL
              AND cardinality(e.credential_indicators) > 0
        ),
        script_rows AS (
            SELECT
                'fail' AS status,
                md5('9009:' || s.share || ':' || lower(s.file_path))::uuid AS object_guid,
                NULL AS stig_severity,
                NULL AS stig_reference,
                NULL AS tool_severity,
                NULL AS tool_reference,
                'high' AS fd_severity,
                s.share || ' file "' || s.file_path || '"'
                    || CASE WHEN s.gpo_guid IS NOT NULL
                            THEN ' (GPO "' || COALESCE(g.display_name, s.gpo_guid::text) || '")'
                            ELSE '' END
                    || ' contains credential patterns readable by every domain user: '
                    || COALESCE(s.patterns, '(unknown)') AS summary,
                jsonb_build_object(
                    'kind', 'script',
                    'share', s.share,
                    'file_path', s.file_path,
                    'size_bytes', s.size_bytes,
                    'credential_indicators', to_jsonb(s.credential_indicators),
                    'gpo_guid', g.gpo_guid,
                    'gpo_object_guid', s.gpo_guid,
                    'gpo_display_name', g.display_name,
                    'note', 'only pattern names and line numbers are collected; review the file to confirm'
                ) AS detail
            FROM script s
            LEFT JOIN ad_gpo g
              ON g.object_guid = s.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
        ),
        reg AS (
            SELECT r.gpo_guid, r.scope, r.section, r.setting_key, r.value_type
            FROM gpo_setting_edge r
            CROSS JOIN sysvol sv
            WHERE sv.collected
              AND r.client_id = %(client_id)s
              AND r.valid_to IS NULL
              AND r.source = 'registry'
              AND r.setting_value = '<redacted>'
        ),
        reg_gpo AS (
            SELECT r.gpo_guid,
                   count(*) AS value_count,
                   string_agg(r.section || '\' || r.setting_key, ', '
                              ORDER BY r.section, lower(r.setting_key), r.scope) AS paths,
                   jsonb_agg(jsonb_build_object(
                       'scope', r.scope, 'hive', r.section, 'value_path', r.setting_key,
                       'value_type', r.value_type)
                       ORDER BY r.section, lower(r.setting_key), r.scope) AS values_list
            FROM reg r
            GROUP BY r.gpo_guid
        ),
        reg_rows AS (
            SELECT
                'fail' AS status,
                rg.gpo_guid AS object_guid,
                NULL AS stig_severity,
                NULL AS stig_reference,
                NULL AS tool_severity,
                NULL AS tool_reference,
                'high' AS fd_severity,
                'GPO "' || COALESCE(g.display_name, d.dn_current) || '" deploys '
                    || rg.value_count || ' credential-like registry value(s) stored in SYSVOL: '
                    || rg.paths AS summary,
                jsonb_build_object(
                    'kind', 'registry_value',
                    'display_name', g.display_name,
                    'gpo_guid', g.gpo_guid,
                    'distinguished_name', d.dn_current,
                    'values', rg.values_list,
                    'has_enabled_link', EXISTS (
                        SELECT 1 FROM gpo_link_edge l
                        WHERE l.client_id = %(client_id)s AND l.gpo_guid = rg.gpo_guid
                          AND l.valid_to IS NULL AND l.link_enabled),
                    'note', 'values are redacted at collection; a redacted value may also be empty'
                ) AS detail
            FROM reg_gpo rg
            JOIN directory_object d
              ON d.object_guid = rg.gpo_guid AND d.client_id = %(client_id)s AND NOT d.is_deleted
            LEFT JOIN ad_gpo g
              ON g.object_guid = rg.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
        )
        SELECT * FROM script_rows
        UNION ALL
        SELECT * FROM reg_rows
    """,
}
