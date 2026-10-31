r"""
Plugin 5020: Display Specifier Admin Context Menu Runs a Program Outside SYSVOL

Reports display specifiers (CN=DisplaySpecifiers in the configuration
partition) whose adminContextMenu adds a menu entry that runs a PROGRAM --
an entry of the form "<order>,<menu text>,<command>" -- rather than the
built-in COM extensions ("<order>,{CLSID}"), which are not reported. One row
per display specifier (object_guid = the display specifier object).

Why it matters: administrative consoles (Active Directory Users and
Computers and the other MMC snap-ins) show these entries on the right-click
menu of every object of that class and run the command as the
administrator who clicks it. Whoever can modify the command's target --
a file share, a web server, a workstation path -- runs code as a domain
admin (PingCastle P-DisplaySpecifier). A command on the domain's own SYSVOL
or NETLOGON share is protected like Group Policy files and is reported only
for inventory.

Windows defaults are not reported: every forest has a "Manage..." entry
running RsAdmin.msc (Remote Storage) on remoteStorageServicePoint-Display,
once per installed language.

Classification of the command (first token, quotes removed):
  * UNC path outside SYSVOL/NETLOGON, or an http(s):// URL -> high (fail)
  * anything else (local path, bare program name)          -> low: it runs
    from each administrator's own machine, so changing it already takes
    admin rights there; reported because it is not a Windows default.
  * UNC path on \\<domain>\SYSVOL or \\<domain>\NETLOGON  -> info (inventory)

Data: ad_display_specifier.admin_context_menu (JSON array of the attribute's
values), ad_domain.dns_root and netbios_name, and the domain controllers'
names.

[v1.2] dead reference link replaced; no query change.

[v1.3] A program on SYSVOL or NETLOGON reached through the domain's NetBIOS
name or a domain controller's name (\\CORP\SYSVOL\..., \\dc01\NETLOGON\...)
counts as SYSVOL, like the DNS name; it was rated as an outside UNC path.
"""

PLUGIN = {
    "plugin_id": 5020,
    "category": "ACLs",
    "name": "Display Specifier Admin Context Menu Runs a Program Outside SYSVOL",
    "version": "1.3",
    "revision_date": "2026-10-30",
    "control_id": "ACL-5020",
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
        "MITRE-ATTCK-T1546",
        "MITRE-ATTCK-T1484",
    ],
    "references": [
        {"title": "Microsoft: Registering the Context Menu COM Object in a Display Specifier (adminContextMenu)",
         "url": "https://learn.microsoft.com/en-us/windows/win32/ad/registering-the-context-menu-com-object-in-a-display-specifier"},
        {"title": "Microsoft: Admin-Context-Menu attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-admincontextmenu"},
        {"title": "PingCastle health check rules (P-DisplaySpecifier)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1546: Event Triggered Execution",
         "url": "https://attack.mitre.org/techniques/T1546/"},
    ],
    "description": (
        "A display specifier's adminContextMenu adds a right-click entry to "
        "the AD administration consoles that runs a program, and the program "
        "is not on the domain's SYSVOL/NETLOGON share. It runs as the "
        "administrator who clicks it, so whoever controls its location runs "
        "code as a domain admin. High for other UNC paths and URLs, low "
        "for local paths, info for SYSVOL-hosted programs. The Windows "
        "default RsAdmin.msc entry is not reported."
    ),
    "remediation": (
        "Review the entry with ADSI Edit (Configuration > CN=DisplaySpecifiers "
        "> CN=<locale> > the display specifier > adminContextMenu). Remove it "
        "if it is not needed. If it is, move the program to the domain's "
        "NETLOGON share, whose permissions only Tier 0 can change, and point "
        "the entry there."
    ),
    "base_severity": "high",
    "query": r"""
        WITH
        -- [v1.3] names that reach this domain's SYSVOL: the DNS name, the
        -- NetBIOS name and each domain controller (FQDN or short name)
        dom_host AS (
            SELECT lower(m.dns_root) AS h FROM ad_domain m
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL AND m.dns_root IS NOT NULL
            UNION
            SELECT lower(m.netbios_name) FROM ad_domain m
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL AND m.netbios_name IS NOT NULL
            UNION
            SELECT lower(c.dns_hostname) FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_domain_controller
              AND c.dns_hostname IS NOT NULL
            UNION
            SELECT lower(rtrim(c.sam_account_name, '$')) FROM ad_computer c
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_domain_controller
              AND c.sam_account_name IS NOT NULL
        ),
        entry AS (
            SELECT d.object_guid, d.schema_cn, o.dn_current, e.value AS raw,
                   split_part(e.value, ',', 1) AS ord,
                   split_part(e.value, ',', 2) AS label,
                   btrim(substr(e.value, length(split_part(e.value, ',', 1))
                                       + length(split_part(e.value, ',', 2)) + 3)) AS command
            FROM ad_display_specifier d
            JOIN directory_object o
              ON o.object_guid = d.object_guid AND o.client_id = d.client_id AND NOT o.is_deleted
            CROSS JOIN LATERAL jsonb_array_elements_text(
                CASE WHEN jsonb_typeof(d.admin_context_menu::jsonb) = 'array'
                     THEN d.admin_context_menu::jsonb ELSE '[]'::jsonb END) AS e(value)
            WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
              AND d.admin_context_menu IS NOT NULL
        ),
        program AS (
            SELECT e.*,
                   lower(CASE WHEN left(btrim(e.command), 1) = '"'
                              THEN split_part(substr(btrim(e.command), 2), '"', 1)
                              ELSE split_part(btrim(e.command), ' ', 1) END) AS target
            FROM entry e
            WHERE btrim(e.command) <> ''
              AND btrim(e.label) !~ '^\{[0-9A-Fa-f-]{36}\}$'
        ),
        classified AS (
            SELECT p.*,
                   CASE WHEN p.target ~ '^\\\\' THEN
                            CASE WHEN split_part(substr(p.target, 3), '\', 2) IN ('sysvol', 'netlogon')
                                      AND split_part(substr(p.target, 3), '\', 3) <> ''
                                      AND split_part(substr(p.target, 3), '\', 1) IN (SELECT h FROM dom_host)
                                 THEN 'sysvol' ELSE 'unc' END
                        WHEN p.target ~ '^https?://' THEN 'url'
                        ELSE 'local' END AS location
            FROM program p
            -- Windows default (Remote Storage), present in every forest
            WHERE NOT (lower(COALESCE(p.schema_cn, '')) = 'remotestorageservicepoint-display'
                       AND COALESCE(p.target, '') = 'rsadmin.msc')
        )
        SELECT
            CASE WHEN bool_or(c.location IN ('unc', 'url')) THEN 'fail' ELSE 'warn' END AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_or(c.location IN ('unc', 'url')) THEN 'high'
                 WHEN bool_or(c.location = 'local') THEN 'low'
                 ELSE 'info' END AS fd_severity,
            'Display specifier ' || COALESCE(c.schema_cn, c.dn_current)
                || ' adds admin context-menu program(s) run by administrators: '
                || string_agg('"' || c.label || '" -> ' || c.command
                              || CASE c.location WHEN 'sysvol' THEN ' (SYSVOL)'
                                                 WHEN 'unc' THEN ' (outside SYSVOL)'
                                                 WHEN 'url' THEN ' (web location)'
                                                 ELSE ' (local path on the admin''s machine)' END,
                              '; ' ORDER BY c.ord, c.label) AS summary,
            jsonb_build_object(
                'display_specifier', c.schema_cn,
                'distinguished_name', c.dn_current,
                'entries', jsonb_agg(jsonb_build_object('order', c.ord, 'label', c.label,
                                                        'command', c.command, 'location', c.location)
                                     ORDER BY c.ord, c.label)
            ) AS detail
        FROM classified c
        GROUP BY c.object_guid, c.schema_cn, c.dn_current
    """,
}
