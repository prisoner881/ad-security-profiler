"""
Plugin 9008: Group Policy Preferences Password (cpassword) in SYSVOL

Reports every GPO whose SYSVOL folder holds a Group Policy Preferences item
(Groups.xml, ScheduledTasks.xml, Services.xml, DataSources.xml, Drives.xml,
Printers.xml) carrying a cpassword attribute.

Why: Group Policy Preferences encrypted these passwords with AES-256 using a
key Microsoft published in MS-GPPREF, so anyone who can read SYSVOL -- every
authenticated domain user and computer -- can decrypt them (MS14-025,
CVE-2014-1812; MITRE ATT&CK T1552.006). The 2014 update only stopped new
passwords being saved through the GPMC UI; existing XML files keep theirs
until someone deletes them. The password is usually a local administrator,
service or scheduled-task account and is often reused.

Scope: every GPO, linked or not -- an unlinked GPO's files are on SYSVOL
and just as readable. Severity is critical for all of them; detail says
whether the GPO is linked and whether it applies to a domain controller.

Data: gpo_preference_item_edge.has_cpassword (the collector never stores
or decrypts the value). One row per GPO listing preference types, item
names and account names only. Zero rows unless SYSVOL has been collected
for the client (adprofiler.py --sysvol). A GPO whose folder could not be
read at the last SYSVOL collection keeps its previously collected items
(the collector carries them forward), so a cpassword seen earlier is still
reported; plugin 9021 lists unreadable GPO folders.
"""

PLUGIN = {
    "plugin_id": 9008,
    "category": "Organizational Units",
    "name": "Group Policy Preferences Password (cpassword) in SYSVOL",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-9008",
    "framework_tags": [
        "NIST-800-53-IA-5(1)", "NIST-800-53-SC-28", "NIST-CSF-2.0-PR.DS-01",
        "PCI-DSS-4.0-8.3.2", "PCI-DSS-4.0-8.6.2", "CIS-CSC-8-3.11",
        "ISO-27001-2022-A.5.17", "SOC2-CC6.1", "HIPAA-164.312(a)(2)(iv)",
        "NIST-800-53-SI-2", "NIST-800-53-RA-5", "NIST-CSF-2.0-ID.RA-01",
        "PCI-DSS-4.0-6.3.3", "CIS-CSC-8-7.3", "ISO-27001-2022-A.8.8", "SOC2-CC7.1",
        "CVE-2014-1812",
        "MITRE-ATTCK-T1552.006",
    ],
    "references": [
        {"title": "Microsoft Security Bulletin MS14-025: Vulnerability in Group Policy Preferences could allow elevation of privilege",
         "url": "https://learn.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-025"},
        {"title": "NVD: CVE-2014-1812",
         "url": "https://nvd.nist.gov/vuln/detail/CVE-2014-1812"},
        {"title": "MITRE ATT&CK T1552.006: Unsecured Credentials: Group Policy Preferences",
         "url": "https://attack.mitre.org/techniques/T1552/006/"},
    ],
    "description": (
        "Reports GPOs whose SYSVOL folder contains a Group Policy Preferences item "
        "(local user or group, scheduled task, service, data source, mapped drive or "
        "printer) with a cpassword. The value is AES-encrypted with a key Microsoft "
        "published, so every domain user can read SYSVOL and decrypt it (MS14-025, "
        "CVE-2014-1812). Linked and unlinked GPOs are reported alike, because the file "
        "is readable either way. One row per GPO, listing the preference types, item "
        "names and account names; the password itself is never collected. Requires "
        "SYSVOL collection (adprofiler.py --sysvol)."
    ),
    "remediation": (
        "Treat every listed account's password as compromised: reset it now (for a "
        "local Administrator account, deploy Windows LAPS instead of a shared "
        "password). Then remove the cpassword from SYSVOL: in Group Policy Management "
        "Editor delete the preference item (or replace it -- e.g. a scheduled task "
        "running as SYSTEM or a gMSA, a service using a gMSA), or delete the XML file "
        "from \\\\<domain>\\SYSVOL\\<domain>\\Policies\\{GUID}\\Machine|User\\Preferences. "
        "Check that no backup copy remains anywhere on SYSVOL: "
        "findstr /S /I cpassword \\\\<domain>\\sysvol\\<domain>\\policies\\*.xml. "
        "Make sure KB2962486 (MS14-025) is installed on administrative workstations so "
        "new passwords cannot be saved."
    ),
    "base_severity": "critical",
    "query": """
        WITH sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS collected
        ),
        item AS (
            SELECT p.gpo_guid, p.scope, p.preference_type, p.item_name, p.account_name,
                   p.action, p.item_uid
            FROM gpo_preference_item_edge p
            CROSS JOIN sysvol sv
            WHERE sv.collected
              AND p.client_id = %(client_id)s
              AND p.valid_to IS NULL
              AND p.has_cpassword
        ),
        per_gpo AS (
            SELECT i.gpo_guid,
                   count(*) AS item_count,
                   string_agg(DISTINCT i.preference_type, ', ' ORDER BY i.preference_type) AS types,
                   string_agg(DISTINCT i.account_name, ', ' ORDER BY i.account_name) AS accounts,
                   string_agg(DISTINCT i.item_name, ', ' ORDER BY i.item_name) AS item_names,
                   jsonb_agg(jsonb_build_object(
                       'scope', i.scope, 'preference_type', i.preference_type,
                       'item_name', i.item_name, 'account_name', i.account_name,
                       'action', i.action)
                       ORDER BY i.scope, i.preference_type, i.item_name, i.account_name, i.item_uid) AS items
            FROM item i
            GROUP BY i.gpo_guid
        )
        SELECT
            'fail' AS status,
            p.gpo_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'GPO "' || COALESCE(g.display_name, d.dn_current) || '" stores '
                || p.item_count || ' Group Policy Preferences password(s) (cpassword, '
                || 'decryptable by any domain user) in SYSVOL: '
                || p.types || ' item(s) '
                || COALESCE(p.item_names, '(unnamed)')
                || COALESCE('; account(s): ' || p.accounts, '') AS summary,
            jsonb_build_object(
                'display_name', g.display_name,
                'gpo_guid', g.gpo_guid,
                'distinguished_name', d.dn_current,
                'sysvol_path', gs.sysvol_path,
                'sysvol_read_status', gs.read_status,
                'items', p.items,
                'has_enabled_link', EXISTS (
                    SELECT 1 FROM gpo_link_edge l
                    WHERE l.client_id = %(client_id)s AND l.gpo_guid = p.gpo_guid
                      AND l.valid_to IS NULL AND l.link_enabled),
                'applies_to_domain_controller', EXISTS (
                    SELECT 1 FROM v_gpo_dc_application a
                    WHERE a.client_id = %(client_id)s AND a.gpo_guid = p.gpo_guid
                      AND a.precedence IS NOT NULL),
                'note', 'cpassword values are never collected; every listed account''s password must be considered disclosed'
            ) AS detail
        FROM per_gpo p
        JOIN directory_object d
          ON d.object_guid = p.gpo_guid AND d.client_id = %(client_id)s AND NOT d.is_deleted
        LEFT JOIN ad_gpo g
          ON g.object_guid = p.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
        LEFT JOIN ad_gpo_sysvol gs
          ON gs.gpo_object_guid = p.gpo_guid AND gs.client_id = %(client_id)s
    """,
}
