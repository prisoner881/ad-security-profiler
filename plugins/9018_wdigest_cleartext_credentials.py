r"""
Plugin 9018: WDigest Stores Cleartext Credentials

Detects Group Policy Objects that set
HKLM\System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential
= 1, which makes the WDigest security package keep users' passwords in
cleartext in LSASS memory on every computer the GPO applies to.

Why it matters: since KB2871997 (Microsoft Security Advisory 2871997) and
Windows 8.1 / Server 2012 R2, WDigest no longer caches cleartext passwords
unless this value is 1. Turning it back on (sometimes done for legacy
applications, and also by attackers) lets anyone with admin/SYSTEM on an
affected machine read the cleartext passwords of everyone logged on to it
with Mimikatz (sekurlsa::wdigest) -- on a domain controller, the passwords
of domain admins (MITRE ATT&CK T1003.001).

Detection (one row per GPO, object_guid = the GPO):
  * an open gpo_setting_edge row, scope 'machine', source 'registry',
    section 'HKLM', key compared case-insensitively, value 1 (value_type
    not DELETE);
  * the GPO has at least one enabled link (gpo_link_edge.link_enabled) --
    the setting applies to whatever the GPO reaches, not only DCs, so it is
    read from the GPO itself rather than from the per-DC effective policy;
  * excluded: GPOs whose computer settings are disabled (gpo_flags 2 or 3),
    since their machine settings apply nowhere.
Severity: critical when the GPO applies to at least one domain controller
(v_gpo_dc_application precedence NOT NULL), high otherwise. Detail lists the
enabled links and the DCs it applies to, and on which DCs it is the winning
value. A higher-precedence GPO setting 0 can override it on some machines;
that is not evaluated for non-DC computers (their OU position is not
resolved), so the finding stands for the GPO.

Gating: returns nothing unless SYSVOL has been collected for the client
(ad_gpo_sysvol has an 'ok' row).
"""

PLUGIN = {
    "plugin_id": 9018,
    "category": "Organizational Units",
    "name": "WDigest Stores Cleartext Credentials",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-9018",
    "framework_tags": [
        "NIST-800-53-IA-5(1)", "NIST-800-53-SC-28", "NIST-CSF-2.0-PR.DS-01", "PCI-DSS-4.0-8.3.2",
        "CIS-CSC-8-3.11", "ISO-27001-2022-A.5.17", "SOC2-CC6.1", "HIPAA-164.312(a)(2)(iv)",
        "NIST-800-53-CM-6", "CIS-CSC-8-4.1", "ISO-27001-2022-A.8.9",
        "DISA-STIG", "MITRE-ATTCK-T1003.001",
    ],
    "references": [
        {"title": "Microsoft Security Advisory 2871997: Update to improve credentials protection and management",
         "url": "https://learn.microsoft.com/en-us/security-updates/securityadvisories/2014/2871997"},
        {"title": "MITRE ATT&CK T1003.001: OS Credential Dumping: LSASS Memory",
         "url": "https://attack.mitre.org/techniques/T1003/001/"},
    ],
    "description": (
        "A linked GPO sets WDigest UseLogonCredential = 1, so computers it applies to keep users' "
        "passwords in cleartext in LSASS memory, readable by anyone with local admin rights."
    ),
    "remediation": (
        "Remove the UseLogonCredential value from the GPO (or set it to 0): in Group Policy "
        "Management edit the GPO and delete the registry setting / Group Policy Preferences item, "
        "or with the MS Security Guide ADMX set 'WDigest Authentication (disabling may require "
        "KB2871997)' = Disabled. Run gpupdate /force and verify on affected machines with "
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' "
        "-Name UseLogonCredential. Cleartext passwords already cached stay in memory until the "
        "users log off or the machine reboots: reboot affected servers and, if compromise is "
        "suspected, reset the passwords of accounts that logged on to them (especially on DCs)."
    ),
    "base_severity": "critical",
    "query": r"""
        WITH gpo AS (
            SELECT g.object_guid, g.display_name, g.gpo_guid, g.gpo_flags
            FROM ad_gpo g
            JOIN directory_object o
              ON o.object_guid = g.object_guid AND o.client_id = g.client_id AND NOT o.is_deleted
            WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL
              AND (g.gpo_flags IS NULL OR (g.gpo_flags & 2) = 0)
              AND EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                          WHERE s.client_id = %(client_id)s AND s.read_status = 'ok')
        ),
        hit AS (
            SELECT DISTINCT ON (s.gpo_guid) s.gpo_guid, s.setting_key, s.value_type, s.setting_value
            FROM gpo_setting_edge s
            JOIN gpo g ON g.object_guid = s.gpo_guid
            WHERE s.client_id = %(client_id)s AND s.valid_to IS NULL
              AND s.scope = 'machine' AND s.source = 'registry' AND s.section = 'HKLM'
              AND lower(s.setting_key) = lower('System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential')
              AND s.value_type IS DISTINCT FROM 'DELETE'
              AND s.setting_value ~ '^\s*0*1\s*$'
            ORDER BY s.gpo_guid, s.edge_id
        ),
        links AS (
            SELECT l.gpo_guid,
                   jsonb_agg(jsonb_build_object('container', COALESCE(o.dn_current, l.container_guid::text),
                                                'enforced', l.link_enforced)
                             ORDER BY COALESCE(o.dn_current, l.container_guid::text)) AS links
            FROM gpo_link_edge l
            JOIN hit h ON h.gpo_guid = l.gpo_guid
            LEFT JOIN directory_object o
              ON o.object_guid = l.container_guid AND o.client_id = l.client_id
            WHERE l.client_id = %(client_id)s AND l.valid_to IS NULL AND l.link_enabled
            GROUP BY l.gpo_guid
        ),
        dcs AS (
            SELECT x.gpo_guid,
                   jsonb_agg(jsonb_build_object('domain_controller', x.dc_name, 'precedence', x.precedence,
                                                'winning_value_here', x.wins)
                             ORDER BY x.dc_name) AS dcs
            FROM (
                SELECT a.gpo_guid, a.dc_guid, min(a.precedence) AS precedence,
                       COALESCE(c.dns_hostname, c.sam_account_name, a.dc_guid::text) AS dc_name,
                       EXISTS (SELECT 1 FROM v_dc_effective_gpo_setting e
                               WHERE e.client_id = a.client_id AND e.dc_guid = a.dc_guid
                                 AND e.winning_gpo_guid = a.gpo_guid AND e.source = 'registry'
                                 AND e.section = 'HKLM'
                                 AND lower(e.setting_key) = lower('System\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential')) AS wins
                FROM v_gpo_dc_application a
                JOIN hit h ON h.gpo_guid = a.gpo_guid
                LEFT JOIN ad_computer c
                  ON c.object_guid = a.dc_guid AND c.client_id = a.client_id AND c.valid_to IS NULL
                WHERE a.client_id = %(client_id)s AND a.precedence IS NOT NULL
                GROUP BY a.client_id, a.gpo_guid, a.dc_guid, c.dns_hostname, c.sam_account_name
            ) x
            GROUP BY x.gpo_guid
        )
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN d.dcs IS NOT NULL THEN 'critical' ELSE 'high' END AS fd_severity,
            'GPO ''' || COALESCE(g.display_name, g.object_guid::text) || ''' sets WDigest '
                || 'UseLogonCredential = 1, so cleartext passwords are kept in LSASS memory on the computers '
                || 'it applies to'
                || CASE WHEN d.dcs IS NOT NULL THEN ', including domain controllers' ELSE '' END AS summary,
            jsonb_build_object(
                'gpo_name', g.display_name,
                'gpo_guid', upper(g.gpo_guid::text),
                'setting', 'HKLM\' || h.setting_key,
                'value', h.setting_value,
                'value_type', h.value_type,
                'enabled_links', l.links,
                'applies_to_domain_controllers', COALESCE(d.dcs, '[]'::jsonb)
            ) AS detail
        FROM hit h
        JOIN gpo g ON g.object_guid = h.gpo_guid
        JOIN links l ON l.gpo_guid = h.gpo_guid
        LEFT JOIN dcs d ON d.gpo_guid = h.gpo_guid
    """,
}
