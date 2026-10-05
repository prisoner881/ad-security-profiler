r"""
Plugin 9019: LSA Protection Not Enforced on Domain Controllers

Detects domain controllers whose effective Group Policy does not enable LSA
protection (LSASS as a protected process light,
HKLM\System\CurrentControlSet\Control\Lsa\RunAsPPL: 0 off, 1 on with UEFI
lock, 2 on without UEFI lock).

Why it matters: without LSA protection any administrator/SYSTEM process can
open LSASS and dump credentials (Mimikatz sekurlsa, comsvcs MiniDump); on a
DC that exposes the credentials of everyone who logged on to it (MITRE
ATT&CK T1003.001).

Results:
  * 0 explicitly -> fail, medium.
  * Not configured by any applying GPO -> warn, low (it may be enabled
    locally; Windows 11 22H2+ clients enable it by default, Windows Server
    does not).
  * 1 or 2 -> not reported. Other values -> warn, low (unrecognised).

Data: the winning machine-scope value of the setting on each domain
controller (v_dc_effective_gpo_setting, from the GPOs' SYSVOL contents and
the GPO links/precedence above the DC). Site-linked GPOs, WMI filters and
local policy are not visible. A value deleted by policy (value_type DELETE)
leaves the OS default and is treated as "not configured".

Gating: returns nothing unless SYSVOL has been collected for the client
(ad_gpo_sysvol has at least one 'ok' row); adaudit then shows NOT ASSESSED.
"Not configured" is reported as 'warn' ("not enforced by Group Policy"),
never as a claim about the DC's actual state. If a GPO applying to the DC
could not be read from SYSVOL, the "not configured" conclusion is flagged as
uncertain and the unreadable GPOs are listed in detail. One row per DC
(object_guid = the DC's computer object); read-only DCs are included.
"""

PLUGIN = {   'plugin_id': 9019,
    'category': 'Organizational Units',
    'name': 'LSA Protection Not Enforced on Domain Controllers',
    'version': '1.0',
    'revision_date': '2026-10-04',
    'control_id': 'GPO-9019',
    'framework_tags': [   'NIST-800-53-IA-5(1)',
                          'NIST-800-53-SC-28',
                          'NIST-CSF-2.0-PR.DS-01',
                          'PCI-DSS-4.0-8.3.2',
                          'CIS-CSC-8-3.11',
                          'ISO-27001-2022-A.5.17',
                          'SOC2-CC6.1',
                          'HIPAA-164.312(a)(2)(iv)',
                          'NIST-800-53-CM-6',
                          'NIST-CSF-2.0-PR.PS-01',
                          'CIS-CSC-8-4.1',
                          'ISO-27001-2022-A.8.9',
                          'MITRE-ATTCK-T1003.001'],
    'references': [   {   'title': 'Microsoft: Configure added LSA protection',
                          'url': 'https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection'},
                      {   'title': 'MITRE ATT&CK T1003.001: OS Credential Dumping: LSASS Memory',
                          'url': 'https://attack.mitre.org/techniques/T1003/001/'}],
    'description': 'The effective Group Policy of a domain controller does not enable LSA '
                   'protection (RunAsPPL is 0, or not configured), so LSASS memory on the DC can '
                   'be read by credential-dumping tools.',
    'remediation': 'Audit first: test with the LSA protection audit mode (CodeIntegrity events '
                   '3065/3066) that no required LSA plug-in or driver is blocked. Then in a GPO '
                   'linked to the Domain Controllers OU set Computer Configuration > '
                   "Administrative Templates > System > Local Security Authority > 'Configure "
                   "LSASS to run as a protected process' = Enabled with UEFI Lock (or set the "
                   'registry value HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1 via '
                   'Group Policy Preferences). Reboot the DCs and confirm System event 12 (LSASS '
                   'started as a protected process).',
    'base_severity': 'medium',
    'query': r"""
        WITH dc AS (
            -- Every current domain controller (RODCs included), only when
            -- SYSVOL has been collected for the client.
            SELECT c.object_guid AS dc_guid,
                   COALESCE(c.dns_hostname, c.sam_account_name, o.dn_current, c.object_guid::text) AS dc_name,
                   c.dns_hostname, c.operating_system, c.operating_system_version
            FROM ad_computer c
            JOIN directory_object o
              ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_domain_controller
              AND EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                          WHERE s.client_id = %(client_id)s AND s.read_status = 'ok')
        ),
        unreadable AS (
            -- GPOs applying to the DC whose SYSVOL folder could not be read:
            -- a "not configured" conclusion is then uncertain.
            SELECT x.dc_guid,
                   jsonb_agg(jsonb_build_object('gpo_guid', x.gpo_guid, 'display_name', x.display_name,
                                                'read_status', x.read_status)
                             ORDER BY x.gpo_guid) AS gpos
            FROM (
                SELECT DISTINCT a.dc_guid, a.gpo_guid, g.display_name,
                       COALESCE(s.read_status, 'not_collected') AS read_status
                FROM v_gpo_dc_application a
                LEFT JOIN ad_gpo_sysvol s
                  ON s.client_id = a.client_id AND s.gpo_object_guid = a.gpo_guid
                LEFT JOIN ad_gpo g
                  ON g.client_id = a.client_id AND g.object_guid = a.gpo_guid AND g.valid_to IS NULL
                WHERE a.client_id = %(client_id)s AND a.precedence IS NOT NULL
                  AND s.read_status IS DISTINCT FROM 'ok'
            ) x
            GROUP BY x.dc_guid
        ),
        eff AS (
            -- The winning value on each DC. A policy that deletes the value
            -- (value_type DELETE) leaves the OS default: treated as absent.
            SELECT e.dc_guid, e.setting_key, e.value_type, e.setting_value, e.winning_gpo_guid,
                   e.precedence, g.display_name AS gpo_name,
                   CASE WHEN e.setting_value ~ '^\s*[0-9]+\s*$'
                        THEN trim(e.setting_value)::numeric END AS num
            FROM v_dc_effective_gpo_setting e
            LEFT JOIN ad_gpo g
              ON g.client_id = e.client_id AND g.object_guid = e.winning_gpo_guid AND g.valid_to IS NULL
            WHERE e.client_id = %(client_id)s
              AND e.source = 'registry' AND e.section = 'HKLM'
              AND lower(e.setting_key) = lower('System\CurrentControlSet\Control\Lsa\RunAsPPL')
              AND e.value_type IS DISTINCT FROM 'DELETE'
        ),
        cls AS (
            SELECT d.*, e.setting_key, e.value_type, e.setting_value, e.winning_gpo_guid, e.precedence,
                   e.gpo_name, e.num, u.gpos AS unreadable_gpos,
                   (e.dc_guid IS NOT NULL) AS configured,
                   CASE WHEN e.dc_guid IS NULL THEN 'warn'
                        WHEN e.num IN (1, 2) THEN 'pass'
                        WHEN e.num = 0 THEN 'fail'
                        ELSE 'warn' END AS status,
                   CASE WHEN e.dc_guid IS NULL THEN 'low'
                        WHEN e.num IN (1, 2) THEN 'info'
                        WHEN e.num = 0 THEN 'medium'
                        ELSE 'low' END AS sev,
                   CASE WHEN e.dc_guid IS NULL THEN NULL
                        WHEN e.num IN (1, 2) THEN 'enabled'
                        WHEN e.num = 0 THEN 'disabled'
                        ELSE 'has an unrecognised value' END AS phrase
            FROM dc d
            LEFT JOIN eff e ON e.dc_guid = d.dc_guid
            LEFT JOIN unreadable u ON u.dc_guid = d.dc_guid
        )
        SELECT
            c.status,
            c.dc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            c.sev AS fd_severity,
            CASE WHEN c.configured THEN
                'Domain controller ' || c.dc_name || ': LSA protection is disabled -- RunAsPPL = '
                    || COALESCE(c.setting_value, '(empty)') || ' (' || c.phrase || '), set by GPO '''
                    || COALESCE(c.gpo_name, c.winning_gpo_guid::text, '(unknown)') || ''''
            ELSE
                'Domain controller ' || c.dc_name || ': LSA protection is not enforced by Group Policy -- RunAsPPL is not '
                    || 'configured by any GPO that applies to it, so the effective value is the OS default '
                    || 'or a local setting that cannot be seen (it may be enabled locally)'
                    || CASE WHEN c.unreadable_gpos IS NOT NULL
                            THEN '; uncertain: some GPOs applying to this DC could not be read from SYSVOL'
                            ELSE '' END
            END AS summary,
            jsonb_build_object(
                'domain_controller', c.dc_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'operating_system_version', c.operating_system_version,
                'setting', 'HKLM\System\CurrentControlSet\Control\Lsa\RunAsPPL',
                'configured_by_group_policy', c.configured,
                'value', c.setting_value,
                'value_type', c.value_type,
                'winning_gpo_guid', c.winning_gpo_guid,
                'winning_gpo_name', c.gpo_name,
                'winning_gpo_precedence', c.precedence,
                'expected', '1 (enabled with UEFI lock) or 2 (enabled without UEFI lock)',
                'unreadable_applying_gpos', COALESCE(c.unreadable_gpos, '[]'::jsonb)
            ) AS detail
        FROM cls c
        WHERE c.status IS DISTINCT FROM 'pass'
    """,
}
