r"""
Plugin 9017: Print Spooler Not Disabled on Domain Controllers

Detects domain controllers whose effective Group Policy does not disable the
Print Spooler service (GptTmpl.inf [Service General Setting] "Spooler"
start mode: 2 automatic, 3 manual, 4 disabled).

Why it matters: the spooler on a DC is exposed to PrintNightmare
(CVE-2021-34527, CISA Emergency Directive 21-04) and to authentication
coercion through MS-RPRN (the "PrinterBug"): any domain user can make the DC
authenticate to an attacker host, which combined with unconstrained
delegation or NTLM relay (e.g. to AD CS web enrollment) gives domain
compromise (MITRE ATT&CK T1187). Microsoft recommends disabling the spooler
on domain controllers.

Results:
  * start mode 2 or 3 set by Group Policy -> fail, medium.
  * Not configured by any applying GPO -> warn, low ("not disabled by Group
    Policy; it may be disabled locally").
  * 4 -> not reported. Other values -> warn, low (unrecognised).
The service name is matched case-insensitively.

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

PLUGIN = {   'plugin_id': 9017,
    'category': 'Organizational Units',
    'name': 'Print Spooler Not Disabled on Domain Controllers',
    'version': '1.0',
    'revision_date': '2026-10-04',
    'control_id': 'GPO-9017',
    'framework_tags': [   'NIST-800-53-CM-6',
                          'NIST-CSF-2.0-PR.PS-01',
                          'PCI-DSS-4.0-2.2.1',
                          'CIS-CSC-8-4.1',
                          'ISO-27001-2022-A.8.9',
                          'SOC2-CC7.1',
                          'NIST-800-53-CM-7',
                          'PCI-DSS-4.0-2.2.4',
                          'CIS-CSC-8-4.8',
                          'NIST-800-53-SI-2',
                          'CVE-2021-34527',
                          'CISA-ED-21-04',
                          'MITRE-ATTCK-T1187'],
    'references': [   {   'title': 'Microsoft CVE-2021-34527: Windows Print Spooler Remote Code '
                                   'Execution (PrintNightmare)',
                          'url': 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-34527'},
                      {   'title': 'CISA Emergency Directive 21-04: Mitigate Windows Print Spooler '
                                   'Service Vulnerability',
                          'url': 'https://www.cisa.gov/news-events/directives/ed-21-04-mitigate-windows-print-spooler-service-vulnerability'},
                      {   'title': 'Microsoft Defender for Identity: Domain controllers with Print '
                                   'spooler service available',
                          'url': 'https://learn.microsoft.com/en-us/defender-for-identity/security-assessment-print-spooler'},
                      {   'title': 'Microsoft: Guidance on disabling system services on Windows '
                                   'Server',
                          'url': 'https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'},
                      {   'title': 'MITRE ATT&CK T1187: Forced Authentication',
                          'url': 'https://attack.mitre.org/techniques/T1187/'}],
    'description': 'The effective Group Policy of a domain controller does not disable the Print '
                   'Spooler service (set to automatic/manual, or not configured). The spooler on a '
                   'DC enables PrintNightmare and authentication coercion (PrinterBug).',
    'remediation': 'In a GPO linked to the Domain Controllers OU set Computer Configuration > '
                   'Policies > Windows Settings > Security Settings > System Services > Print '
                   'Spooler = Disabled, and remove any GPO setting it to Automatic/Manual for DCs. '
                   'Run gpupdate /force; verify on each DC with Get-Service Spooler | Select '
                   'Status,StartType (or immediately: Stop-Service Spooler; Set-Service Spooler '
                   '-StartupType Disabled). Make sure no DC is used as a print server.',
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
              AND e.source = 'security_template' AND e.section = 'Service General Setting'
              AND lower(e.setting_key) = lower('Spooler')
              AND e.value_type IS DISTINCT FROM 'DELETE'
        ),
        cls AS (
            SELECT d.*, e.setting_key, e.value_type, e.setting_value, e.winning_gpo_guid, e.precedence,
                   e.gpo_name, e.num, u.gpos AS unreadable_gpos,
                   (e.dc_guid IS NOT NULL) AS configured,
                   CASE WHEN e.dc_guid IS NULL THEN 'warn'
                        WHEN e.num = 4 THEN 'pass'
                        WHEN e.num = 2 THEN 'fail'
                        WHEN e.num = 3 THEN 'fail'
                        ELSE 'warn' END AS status,
                   CASE WHEN e.dc_guid IS NULL THEN 'low'
                        WHEN e.num = 4 THEN 'info'
                        WHEN e.num = 2 THEN 'medium'
                        WHEN e.num = 3 THEN 'medium'
                        ELSE 'low' END AS sev,
                   CASE WHEN e.dc_guid IS NULL THEN NULL
                        WHEN e.num = 4 THEN 'disabled'
                        WHEN e.num = 2 THEN 'automatic'
                        WHEN e.num = 3 THEN 'manual'
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
                'Domain controller ' || c.dc_name || ': the Print Spooler service is not disabled -- Spooler start mode = '
                    || COALESCE(c.setting_value, '(empty)') || ' (' || c.phrase || '), set by GPO '''
                    || COALESCE(c.gpo_name, c.winning_gpo_guid::text, '(unknown)') || ''''
            ELSE
                'Domain controller ' || c.dc_name || ': the Print Spooler service is not disabled by Group Policy -- Spooler start mode is not '
                    || 'configured by any GPO that applies to it, so the effective value is the OS default '
                    || 'or a local setting that cannot be seen (it may be disabled locally)'
                    || CASE WHEN c.unreadable_gpos IS NOT NULL
                            THEN '; uncertain: some GPOs applying to this DC could not be read from SYSVOL'
                            ELSE '' END
            END AS summary,
            jsonb_build_object(
                'domain_controller', c.dc_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'operating_system_version', c.operating_system_version,
                'setting', '[Service General Setting] Spooler (start mode)',
                'configured_by_group_policy', c.configured,
                'value', c.setting_value,
                'value_type', c.value_type,
                'winning_gpo_guid', c.winning_gpo_guid,
                'winning_gpo_name', c.gpo_name,
                'winning_gpo_precedence', c.precedence,
                'expected', '4 (disabled)',
                'unreadable_applying_gpos', COALESCE(c.unreadable_gpos, '[]'::jsonb)
            ) AS detail
        FROM cls c
        WHERE c.status IS DISTINCT FROM 'pass'
    """,
}
