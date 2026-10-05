r"""
Plugin 9012: SMB Signing Not Required on Domain Controllers

Detects domain controllers whose effective Group Policy does not require SMB
server signing ("Microsoft network server: Digitally sign communications
(always)",
HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature).

Why it matters: without required SMB signing, NTLM authentication coerced
from another machine (PetitPotam, PrinterBug, ...) can be relayed to the DC's
SMB service, and SMB sessions can be tampered with (MITRE ATT&CK T1557.001).
The Default Domain Controllers Policy sets this to Enabled out of the box.

Results:
  * 0 explicitly -> fail, high.
  * Not configured by any applying GPO -> warn, medium (normally the Default
    Domain Controllers Policy sets it; Windows Server 2025 requires SMB
    signing by default, older versions don't on their own).
  * 1 -> not reported. Other values -> warn, medium (unrecognised).

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

PLUGIN = {   'plugin_id': 9012,
    'category': 'Organizational Units',
    'name': 'SMB Signing Not Required on Domain Controllers',
    'version': '1.0',
    'revision_date': '2026-10-04',
    'control_id': 'GPO-9012',
    'framework_tags': [   'NIST-800-53-CM-6',
                          'NIST-CSF-2.0-PR.PS-01',
                          'PCI-DSS-4.0-2.2.1',
                          'CIS-CSC-8-4.1',
                          'ISO-27001-2022-A.8.9',
                          'SOC2-CC7.1',
                          'NIST-CSF-2.0-PR.DS-02',
                          'CIS-CSC-8-3.10',
                          'DISA-STIG',
                          'MITRE-ATTCK-T1557.001'],
    'references': [   {   'title': 'Microsoft: Overview of Server Message Block signing',
                          'url': 'https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/overview-server-message-block-signing'},
                      {   'title': 'Microsoft: Microsoft network server: Digitally sign '
                                   'communications (always)',
                          'url': 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/microsoft-network-server-digitally-sign-communications-always'},
                      {   'title': 'MITRE ATT&CK T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay',
                          'url': 'https://attack.mitre.org/techniques/T1557/001/'}],
    'description': 'The effective Group Policy of a domain controller does not require SMB signing '
                   '(RequireSecuritySignature is 0, or not configured). NTLM authentication can be '
                   'relayed to the DC over SMB.',
    'remediation': 'In the Default Domain Controllers Policy (or a GPO linked to the Domain '
                   "Controllers OU with higher precedence) set Security Options > 'Microsoft "
                   "network server: Digitally sign communications (always)' = Enabled; remove any "
                   'GPO that sets it to Disabled. Run gpupdate /force on the DCs and verify with '
                   'Get-SmbServerConfiguration | Select RequireSecuritySignature.',
    'base_severity': 'high',
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
              AND lower(e.setting_key) = lower('System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature')
              AND e.value_type IS DISTINCT FROM 'DELETE'
        ),
        cls AS (
            SELECT d.*, e.setting_key, e.value_type, e.setting_value, e.winning_gpo_guid, e.precedence,
                   e.gpo_name, e.num, u.gpos AS unreadable_gpos,
                   (e.dc_guid IS NOT NULL) AS configured,
                   CASE WHEN e.dc_guid IS NULL THEN 'warn'
                        WHEN e.num = 1 THEN 'pass'
                        WHEN e.num = 0 THEN 'fail'
                        ELSE 'warn' END AS status,
                   CASE WHEN e.dc_guid IS NULL THEN 'medium'
                        WHEN e.num = 1 THEN 'info'
                        WHEN e.num = 0 THEN 'high'
                        ELSE 'medium' END AS sev,
                   CASE WHEN e.dc_guid IS NULL THEN NULL
                        WHEN e.num = 1 THEN 'required'
                        WHEN e.num = 0 THEN 'signing not required'
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
                'Domain controller ' || c.dc_name || ': SMB signing is not required -- RequireSecuritySignature = '
                    || COALESCE(c.setting_value, '(empty)') || ' (' || c.phrase || '), set by GPO '''
                    || COALESCE(c.gpo_name, c.winning_gpo_guid::text, '(unknown)') || ''''
            ELSE
                'Domain controller ' || c.dc_name || ': SMB signing is not enforced by Group Policy -- RequireSecuritySignature is not '
                    || 'configured by any GPO that applies to it, so the effective value is the OS default '
                    || 'or a local setting that cannot be seen (the Default Domain Controllers Policy normally sets it; Windows Server 2025 requires it by default)'
                    || CASE WHEN c.unreadable_gpos IS NOT NULL
                            THEN '; uncertain: some GPOs applying to this DC could not be read from SYSVOL'
                            ELSE '' END
            END AS summary,
            jsonb_build_object(
                'domain_controller', c.dc_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'operating_system_version', c.operating_system_version,
                'setting', 'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\RequireSecuritySignature',
                'configured_by_group_policy', c.configured,
                'value', c.setting_value,
                'value_type', c.value_type,
                'winning_gpo_guid', c.winning_gpo_guid,
                'winning_gpo_name', c.gpo_name,
                'winning_gpo_precedence', c.precedence,
                'expected', '1 (required)',
                'unreadable_applying_gpos', COALESCE(c.unreadable_gpos, '[]'::jsonb)
            ) AS detail
        FROM cls c
        WHERE c.status IS DISTINCT FROM 'pass'
    """,
}
