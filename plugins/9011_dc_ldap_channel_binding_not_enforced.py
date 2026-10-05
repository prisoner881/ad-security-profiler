r"""
Plugin 9011: LDAP Channel Binding Not Enforced on Domain Controllers

Detects domain controllers whose effective Group Policy does not enforce
LDAP channel binding tokens ("Domain controller: LDAP server channel binding
token requirements",
HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding:
0 = never, 1 = when supported, 2 = always).

Why it matters: LDAP signing does not protect LDAPS (TLS) binds; without
channel binding an attacker can relay NTLM authentication to LDAPS on the DC
(CVE-2017-8563, Microsoft ADV190023 / KB4520412; MITRE ATT&CK T1557).

Results:
  * 0 (never) -> fail, medium.
  * 1 (when supported) -> warn, low: clients that don't send a channel
    binding token (unpatched or legacy) are still accepted.
  * Not configured by any applying GPO -> warn, medium (Windows defaults
    differ by version and update level; Windows Server 2025 defaults to
    "when supported").
  * 2 -> not reported. Other values -> warn, medium (unrecognised).

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

PLUGIN = {   'plugin_id': 9011,
    'category': 'Organizational Units',
    'name': 'LDAP Channel Binding Not Enforced on Domain Controllers',
    'version': '1.0',
    'revision_date': '2026-10-04',
    'control_id': 'GPO-9011',
    'framework_tags': [   'NIST-800-53-CM-6',
                          'NIST-CSF-2.0-PR.PS-01',
                          'PCI-DSS-4.0-2.2.1',
                          'CIS-CSC-8-4.1',
                          'ISO-27001-2022-A.8.9',
                          'SOC2-CC7.1',
                          'NIST-CSF-2.0-PR.DS-02',
                          'CIS-CSC-8-3.10',
                          'DISA-STIG',
                          'MITRE-ATTCK-T1557',
                          'CVE-2017-8563'],
    'references': [   {   'title': 'Microsoft ADV190023: Guidance for enabling LDAP channel '
                                   'binding and LDAP signing',
                          'url': 'https://msrc.microsoft.com/update-guide/vulnerability/ADV190023'},
                      {   'title': 'Microsoft KB4520412: LDAP channel binding and LDAP signing '
                                   'requirements for Windows',
                          'url': 'https://support.microsoft.com/en-us/topic/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412-ef185fb8-00f7-167d-744c-f299a66fc00a'},
                      {   'title': 'Microsoft CVE-2017-8563: Windows Elevation of Privilege '
                                   'Vulnerability (LDAP relay)',
                          'url': 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2017-8563'},
                      {   'title': 'NVD: CVE-2017-8563',
                          'url': 'https://nvd.nist.gov/vuln/detail/CVE-2017-8563'},
                      {   'title': 'MITRE ATT&CK T1557: Adversary-in-the-Middle',
                          'url': 'https://attack.mitre.org/techniques/T1557/'}],
    'description': 'The effective Group Policy of a domain controller does not set LDAP channel '
                   "binding to 'Always' (LdapEnforceChannelBinding is 0/1, or not configured). "
                   'NTLM authentication can then be relayed to LDAPS.',
    'remediation': "Install current updates on DCs and clients. Set the policy to 'When supported' "
                   'first and monitor Directory Service event 3039 (clients failing channel '
                   'binding) and 3040/3041; fix the reported clients. Then in a GPO linked to the '
                   "Domain Controllers OU set Security Options > 'Domain controller: LDAP server "
                   "channel binding token requirements' = 'Always' (LdapEnforceChannelBinding = "
                   '2), run gpupdate /force and verify with Get-ItemProperty '
                   "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters' -Name "
                   'LdapEnforceChannelBinding.',
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
              AND lower(e.setting_key) = lower('System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding')
              AND e.value_type IS DISTINCT FROM 'DELETE'
        ),
        cls AS (
            SELECT d.*, e.setting_key, e.value_type, e.setting_value, e.winning_gpo_guid, e.precedence,
                   e.gpo_name, e.num, u.gpos AS unreadable_gpos,
                   (e.dc_guid IS NOT NULL) AS configured,
                   CASE WHEN e.dc_guid IS NULL THEN 'warn'
                        WHEN e.num = 2 THEN 'pass'
                        WHEN e.num = 1 THEN 'warn'
                        WHEN e.num = 0 THEN 'fail'
                        ELSE 'warn' END AS status,
                   CASE WHEN e.dc_guid IS NULL THEN 'medium'
                        WHEN e.num = 2 THEN 'info'
                        WHEN e.num = 1 THEN 'low'
                        WHEN e.num = 0 THEN 'medium'
                        ELSE 'medium' END AS sev,
                   CASE WHEN e.dc_guid IS NULL THEN NULL
                        WHEN e.num = 2 THEN 'always'
                        WHEN e.num = 1 THEN 'when supported: clients without channel binding are still accepted'
                        WHEN e.num = 0 THEN 'never'
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
                'Domain controller ' || c.dc_name || ': LDAP channel binding is not enforced -- LdapEnforceChannelBinding = '
                    || COALESCE(c.setting_value, '(empty)') || ' (' || c.phrase || '), set by GPO '''
                    || COALESCE(c.gpo_name, c.winning_gpo_guid::text, '(unknown)') || ''''
            ELSE
                'Domain controller ' || c.dc_name || ': LDAP channel binding is not enforced by Group Policy -- LdapEnforceChannelBinding is not '
                    || 'configured by any GPO that applies to it, so the effective value is the OS default '
                    || 'or a local setting that cannot be seen (the default depends on the Windows version and update level)'
                    || CASE WHEN c.unreadable_gpos IS NOT NULL
                            THEN '; uncertain: some GPOs applying to this DC could not be read from SYSVOL'
                            ELSE '' END
            END AS summary,
            jsonb_build_object(
                'domain_controller', c.dc_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'operating_system_version', c.operating_system_version,
                'setting', 'HKLM\System\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding',
                'configured_by_group_policy', c.configured,
                'value', c.setting_value,
                'value_type', c.value_type,
                'winning_gpo_guid', c.winning_gpo_guid,
                'winning_gpo_name', c.gpo_name,
                'winning_gpo_precedence', c.precedence,
                'expected', '2 (always)',
                'unreadable_applying_gpos', COALESCE(c.unreadable_gpos, '[]'::jsonb)
            ) AS detail
        FROM cls c
        WHERE c.status IS DISTINCT FROM 'pass'
    """,
}
