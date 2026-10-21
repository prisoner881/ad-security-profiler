r"""Plugin 9032: Domain Controllers Refuse Machine Account Password Changes

Reports domain controllers whose effective Group Policy sets "Domain
controller: Refuse machine account password changes" (HKLM\System\
CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange = 1).
One row per DC (object_guid = the DC's computer object).

Why it matters: with it, the DC rejects the automatic 30-day password change
of every computer account, so machine passwords never rotate. A computer
password stolen once (from a backup, a decommissioned disk, a memory dump)
then works for ever -- for silver tickets against that computer and for
authenticating as it (MITRE ATT&CK T1558.002; PingCastle
A-DCRefuseComputerPwdChange). Plugin 2007 shows the resulting stale
computer passwords.

Severity ('fail'): medium. Read from v_dc_effective_gpo_setting (GPO links,
precedence and security filtering above the DC).
"""

PLUGIN = {   'plugin_id': 9032,
    'category': 'Organizational Units',
    'name': 'Domain Controllers Refuse Machine Account Password Changes',
    'version': '1.0',
    'revision_date': '2026-10-20',
    'control_id': 'GPO-9032',
    'framework_tags': [   'NIST-800-53-CM-6',
                          'NIST-800-53-CM-7',
                          'NIST-CSF-2.0-PR.PS-01',
                          'PCI-DSS-4.0-2.2.1',
                          'CIS-CSC-8-4.1',
                          'ISO-27001-2022-A.8.9',
                          'SOC2-CC7.1',
                          'HIPAA-164.312(c)(1)',
                          'NIST-800-53-IA-5',
                          'NIST-800-53-IA-5(1)',
                          'PCI-DSS-4.0-8.3.9',
                          'CIS-CSC-8-5.2',
                          'MITRE-ATTCK-T1558.002'],
    'references': [   {   'title': 'Microsoft: Domain controller: Refuse machine account password '
                                   'changes',
                          'url': 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/domain-controller-refuse-machine-account-password-changes'},
                      {   'title': 'PingCastle health check rules',
                          'url': 'https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html'}],
    'description': "A GPO applying to the domain controller enables 'Refuse machine account "
                   "password changes', so computer account passwords are never rotated.",
    'remediation': "Set 'Domain controller: Refuse machine account password changes' to Disabled "
                   '(or remove it) in the GPO linked to the Domain Controllers OU, then gpupdate '
                   '/force on the DCs.',
    'base_severity': 'medium',
    'query': r"""
        WITH dc AS (
            SELECT c.object_guid AS dc_guid,
                   COALESCE(c.dns_hostname, c.sam_account_name, o.dn_current, c.object_guid::text) AS dc_name,
                   c.dns_hostname, c.operating_system
            FROM ad_computer c
            JOIN directory_object o
              ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_domain_controller
              AND EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                          WHERE s.client_id = %(client_id)s AND s.read_status = 'ok')
        ),
        eff AS (
            SELECT e.dc_guid, e.setting_value, e.winning_gpo_guid, g.display_name AS gpo_name
            FROM v_dc_effective_gpo_setting e
            LEFT JOIN ad_gpo g
              ON g.client_id = e.client_id AND g.object_guid = e.winning_gpo_guid AND g.valid_to IS NULL
            WHERE e.client_id = %(client_id)s
              AND e.source = 'registry' AND e.section = 'HKLM'
              AND lower(e.setting_key) = lower('System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange')
              AND e.value_type IS DISTINCT FROM 'DELETE'
              AND trim(e.setting_value) ~ '^0*1$'
        )
        SELECT
            'fail' AS status,
            d.dc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain controller ' || d.dc_name || ' refuses machine account password changes '
                || '(RefusePasswordChange = 1, set by GPO '''
                || COALESCE(e.gpo_name, e.winning_gpo_guid::text) || ''')' AS summary,
            jsonb_build_object(
                'domain_controller', d.dc_name,
                'setting', 'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\RefusePasswordChange',
                'value', e.setting_value,
                'winning_gpo_guid', e.winning_gpo_guid,
                'winning_gpo_name', e.gpo_name
            ) AS detail
        FROM dc d
        JOIN eff e ON e.dc_guid = d.dc_guid
    """,
}
