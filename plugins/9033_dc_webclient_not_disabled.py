r"""Plugin 9033: WebClient Service Not Disabled on Domain Controllers

Reports domain controllers whose effective Group Policy does not disable the
WebClient service (GptTmpl.inf [Service General Setting] "WebClient" start
mode: 2 automatic, 3 manual, 4 disabled). One row per DC (object_guid = the
DC's computer object).

Why it matters: the WebClient (WebDAV redirector) service lets a coerced
authentication (PetitPotam, PrinterBug, DFSCoerce) be sent over HTTP rather
than SMB. HTTP authentication can be relayed to LDAP without signing
protection, which turns a coercion of the DC into a domain takeover
(MITRE ATT&CK T1187). It is not installed on Server Core and not started on
most DCs, so "not configured" is informational; set to automatic or manual
by policy is low (PingCastle A-DC-WebClient, informative).

Severity ('warn'): low when set to 2 or 3 by Group Policy, info when not
configured by any GPO that applies to the DC. Same model as plugin 9017
(Print Spooler).
"""

PLUGIN = {   'plugin_id': 9033,
    'category': 'Organizational Units',
    'name': 'WebClient Service Not Disabled on Domain Controllers',
    'version': '1.0',
    'revision_date': '2026-10-20',
    'control_id': 'GPO-9033',
    'framework_tags': [   'NIST-800-53-CM-6',
                          'NIST-800-53-CM-7',
                          'NIST-CSF-2.0-PR.PS-01',
                          'PCI-DSS-4.0-2.2.1',
                          'CIS-CSC-8-4.1',
                          'ISO-27001-2022-A.8.9',
                          'SOC2-CC7.1',
                          'HIPAA-164.312(c)(1)',
                          'PCI-DSS-4.0-2.2.4',
                          'CIS-CSC-8-4.8',
                          'MITRE-ATTCK-T1187'],
    'references': [   {   'title': 'Microsoft: Guidance on disabling system services on Windows '
                                   'Server (WebClient)',
                          'url': 'https://learn.microsoft.com/en-us/windows-server/security/windows-services/security-guidelines-for-disabling-system-services-in-windows-server'},
                      {   'title': 'MITRE ATT&CK T1187: Forced Authentication',
                          'url': 'https://attack.mitre.org/techniques/T1187/'},
                      {   'title': 'PingCastle health check rules',
                          'url': 'https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html'}],
    'description': 'The effective Group Policy of a domain controller does not disable the '
                   'WebClient (WebDAV) service, which lets coerced DC authentication travel over '
                   'relayable HTTP.',
    'remediation': 'In a GPO linked to the Domain Controllers OU set Computer Configuration > '
                   'Policies > Windows Settings > Security Settings > System Services > WebClient '
                   '= Disabled (the service is only present when the WebDAV redirector / Desktop '
                   'Experience is installed).',
    'base_severity': 'low',
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
            SELECT e.dc_guid, e.setting_value, e.winning_gpo_guid, g.display_name AS gpo_name,
                   CASE WHEN e.setting_value ~ '^\s*[0-9]+\s*$' THEN trim(e.setting_value)::int END AS num
            FROM v_dc_effective_gpo_setting e
            LEFT JOIN ad_gpo g
              ON g.client_id = e.client_id AND g.object_guid = e.winning_gpo_guid AND g.valid_to IS NULL
            WHERE e.client_id = %(client_id)s
              AND e.source = 'security_template' AND e.section = 'Service General Setting'
              AND lower(e.setting_key) = 'webclient'
              AND e.value_type IS DISTINCT FROM 'DELETE'
        )
        SELECT
            'warn' AS status,
            d.dc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN e.num IN (2, 3) THEN 'low' ELSE 'info' END AS fd_severity,
            CASE WHEN e.dc_guid IS NOT NULL
                 THEN 'Domain controller ' || d.dc_name || ': the WebClient service is not disabled -- start mode = '
                      || COALESCE(e.setting_value, '(empty)')
                      || CASE e.num WHEN 2 THEN ' (automatic)' WHEN 3 THEN ' (manual)' ELSE ' (unrecognised)' END
                      || ', set by GPO ''' || COALESCE(e.gpo_name, e.winning_gpo_guid::text) || ''''
                 ELSE 'Domain controller ' || d.dc_name || ': the WebClient service is not disabled by Group '
                      || 'Policy (not configured by any GPO that applies to it; it may be absent or disabled locally)'
            END AS summary,
            jsonb_build_object(
                'domain_controller', d.dc_name,
                'operating_system', d.operating_system,
                'setting', '[Service General Setting] WebClient (start mode)',
                'configured_by_group_policy', e.dc_guid IS NOT NULL,
                'value', e.setting_value,
                'winning_gpo_name', e.gpo_name,
                'expected', '4 (disabled)'
            ) AS detail
        FROM dc d
        LEFT JOIN eff e ON e.dc_guid = d.dc_guid
        WHERE e.num IS DISTINCT FROM 4
    """,
}
