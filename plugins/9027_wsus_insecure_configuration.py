r"""Plugin 9027: Insecure WSUS Configuration by Group Policy

Reports GPOs whose Windows Update policy (HKLM\Software\Policies\Microsoft\
Windows\WindowsUpdate) is the winning value on at least one enabled
computer and:
  * points WUServer or WUStatusServer at an http:// URL -- medium; high
    when it applies to a domain controller;
  * sets SetProxyBehaviorForUpdateDetection = 1 (use the logged-on user's
    proxy) with an HTTP WSUS server -- low;
  * sets DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection = 1
    (WSUS certificate pinning off) -- low.
One row per GPO (object_guid = the GPO), listing every issue.

Why it matters: Windows Update installs whatever the WSUS server offers as
SYSTEM. Over HTTP anyone on the network path can inject a "update" -- any
Microsoft-signed binary with attacker-chosen arguments (WSUSpect, PyWSUS,
WSUSpendu; CVE-2020-1013 for the user-proxy case) -- and run code as SYSTEM
on every client, domain controllers included (MITRE ATT&CK T1557,
T1072; PingCastle S-WSUS-HTTP, S-WSUS-UserProxy, S-WSUS-NoPinning).
"""

# ---------------------------------------------------------------------------
# Shared definition (copied verbatim into plugins 9024-9038): the effective
# machine Group Policy of every enabled Windows computer (operatingSystem
# "Windows ..." or a domain controller; Linux and NAS joins have no Group
# Policy client, and other computers with no operatingSystem are left out).
# gpo_comp = the computers;
# gpo_applies = the GPOs linked above each one with their precedence, as in
# v_gpo_dc_application (enforced links first, higher container wins; then the
# deeper OU wins; then GPMC link order; block inheritance honoured; disabled
# links and GPOs with computer settings disabled ignored). Not evaluated:
# security filtering, WMI filters, site-linked GPOs, loopback, local policy.
# gpo_eff = the winning value of each selected setting per computer
# (@SETTINGS@ is replaced by each plugin's filter on gpo_setting_edge s).
# ---------------------------------------------------------------------------
COMPUTER_GPO_SQL = r"""        gpo_som AS (
            SELECT o.object_guid AS container_guid, lower(d.dn_current) AS dn, false AS is_domain,
                   COALESCE(o.block_inheritance, false) AS block_inheritance
            FROM ad_ou o
            JOIN directory_object d
              ON d.object_guid = o.object_guid AND d.client_id = o.client_id AND NOT d.is_deleted
            WHERE o.client_id = %(client_id)s AND o.valid_to IS NULL
            UNION ALL
            SELECT m.object_guid, lower(d.dn_current), true, COALESCE(m.block_inheritance, false)
            FROM ad_domain m
            JOIN directory_object d
              ON d.object_guid = m.object_guid AND d.client_id = m.client_id AND NOT d.is_deleted
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL
        ),
        gpo_comp AS (
            SELECT c.object_guid AS computer_guid, lower(d.dn_current) AS dn,
                   COALESCE(c.is_domain_controller, false) AS is_dc,
                   COALESCE(c.dns_hostname, c.sam_account_name, d.dn_current) AS computer_name,
                   c.operating_system,
                   substr(d.dn_current, strpos(d.dn_current, ',') + 1) AS container_dn
            FROM ad_computer c
            JOIN directory_object d
              ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_enabled IS NOT FALSE
              AND NOT COALESCE(c.is_gmsa, false) AND NOT COALESCE(c.is_dmsa, false)
              -- Group Policy applies to Windows only (Linux/NAS joins and
              -- non-DC accounts with no operatingSystem are left out)
              AND (COALESCE(c.is_domain_controller, false) OR c.operating_system ILIKE 'windows%%')
        ),
        gpo_chain AS (
            SELECT p.computer_guid, s.container_guid, s.is_domain, s.block_inheritance,
                   length(s.dn) - length(replace(s.dn, ',', '')) AS depth
            FROM gpo_comp p
            JOIN gpo_som s ON right(p.dn, length(s.dn) + 1) = ',' || s.dn
        ),
        gpo_blocked AS (
            SELECT computer_guid, max(depth) AS block_depth
            FROM gpo_chain WHERE block_inheritance AND NOT is_domain
            GROUP BY computer_guid
        ),
        gpo_lnk AS (
            SELECT x.container_guid, x.gpo_guid, x.link_enforced, x.gpmc_link_order
            FROM (
                SELECT l.container_guid, l.gpo_guid, l.link_enforced, l.link_enabled,
                       max(l.link_order) OVER (PARTITION BY l.container_guid) - l.link_order + 1
                           AS gpmc_link_order
                FROM gpo_link_edge l
                WHERE l.client_id = %(client_id)s AND l.valid_to IS NULL
            ) x
            JOIN ad_gpo g ON g.object_guid = x.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
            WHERE x.link_enabled AND (g.gpo_flags IS NULL OR (g.gpo_flags & 2) = 0)
        ),
        gpo_applies AS (
            -- Precedence as in v_gpo_dc_application (enforced links first,
            -- higher container wins; then deeper OU wins; then GPMC link
            -- order), without security filtering, WMI filters or sites.
            SELECT ch.computer_guid, lk.gpo_guid,
                   row_number() OVER (
                       PARTITION BY ch.computer_guid
                       ORDER BY lk.link_enforced DESC,
                                CASE WHEN lk.link_enforced THEN ch.depth END ASC,
                                CASE WHEN NOT lk.link_enforced THEN ch.depth END DESC,
                                lk.gpmc_link_order ASC) AS precedence
            FROM gpo_chain ch
            JOIN gpo_lnk lk ON lk.container_guid = ch.container_guid
            LEFT JOIN gpo_blocked b ON b.computer_guid = ch.computer_guid
            WHERE lk.link_enforced OR b.block_depth IS NULL OR ch.depth >= b.block_depth
        ),
        gpo_eff AS (
            SELECT DISTINCT ON (a.computer_guid, s.source, s.section, lower(s.setting_key))
                   a.computer_guid, s.source, s.section, s.setting_key, s.value_type, s.setting_value,
                   s.gpo_guid AS winning_gpo_guid, a.precedence
            FROM gpo_applies a
            JOIN gpo_setting_edge s
              ON s.client_id = %(client_id)s AND s.gpo_guid = a.gpo_guid
             AND s.valid_to IS NULL AND s.scope = 'machine'
            WHERE @SETTINGS@
            ORDER BY a.computer_guid, s.source, s.section, lower(s.setting_key), a.precedence
        )"""

PLUGIN = {   'plugin_id': 9027,
    'category': 'Organizational Units',
    'name': 'Insecure WSUS Configuration by Group Policy',
    'version': '1.1',
    'revision_date': '2026-10-21',
    'control_id': 'GPO-9027',
    'framework_tags': [   'NIST-800-53-CM-6',
                          'NIST-800-53-CM-7',
                          'NIST-CSF-2.0-PR.PS-01',
                          'PCI-DSS-4.0-2.2.1',
                          'CIS-CSC-8-4.1',
                          'ISO-27001-2022-A.8.9',
                          'SOC2-CC7.1',
                          'HIPAA-164.312(c)(1)',
                          'NIST-800-53-SI-2',
                          'NIST-800-53-SC-8',
                          'CIS-CSC-8-7.3',
                          'CVE-2020-1013',
                          'MITRE-ATTCK-T1557',
                          'MITRE-ATTCK-T1072'],
    'references': [   {   'title': 'Microsoft: Secure WSUS with the Secure Sockets Layer protocol',
                          'url': 'https://learn.microsoft.com/en-us/windows-server/administration/windows-server-update-services/deploy/2-configure-wsus#bkmk_2_5_ConfigSSL'},
                      {   'title': 'Microsoft: CVE-2020-1013 Windows Update for Business elevation '
                                   'of privilege',
                          'url': 'https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1013'},
                      {   'title': 'PingCastle health check rules',
                          'url': 'https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html'}],
    'description': "A GPO points Windows Update at a WSUS server over HTTP (or uses the user's "
                   'proxy for it, or turns off WSUS certificate pinning), so an attacker on the '
                   'network path can push code that runs as SYSTEM. High when it applies to domain '
                   'controllers.',
    'remediation': "Configure WSUS with TLS (https://, port 8531) and set 'Specify intranet "
                   "Microsoft update service location' to the https:// URL in the GPO. Do not set "
                   'SetProxyBehaviorForUpdateDetection or turn off certificate pinning.',
    'base_severity': 'medium',
    'query': r"""
        WITH
        sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS ok
        ),
        @COMPGPO@,
        v AS (
            SELECT e.*, lower(substr(e.setting_key, length('Software\Policies\Microsoft\Windows\WindowsUpdate\') + 1)) AS name
            FROM gpo_eff e
            WHERE (SELECT ok FROM sysvol) AND e.value_type IS DISTINCT FROM 'DELETE'
        ),
        per_comp AS (
            SELECT p.computer_guid, p.is_dc, p.computer_name,
                   max(v.setting_value) FILTER (WHERE v.name = 'wuserver') AS wu_server,
                   (array_agg(v.winning_gpo_guid) FILTER (WHERE v.name = 'wuserver'))[1] AS wu_gpo,
                   max(v.setting_value) FILTER (WHERE v.name = 'wustatusserver') AS wu_status,
                   (array_agg(v.winning_gpo_guid) FILTER (WHERE v.name = 'wustatusserver'))[1] AS wu_status_gpo,
                   (array_agg(v.winning_gpo_guid) FILTER (
                       WHERE v.name = 'setproxybehaviorforupdatedetection'
                         AND trim(v.setting_value) ~ '^0*1$'))[1] AS proxy_gpo,
                   (array_agg(v.winning_gpo_guid) FILTER (
                       WHERE v.name = 'donotenforceenterprisetlscertpinningforupdatedetection'
                         AND trim(v.setting_value) ~ '^0*1$'))[1] AS pinning_gpo
            FROM gpo_comp p
            JOIN v ON v.computer_guid = p.computer_guid
            GROUP BY p.computer_guid, p.is_dc, p.computer_name
        ),
        issue AS (
            SELECT c.wu_gpo AS gpo_guid, c.computer_guid, c.is_dc, 'WSUS server over HTTP: ' || c.wu_server AS issue,
                   CASE WHEN c.is_dc THEN 3 ELSE 2 END AS sev
            FROM per_comp c WHERE lower(btrim(c.wu_server)) LIKE 'http://%%'
            UNION ALL
            SELECT c.wu_status_gpo, c.computer_guid, c.is_dc, 'WSUS status server over HTTP: ' || c.wu_status,
                   CASE WHEN c.is_dc THEN 3 ELSE 2 END
            FROM per_comp c WHERE lower(btrim(c.wu_status)) LIKE 'http://%%'
            UNION ALL
            SELECT c.proxy_gpo, c.computer_guid, c.is_dc,
                   'update detection uses the user''s proxy (SetProxyBehaviorForUpdateDetection = 1) with an HTTP WSUS server', 1
            FROM per_comp c WHERE c.proxy_gpo IS NOT NULL AND lower(btrim(c.wu_server)) LIKE 'http://%%'
            UNION ALL
            SELECT c.pinning_gpo, c.computer_guid, c.is_dc,
                   'WSUS certificate pinning disabled (DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection = 1)', 1
            FROM per_comp c WHERE c.pinning_gpo IS NOT NULL
        )
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE max(i.sev) WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS fd_severity,
            'GPO ''' || COALESCE(g.display_name, g.object_guid::text) || ''' configures Windows Update insecurely: '
                || string_agg(DISTINCT i.issue, '; ' ORDER BY i.issue)
                || CASE WHEN bool_or(i.is_dc) THEN ' (applies to domain controllers)' ELSE '' END AS summary,
            jsonb_build_object(
                'gpo_name', g.display_name,
                'gpo_guid', upper(g.gpo_guid::text),
                'issues', jsonb_agg(DISTINCT i.issue),
                'computers_affected', count(DISTINCT i.computer_guid),
                'applies_to_domain_controllers', bool_or(i.is_dc)
            ) AS detail
        FROM issue i
        JOIN ad_gpo g ON g.object_guid = i.gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
        GROUP BY g.object_guid, g.display_name, g.gpo_guid
    """.replace('@COMPGPO@', COMPUTER_GPO_SQL.strip()).replace('@SETTINGS@', "s.source = 'registry' AND s.section = 'HKLM' AND lower(s.setting_key) IN (lower('Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUServer'), lower('Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\WUStatusServer'), lower('Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\SetProxyBehaviorForUpdateDetection'), lower('Software\\Policies\\Microsoft\\Windows\\WindowsUpdate\\DoNotEnforceEnterpriseTLSCertPinningForUpdateDetection'))"),
}
