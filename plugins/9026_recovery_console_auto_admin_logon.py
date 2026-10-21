r"""Plugin 9026: Recovery Console Automatic Administrative Logon Enabled

Reports GPOs whose setting "Recovery console: Allow automatic administrative
logon" (HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\
RecoveryConsole\SecurityLevel = 1) is the winning value on at least one
enabled computer. One row per GPO (object_guid = the GPO).

Why it matters: with it, the Windows Recovery Console / recovery environment
opens an administrator session without asking for the local Administrator
password -- anyone with physical or out-of-band console access (a
virtualisation console, an iLO/iDRAC session, a stolen laptop) gets a
SYSTEM-level shell. On a domain controller that is the domain
(PingCastle P-RecoveryModeUnprotected).

Severity ('fail'): high when it wins on a domain controller, medium
otherwise. Winning values are computed per computer from GPO links and
precedence (see COMPUTER_GPO_SQL); the detail lists where it wins.
"""

# ---------------------------------------------------------------------------
# Shared definition (copied verbatim into plugins 9024-9038): the effective
# machine Group Policy of every enabled computer. gpo_comp = the computers;
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

PLUGIN = {   'plugin_id': 9026,
    'category': 'Organizational Units',
    'name': 'Recovery Console Automatic Administrative Logon Enabled',
    'version': '1.0',
    'revision_date': '2026-10-20',
    'control_id': 'GPO-9026',
    'framework_tags': [   'NIST-800-53-CM-6',
                          'NIST-800-53-CM-7',
                          'NIST-CSF-2.0-PR.PS-01',
                          'PCI-DSS-4.0-2.2.1',
                          'CIS-CSC-8-4.1',
                          'ISO-27001-2022-A.8.9',
                          'SOC2-CC7.1',
                          'HIPAA-164.312(c)(1)',
                          'NIST-800-53-AC-3',
                          'NIST-800-53-IA-2',
                          'MITRE-ATTCK-T1078.003'],
    'references': [   {   'title': 'Microsoft: Recovery console: Allow automatic administrative '
                                   'logon',
                          'url': 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/recovery-console-allow-automatic-administrative-logon'},
                      {   'title': 'PingCastle health check rules',
                          'url': 'https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html'}],
    'description': "A GPO enables 'Recovery console: Allow automatic administrative logon', so the "
                   'recovery console gives an administrator session without a password on the '
                   'computers where it wins. High when that includes domain controllers.',
    'remediation': 'Set Computer Configuration > Policies > Windows Settings > Security Settings > '
                   "Local Policies > Security Options > 'Recovery console: Allow automatic "
                   "administrative logon' to Disabled in the GPO (or remove the setting), then "
                   'gpupdate /force.',
    'base_severity': 'medium',
    'query': r"""
        WITH
        sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS ok
        ),
        @COMPGPO@,
        bad AS (
            SELECT e.winning_gpo_guid, e.setting_key, e.value_type, e.setting_value,
                   p.computer_guid, p.computer_name, p.is_dc
            FROM gpo_eff e
            JOIN gpo_comp p ON p.computer_guid = e.computer_guid
            WHERE (SELECT ok FROM sysvol)
              AND e.value_type IS DISTINCT FROM 'DELETE'
              AND (trim(e.setting_value) ~ '^0*1$')
        )
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_or(b.is_dc) THEN 'high' ELSE 'medium' END AS fd_severity,
            'GPO ''' || COALESCE(g.display_name, g.object_guid::text) || ''' enables Recovery Console automatic administrative logon (no password needed at the console)'
                || CASE WHEN bool_or(b.is_dc) THEN ', including on domain controllers' ELSE '' END AS summary,
            jsonb_build_object(
                'gpo_name', g.display_name,
                'gpo_guid', upper(g.gpo_guid::text),
                'setting', 'HKLM\Software\Microsoft\Windows NT\CurrentVersion\Setup\RecoveryConsole\SecurityLevel',
                'values', jsonb_agg(DISTINCT jsonb_build_object('key', 'HKLM\' || b.setting_key,
                                                                'value', b.setting_value)),
                'computers_where_it_wins', count(DISTINCT b.computer_guid),
                'domain_controllers_where_it_wins',
                    COALESCE(jsonb_agg(DISTINCT b.computer_name) FILTER (WHERE b.is_dc), '[]'::jsonb),
                'sample_computers',
                    (SELECT jsonb_agg(x.n ORDER BY x.n) FROM (
                        SELECT DISTINCT b2.computer_name AS n FROM bad b2
                        WHERE b2.winning_gpo_guid = g.object_guid ORDER BY 1 LIMIT 25) x)
            ) AS detail
        FROM bad b
        JOIN ad_gpo g ON g.object_guid = b.winning_gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
        GROUP BY g.object_guid, g.display_name, g.gpo_guid
    """.replace('@COMPGPO@', COMPUTER_GPO_SQL.strip()).replace('@SETTINGS@', "s.source = 'registry' AND s.section = 'HKLM' AND lower(s.setting_key) = lower('Software\\Microsoft\\Windows NT\\CurrentVersion\\Setup\\RecoveryConsole\\SecurityLevel')"),
}
