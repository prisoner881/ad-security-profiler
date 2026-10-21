r"""Plugin 9035: Kerberos Armoring (FAST) Not Enabled by Group Policy

Reports, once per domain whose functional level is Windows Server 2012 or
higher, computers whose effective Group Policy does not enable Kerberos
armoring:
  * domain controllers: "KDC support for claims, compound authentication and
    Kerberos armoring" (HKLM\Software\Microsoft\Windows\CurrentVersion\
    Policies\System\KDC\Parameters\EnableCbacAndArmor = 1, 2 or 3);
  * other computers: "Kerberos client support for claims, compound
    authentication and Kerberos armoring" (...\Kerberos\Parameters\
    EnableCbacAndArmor = 1).

Why it matters: Kerberos armoring (FAST, RFC 6113) wraps the AS exchange in
the computer's own ticket, so a user's pre-authentication data can no longer
be captured and cracked offline (AS-REQ roasting) or spoofed, and the KDC
returns protected errors. It is also a prerequisite for claims and compound
authentication used by authentication policies and silos (plugin 4036)
(PingCastle S-KerberosArmoring / S-KerberosArmoringDC, informative).

One row per domain (object_guid = the domain). Severity ('warn'): low when
domain controllers do not support armoring, info when only other computers
lack it.
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

PLUGIN = {   'plugin_id': 9035,
    'category': 'Organizational Units',
    'name': 'Kerberos Armoring (FAST) Not Enabled by Group Policy',
    'version': '1.0',
    'revision_date': '2026-10-20',
    'control_id': 'GPO-9035',
    'framework_tags': [   'NIST-800-53-IA-2(8)',
                          'NIST-800-53-CM-6',
                          'NIST-CSF-2.0-PR.AA-03',
                          'NIST-CSF-2.0-PR.PS-01',
                          'CIS-CSC-8-4.1',
                          'ISO-27001-2022-A.8.5',
                          'ISO-27001-2022-A.8.9',
                          'SOC2-CC6.1',
                          'MITRE-ATTCK-T1558.004'],
    'references': [   {   'title': "Microsoft: Kerberos armoring (FAST) -- What's new in Kerberos "
                                   'authentication',
                          'url': 'https://learn.microsoft.com/en-us/windows-server/security/kerberos/whats-new-in-kerberos-authentication'},
                      {   'title': 'RFC 6113: A Generalized Framework for Kerberos '
                                   'Pre-Authentication (FAST)',
                          'url': 'https://www.rfc-editor.org/rfc/rfc6113'},
                      {   'title': 'PingCastle health check rules',
                          'url': 'https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html'}],
    'description': 'At domain functional level 2012 or higher, Group Policy does not enable '
                   'Kerberos armoring (FAST) on the domain controllers (low) or on other computers '
                   '(info), so pre-authentication exchanges are not protected.',
    'remediation': 'In a GPO linked to the Domain Controllers OU enable Computer Configuration > '
                   "Administrative Templates > System > KDC > 'KDC support for claims, compound "
                   "authentication and Kerberos armoring' (Supported). In a GPO for all computers "
                   "enable System > Kerberos > 'Kerberos client support for claims, compound "
                   "authentication and Kerberos armoring'. Move to 'Fail unarmored authentication "
                   "requests' only after every client supports it.",
    'base_severity': 'low',
    'query': r"""
        WITH
        sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS ok
        ),
        dom AS (
            SELECT m.object_guid, m.dns_root, m.functional_level
            FROM ad_domain m
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL
            ORDER BY m.object_guid LIMIT 1
        ),
        @COMPGPO@,
        pv AS (
            -- winning HKLM registry values per computer, keyed by lower-case path
            SELECT e.computer_guid, jsonb_object_agg(lower(e.setting_key), e.setting_value) AS v
            FROM gpo_eff e
            WHERE e.source = 'registry' AND e.section = 'HKLM' AND e.value_type IS DISTINCT FROM 'DELETE'
            GROUP BY e.computer_guid
        ),
        st AS (
            SELECT p.computer_guid, p.computer_name, p.is_dc, p.container_dn, COALESCE((CASE WHEN p.is_dc THEN COALESCE(trim((pv.v ->> lower('Software\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters\EnableCbacAndArmor'))), '') ~ '^0*[123]$' ELSE COALESCE(trim((pv.v ->> lower('Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\EnableCbacAndArmor'))), '') ~ '^0*1$' END), false) AS ok
            FROM gpo_comp p
            LEFT JOIN pv ON pv.computer_guid = p.computer_guid
            WHERE (SELECT ok FROM sysvol) AND (COALESCE((SELECT functional_level FROM dom), 0) >= 5)
        ),
        by_container AS (
            SELECT s.container_dn, count(*) AS not_covered
            FROM st s WHERE NOT s.ok
            GROUP BY s.container_dn
        )
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_or(s.is_dc AND NOT s.ok) THEN 'low' ELSE 'info' END AS fd_severity,
            'Kerberos armoring (FAST) is not enforced by Group Policy on '
                || CASE WHEN bool_and(NOT s.ok) THEN 'any computer in scope'
                        ELSE 'part of the domain (see detail for the computers and OUs)' END
                || CASE WHEN bool_or(s.is_dc AND NOT s.ok) THEN ', including domain controllers' ELSE '' END
                AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'computers_in_scope', count(*),
                'computers_not_covered', count(*) FILTER (WHERE NOT s.ok),
                'domain_controllers_not_covered',
                    COALESCE(jsonb_agg(s.computer_name ORDER BY s.computer_name)
                             FILTER (WHERE s.is_dc AND NOT s.ok), '[]'::jsonb),
                'containers_not_covered',
                    (SELECT jsonb_agg(jsonb_build_object('container', c.container_dn, 'computers', c.not_covered)
                                      ORDER BY c.not_covered DESC, c.container_dn)
                       FROM (SELECT * FROM by_container ORDER BY not_covered DESC, container_dn LIMIT 25) c),
                'sample_computers_not_covered',
                    (SELECT jsonb_agg(x.computer_name ORDER BY x.computer_name)
                       FROM (SELECT computer_name FROM st WHERE NOT ok ORDER BY computer_name LIMIT 25) x),
                'note', 'Evaluated from GPO links and precedence; security filtering, WMI filters, '
                        || 'site-linked GPOs and local settings are not visible.'
            ) AS detail
        FROM st s
        CROSS JOIN dom d
        GROUP BY d.object_guid, d.dns_root
        HAVING count(*) FILTER (WHERE NOT s.ok) > 0
    """.replace('@COMPGPO@', COMPUTER_GPO_SQL.strip()).replace('@SETTINGS@', "s.source = 'registry' AND s.section = 'HKLM' AND lower(s.setting_key) IN (lower('Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\KDC\\Parameters\\EnableCbacAndArmor'), lower('Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Kerberos\\Parameters\\EnableCbacAndArmor'))"),
}
