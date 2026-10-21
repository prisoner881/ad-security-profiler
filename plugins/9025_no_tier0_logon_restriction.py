r"""Plugin 9025: No Group Policy Denies Tier 0 Logon to Lower-Tier Computers

Reports, once per domain, enabled computers other than domain controllers
whose effective Group Policy does not deny interactive or Remote Desktop
logon to Domain Admins or Enterprise Admins: [Privilege Rights]
SeDenyInteractiveLogonRight or SeDenyRemoteInteractiveLogonRight naming
the group (by SID -512 / -519 or by name).

Why it matters: every interactive or RDP logon leaves the account's
credentials (NT hash, Kerberos tickets) in the memory of the computer used.
When a domain admin logs on to a workstation or member server, anyone who is
local admin there -- malware included -- can take those credentials and
become domain admin. The tiering model forbids it, and the deny-logon user
rights are how Group Policy enforces it (Microsoft enterprise access model;
PingCastle P-LogonDenied).

One row per domain (object_guid = the domain) listing the OUs and computers
not covered. Severity ('warn'): medium when 200 or more non-DC computers are
in scope (PingCastle applies the rule above that size), low otherwise.
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

PLUGIN = {   'plugin_id': 9025,
    'category': 'Organizational Units',
    'name': 'No Group Policy Denies Tier 0 Logon to Lower-Tier Computers',
    'version': '1.1',
    'revision_date': '2026-10-21',
    'control_id': 'GPO-9025',
    'framework_tags': [   'NIST-800-53-AC-6(5)',
                          'NIST-800-53-AC-2(7)',
                          'NIST-800-53-AC-3',
                          'NIST-CSF-2.0-PR.AA-05',
                          'PCI-DSS-4.0-7.2.2',
                          'CIS-CSC-8-5.4',
                          'ISO-27001-2022-A.8.2',
                          'SOC2-CC6.3',
                          'HIPAA-164.308(a)(4)(ii)(B)',
                          'MITRE-ATTCK-T1003',
                          'MITRE-ATTCK-T1078.002'],
    'references': [   {   'title': 'Microsoft: Securing privileged access -- enterprise access '
                                   'model',
                          'url': 'https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model'},
                      {   'title': 'Microsoft: Deny log on locally / Deny log on through Remote '
                                   'Desktop Services',
                          'url': 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/deny-log-on-locally'},
                      {   'title': 'PingCastle health check rules',
                          'url': 'https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html'}],
    'description': 'Group Policy does not deny interactive or Remote Desktop logon to Domain '
                   'Admins / Enterprise Admins on some or all workstations and member servers, so '
                   'Tier 0 credentials can be left on lower-tier machines.',
    'remediation': 'Create a GPO linked to the OUs holding workstations and member servers that '
                   "adds Domain Admins and Enterprise Admins (and other Tier 0 groups) to 'Deny "
                   "log on locally' and 'Deny log on through Remote Desktop Services' (also 'Deny "
                   "log on as a batch job' and 'as a service'). Administer those machines with "
                   'separate lower-tier admin accounts.',
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
        dom_sid AS (
            SELECT d.object_sid::text AS dsid
            FROM ad_domain m
            JOIN directory_object d
              ON d.object_guid = m.object_guid AND d.client_id = m.client_id AND NOT d.is_deleted
            WHERE m.client_id = %(client_id)s AND m.valid_to IS NULL AND d.object_sid IS NOT NULL
            ORDER BY d.object_guid LIMIT 1
        ),
        deny AS (
            SELECT DISTINCT e.computer_guid
            FROM gpo_eff e
            CROSS JOIN LATERAL unnest(string_to_array(COALESCE(e.setting_value, ''), ',')) AS x(entry)
            WHERE e.source = 'security_template' AND lower(e.section) = 'privilege rights'
              AND lower(e.setting_key) IN ('sedenyinteractivelogonright', 'sedenyremoteinteractivelogonright')
              AND (upper(btrim(x.entry)) IN ('*' || (SELECT dsid FROM dom_sid) || '-512',
                                             '*' || (SELECT dsid FROM dom_sid) || '-519')
                   OR lower(reverse(split_part(reverse(btrim(x.entry)), chr(92), 1)))
                      IN ('domain admins', 'enterprise admins'))
        ),
        st AS (
            SELECT p.computer_guid, p.computer_name, p.is_dc, p.container_dn, COALESCE((deny.computer_guid IS NOT NULL), false) AS ok
            FROM gpo_comp p
            LEFT JOIN pv ON pv.computer_guid = p.computer_guid
            LEFT JOIN deny ON deny.computer_guid = p.computer_guid
            WHERE (SELECT ok FROM sysvol) AND (NOT p.is_dc)
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
            CASE WHEN count(*) >= 200 THEN 'medium' ELSE 'low' END AS fd_severity,
            'Denying logon to Domain Admins / Enterprise Admins is not enforced by Group Policy on '
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
                'note', 'Evaluated from GPO links and precedence for enabled Windows computers; '
                        || 'security filtering, WMI filters, site-linked GPOs and local settings are '
                        || 'not visible, and non-Windows computers are not counted.'
            ) AS detail
        FROM st s
        CROSS JOIN dom d
        GROUP BY d.object_guid, d.dns_root
        HAVING count(*) FILTER (WHERE NOT s.ok) > 0
    """.replace('@COMPGPO@', COMPUTER_GPO_SQL.strip()).replace('@SETTINGS@', "s.source = 'security_template' AND lower(s.section) = 'privilege rights' AND lower(s.setting_key) IN ('sedenyinteractivelogonright', 'sedenyremoteinteractivelogonright')"),
}
