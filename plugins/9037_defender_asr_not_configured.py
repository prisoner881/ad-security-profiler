r"""Plugin 9037: Microsoft Defender Attack Surface Reduction Rules Not Configured

Reports, once per domain, enabled computers whose effective Group Policy does
not turn on Microsoft Defender attack surface reduction (ASR) with at least
one rule in block mode: HKLM\Software\Policies\Microsoft\Windows Defender\
Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules = 1 and a value
of 1 under ...\ASR\Rules\<rule GUID>. The detail counts, for Microsoft's
three "standard protection" rules, the computers where each is not in block
mode:
  9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2  Block credential stealing from LSASS
  56a863a9-875e-4185-98a7-b882c64b5ce5  Block abuse of exploited vulnerable signed drivers
  e6db77e5-3df2-4cf1-b95a-636979351e5b  Block persistence through WMI event subscription

Why it matters: ASR rules stop common intrusion steps -- LSASS credential
dumping, Office macros spawning processes, script-based downloaders,
vulnerable-driver loading -- before they run (PingCastle S-DefenderASR,
informative). ASR configured through Intune or Defender for Endpoint instead
of Group Policy is not visible here; the finding then says only that Group
Policy does not configure it.

One row per domain (object_guid = the domain). Severity ('warn'): low.
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

PLUGIN = {   'plugin_id': 9037,
    'category': 'Organizational Units',
    'name': 'Microsoft Defender Attack Surface Reduction Rules Not Configured',
    'version': '1.1',
    'revision_date': '2026-10-21',
    'control_id': 'GPO-9037',
    'framework_tags': [   'NIST-800-53-CM-6',
                          'NIST-800-53-CM-7',
                          'NIST-CSF-2.0-PR.PS-01',
                          'PCI-DSS-4.0-2.2.1',
                          'CIS-CSC-8-4.1',
                          'ISO-27001-2022-A.8.9',
                          'SOC2-CC7.1',
                          'HIPAA-164.312(c)(1)',
                          'NIST-800-53-SI-3',
                          'CIS-CSC-8-10.1',
                          'MITRE-ATTCK-T1003.001'],
    'references': [   {   'title': 'Microsoft: Attack surface reduction rules reference',
                          'url': 'https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference'},
                      {   'title': 'PingCastle health check rules',
                          'url': 'https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html'}],
    'description': 'Group Policy does not enable Defender attack surface reduction with at least '
                   'one rule in block mode on some or all computers (ASR managed by Intune or MDE '
                   'is not visible here).',
    'remediation': 'Configure ASR (Computer Configuration > Administrative Templates > Windows '
                   'Components > Microsoft Defender Antivirus > Microsoft Defender Exploit Guard > '
                   "Attack Surface Reduction): enable 'Configure Attack Surface Reduction rules' "
                   'and put at least the standard protection rules in Block (1). Start other rules '
                   'in Audit (2), review the events, then block.',
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
        asr AS (
            SELECT e.computer_guid,
                   count(*) FILTER (WHERE trim(e.setting_value) = '1') AS block_rules,
                   count(*) FILTER (WHERE trim(e.setting_value) IN ('2', '6')) AS audit_or_warn_rules
            FROM gpo_eff e
            WHERE starts_with(lower(e.setting_key), lower('Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\'))
              AND e.value_type IS DISTINCT FROM 'DELETE'
            GROUP BY e.computer_guid
        ),
        st AS (
            SELECT p.computer_guid, p.computer_name, p.is_dc, p.container_dn, COALESCE((COALESCE(trim((pv.v ->> lower('Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\ExploitGuard_ASR_Rules'))), '') ~ '^0*1$' AND COALESCE(asr.block_rules, 0) > 0), false) AS ok,
                   COALESCE(trim((pv.v ->> lower('Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'))), '') = '1' AS std_0,
                   COALESCE(trim((pv.v ->> lower('Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\56a863a9-875e-4185-98a7-b882c64b5ce5'))), '') = '1' AS std_1,
                   COALESCE(trim((pv.v ->> lower('Software\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR\Rules\e6db77e5-3df2-4cf1-b95a-636979351e5b'))), '') = '1' AS std_2
            FROM gpo_comp p
            LEFT JOIN pv ON pv.computer_guid = p.computer_guid
            LEFT JOIN asr ON asr.computer_guid = p.computer_guid
            WHERE (SELECT ok FROM sysvol) AND (true)
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
            CASE WHEN bool_or(s.is_dc AND NOT s.ok) THEN 'low' ELSE 'low' END AS fd_severity,
            'Defender attack surface reduction (rules in block mode) is not enforced by Group Policy on '
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
                'standard_protection_rules_not_blocking', jsonb_build_object('Block credential stealing from LSASS', count(*) FILTER (WHERE NOT s.std_0), 'Block abuse of exploited vulnerable signed drivers', count(*) FILTER (WHERE NOT s.std_1), 'Block persistence through WMI event subscription', count(*) FILTER (WHERE NOT s.std_2)),
                'note', 'Evaluated from GPO links and precedence for enabled Windows computers; '
                        || 'security filtering, WMI filters, site-linked GPOs and local settings are '
                        || 'not visible, and non-Windows computers are not counted.'
            ) AS detail
        FROM st s
        CROSS JOIN dom d
        GROUP BY d.object_guid, d.dns_root
        HAVING count(*) FILTER (WHERE NOT s.ok) > 0
    """.replace('@COMPGPO@', COMPUTER_GPO_SQL.strip()).replace('@SETTINGS@', "s.source = 'registry' AND s.section = 'HKLM' AND starts_with(lower(s.setting_key), lower('Software\\Policies\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\ASR\\'))"),
}
