r"""Plugin 9024: Dangerous User Rights Granted to Broad Groups by Group Policy

Reports GPOs whose [Privilege Rights] (GptTmpl.inf) give a dangerous
privilege to a broad group -- Everyone, Authenticated Users, Anonymous
Logon, Users, Domain Users or Domain Computers -- and are the winning value
on at least one enabled computer that is not a domain controller (DCs are
plugin 9015's). One row per GPO (object_guid = the GPO).

Privileges: SeDebugPrivilege, SeBackupPrivilege, SeRestorePrivilege,
SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeTcbPrivilege,
SeEnableDelegationPrivilege, SeSecurityPrivilege, SeImpersonatePrivilege,
SeAssignPrimaryTokenPrivilege, SeCreateTokenPrivilege,
SeManageVolumePrivilege, SeSyncAgentPrivilege, SeRelabelPrivilege and
SeTrustedCredManAccessPrivilege ("Access Credential Manager as a trusted
caller", which reads every saved credential).

Why it matters: each is a direct path to SYSTEM or to the machine's secrets
(debug any process including LSASS, load a kernel driver, read any file
regardless of ACL, take ownership of anything, impersonate tokens). Granted
to a broad group, every user of the computer is in effect a local
administrator -- and on the servers where admins log on, can harvest their
credentials (PingCastle P-PrivilegeEveryone, P-TrustedCredManAccessPrivilege).

Severity ('fail'): high. Winning values are computed per computer from GPO
links and precedence (see COMPUTER_GPO_SQL).
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

PLUGIN = {   'plugin_id': 9024,
    'category': 'Organizational Units',
    'name': 'Dangerous User Rights Granted to Broad Groups by Group Policy',
    'version': '1.1',
    'revision_date': '2026-10-21',
    'control_id': 'GPO-9024',
    'framework_tags': [   'NIST-800-53-AC-6',
                          'NIST-800-53-AC-6(1)',
                          'NIST-800-53-AC-3',
                          'NIST-800-53-CM-6',
                          'NIST-CSF-2.0-PR.AA-05',
                          'PCI-DSS-4.0-7.2.1',
                          'PCI-DSS-4.0-7.2.2',
                          'CIS-CSC-8-6.8',
                          'CIS-CSC-8-4.1',
                          'ISO-27001-2022-A.8.2',
                          'ISO-27001-2022-A.8.9',
                          'SOC2-CC6.3',
                          'HIPAA-164.312(a)(1)',
                          'MITRE-ATTCK-T1134',
                          'MITRE-ATTCK-T1003'],
    'references': [   {   'title': 'Microsoft: User Rights Assignment',
                          'url': 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/user-rights-assignment'},
                      {   'title': 'Microsoft: Access Credential Manager as a trusted caller',
                          'url': 'https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/access-credential-manager-as-a-trusted-caller'},
                      {   'title': 'PingCastle health check rules',
                          'url': 'https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html'}],
    'description': 'A GPO grants a dangerous privilege (debug, backup/restore, take ownership, '
                   'load driver, act as OS, impersonate, Credential Manager trusted caller, ...) '
                   'to Everyone, Authenticated Users, Users, Domain Users or Domain Computers on '
                   'member computers, making every user effectively a local administrator.',
    'remediation': 'Edit the GPO (Computer Configuration > Policies > Windows Settings > Security '
                   'Settings > Local Policies > User Rights Assignment) and remove the broad group '
                   'from the right; grant it only to the specific service account or admin group '
                   "that needs it. Leave 'Access Credential Manager as a trusted caller' empty.",
    'base_severity': 'high',
    'query': r"""
        WITH
        sysvol AS (
            SELECT EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                           WHERE s.client_id = %(client_id)s AND s.read_status = 'ok') AS ok
        ),
        rights (right_lower, right_name) AS (
            VALUES ('sedebugprivilege', 'SeDebugPrivilege'),
                   ('sebackupprivilege', 'SeBackupPrivilege'),
                   ('serestoreprivilege', 'SeRestorePrivilege'),
                   ('setakeownershipprivilege', 'SeTakeOwnershipPrivilege'),
                   ('seloaddriverprivilege', 'SeLoadDriverPrivilege'),
                   ('setcbprivilege', 'SeTcbPrivilege'),
                   ('seenabledelegationprivilege', 'SeEnableDelegationPrivilege'),
                   ('sesecurityprivilege', 'SeSecurityPrivilege'),
                   ('seimpersonateprivilege', 'SeImpersonatePrivilege'),
                   ('seassignprimarytokenprivilege', 'SeAssignPrimaryTokenPrivilege'),
                   ('secreatetokenprivilege', 'SeCreateTokenPrivilege'),
                   ('semanagevolumeprivilege', 'SeManageVolumePrivilege'),
                   ('sesyncagentprivilege', 'SeSyncAgentPrivilege'),
                   ('setrustedcredmanaccessprivilege', 'SeTrustedCredManAccessPrivilege'),
                   ('serelabelprivilege', 'SeRelabelPrivilege')
        ),
        @COMPGPO@,
        entry AS (
            SELECT e.winning_gpo_guid, e.computer_guid, r.right_name, btrim(x.entry) AS raw_entry
            FROM gpo_eff e
            JOIN gpo_comp p ON p.computer_guid = e.computer_guid AND NOT p.is_dc
            JOIN rights r ON r.right_lower = lower(e.setting_key)
            CROSS JOIN LATERAL unnest(string_to_array(COALESCE(e.setting_value, ''), ',')) AS x(entry)
            WHERE (SELECT ok FROM sysvol) AND btrim(x.entry) <> ''
        ),
        broad AS (
            SELECT en.*,
                   CASE
                     WHEN upper(en.raw_entry) = '*S-1-1-0' OR lower(en.raw_entry) = 'everyone' THEN 'Everyone'
                     WHEN upper(en.raw_entry) = '*S-1-5-11'
                       OR lower(reverse(split_part(reverse(en.raw_entry), chr(92), 1))) = 'authenticated users'
                       THEN 'Authenticated Users'
                     WHEN upper(en.raw_entry) = '*S-1-5-7'
                       OR lower(reverse(split_part(reverse(en.raw_entry), chr(92), 1))) = 'anonymous logon'
                       THEN 'Anonymous Logon'
                     WHEN upper(en.raw_entry) = '*S-1-5-32-545'
                       OR lower(en.raw_entry) IN ('users', 'builtin\users') THEN 'Users'
                     WHEN upper(en.raw_entry) ~ '^\*S-1-5-21-[0-9-]+-513$'
                       OR lower(reverse(split_part(reverse(en.raw_entry), chr(92), 1))) = 'domain users'
                       THEN 'Domain Users'
                     WHEN upper(en.raw_entry) ~ '^\*S-1-5-21-[0-9-]+-515$'
                       OR lower(reverse(split_part(reverse(en.raw_entry), chr(92), 1))) = 'domain computers'
                       THEN 'Domain Computers'
                   END AS principal
            FROM entry en
        ),
        hit AS (
            SELECT * FROM broad WHERE principal IS NOT NULL
        )
        SELECT
            'fail' AS status,
            g.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'GPO ''' || COALESCE(g.display_name, g.object_guid::text) || ''' grants dangerous user rights to '
                || 'broad groups on the computers where it applies: '
                || string_agg(DISTINCT h.right_name || ' to ' || h.principal, ', '
                              ORDER BY h.right_name || ' to ' || h.principal) AS summary,
            jsonb_build_object(
                'gpo_name', g.display_name,
                'gpo_guid', upper(g.gpo_guid::text),
                'grants', jsonb_agg(DISTINCT jsonb_build_object('right', h.right_name, 'principal', h.principal,
                                                                'entry', h.raw_entry)),
                'computers_where_it_wins', count(DISTINCT h.computer_guid),
                'note', 'Domain controllers are checked by plugin 9015.'
            ) AS detail
        FROM hit h
        JOIN ad_gpo g ON g.object_guid = h.winning_gpo_guid AND g.client_id = %(client_id)s AND g.valid_to IS NULL
        GROUP BY g.object_guid, g.display_name, g.gpo_guid
    """.replace('@COMPGPO@', COMPUTER_GPO_SQL.strip()).replace('@SETTINGS@', "s.source = 'security_template' AND lower(s.section) = 'privilege rights' AND lower(s.setting_key) IN ('sedebugprivilege', 'sebackupprivilege', 'serestoreprivilege', 'setakeownershipprivilege', 'seloaddriverprivilege', 'setcbprivilege', 'seenabledelegationprivilege', 'sesecurityprivilege', 'seimpersonateprivilege', 'seassignprimarytokenprivilege', 'secreatetokenprivilege', 'semanagevolumeprivilege', 'sesyncagentprivilege', 'setrustedcredmanaccessprivilege', 'serelabelprivilege')"),
}
