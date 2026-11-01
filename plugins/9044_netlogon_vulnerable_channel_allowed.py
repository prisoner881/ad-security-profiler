r"""
Plugin 9044: Domain Controllers Allow Vulnerable Netlogon Secure Channels (ZeroLogon Exception)

"Domain controller: Allow vulnerable Netlogon secure channel connections"
(HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\
VulnerableChannelAllowList, an SDDL security descriptor) names accounts that
may still open a Netlogon secure channel without secure RPC. Microsoft added
it with the ZeroLogon fix (CVE-2020-1472, CISA KEV) for third-party devices
that could not be updated; the DC enforces secure RPC for everyone else
since February 2021. For each account it allows, ZeroLogon still works:
an unauthenticated attacker on the network can authenticate as that account
and reset its password. Allowing a group of domain controllers, or a group
they belong to, re-opens the full domain takeover. 2026 brought two more
unauthenticated Netlogon remote code execution fixes (CVE-2026-41089,
CVE-2026-72982); their patch level is not visible, but an allow-list that
undoes the 2021 enforcement is.

Reads the winning value on each domain controller from Group Policy
(v_dc_effective_gpo_setting, GptTmpl.inf [Registry Values] or
Registry.pol) and lists the trustees of its allow ACEs (SDDL aliases
resolved: WD Everyone, AU Authenticated Users, DC Domain Computers, DD
Domain Controllers, ED Enterprise Domain Controllers, DU Domain Users, BU
Users, AN Anonymous Logon; SIDs resolved to collected accounts).
Results, one row per domain controller, status 'fail':
  * critical: a trustee includes domain controllers -- Everyone,
    Authenticated Users, Anonymous Logon, Domain Controllers, Enterprise
    Domain Controllers, Enterprise Read-only Domain Controllers, or a
    domain controller account;
  * high: a broad group -- Domain Computers, Domain Users, Users -- or a
    trustee that could not be resolved;
  * medium: named accounts or groups only (the documented exception for
    devices that cannot use secure RPC: those accounts can be taken over).
An empty allow-list, or one with no allow ACE, is not reported.

Limits: a value written to the DC's registry outside Group Policy is not
visible; a value deleted by policy is treated as not configured. The
Microsoft Entra Kerberos server object is left out. Requires SYSVOL
collected by the evaluated run (adprofiler.py --sysvol).
"""

PLUGIN = {
    "plugin_id": 9044,
    "category": "Organizational Units",
    "name": "Domain Controllers Allow Vulnerable Netlogon Secure Channels (ZeroLogon Exception)",
    "version": "1.0",
    "revision_date": "2026-11-01",
    "control_id": "GPO-9044",
    "framework_tags": [
        "NIST-800-53-SI-2",
        "NIST-800-53-SC-8",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-6.3.3",
        "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1210",
        "CVE-2020-1472",
    ],
    "references": [
        {"title": "Microsoft: How to manage the changes in Netlogon secure channel connections associated with CVE-2020-1472",
         "url": "https://support.microsoft.com/en-us/topic/how-to-manage-the-changes-in-netlogon-secure-channel-connections-associated-with-cve-2020-1472-f7e8cc17-0309-1d6a-304e-5ba73cd1a11e"},
        {"title": "Microsoft Security Update Guide: CVE-2020-1472 (Netlogon Elevation of Privilege)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"},
        {"title": "CISA: Emergency Directive 20-04 (Netlogon)",
         "url": "https://www.cisa.gov/news-events/directives/ed-20-04-mitigate-netlogon-elevation-privilege-vulnerability-august-2020-patch-tuesday"},
        {"title": "MITRE ATT&CK T1210: Exploitation of Remote Services",
         "url": "https://attack.mitre.org/techniques/T1210/"},
    ],
    "description": (
        "Group Policy on a domain controller sets 'Domain controller: Allow vulnerable Netlogon "
        "secure channel connections', the ZeroLogon (CVE-2020-1472) exception list. Every account "
        "it allows can be impersonated over Netlogon by an unauthenticated attacker, who can then "
        "reset its password. Critical when the list includes domain controllers (directly or "
        "through Everyone, Authenticated Users or a domain controller group); high for Domain "
        "Computers, Domain Users or an unresolved trustee; medium for named accounts."
    ),
    "remediation": (
        "Remove the setting from the GPO named in the detail, or reduce it to the specific "
        "third-party devices that cannot use secure RPC -- never a group, never a domain "
        "controller. Update or replace those devices so the exception can be removed. Check "
        "each DC's System log for Netlogon events 5827-5831, which name the accounts allowed or "
        "denied a vulnerable channel."
    ),
    "base_severity": "critical",
    "query": r"""
        WITH dc AS (
            SELECT c.object_guid AS dc_guid,
                   COALESCE(c.dns_hostname, c.sam_account_name, o.dn_current, c.object_guid::text) AS dc_name,
                   c.dns_hostname
            FROM ad_computer c
            JOIN directory_object o
              ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_domain_controller
              AND NOT is_entra_kerberos_server(c.sam_account_name, c.krbtgt_link)
        ),
        eff AS (
            SELECT e.dc_guid, e.setting_value, e.winning_gpo_guid,
                   COALESCE(g.display_name, e.winning_gpo_guid::text) AS gpo_name
            FROM v_dc_effective_gpo_setting e
            JOIN dc ON dc.dc_guid = e.dc_guid
            LEFT JOIN ad_gpo g
              ON g.client_id = e.client_id AND g.object_guid = e.winning_gpo_guid AND g.valid_to IS NULL
            WHERE e.client_id = %(client_id)s AND e.source = 'registry' AND e.section = 'HKLM'
              AND lower(e.setting_key) = lower('System\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList')
              AND e.value_type IS DISTINCT FROM 'DELETE'
              AND btrim(COALESCE(e.setting_value, '')) <> ''
        ),
        ace AS (
            SELECT e.dc_guid, upper(btrim(m[1])) AS trustee
            FROM eff e
            CROSS JOIN LATERAL regexp_matches(e.setting_value, '\(A;[^;()]*;[^;()]*;[^;()]*;[^;()]*;([^;()]+)\)', 'g') AS m
        ),
        trustee AS (
            SELECT a.dc_guid, a.trustee,
                   COALESCE(
                       CASE a.trustee WHEN 'WD' THEN 'Everyone' WHEN 'AU' THEN 'Authenticated Users'
                                      WHEN 'AN' THEN 'Anonymous Logon' WHEN 'DC' THEN 'Domain Computers'
                                      WHEN 'DD' THEN 'Domain Controllers' WHEN 'ED' THEN 'Enterprise Domain Controllers'
                                      WHEN 'DU' THEN 'Domain Users' WHEN 'BU' THEN 'Users'
                                      WHEN 'S-1-1-0' THEN 'Everyone' WHEN 'S-1-5-11' THEN 'Authenticated Users'
                                      WHEN 'S-1-5-7' THEN 'Anonymous Logon' WHEN 'S-1-5-9' THEN 'Enterprise Domain Controllers'
                                      WHEN 'S-1-5-32-545' THEN 'Users' END,
                       o.sam_account_name,
                       CASE substring(a.trustee from '^S-1-5-21-[0-9-]+-(\d+)$')
                            WHEN '498' THEN 'Enterprise Read-only Domain Controllers'
                            WHEN '513' THEN 'Domain Users' WHEN '515' THEN 'Domain Computers'
                            WHEN '516' THEN 'Domain Controllers' WHEN '521' THEN 'Read-only Domain Controllers' END,
                       a.trustee) AS name,
                   CASE WHEN a.trustee IN ('WD', 'AU', 'AN', 'DD', 'ED', 'S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-9')
                             OR a.trustee ~ '^S-1-5-21-[0-9-]+-(516|521|498)$'
                             OR COALESCE(c.is_domain_controller, false)
                             OR EXISTS (SELECT 1 FROM v_effective_group_membership vem
                                        JOIN ad_computer mc
                                          ON mc.client_id = vem.client_id AND mc.object_guid = vem.member_guid
                                         AND mc.valid_to IS NULL AND mc.is_domain_controller
                                         AND NOT is_entra_kerberos_server(mc.sam_account_name, mc.krbtgt_link)
                                        WHERE vem.client_id = %(client_id)s AND vem.group_guid = o.object_guid)
                             THEN 3
                        WHEN a.trustee IN ('DC', 'DU', 'BU', 'S-1-5-32-545')
                             OR a.trustee ~ '^S-1-5-21-[0-9-]+-(513|515)$'
                             OR o.object_guid IS NULL
                             THEN 2
                        ELSE 1 END AS rank
            FROM ace a
            LEFT JOIN directory_object o
              ON o.client_id = %(client_id)s AND o.object_sid::text = a.trustee AND NOT o.is_deleted
            LEFT JOIN ad_computer c
              ON c.client_id = o.client_id AND c.object_guid = o.object_guid AND c.valid_to IS NULL
        ),
        per_dc AS (
            SELECT d.dc_guid, d.dc_name, d.dns_hostname, e.setting_value, e.winning_gpo_guid, e.gpo_name,
                   max(t.rank) AS rank,
                   string_agg(DISTINCT t.name, ', ') AS trustee_text,
                   jsonb_agg(DISTINCT jsonb_build_object('trustee', t.trustee, 'name', t.name,
                                                         'includes_domain_controllers', t.rank = 3)) AS trustees
            FROM dc d
            JOIN eff e ON e.dc_guid = d.dc_guid
            JOIN trustee t ON t.dc_guid = d.dc_guid
            GROUP BY d.dc_guid, d.dc_name, d.dns_hostname, e.setting_value, e.winning_gpo_guid, e.gpo_name
        )
        SELECT
            'fail' AS status,
            p.dc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE p.rank WHEN 3 THEN 'critical' WHEN 2 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Domain controller ' || p.dc_name || ' allows vulnerable Netlogon secure channels (ZeroLogon, '
                || 'CVE-2020-1472) for ' || p.trustee_text || ' (GPO ''' || p.gpo_name || ''')'
                || CASE p.rank WHEN 3 THEN ': this includes domain controllers -- an unauthenticated attacker '
                                           || 'can impersonate a DC and take over the domain'
                               WHEN 2 THEN ': a broad or unresolved trustee -- many accounts can be impersonated'
                               ELSE ': these accounts can be impersonated and their passwords reset' END AS summary,
            jsonb_build_object(
                'domain_controller', p.dc_name,
                'dns_hostname', p.dns_hostname,
                'setting', 'HKLM\System\CurrentControlSet\Services\Netlogon\Parameters\VulnerableChannelAllowList',
                'value', p.setting_value,
                'winning_gpo_guid', p.winning_gpo_guid,
                'winning_gpo_name', p.gpo_name,
                'allowed_trustees', p.trustees,
                'cves', jsonb_build_array('CVE-2020-1472')
            ) AS detail
        FROM per_dc p
    """,
}
