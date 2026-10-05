r"""
Plugin 9023: Anonymous Access to Domain Controllers Allowed by Policy

Detects domain controllers whose effective Group Policy explicitly weakens
the restrictions on anonymous (null session) access:
  * "Network access: Do not allow anonymous enumeration of SAM accounts"
    disabled -- HKLM\System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM
    = 0 -> high (anonymous users can enumerate domain accounts);
  * "Network access: Let Everyone permissions apply to anonymous users"
    enabled -- HKLM\System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous
    = 1 -> high (anything granted to Everyone, e.g. read access to most of
    the directory, becomes anonymous);
  * "Network access: Allow anonymous SID/Name translation" enabled --
    GptTmpl.inf [System Access] LSAAnonymousNameLookup = 1 -> medium;
  * "Network access: Shares that can be accessed anonymously"
    (LanManServer\Parameters\NullSessionShares) with any entry -> medium;
  * "Network access: Named Pipes that can be accessed anonymously"
    (LanManServer\Parameters\NullSessionPipes) with entries other than the
    domain controller defaults netlogon, samr and lsarpc -> medium (only the
    extra entries are reported).
RestrictAnonymous = 0 is the Windows default and is NOT flagged. Settings no
applying GPO configures keep the Windows defaults, which are restrictive, so
absence is never a finding (no uncertainty handling needed).

Why it matters: anonymous enumeration of users, groups and the password
policy gives attackers a target list for password spraying without any
credentials, and extra null-session pipes/shares widen the unauthenticated
RPC/SMB attack surface of the DC (MITRE ATT&CK T1087.002).

One row per DC with at least one problem: status fail, severity the worst
of its problems. Multi-string values are split on newlines (and commas);
pipe/share names are compared case-insensitively. Values deleted by policy
(value_type DELETE) are ignored.

Data: winning machine-scope values per DC (v_dc_effective_gpo_setting);
site-linked GPOs, WMI filters and local policy are not visible. Gating:
returns nothing unless SYSVOL has been collected for the client
(ad_gpo_sysvol has an 'ok' row). Read-only DCs are included.
"""

PLUGIN = {
    "plugin_id": 9023,
    "category": "Organizational Units",
    "name": "Anonymous Access to Domain Controllers Allowed by Policy",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-9023",
    "framework_tags": [
        "NIST-800-53-AC-3", "NIST-CSF-2.0-PR.AA-05", "CIS-CSC-8-3.3", "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "NIST-800-53-CM-6", "NIST-CSF-2.0-PR.PS-01", "PCI-DSS-4.0-2.2.1", "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9", "SOC2-CC7.1",
        "DISA-STIG", "MITRE-ATTCK-T1087.002",
    ],
    "references": [
        {"title": "Microsoft: Network access: Do not allow anonymous enumeration of SAM accounts",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-do-not-allow-anonymous-enumeration-of-sam-accounts"},
        {"title": "Microsoft: Network access: Let Everyone permissions apply to anonymous users",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-let-everyone-permissions-apply-to-anonymous-users"},
        {"title": "Microsoft: Network access: Allow anonymous SID/Name translation",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-allow-anonymous-sidname-translation"},
        {"title": "Microsoft: Network access: Named Pipes that can be accessed anonymously",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-named-pipes-that-can-be-accessed-anonymously"},
        {"title": "Microsoft: Network access: Shares that can be accessed anonymously",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-access-shares-that-can-be-accessed-anonymously"},
        {"title": "MITRE ATT&CK T1087.002: Account Discovery: Domain Account",
         "url": "https://attack.mitre.org/techniques/T1087/002/"},
    ],
    "description": (
        "The effective Group Policy of a domain controller allows anonymous access beyond the "
        "Windows defaults: anonymous SAM enumeration, Everyone permissions applying to anonymous "
        "users, anonymous SID/name translation, or extra anonymously accessible shares or named "
        "pipes."
    ),
    "remediation": (
        "In the GPO named in the finding (or a higher-precedence GPO linked to the Domain "
        "Controllers OU) set Security Options: 'Network access: Do not allow anonymous enumeration "
        "of SAM accounts' = Enabled; 'Network access: Let Everyone permissions apply to anonymous "
        "users' = Disabled; 'Network access: Allow anonymous SID/Name translation' = Disabled; "
        "'Network access: Shares that can be accessed anonymously' = empty; 'Network access: Named "
        "Pipes that can be accessed anonymously' = only what is required (on DCs: netlogon, samr, "
        "lsarpc). Check first which legacy systems (e.g. old NAS or Windows NT trusts) rely on "
        "null sessions. Run gpupdate /force and verify with Get-ItemProperty "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' and "
        "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanManServer\\Parameters'."
    ),
    "base_severity": "high",
    "query": r"""
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
            SELECT e.dc_guid, lower(e.setting_key) AS k, e.setting_key, e.setting_value, e.winning_gpo_guid,
                   COALESCE(g.display_name, e.winning_gpo_guid::text) AS gpo_name,
                   CASE WHEN e.setting_value ~ '^\s*[0-9]+\s*$'
                        THEN trim(e.setting_value)::numeric END AS num
            FROM v_dc_effective_gpo_setting e
            JOIN dc d ON d.dc_guid = e.dc_guid
            LEFT JOIN ad_gpo g
              ON g.client_id = e.client_id AND g.object_guid = e.winning_gpo_guid AND g.valid_to IS NULL
            WHERE e.client_id = %(client_id)s
              AND e.value_type IS DISTINCT FROM 'DELETE'
              AND ((e.source = 'registry' AND e.section = 'HKLM'
                    AND lower(e.setting_key) IN (
                        lower('System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM'),
                        lower('System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous'),
                        lower('System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares'),
                        lower('System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes')))
                   OR (e.source = 'security_template' AND e.section = 'System Access'
                       AND lower(e.setting_key) = 'lsaanonymousnamelookup'))
        ),
        entries AS (
            -- Multi-string entries of the share/pipe lists, minus the defaults.
            SELECT e.dc_guid, e.k, e.gpo_name, e.winning_gpo_guid,
                   string_agg(DISTINCT lower(trim(x.item)), ', ') AS extra
            FROM eff e
            CROSS JOIN LATERAL regexp_split_to_table(COALESCE(e.setting_value, ''), '[\r\n,]+') AS x(item)
            WHERE e.k IN (lower('System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares'),
                          lower('System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes'))
              AND trim(x.item) <> ''
              AND NOT (e.k = lower('System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes')
                       AND lower(trim(x.item)) IN ('netlogon', 'samr', 'lsarpc'))
            GROUP BY e.dc_guid, e.k, e.gpo_name, e.winning_gpo_guid
        ),
        finding AS (
            SELECT e.dc_guid, 1 AS ord, 3 AS rank, 'high' AS sev,
                   'RestrictAnonymousSAM = 0: anonymous enumeration of SAM accounts is allowed (GPO '''
                       || e.gpo_name || ''')' AS text,
                   'HKLM\' || e.setting_key AS setting, e.setting_value AS value,
                   e.winning_gpo_guid, e.gpo_name
            FROM eff e
            WHERE e.k = lower('System\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM') AND e.num = 0
            UNION ALL
            SELECT e.dc_guid, 2, 3, 'high',
                   'EveryoneIncludesAnonymous = 1: Everyone permissions apply to anonymous users (GPO '''
                       || e.gpo_name || ''')',
                   'HKLM\' || e.setting_key, e.setting_value, e.winning_gpo_guid, e.gpo_name
            FROM eff e
            WHERE e.k = lower('System\CurrentControlSet\Control\Lsa\EveryoneIncludesAnonymous') AND e.num = 1
            UNION ALL
            SELECT e.dc_guid, 3, 2, 'medium',
                   'LSAAnonymousNameLookup = 1: anonymous SID/name translation is allowed (GPO '''
                       || e.gpo_name || ''')',
                   '[System Access] ' || e.setting_key, e.setting_value, e.winning_gpo_guid, e.gpo_name
            FROM eff e
            WHERE e.k = 'lsaanonymousnamelookup' AND e.num = 1
            UNION ALL
            SELECT n.dc_guid,
                   CASE WHEN n.k LIKE '%%nullsessionshares' THEN 4 ELSE 5 END, 2, 'medium',
                   CASE WHEN n.k LIKE '%%nullsessionshares'
                        THEN 'shares accessible anonymously: '
                        ELSE 'non-default named pipes accessible anonymously: ' END
                       || n.extra || ' (GPO ''' || n.gpo_name || ''')',
                   CASE WHEN n.k LIKE '%%nullsessionshares'
                        THEN 'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionShares'
                        ELSE 'HKLM\System\CurrentControlSet\Services\LanManServer\Parameters\NullSessionPipes' END,
                   n.extra, n.winning_gpo_guid, n.gpo_name
            FROM entries n
        )
        SELECT
            'fail' AS status,
            d.dc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE max(f.rank) WHEN 3 THEN 'high' ELSE 'medium' END AS fd_severity,
            'Domain controller ' || d.dc_name || ': anonymous access allowed by Group Policy -- '
                || string_agg(f.text, '; ' ORDER BY f.ord) AS summary,
            jsonb_build_object(
                'domain_controller', d.dc_name,
                'dns_hostname', d.dns_hostname,
                'operating_system', d.operating_system,
                'problems', jsonb_agg(jsonb_build_object(
                    'setting', f.setting, 'value', f.value, 'severity', f.sev,
                    'issue', f.text, 'winning_gpo_guid', f.winning_gpo_guid,
                    'winning_gpo_name', f.gpo_name) ORDER BY f.ord)
            ) AS detail
        FROM finding f
        JOIN dc d ON d.dc_guid = f.dc_guid
        GROUP BY d.dc_guid, d.dc_name, d.dns_hostname, d.operating_system
    """,
}
