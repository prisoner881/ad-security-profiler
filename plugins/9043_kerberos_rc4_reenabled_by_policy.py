r"""
Plugin 9043: RC4 or DES Re-Enabled for Kerberos on Domain Controllers by Group Policy

CVE-2026-20833 (January 2026, Kerberos information disclosure) is fixed by
removing RC4 from what the KDC issues by default. The January 2026 update
added audit events; from the April 2026 update a domain controller treats an
account whose msDS-SupportedEncryptionTypes is not set as AES-SHA1 only
(DefaultDomainSupportedEncTypes 0x18), and the July 2026 update removed the
rollback. What remains is RC4 turned back on deliberately: per account
(plugins 1024 and 2018) or for the whole domain through the KDC's
DefaultDomainSupportedEncTypes registry value. Microsoft: explicit RC4 keeps
those services exposed to the CVE. RC4 service tickets are encrypted with
the account's NT hash and are the cheap kind to crack offline (Kerberoasting,
MITRE ATT&CK T1558.003); DES is broken outright.

Reads, on each domain controller, the winning machine-scope value from
Group Policy (v_dc_effective_gpo_setting; Registry.pol and GptTmpl.inf
[Registry Values]) of:
  * HKLM\System\CurrentControlSet\Services\KDC\DefaultDomainSupportedEncTypes
    -- the encryption types the KDC assumes for every account without its
    own msDS-SupportedEncryptionTypes:
      includes RC4 (0x4) or DES (0x1/0x2) -> fail, high (domain-wide);
  * "Network security: Configure encryption types allowed for Kerberos",
    HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\
    Parameters\SupportedEncryptionTypes -- what the DC itself allows:
      includes DES -> fail, high;
      includes RC4 -> fail, medium (the KDC still issues RC4 to accounts
      explicitly set to it; leave RC4 out once none is).
Not configured is not reported: since the July 2026 update the domain
controller's default is AES. Bits: 0x1 DES-CBC-CRC, 0x2 DES-CBC-MD5, 0x4
RC4-HMAC, 0x8 AES128, 0x10 AES256, 0x20 AES256-SK, higher bits "future
encryption types".

One row per domain controller combining both values (worst severity).
Limits: a value written to a DC's registry outside Group Policy, or by a
Group Policy Preferences registry item (not collected), is not visible; a
value deleted by policy (value_type DELETE) is treated as not configured.
The Microsoft Entra Kerberos server object is left out. Requires SYSVOL
collected by the evaluated run (adprofiler.py --sysvol).
"""

PLUGIN = {
    "plugin_id": 9043,
    "category": "Organizational Units",
    "name": "RC4 or DES Re-Enabled for Kerberos on Domain Controllers by Group Policy",
    "version": "1.0",
    "revision_date": "2026-11-01",
    "control_id": "GPO-9043",
    "framework_tags": [
        "NIST-800-53-SC-13",
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.DS-02",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "PCI-DSS-4.0-4.2.1",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.24",
        "SOC2-CC6.1",
        "DISA-STIG",
        "MITRE-ATTCK-T1558.003",
        "CVE-2026-20833",
    ],
    "references": [
        {"title": "Microsoft: How to manage Kerberos KDC usage of RC4 for service account ticket issuance changes related to CVE-2026-20833",
         "url": "https://support.microsoft.com/en-us/topic/how-to-manage-kerberos-kdc-usage-of-rc4-for-service-account-ticket-issuance-changes-related-to-cve-2026-20833-1ebcda33-720a-4da8-93c1-b0496e1910dc"},
        {"title": "Microsoft Security Update Guide: CVE-2026-20833 (Windows Kerberos Information Disclosure)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-20833"},
        {"title": "Microsoft: Network security -- Configure encryption types allowed for Kerberos",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-configure-encryption-types-allowed-for-kerberos"},
        {"title": "Microsoft [MS-KILE]: msDS-SupportedEncryptionTypes bit flags",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-kile/6cfc7b50-11ed-4b4d-846d-6f08f0812919"},
    ],
    "description": (
        "Group Policy on a domain controller turns RC4 or DES back on for Kerberos: the KDC's "
        "DefaultDomainSupportedEncTypes includes RC4 or DES (every account without its own "
        "encryption types gets them again, undoing the CVE-2026-20833 hardening domain-wide), or "
        "the DC's 'Configure encryption types allowed for Kerberos' policy allows DES or RC4. "
        "High for the KDC default or DES; medium when the DC policy allows RC4."
    ),
    "remediation": (
        "Remove DefaultDomainSupportedEncTypes from the GPO named in the detail (the KDC then "
        "uses AES only for accounts without msDS-SupportedEncryptionTypes), or set it to 0x18 "
        "(24, AES128 + AES256). For the few services that still need RC4, set "
        "msDS-SupportedEncryptionTypes on those accounts only, and plan their move to AES "
        "(reset the password once after enabling AES so AES keys exist). In 'Network security: "
        "Configure encryption types allowed for Kerberos' for domain controllers, select "
        "AES128, AES256 and Future encryption types only (2147483640); never DES. Before "
        "removing RC4 from the DCs, check the System log on each DC for KDCSVC events 201-209, "
        "which name the accounts and clients still using RC4."
    ),
    "base_severity": "high",
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
            SELECT e.dc_guid, lower(e.setting_key) AS k, e.setting_value, e.winning_gpo_guid,
                   COALESCE(g.display_name, e.winning_gpo_guid::text) AS gpo_name,
                   CASE WHEN e.setting_value ~ '^\s*[0-9]{1,10}\s*$' THEN trim(e.setting_value)::bigint
                        WHEN e.setting_value ~* '^\s*0x[0-9a-f]{1,8}\s*$'
                             THEN ('x' || lpad(substr(trim(e.setting_value), 3), 8, '0'))::bit(32)::bigint
                   END AS num
            FROM v_dc_effective_gpo_setting e
            LEFT JOIN ad_gpo g
              ON g.client_id = e.client_id AND g.object_guid = e.winning_gpo_guid AND g.valid_to IS NULL
            WHERE e.client_id = %(client_id)s AND e.source = 'registry' AND e.section = 'HKLM'
              AND lower(e.setting_key) IN (
                  lower('System\CurrentControlSet\Services\KDC\DefaultDomainSupportedEncTypes'),
                  lower('Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes'))
              AND e.value_type IS DISTINCT FROM 'DELETE'
        ),
        cls AS (
            SELECT d.*,
                   kd.setting_value AS kdc_value, kd.num AS kdc_num, kd.gpo_name AS kdc_gpo,
                   kd.winning_gpo_guid AS kdc_gpo_guid,
                   pol.setting_value AS pol_value, pol.num AS pol_num, pol.gpo_name AS pol_gpo,
                   pol.winning_gpo_guid AS pol_gpo_guid,
                   COALESCE((kd.num & 3) <> 0, false) AS kdc_des,
                   COALESCE((kd.num & 4) <> 0, false) AS kdc_rc4,
                   COALESCE((pol.num & 3) <> 0, false) AS pol_des,
                   COALESCE((pol.num & 4) <> 0, false) AS pol_rc4
            FROM dc d
            LEFT JOIN eff kd ON kd.dc_guid = d.dc_guid
                            AND kd.k = lower('System\CurrentControlSet\Services\KDC\DefaultDomainSupportedEncTypes')
            LEFT JOIN eff pol ON pol.dc_guid = d.dc_guid
                             AND pol.k = lower('Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes')
        ),
        prob AS (
            SELECT c.*,
                   ARRAY_REMOVE(ARRAY[
                       CASE WHEN c.kdc_rc4 OR c.kdc_des
                            THEN 'KDC DefaultDomainSupportedEncTypes = ' || c.kdc_value
                                 || ' (set by GPO ''' || c.kdc_gpo || ''') includes '
                                 || concat_ws(' and ', CASE WHEN c.kdc_rc4 THEN 'RC4' END,
                                                       CASE WHEN c.kdc_des THEN 'DES' END)
                                 || ': every account without its own encryption types gets it again, '
                                 || 'undoing the CVE-2026-20833 hardening domain-wide' END,
                       CASE WHEN c.pol_rc4 OR c.pol_des
                            THEN '"Configure encryption types allowed for Kerberos" = ' || c.pol_value
                                 || ' (set by GPO ''' || c.pol_gpo || ''') allows '
                                 || concat_ws(' and ', CASE WHEN c.pol_des THEN 'DES' END,
                                                       CASE WHEN c.pol_rc4 THEN 'RC4' END)
                                 || ' on the domain controller' END
                   ], NULL) AS problems,
                   CASE WHEN c.kdc_rc4 OR c.kdc_des OR c.pol_des THEN 'high'
                        WHEN c.pol_rc4 THEN 'medium' END AS sev
            FROM cls c
        )
        SELECT
            'fail' AS status,
            p.dc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            p.sev AS fd_severity,
            'Domain controller ' || p.dc_name || ': ' || array_to_string(p.problems, '; ') AS summary,
            jsonb_build_object(
                'domain_controller', p.dc_name,
                'dns_hostname', p.dns_hostname,
                'kdc_default_domain_supported_enc_types', jsonb_build_object(
                    'setting', 'HKLM\System\CurrentControlSet\Services\KDC\DefaultDomainSupportedEncTypes',
                    'value', p.kdc_value, 'rc4', p.kdc_rc4, 'des', p.kdc_des,
                    'winning_gpo_guid', p.kdc_gpo_guid, 'winning_gpo_name', p.kdc_gpo),
                'allowed_encryption_types_policy', jsonb_build_object(
                    'setting', 'HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters\SupportedEncryptionTypes',
                    'value', p.pol_value, 'rc4', p.pol_rc4, 'des', p.pol_des,
                    'winning_gpo_guid', p.pol_gpo_guid, 'winning_gpo_name', p.pol_gpo),
                'problems', to_jsonb(p.problems),
                'cves', jsonb_build_array('CVE-2026-20833')
            ) AS detail
        FROM prob p
        WHERE p.sev IS NOT NULL
    """,
}
