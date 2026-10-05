r"""
Plugin 9013: LM / NTLMv1 Authentication Accepted by Domain Controllers

Detects domain controllers whose effective Group Policy lets them accept LM
or NTLMv1 authentication, or store LM password hashes:
  * "Network security: LAN Manager authentication level",
    HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel. On a DC
    (which validates NTLM for the whole domain) only level 5 refuses LM and
    NTLMv1; level 4 refuses LM but accepts NTLMv1; levels 0-3 accept both,
    and levels 0-2 also make the DC itself send LM/NTLMv1 responses.
  * "Network security: Do not store LAN Manager hash value on next password
    change", HKLM\System\CurrentControlSet\Control\Lsa\NoLMHash (default 1).

Why it matters: NTLMv1 and LM responses can be cracked or, with a chosen
challenge, converted to the account's NT hash (for a DC computer account:
DCSync); coerced DC authentication downgraded to NTLMv1 can also be relayed
to LDAP regardless of signing ("drop the MIC"). Stored LM hashes are
trivially crackable from ntds.dit. MITRE ATT&CK T1557.001, T1110.002.

Results (one row per DC combining both settings, worst status and highest
severity):
  * LmCompatibilityLevel 0-2 -> fail, high; 3 or 4 -> fail, medium.
  * NoLMHash = 0 -> fail, high.
  * LmCompatibilityLevel not configured by any applying GPO -> warn, low (OS
    default 3: LM and NTLMv1 accepted, but it may be set locally).
  * LmCompatibilityLevel 5 and NoLMHash absent or 1 -> not reported.
  * Unrecognised values -> warn, low.

Data: the winning machine-scope value on each DC
(v_dc_effective_gpo_setting). Site-linked GPOs, WMI filters and local
policy are not visible. A value deleted by policy (value_type DELETE) is
treated as not configured.

Gating: returns nothing unless SYSVOL has been collected for the client
(ad_gpo_sysvol has an 'ok' row). "Not configured" is never a claim about
the DC's actual state; if a GPO applying to the DC could not be read from
SYSVOL that conclusion is marked uncertain and the GPOs are listed in
detail. Read-only DCs are included.
"""

PLUGIN = {
    "plugin_id": 9013,
    "category": "Organizational Units",
    "name": "LM / NTLMv1 Authentication Accepted by Domain Controllers",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "GPO-9013",
    "framework_tags": [
        "NIST-800-53-CM-6", "NIST-CSF-2.0-PR.PS-01", "PCI-DSS-4.0-2.2.1", "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9", "SOC2-CC7.1",
        "NIST-800-53-SC-13", "ISO-27001-2022-A.8.24",
        "NIST-800-53-IA-5(1)", "NIST-800-53-SC-28", "PCI-DSS-4.0-8.3.2",
        "DISA-STIG", "MITRE-ATTCK-T1557.001", "MITRE-ATTCK-T1110.002",
    ],
    "references": [
        {"title": "Microsoft: Network security: LAN Manager authentication level",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-lan-manager-authentication-level"},
        {"title": "Microsoft: Network security: Do not store LAN Manager hash value on next password change",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-do-not-store-lan-manager-hash-value-on-next-password-change"},
        {"title": "MITRE ATT&CK T1557.001: LLMNR/NBT-NS Poisoning and SMB Relay",
         "url": "https://attack.mitre.org/techniques/T1557/001/"},
        {"title": "MITRE ATT&CK T1110.002: Password Cracking",
         "url": "https://attack.mitre.org/techniques/T1110/002/"},
    ],
    "description": (
        "The effective Group Policy of a domain controller lets it accept LM or NTLMv1 "
        "authentication (LmCompatibilityLevel below 5, or not configured) or store LM password "
        "hashes (NoLMHash = 0). LM/NTLMv1 responses can be cracked or converted to NT hashes."
    ),
    "remediation": (
        "Find remaining NTLMv1/LM users first: on the DCs review Security event 4624 "
        "('Package Name (NTLM only)' = NTLM V1 / LM) or enable 'Network security: Restrict NTLM: "
        "Audit NTLM authentication in this domain'. Upgrade or reconfigure those clients. Then in "
        "a GPO linked to the Domain Controllers OU (and ideally domain-wide) set Security Options > "
        "'Network security: LAN Manager authentication level' = 'Send NTLMv2 response only. Refuse "
        "LM & NTLM' (LmCompatibilityLevel = 5) and 'Network security: Do not store LAN Manager hash "
        "value on next password change' = Enabled (NoLMHash = 1). LM hashes already stored are only "
        "removed when each password is next changed. Run gpupdate /force and verify with "
        "Get-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name LmCompatibilityLevel,NoLMHash."
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
        unreadable AS (
            SELECT x.dc_guid,
                   jsonb_agg(jsonb_build_object('gpo_guid', x.gpo_guid, 'display_name', x.display_name,
                                                'read_status', x.read_status)
                             ORDER BY x.gpo_guid) AS gpos
            FROM (
                SELECT DISTINCT a.dc_guid, a.gpo_guid, g.display_name,
                       COALESCE(s.read_status, 'not_collected') AS read_status
                FROM v_gpo_dc_application a
                LEFT JOIN ad_gpo_sysvol s
                  ON s.client_id = a.client_id AND s.gpo_object_guid = a.gpo_guid
                LEFT JOIN ad_gpo g
                  ON g.client_id = a.client_id AND g.object_guid = a.gpo_guid AND g.valid_to IS NULL
                WHERE a.client_id = %(client_id)s AND a.precedence IS NOT NULL
                  AND s.read_status IS DISTINCT FROM 'ok'
            ) x
            GROUP BY x.dc_guid
        ),
        eff AS (
            SELECT e.dc_guid, lower(e.setting_key) AS k, e.setting_value, e.winning_gpo_guid,
                   COALESCE(g.display_name, e.winning_gpo_guid::text) AS gpo_name,
                   CASE WHEN e.setting_value ~ '^\s*[0-9]+\s*$'
                        THEN trim(e.setting_value)::numeric END AS num
            FROM v_dc_effective_gpo_setting e
            LEFT JOIN ad_gpo g
              ON g.client_id = e.client_id AND g.object_guid = e.winning_gpo_guid AND g.valid_to IS NULL
            WHERE e.client_id = %(client_id)s AND e.source = 'registry' AND e.section = 'HKLM'
              AND lower(e.setting_key) IN (lower('System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel'),
                                           lower('System\CurrentControlSet\Control\Lsa\NoLMHash'))
              AND e.value_type IS DISTINCT FROM 'DELETE'
        ),
        cls AS (
            SELECT d.*, u.gpos AS unreadable_gpos,
                   lm.setting_value AS lm_value, lm.gpo_name AS lm_gpo, lm.winning_gpo_guid AS lm_gpo_guid,
                   nh.setting_value AS nh_value, nh.gpo_name AS nh_gpo, nh.winning_gpo_guid AS nh_gpo_guid,
                   CASE WHEN lm.dc_guid IS NULL THEN 'absent'
                        WHEN lm.num = 5 THEN 'ok'
                        WHEN lm.num IN (3, 4) THEN 'medium'
                        WHEN lm.num IN (0, 1, 2) THEN 'high'
                        ELSE 'unrecognised' END AS lm_state,
                   CASE WHEN nh.dc_guid IS NULL OR nh.num = 1 THEN 'ok'
                        WHEN nh.num = 0 THEN 'high'
                        ELSE 'unrecognised' END AS nh_state,
                   lm.num AS lm_num
            FROM dc d
            LEFT JOIN eff lm ON lm.dc_guid = d.dc_guid
                            AND lm.k = lower('System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel')
            LEFT JOIN eff nh ON nh.dc_guid = d.dc_guid
                            AND nh.k = lower('System\CurrentControlSet\Control\Lsa\NoLMHash')
            LEFT JOIN unreadable u ON u.dc_guid = d.dc_guid
        ),
        prob AS (
            SELECT c.*,
                   ARRAY_REMOVE(ARRAY[
                       CASE c.lm_state
                           WHEN 'high' THEN 'LmCompatibilityLevel = ' || c.lm_value
                               || ' (set by GPO ''' || c.lm_gpo || '''): the DC accepts LM and NTLMv1 '
                               || 'authentication and itself sends LM/NTLMv1 responses'
                           WHEN 'medium' THEN 'LmCompatibilityLevel = ' || c.lm_value
                               || ' (set by GPO ''' || c.lm_gpo || '''): the DC still accepts '
                               || CASE WHEN c.lm_num = 3 THEN 'LM and NTLMv1' ELSE 'NTLMv1' END
                               || ' authentication'
                           WHEN 'unrecognised' THEN 'LmCompatibilityLevel = ' || COALESCE(c.lm_value, '(empty)')
                               || ' (set by GPO ''' || c.lm_gpo || '''): unrecognised value'
                           WHEN 'absent' THEN 'LmCompatibilityLevel is not enforced by Group Policy (not '
                               || 'configured by any applying GPO; the OS default 3 accepts LM and NTLMv1, '
                               || 'but it may be set locally)'
                               || CASE WHEN c.unreadable_gpos IS NOT NULL
                                       THEN ' -- uncertain: some GPOs applying to this DC could not be read'
                                       ELSE '' END
                       END,
                       CASE c.nh_state
                           WHEN 'high' THEN 'NoLMHash = 0 (set by GPO ''' || c.nh_gpo
                               || '''): LM hashes of passwords are stored'
                           WHEN 'unrecognised' THEN 'NoLMHash = ' || COALESCE(c.nh_value, '(empty)')
                               || ' (set by GPO ''' || c.nh_gpo || '''): unrecognised value'
                       END
                   ], NULL) AS problems,
                   CASE WHEN c.lm_state IN ('high', 'medium') OR c.nh_state = 'high' THEN 'fail'
                        WHEN c.lm_state IN ('absent', 'unrecognised') OR c.nh_state = 'unrecognised' THEN 'warn'
                        ELSE 'pass' END AS status,
                   CASE WHEN c.lm_state = 'high' OR c.nh_state = 'high' THEN 'high'
                        WHEN c.lm_state = 'medium' THEN 'medium'
                        ELSE 'low' END AS sev
            FROM cls c
        )
        SELECT
            p.status,
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
                'operating_system', p.operating_system,
                'lm_compatibility_level', jsonb_build_object(
                    'setting', 'HKLM\System\CurrentControlSet\Control\Lsa\LmCompatibilityLevel',
                    'configured_by_group_policy', p.lm_state <> 'absent',
                    'value', p.lm_value, 'winning_gpo_guid', p.lm_gpo_guid, 'winning_gpo_name', p.lm_gpo,
                    'assessment', p.lm_state, 'expected', '5'),
                'no_lm_hash', jsonb_build_object(
                    'setting', 'HKLM\System\CurrentControlSet\Control\Lsa\NoLMHash',
                    'configured_by_group_policy', p.nh_value IS NOT NULL,
                    'value', p.nh_value, 'winning_gpo_guid', p.nh_gpo_guid, 'winning_gpo_name', p.nh_gpo,
                    'assessment', p.nh_state, 'expected', '1 (default when not configured)'),
                'problems', to_jsonb(p.problems),
                'unreadable_applying_gpos', COALESCE(p.unreadable_gpos, '[]'::jsonb)
            ) AS detail
        FROM prob p
        WHERE p.status <> 'pass'
    """,
}
