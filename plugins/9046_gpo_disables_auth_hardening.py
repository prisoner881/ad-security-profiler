r"""
Plugin 9046: Group Policy Turns Off the 2026 Authentication Hardening

Microsoft's October and November 2026 updates turned on four protections
by default, each with a registry value to turn it back off "temporarily"
for compatibility. Pushed by Group Policy, such an opt-out quietly undoes
the protection on every computer the GPO reaches:

  * KB5134907 (DC updates from 2026-10-13): LDAP binds must present a
    Kerberos ticket for a registered LDAP SPN of the target DC.
    HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\
    LdapSPNVerificationLevel = 0 turns the check off.
  * KB5135557 (2026-11-10, NTLM signing phase 1): clients offer NTLM
    signing. HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0\
    ClientAllowUnsignedNtlm = 1 stops them offering it (relayable NTLM).
  * KB5066470 (2026-10-13): NTLMv1-derived single sign-on blocked by
    default. ...\Lsa\MSV1_0\BlockNtlmv1SSO = 0 sets it back to audit only.
  * KB5121391 (CVE-2026-56155, exploited; enforcement 2026-10-13): AD FS
    repairs the ACL of its DKM key container. HKLM\SOFTWARE\Microsoft\ADFS\
    RemediateDkmAcl = 0 stops the repair, leaving the token-signing keys
    readable as before.

One finding per GPO that sets one of these values and has at least one
enabled link (computer settings not disabled), status 'fail':
  * high: it sets RemediateDkmAcl = 0 (an exploited AD FS flaw), or it sets
    LdapSPNVerificationLevel = 0 and applies to a domain controller;
  * medium: otherwise.
The detail lists each opt-out, the KB, and where the GPO is linked.
Needs SYSVOL (adprofiler.py --sysvol). A value set locally is not visible.

Data: gpo_setting_edge, gpo_link_edge, ad_gpo, directory_object,
v_gpo_dc_application. Identity = the GPO.
"""

PLUGIN = {
    "plugin_id": 9046,
    "category": "Organizational Units",
    "name": "Group Policy Turns Off the 2026 Authentication Hardening",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "GPO-9046",
    "framework_tags": [
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-2",
        "NIST-800-53-SI-2",
        "NIST-800-53-SC-8",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.1",
        "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-4.1",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1557.001",
        "MITRE-ATTCK-T1562.001",
        "CVE-2026-56155",
    ],
    "references": [
        {"title": "Microsoft KB5134907: Access to NetApp SMB shares might fail after installing the October 2026 Windows security update (LdapSPNVerificationLevel)",
         "url": "https://support.microsoft.com/help/5134907"},
        {"title": "Microsoft KB5135557: NTLM signing security improvements in Windows",
         "url": "https://support.microsoft.com/en-us/servicing/os/windows/docs/2026/11/kb5135557-ntlm-signing-security-improvements"},
        {"title": "Microsoft KB5066470: NTLMv1-derived single sign-on blocked by default (BlockNtlmv1SSO)",
         "url": "https://support.microsoft.com/help/5066470"},
        {"title": "Microsoft KB5121391: AD FS DKM container ACL hardening (RemediateDkmAcl)",
         "url": "https://support.microsoft.com/help/5121391"},
    ],
    "description": (
        "A linked GPO sets a registry value that turns off one of Microsoft's October-November 2026 "
        "authentication protections: the domain controllers' LDAP SPN check "
        "(LdapSPNVerificationLevel = 0, KB5134907), NTLM signing offered by clients "
        "(ClientAllowUnsignedNtlm = 1, KB5135557), the NTLMv1 single sign-on block "
        "(BlockNtlmv1SSO = 0, KB5066470) or AD FS's repair of its key container permissions "
        "(RemediateDkmAcl = 0, KB5121391, exploited CVE-2026-56155). High for the AD FS opt-out "
        "or the LDAP opt-out on domain controllers; medium otherwise. Needs SYSVOL."
    ),
    "remediation": (
        "Remove the value from the GPO (or set it to its default) once the incompatible system "
        "is fixed: for LDAP, configure the client (for example NetApp ONTAP) to use LDAP signing "
        "or sealing so it requests an ldap/ ticket; for NTLM, update or replace clients that "
        "cannot sign; for NTLMv1 SSO, remove the NTLMv1 dependency; for AD FS, let it repair the "
        "DKM container ACL and grant the service account only the rights KB5121391 lists. If an "
        "opt-out has to stay, link it only to the computers that need it, record an end date, and "
        "waive this finding with that date."
    ),
    "base_severity": "high",
    "query": r"""
        WITH
        optout(key_lc, bad_value, label, kb, sev, dc_only) AS (
            VALUES (lower('System\CurrentControlSet\Services\NTDS\Parameters\LdapSPNVerificationLevel'), 0,
                    'LdapSPNVerificationLevel = 0 (LDAP service-ticket SPN check off)', 'KB5134907', 'medium', true),
                   (lower('System\CurrentControlSet\Control\Lsa\MSV1_0\ClientAllowUnsignedNtlm'), 1,
                    'ClientAllowUnsignedNtlm = 1 (clients stop offering NTLM signing)', 'KB5135557', 'medium', false),
                   (lower('System\CurrentControlSet\Control\Lsa\MSV1_0\BlockNtlmv1SSO'), 0,
                    'BlockNtlmv1SSO = 0 (NTLMv1-derived single sign-on only audited)', 'KB5066470', 'medium', false),
                   (lower('SOFTWARE\Microsoft\ADFS\RemediateDkmAcl'), 0,
                    'RemediateDkmAcl = 0 (AD FS DKM container ACL not repaired, CVE-2026-56155)', 'KB5121391',
                    'high', false)
        ),
        hit AS (
            SELECT s.gpo_guid, o.label, o.kb, o.sev, o.dc_only, s.setting_value
              FROM gpo_setting_edge s
              JOIN optout o ON o.key_lc = lower(s.setting_key)
             WHERE s.client_id = %(client_id)s AND s.valid_to IS NULL
               AND s.scope = 'machine' AND s.source = 'registry' AND s.section = 'HKLM'
               AND s.value_type IS DISTINCT FROM 'DELETE'
               AND s.setting_value ~ '^\s*[0-9]+\s*$'
               AND trim(s.setting_value)::numeric = o.bad_value
        ),
        linked AS (
            SELECT l.gpo_guid,
                   jsonb_agg(DISTINCT COALESCE(d.dn_current, l.container_guid::text)) AS linked_to
              FROM gpo_link_edge l
              JOIN ad_gpo g
                ON g.client_id = l.client_id AND g.object_guid = l.gpo_guid AND g.valid_to IS NULL
              LEFT JOIN directory_object d
                ON d.client_id = l.client_id AND d.object_guid = l.container_guid
             WHERE l.client_id = %(client_id)s AND l.valid_to IS NULL AND l.link_enabled
               AND (g.gpo_flags IS NULL OR (g.gpo_flags & 2) = 0)
             GROUP BY l.gpo_guid
        ),
        on_dc AS (
            SELECT DISTINCT a.gpo_guid
              FROM v_gpo_dc_application a
             WHERE a.client_id = %(client_id)s AND a.precedence IS NOT NULL
        ),
        per_gpo AS (
            SELECT h.gpo_guid,
                   COALESCE(g.display_name, h.gpo_guid::text) AS gpo_name,
                   lk.linked_to,
                   EXISTS (SELECT 1 FROM on_dc d WHERE d.gpo_guid = h.gpo_guid) AS applies_to_dc,
                   bool_or(h.sev = 'high'
                           OR (h.dc_only AND EXISTS (SELECT 1 FROM on_dc d WHERE d.gpo_guid = h.gpo_guid)))
                       AS is_high,
                   string_agg(h.label, '; ' ORDER BY h.label) AS label_text,
                   jsonb_agg(jsonb_build_object('setting', h.label, 'kb', h.kb, 'value', h.setting_value)
                             ORDER BY h.label) AS optouts
              FROM hit h
              JOIN linked lk ON lk.gpo_guid = h.gpo_guid
              LEFT JOIN ad_gpo g
                ON g.client_id = %(client_id)s AND g.object_guid = h.gpo_guid AND g.valid_to IS NULL
             GROUP BY h.gpo_guid, g.display_name, lk.linked_to
        )
        SELECT
            'fail' AS status,
            p.gpo_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN p.is_high THEN 'high' ELSE 'medium' END AS fd_severity,
            'GPO "' || p.gpo_name || '" turns off 2026 authentication hardening: ' || p.label_text
                || CASE WHEN p.applies_to_dc THEN ' (applies to domain controllers)' ELSE '' END AS summary,
            jsonb_build_object(
                'gpo', p.gpo_name,
                'gpo_guid', p.gpo_guid,
                'linked_to', p.linked_to,
                'applies_to_domain_controllers', p.applies_to_dc,
                'opt_outs', p.optouts,
                'note', 'Read from the GPO''s registry settings; a value set locally on a computer is '
                        'not visible.'
            ) AS detail
        FROM per_gpo p
    """,
}
