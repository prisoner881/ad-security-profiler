r"""
Plugin 9047: Domain Controllers Accept Certificates Whose Revocation Cannot Be Checked

The KDC checks a smart-card / PKINIT logon certificate against its CA's
revocation list. HKLM\SYSTEM\CurrentControlSet\Services\Kdc\
UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors (REG_DWORD, any non-zero
value) tells it to use only
cached CRLs and to accept the certificate when revocation status is
unknown -- it fails open. Semperis, "Battling Zombie Certificates"
(2026-10-07): an attacker with domain or enterprise admin rights sets this
value and has the CA leave the CRL Distribution Point out of the
certificates it issues; the certificates they enroll then keep logging on
after they are revoked, surviving password resets and the usual clean-up
(persistence, MITRE T1649). The value is also set for legitimate reasons
(CRLs unreachable from the DCs), which leaves every revoked smart card
working.

Read from the domain controllers' effective Group Policy
(v_dc_effective_gpo_setting): a value set locally on a DC is not visible.
The CA side (DisableExtensionList holding 2.5.29.31) is CA registry and is
not collected.

One finding per domain controller where the winning GPO value is non-zero,
status 'fail', medium.

Needs SYSVOL (adprofiler.py --sysvol). Data: v_dc_effective_gpo_setting,
ad_computer, directory_object, ad_gpo. Identity = the domain controller.
Related: 1046 (weak certificate mapping), 6001-6015 (AD CS).
"""

PLUGIN = {
    "plugin_id": 9047,
    "category": "Organizational Units",
    "name": "Domain Controllers Accept Certificates Whose Revocation Cannot Be Checked",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "GPO-9047",
    "framework_tags": [
        "NIST-800-53-SC-17",
        "NIST-800-53-IA-5(2)",
        "NIST-800-53-CM-6",
        "NIST-CSF-2.0-PR.DS-02",
        "PCI-DSS-4.0-4.2.1.1",
        "CIS-CSC-8-3.10",
        "ISO-27001-2022-A.8.24",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1649",
    ],
    "references": [
        {"title": "Semperis: How to Battle Zombie Certificates (2026-10-07)",
         "url": "https://www.semperis.com/blog/how-to-battle-zombie-certificates-persistent-ad-cs-risk/"},
        {"title": "Microsoft (archived blog): Event ID 29 when starting the KDC service (UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors)",
         "url": "https://learn.microsoft.com/en-us/archive/blogs/instan/event-id-29-when-starting-kdc-service-on-windows-server-2008-r2-dcs"},
        {"title": "MITRE ATT&CK T1649: Steal or Forge Authentication Certificates",
         "url": "https://attack.mitre.org/techniques/T1649/"},
    ],
    "description": (
        "Group Policy sets UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors = 1 on the KDC of a "
        "domain controller: certificate logons (smart card, PKINIT) are accepted when the "
        "certificate's revocation status cannot be determined, so revoked certificates can keep "
        "working -- the persistence technique Semperis described in October 2026 (\"zombie "
        "certificates\"). Needs SYSVOL."
    ),
    "remediation": (
        "Remove the value from the GPO and from the DC's registry, then restart the KDC service. "
        "Make sure every DC can reach the CRL Distribution Points of the CAs that issue logon "
        "certificates. On each CA, check certutil -getreg policy\\DisableExtensionList and remove "
        "2.5.29.31 (CRL Distribution Points) if present; revoke and re-enroll certificates issued "
        "without a CDP. Find who set the value (GPO change history, event 5136 on the GPO object)."
    ),
    "base_severity": "medium",
    "query": r"""
        WITH
        dc AS (
            SELECT c.object_guid AS dc_guid,
                   COALESCE(c.dns_hostname, c.sam_account_name, o.dn_current) AS dc_name
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
              LEFT JOIN ad_gpo g
                ON g.client_id = e.client_id AND g.object_guid = e.winning_gpo_guid AND g.valid_to IS NULL
             WHERE e.client_id = %(client_id)s AND e.source = 'registry' AND e.section = 'HKLM'
               AND lower(e.setting_key) =
                   lower('System\CurrentControlSet\Services\Kdc\UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors')
               AND e.value_type IS DISTINCT FROM 'DELETE'
               AND e.setting_value ~ '^\s*[0-9]+\s*$'
               AND trim(e.setting_value)::numeric <> 0
        )
        SELECT
            'fail' AS status,
            d.dc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            'Domain controller ' || d.dc_name || ': GPO "' || e.gpo_name
                || '" sets UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors = ' || trim(e.setting_value)
                || ', so the KDC accepts logon '
                || 'certificates whose revocation cannot be checked (revoked certificates may keep working)'
                AS summary,
            jsonb_build_object(
                'domain_controller', d.dc_name,
                'setting', 'HKLM\SYSTEM\CurrentControlSet\Services\Kdc\UseCachedCRLOnlyAndIgnoreRevocationUnknownErrors',
                'value', e.setting_value,
                'winning_gpo', e.gpo_name,
                'winning_gpo_guid', e.winning_gpo_guid,
                'expected', 'not set (0)'
            ) AS detail
        FROM dc d
        JOIN eff e ON e.dc_guid = d.dc_guid
    """,
}
