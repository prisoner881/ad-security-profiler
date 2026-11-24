"""
Plugin 5023: Confirm the November 2026 Security Update on Domain Controllers

The November 2026 Windows update (2026-11-10) fixed three Critical or
near-Critical flaws on domain controllers that leave nothing in the
directory to detect:
  * CVE-2026-119958: LDAP remote code execution, unauthenticated, CVSS 9.8;
  * CVE-2026-85844: Kerberos elevation of privilege, CVSS 9.8: "An
    unauthenticated attacker could send specially crafted Kerberos
    authentication traffic and relay the resulting authentication to an
    affected domain controller" and gain SYSTEM;
  * CVE-2026-118146: Active Directory Domain Services remote code
    execution by any authenticated user, CVSS 8.8, "Exploitation More
    Likely";
and further AD DS fixes (CVE-2026-118148 elevation to SYSTEM,
CVE-2026-118735, CVE-2026-119948, denial-of-service fixes).

[v1.1] The cumulative update also carries the October 2026 fix for
CVE-2026-70229 (AD DS, CVSS 8.1): SpecterOps ("Signed, Sealed, and
Relayed", 2026-10-23) published a working bypass of LDAP signing -- an
NTLM authentication relayed inside the attacker's own signed LDAP session
on port 389 runs an attacker-chosen modification (RBCD, shadow
credentials) as the victim, even with LDAP signing and channel binding
required (plugins 9010 / 9011). The exploit ("LDAP Switcheroo") is in
ntlmrelayx. A DC still without the October update is exposed.

Patch level is not visible in the directory: the finding stands while the
domain has domain controllers, as a prompt to confirm the update -- like
plugin 5022 for AD FS and 6014 for NDES. Waive it (exception_waiver) once
every DC listed has the November 2026 update or later. Domain controllers
whose operating system no longer receives security updates (Windows
Server 2012 R2 and earlier: Extended Security Updates for 2012 / 2012 R2
ended in October 2026) are named separately; plugin 2003 covers them in
full.

One finding per domain, status 'warn', high. Data: ad_domain, ad_computer,
directory_object. Identity = the domain object. Related: 7010
(CVE-2026-122164, cross-forest), 4040 (CVE-2026-123387, crafted names),
9010-9012 (relay protections that also limit CVE-2026-85844).
"""

PLUGIN = {
    "plugin_id": 5023,
    "category": "Domain",
    "name": "Confirm the November 2026 Security Update on Domain Controllers",
    "version": "1.1",
    "revision_date": "2026-11-20",
    "control_id": "DOMAIN-5023",
    "framework_tags": [
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-CSF-2.0-ID.RA-01",
        "PCI-DSS-4.0-6.3.3",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.8.8",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1210",
        "MITRE-ATTCK-T1068",
        "CVE-2026-119958",
        "CVE-2026-85844",
        "CVE-2026-118146",
        "CVE-2026-118148",
        "CVE-2026-118735",
        "CVE-2026-119948",
        "CVE-2026-70229",
    ],
    "references": [
        {"title": "Microsoft Security Update Guide: CVE-2026-119958 (Windows LDAP Remote Code Execution)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-119958"},
        {"title": "Microsoft Security Update Guide: CVE-2026-85844 (Windows Kerberos Elevation of Privilege)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-85844"},
        {"title": "Microsoft Security Update Guide: CVE-2026-118146 (Active Directory Domain Services Remote Code Execution)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-118146"},
        {"title": "Microsoft Security Update Guide: CVE-2026-118148 (Active Directory Domain Services Elevation of Privilege)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-118148"},
        {"title": "SpecterOps: Signed, Sealed, and Relayed -- Bypassing LDAP Signing Through Reauthentication (CVE-2026-70229, 2026-10-23)",
         "url": "https://specterops.io/blog/2026/10/23/ldap-signing-bypass-ntlm-relay/"},
        {"title": "MITRE ATT&CK T1210: Exploitation of Remote Services",
         "url": "https://attack.mitre.org/techniques/T1210/"},
    ],
    "description": (
        "The November 2026 Windows update fixed an unauthenticated LDAP remote code execution "
        "(CVE-2026-119958, CVSS 9.8), a Kerberos relay to SYSTEM on domain controllers "
        "(CVE-2026-85844, CVSS 9.8) and an AD DS remote code execution open to any authenticated "
        "user (CVE-2026-118146, exploitation more likely), among other AD DS fixes; it also "
        "carries October's fix for the LDAP signing bypass CVE-2026-70229, for which a public "
        "exploit appeared on 23 October. Patch level is "
        "not visible in the directory: this lists the domain controllers to confirm, and stands "
        "until waived."
    ),
    "remediation": (
        "Confirm the November 2026 cumulative update (or later) is installed on every domain "
        "controller listed (Get-HotFix, or the update history in Settings / sconfig), including "
        "read-only DCs. A DC whose operating system no longer receives updates cannot be fixed: "
        "replace it. Until every DC is updated, keep LDAP (TCP 389/636/3268/3269) and Kerberos (TCP/UDP "
        "88) reachable only from the networks that need them, require LDAP signing and channel "
        "binding (plugins 9010, 9011), and watch the DCs for unexpected LSASS crashes and new "
        "services. Waive this finding once the update is confirmed everywhere."
    ),
    "base_severity": "high",
    "query": r"""
        WITH
        dc AS (
            SELECT c.object_guid,
                   COALESCE(c.dns_hostname, c.sam_account_name, o.dn_current) AS dc_name,
                   c.operating_system, c.operating_system_version,
                   (c.user_account_control & 67108864) <> 0 AS is_rodc,
                   COALESCE(c.operating_system ~* 'Windows Server (2003|2008|2012)', false) AS unsupported_os
              FROM ad_computer c
              JOIN directory_object o
                ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
             WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_domain_controller
               AND NOT is_entra_kerberos_server(c.sam_account_name, c.krbtgt_link)
        ),
        dc_sum AS (
            SELECT count(*) AS dc_count,
                   count(*) FILTER (WHERE unsupported_os) AS unsupported_count,
                   string_agg(dc_name, ', ' ORDER BY dc_name) AS dc_text,
                   string_agg(dc_name, ', ' ORDER BY dc_name) FILTER (WHERE unsupported_os) AS unsupported_text,
                   jsonb_agg(jsonb_build_object(
                       'domain_controller', dc_name,
                       'operating_system', operating_system,
                       'operating_system_version', operating_system_version,
                       'read_only', is_rodc,
                       'operating_system_out_of_support', unsupported_os) ORDER BY dc_name) AS dcs
              FROM dc
        )
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, d.object_guid::text) || ': confirm the November 2026 '
                || 'security update is installed on its ' || s.dc_count || ' domain controller(s) ('
                || s.dc_text || ') -- it fixes unauthenticated LDAP remote code execution '
                || '(CVE-2026-119958), Kerberos relay to SYSTEM (CVE-2026-85844) and AD DS remote '
                || 'code execution (CVE-2026-118146)'
                || CASE WHEN s.unsupported_count > 0
                        THEN '; ' || s.unsupported_text
                             || CASE WHEN s.unsupported_count = 1 THEN ' runs' ELSE ' run' END
                             || ' an operating system that no longer receives updates (replace)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'domain', d.dns_root,
                'domain_controllers', s.dcs,
                'domain_controllers_out_of_support', s.unsupported_count,
                'update', 'November 2026 cumulative update (2026-11-10) or later',
                'cves_critical', jsonb_build_array('CVE-2026-119958', 'CVE-2026-85844', 'CVE-2026-118146',
                                                   'CVE-2026-118148'),
                'cves_other', jsonb_build_array('CVE-2026-118735', 'CVE-2026-119948'),
                'october_2026_fix_included', 'CVE-2026-70229 (LDAP signing bypass, public exploit 2026-10-23)',
                'note', 'Patch level is not visible in the directory. Waive this finding once every '
                        'domain controller is confirmed updated.'
            ) AS detail
        FROM ad_domain d
        CROSS JOIN dc_sum s
        WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
          AND s.dc_count > 0
    """,
}
