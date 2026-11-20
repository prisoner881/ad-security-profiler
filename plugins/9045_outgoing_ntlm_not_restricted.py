"""
Plugin 9045: Outgoing NTLM Is Not Restricted by Group Policy (NTLM Hash Leak and Relay)

November 2026 brought two NTLM hash-disclosure flaws reached through email:
  * CVE-2026-124194 (Microsoft Outlook, NTLMv2 hash disclosure) --
    exploited in the wild;
  * CVE-2026-121680 (Windows NTLM spoofing, CVSS 7.5): a crafted message
    makes the computer connect to an attacker's server, which captures the
    user's Net-NTLMv2 response and relays it to another service.
Both depend on Windows sending NTLM to a server the attacker names. The
Group Policy setting "Network security: Restrict NTLM: Outgoing NTLM
traffic to remote servers" (HKLM\\System\\CurrentControlSet\\Control\\Lsa\\
MSV1_0\\RestrictSendingNTLMTraffic: 0 allow all, 1 audit all, 2 deny all)
stops that for every flaw of the class; "Add remote server exceptions for
NTLM authentication" (ClientAllowedNTLMServers) keeps the servers that still
need NTLM working. Microsoft's guidance is to audit first (1), then deny (2)
with exceptions.

The setting matters on workstations and servers, where mail is read, not
only on domain controllers, so this reads every enabled GPO link (domain
root and OUs) rather than the DC-only effective-settings view. Whether a
given computer is under a link is not worked out (security filtering, WMI
filters and site links are not evaluated).

One finding per domain, status 'warn':
  * medium: no linked GPO sets the value to 1 or 2 (not configured, or set
    to 0 / allow all);
  * low: the value is 2 (deny) only in GPOs linked to OUs, not at the
    domain root -- confirm every computer is under them; or it is 1 (audit)
    at best -- NTLM is still sent.
No finding when a GPO linked at the domain root sets 2.
The detail lists each linked GPO that sets the value (with where it is
linked), the exception list where set, and the linked GPOs whose SYSVOL
files could not be read (their settings are unknown).

Needs SYSVOL (adprofiler.py --sysvol). Data: gpo_setting_edge,
gpo_link_edge, ad_gpo, ad_gpo_sysvol, ad_domain, directory_object.
Identity = the domain object. Related: 9010-9012 (LDAP and SMB signing,
channel binding: relay targets), 9013 (LM / NTLMv1), 6011 (certificate
enrollment over HTTP), 1040 (privileged accounts outside Protected Users,
whose members never use NTLM).
"""

PLUGIN = {
    "plugin_id": 9045,
    "category": "Organizational Units",
    "name": "Outgoing NTLM Is Not Restricted by Group Policy (NTLM Hash Leak and Relay)",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "GPO-9045",
    "framework_tags": [
        "NIST-800-53-SI-2",
        "NIST-800-53-RA-5",
        "NIST-800-53-CM-6",
        "NIST-800-53-CM-7",
        "NIST-800-53-IA-2(8)",
        "NIST-CSF-2.0-ID.RA-01",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-6.3.3",
        "PCI-DSS-4.0-2.2.4",
        "CIS-CSC-8-4.8",
        "CIS-CSC-8-7.3",
        "ISO-27001-2022-A.8.8",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC7.1",
        "MITRE-ATTCK-T1187",
        "MITRE-ATTCK-T1557.001",
        "CVE-2026-124194",
        "CVE-2026-121680",
    ],
    "references": [
        {"title": "Microsoft Security Update Guide: CVE-2026-124194 (Microsoft Outlook, exploited)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-124194"},
        {"title": "Microsoft Security Update Guide: CVE-2026-121680 (Windows NTLM Spoofing)",
         "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2026-121680"},
        {"title": "Microsoft: Network security: Restrict NTLM: Outgoing NTLM traffic to remote servers",
         "url": "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/network-security-restrict-ntlm-outgoing-ntlm-traffic-to-remote-servers"},
        {"title": "MITRE ATT&CK T1187: Forced Authentication",
         "url": "https://attack.mitre.org/techniques/T1187/"},
    ],
    "description": (
        "No Group Policy restricts outgoing NTLM (\"Network security: Restrict NTLM: Outgoing NTLM "
        "traffic to remote servers\"), so computers send users' NTLM responses to any server they "
        "are steered to. November 2026 fixed two such flaws reached through email: Outlook "
        "CVE-2026-124194 (exploited in the wild) and NTLM CVE-2026-121680 (hash captured and "
        "relayed). Medium when not configured or set to allow all; low when it is only audited, "
        "or denied only in GPOs linked to OUs. Needs SYSVOL."
    ),
    "remediation": (
        "Install the November 2026 Windows and Office updates. Then set \"Network security: "
        "Restrict NTLM: Outgoing NTLM traffic to remote servers\" in a GPO linked at the domain "
        "root: start with \"Audit all\" and review the NTLM Operational log (Applications and "
        "Services Logs\\Microsoft\\Windows\\NTLM) for the servers that still need NTLM, list those "
        "in \"Add remote server exceptions for NTLM authentication\", then change it to \"Deny "
        "all\". Block outbound SMB (TCP 445) and WebDAV to the internet at the perimeter, and add "
        "privileged accounts to Protected Users (plugin 1040)."
    ),
    "base_severity": "medium",
    "query": r"""
        WITH
        dom AS (
            SELECT d.object_guid, d.dns_root
              FROM ad_domain d
             WHERE d.client_id = %(client_id)s AND d.valid_to IS NULL
               AND EXISTS (SELECT 1 FROM ad_gpo_sysvol s
                            WHERE s.client_id = %(client_id)s AND s.read_status = 'ok')
        ),
        lnk AS (
            SELECT l.gpo_guid, l.container_guid, o.dn_current AS container_dn,
                   EXISTS (SELECT 1 FROM ad_domain m
                            WHERE m.client_id = l.client_id AND m.object_guid = l.container_guid
                              AND m.valid_to IS NULL) AS at_domain_root,
                   COALESCE(g.display_name, l.gpo_guid::text) AS gpo_name
              FROM gpo_link_edge l
              JOIN ad_gpo g
                ON g.client_id = l.client_id AND g.object_guid = l.gpo_guid AND g.valid_to IS NULL
              LEFT JOIN directory_object o
                ON o.client_id = l.client_id AND o.object_guid = l.container_guid
             WHERE l.client_id = %(client_id)s AND l.valid_to IS NULL AND l.link_enabled
               AND (g.gpo_flags IS NULL OR (g.gpo_flags & 2) = 0)
        ),
        setting AS (
            SELECT s.gpo_guid, lower(s.setting_key) AS k, s.setting_value,
                   CASE WHEN s.setting_value ~ '^\s*[0-9]+\s*$' THEN trim(s.setting_value)::numeric END AS num
              FROM gpo_setting_edge s
             WHERE s.client_id = %(client_id)s AND s.valid_to IS NULL
               AND s.scope = 'machine' AND s.source = 'registry' AND s.section = 'HKLM'
               AND lower(s.setting_key) IN (
                     lower('System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic'),
                     lower('System\CurrentControlSet\Control\Lsa\MSV1_0\ClientAllowedNTLMServers'))
               AND s.value_type IS DISTINCT FROM 'DELETE'
        ),
        restrict_link AS (
            SELECT l.*, s.setting_value, s.num
              FROM lnk l
              JOIN setting s ON s.gpo_guid = l.gpo_guid
               AND s.k = lower('System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic')
        ),
        summary AS (
            SELECT bool_or(r.num = 2 AND r.at_domain_root) AS deny_at_root,
                   bool_or(r.num = 2) AS deny_somewhere,
                   bool_or(r.num = 1) AS audit_somewhere,
                   jsonb_agg(DISTINCT jsonb_build_object(
                       'gpo', r.gpo_name, 'gpo_guid', r.gpo_guid, 'linked_to', r.container_dn,
                       'at_domain_root', r.at_domain_root, 'value', r.setting_value,
                       'meaning', CASE r.num WHEN 0 THEN 'allow all' WHEN 1 THEN 'audit all'
                                             WHEN 2 THEN 'deny all' ELSE 'unrecognised' END))
                       FILTER (WHERE r.gpo_guid IS NOT NULL) AS restrict_gpos
              FROM restrict_link r
        ),
        exceptions AS (
            SELECT jsonb_agg(DISTINCT jsonb_build_object('gpo', l.gpo_name, 'servers', s.setting_value))
                       AS exception_gpos
              FROM lnk l
              JOIN setting s ON s.gpo_guid = l.gpo_guid
               AND s.k = lower('System\CurrentControlSet\Control\Lsa\MSV1_0\ClientAllowedNTLMServers')
        ),
        unreadable AS (
            SELECT jsonb_agg(DISTINCT jsonb_build_object(
                       'gpo', l.gpo_name, 'gpo_guid', l.gpo_guid,
                       'read_status', COALESCE(sv.read_status, 'not_collected'))) AS gpos
              FROM lnk l
              LEFT JOIN ad_gpo_sysvol sv
                ON sv.client_id = %(client_id)s AND sv.gpo_object_guid = l.gpo_guid
             WHERE sv.read_status IS DISTINCT FROM 'ok'
        ),
        cls AS (
            SELECT d.*, s.*, e.exception_gpos, u.gpos AS unreadable_gpos,
                   CASE WHEN COALESCE(s.deny_at_root, false) THEN 'ok'
                        WHEN COALESCE(s.deny_somewhere, false) THEN 'deny_ou_only'
                        WHEN COALESCE(s.audit_somewhere, false) THEN 'audit_only'
                        ELSE 'not_restricted' END AS state
              FROM dom d
              CROSS JOIN summary s
              CROSS JOIN exceptions e
              CROSS JOIN unreadable u
        )
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.state = 'not_restricted' THEN 'medium' ELSE 'low' END AS fd_severity,
            'Domain ' || COALESCE(c.dns_root, c.object_guid::text) || ': '
                || CASE c.state
                       WHEN 'not_restricted'
                       THEN 'no Group Policy restricts or audits outgoing NTLM (RestrictSendingNTLMTraffic '
                            || 'not set to audit or deny), so computers send NTLM responses to any server '
                            || 'they are steered to'
                       WHEN 'audit_only'
                       THEN 'outgoing NTLM is only audited by Group Policy (RestrictSendingNTLMTraffic = 1), '
                            || 'so NTLM responses are still sent to any server'
                       ELSE 'outgoing NTLM is denied only by GPOs linked to OUs, not at the domain root: '
                            || 'confirm every computer is under them'
                   END
                || ' -- the path of the Outlook (CVE-2026-124194, exploited) and NTLM (CVE-2026-121680) '
                || 'hash-leak flaws'
                || CASE WHEN c.unreadable_gpos IS NOT NULL
                        THEN '; uncertain: some linked GPOs could not be read' ELSE '' END AS summary,
            jsonb_build_object(
                'domain', c.dns_root,
                'setting', 'HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0\RestrictSendingNTLMTraffic',
                'assessment', c.state,
                'expected', '2 (deny all) in a GPO linked at the domain root, with exceptions as needed',
                'gpos_setting_it', COALESCE(c.restrict_gpos, '[]'::jsonb),
                'exception_lists', COALESCE(c.exception_gpos, '[]'::jsonb),
                'unreadable_linked_gpos', COALESCE(c.unreadable_gpos, '[]'::jsonb),
                'cves', jsonb_build_array('CVE-2026-124194', 'CVE-2026-121680'),
                'note', 'Linked GPOs are read as configured; security filtering, WMI filters and '
                        'site-linked GPOs are not evaluated, and a locally set value is not visible.'
            ) AS detail
        FROM cls c
        WHERE c.state <> 'ok'
    """,
}
