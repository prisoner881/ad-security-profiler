"""
Plugin 5019: Write Access to DNS Zones Held by Principals Other Than DnsAdmins or Tier 0

Reports AD-integrated DNS zones whose ACL grants a write-level right on the
zone object itself -- GenericAll, GenericWrite, WriteDacl, WriteOwner, Delete
or WriteProperty -- to a principal other than DnsAdmins and Tier 0. One row
per zone (object_guid = the zone), listing each trustee and its rights.

Why it matters: write access to a zone is DnsAdmins-equivalent for that
zone: the holder can change or delete any record (hijack name resolution,
add a WPAD or wildcard record for credential interception, redirect a
server's name for NTLM relay), or rewrite the zone's ACL. Delegating it
outside DnsAdmins bypasses the group that administrators watch
(PingCastle P-DNSDelegation). CreateChild alone -- the "any user can add a
new record" default for Authenticated Users -- is plugin 4035's finding,
not this one.

Never reported: SYSTEM, CREATOR OWNER (applies to records created by the
holder), Administrators, Enterprise Domain Controllers, Domain Admins,
Domain Controllers, Schema Admins, Enterprise Admins, DnsAdmins (by name),
v_privileged_principal. Only ACEs that apply to the zone object itself are
considered (inherit-only ACEs are not).

Severity ('warn'): medium; high ('fail') when a broad principal (Everyone,
Authenticated Users, Domain Users, Domain Computers, Users) holds the right.
"""

PLUGIN = {
    "plugin_id": 5019,
    "category": "ACLs",
    "name": "Write Access to DNS Zones Held by Principals Other Than DnsAdmins or Tier 0",
    "version": "1.0",
    "revision_date": "2026-10-20",
    "control_id": "ACL-5019",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-CSF-2.0-PR.AA-05",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "CIS-CSC-8-3.3",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "MITRE-ATTCK-T1557",
        "MITRE-ATTCK-T1584.002",
    ],
    "references": [
        {"title": "NetSPI: Beyond LLMNR/NBNS Spoofing -- Exploiting Active Directory-Integrated DNS",
         "url": "https://blog.netspi.com/exploiting-adidns/"},
        {"title": "PingCastle health check rules (P-DNSDelegation)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1557: Adversary-in-the-Middle",
         "url": "https://attack.mitre.org/techniques/T1557/"},
    ],
    "description": (
        "A principal other than DnsAdmins or Tier 0 holds write rights "
        "(full control, write, write DACL/owner, delete, write property) on "
        "an AD-integrated DNS zone, so it can change any record in the zone. "
        "Medium; high when the holder is a broad group."
    ),
    "remediation": (
        "Remove the ACE (DNS Manager > zone > Properties > Security, or "
        "dsacls on the zone's distinguished name). If someone really needs "
        "to manage the zone, add them to DnsAdmins, which is monitored and "
        "protected, or delegate record-level rights only."
    ),
    "base_severity": "medium",
    "query": """
        WITH zone AS (
            SELECT z.object_guid, z.zone_name, o.dn_current
            FROM ad_dns_zone z
            JOIN directory_object o
              ON o.object_guid = z.object_guid AND o.client_id = z.client_id AND NOT o.is_deleted
            WHERE z.client_id = %(client_id)s AND z.valid_to IS NULL
        ),
        ace AS (
            SELECT z.object_guid, z.zone_name, z.dn_current, a.trustee_sid::text AS sid,
                   bit_or(a.access_mask) AS mask
            FROM acl_edge a
            JOIN zone z ON z.object_guid = a.object_guid
            WHERE a.client_id = %(client_id)s AND a.valid_to IS NULL
              AND a.ace_type = 'allow' AND a.inherit_only IS NOT TRUE
              -- GenericAll, GenericWrite, WriteDacl, WriteOwner, Delete, WriteProperty
              AND (a.access_mask & (268435456 | 1073741824 | 262144 | 524288 | 65536 | 32)) <> 0
            GROUP BY z.object_guid, z.zone_name, z.dn_current, a.trustee_sid
        ),
        labelled AS (
            SELECT x.*,
                   COALESCE(p.sam_account_name,
                            CASE x.sid WHEN 'S-1-1-0' THEN 'Everyone' WHEN 'S-1-5-11' THEN 'Authenticated Users'
                                       WHEN 'S-1-5-7' THEN 'Anonymous Logon' WHEN 'S-1-5-32-545' THEN 'Users'
                                       WHEN 'S-1-5-10' THEN 'SELF' END,
                            x.sid) AS trustee,
                   (x.sid IN ('S-1-1-0', 'S-1-5-11', 'S-1-5-7', 'S-1-5-32-545')
                    OR x.sid ~ '^S-1-5-21-[0-9-]+-(513|515)$') AS broad,
                   array_to_string(ARRAY_REMOVE(ARRAY[
                       CASE WHEN (x.mask & 268435456) <> 0 OR (x.mask & 983551) = 983551 THEN 'GenericAll' END,
                       CASE WHEN (x.mask & 1073741824) <> 0 THEN 'GenericWrite' END,
                       CASE WHEN (x.mask & 262144) <> 0 THEN 'WriteDacl' END,
                       CASE WHEN (x.mask & 524288) <> 0 THEN 'WriteOwner' END,
                       CASE WHEN (x.mask & 65536) <> 0 THEN 'Delete' END,
                       CASE WHEN (x.mask & 32) <> 0 THEN 'WriteProperty' END], NULL), ', ') AS rights
            FROM ace x
            LEFT JOIN directory_object p
              ON p.object_sid = x.sid AND p.client_id = %(client_id)s AND NOT p.is_deleted
            WHERE x.sid NOT IN ('S-1-5-18', 'S-1-3-0', 'S-1-5-32-544', 'S-1-5-9', 'S-1-5-10')
              AND x.sid !~ '-(512|516|518|519)$'
              AND lower(COALESCE(p.sam_account_name, '')) <> 'dnsadmins'
              AND NOT EXISTS (SELECT 1 FROM v_privileged_principal vp
                              WHERE vp.client_id = %(client_id)s AND vp.object_guid = p.object_guid)
        )
        SELECT
            CASE WHEN bool_or(l.broad) THEN 'fail' ELSE 'warn' END AS status,
            l.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN bool_or(l.broad) THEN 'high' ELSE 'medium' END AS fd_severity,
            'DNS zone "' || COALESCE(l.zone_name, l.dn_current) || '" grants write access to principals '
                || 'outside DnsAdmins and Tier 0: '
                || string_agg(l.trustee || ' (' || l.rights || ')', ', ' ORDER BY lower(l.trustee), l.sid) AS summary,
            jsonb_build_object(
                'zone_name', l.zone_name,
                'zone_dn', l.dn_current,
                'grants', jsonb_agg(jsonb_build_object('trustee', l.trustee, 'trustee_sid', l.sid,
                                                       'rights', l.rights, 'access_mask', l.mask,
                                                       'broad_principal', l.broad)
                                    ORDER BY lower(l.trustee), l.sid)
            ) AS detail
        FROM labelled l
        GROUP BY l.object_guid, l.zone_name, l.dn_current
    """,
}
