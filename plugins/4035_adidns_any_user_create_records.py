"""
Plugin 4035: Any Authenticated User Can Create DNS Records (ADIDNS Spoofing / WPAD)

Active Directory-integrated DNS zones (dnsZone objects in the DomainDnsZones
and ForestDnsZones partitions) store each record as a dnsNode child object.
The default zone ACL grants Authenticated Users "Create all child objects",
so that clients can register their own records with secure dynamic updates.
The same right lets ANY domain user (or any computer account, including one a
user just created via MachineAccountQuota) add arbitrary dnsNode objects over
LDAP: a wildcard record ("*") that answers every name not otherwise defined,
a "wpad" record that hijacks web-proxy auto-discovery, or any not-yet-
registered host name. Kevin Robertson's ADIDNS research (Powermad,
Inveigh) showed this turns every name-resolution miss into a
man-in-the-middle and NTLM-relay opportunity, without LLMNR/NBT-NS and
across subnets (MITRE ATT&CK T1557). The default IS the risk: this plugin
reports default-configured zones on purpose.

Detection: current ad_dns_zone rows (both partitions; system zones
RootDNSServers, ..TrustAnchors and any name starting with '..' are skipped)
whose current acl_edge has an allow ACE that applies to the zone itself
(inherit_only not TRUE) granting CreateChild (0x1, all classes or the dnsNode
class e0fa1e8c-9b45-11d0-afdd-00c04fd930c9), GenericAll or GenericWrite to
Authenticated Users (S-1-5-11), Everyone (S-1-1-0), Anonymous Logon
(S-1-5-7), Domain Users (RID 513) or Domain Computers (RID 515). One row per
zone.

Severity: medium when the wildcard or the wpad name is still unclaimed
(has_wildcard_record / has_wpad_record FALSE), since an attacker can register
it today; low when both records already exist (pre-registered as a
mitigation, so only other names remain) or when presence could not be
checked (NULL).

Caveat: the DNS Server service's GlobalQueryBlockList (a registry setting
on each DNS server, not visible over LDAP) blocks resolution of "wpad" and
"isatap" by default, so a wpad record may not resolve even if created; it
does not block "*" or arbitrary names, and administrators often clear the
list. GenericWrite does not itself create records but lets the trustee
change zone settings such as dynamic-update mode.
"""

PLUGIN = {
    "plugin_id": 4035,
    "category": "Domain",
    "name": "Any Authenticated User Can Create DNS Records (ADIDNS Spoofing / WPAD)",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "DOM-4035",
    "framework_tags": [
        "NIST-800-53-AC-3", "NIST-800-53-AC-6", "NIST-800-53-CM-6",
        "NIST-800-53-CM-7", "NIST-CSF-2.0-PR.PS-01", "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1", "ISO-27001-2022-A.8.9", "SOC2-CC7.1",
        "MITRE-ATTCK-T1557",
    ],
    "references": [
        {"title": "Kevin Robertson: Powermad (ADIDNS record tooling)",
         "url": "https://github.com/Kevin-Robertson/Powermad"},
        {"title": "NetSPI: Beyond LLMNR/NBNS Spoofing - Exploiting Active Directory-Integrated DNS",
         "url": "https://blog.netspi.com/exploiting-adidns/"},
        {"title": "MITRE ATT&CK T1557: Adversary-in-the-Middle",
         "url": "https://attack.mitre.org/techniques/T1557/"},
        {"title": "PingCastle health check rules",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "An AD-integrated DNS zone lets a broad principal (Authenticated "
        "Users, Everyone, Anonymous, Domain Users or Domain Computers) "
        "create child records (or holds GenericAll/GenericWrite). That is the "
        "default zone ACL, and it lets any domain user register a wildcard "
        "'*' record, a 'wpad' record or any unregistered name, enabling "
        "man-in-the-middle and NTLM relay. Medium when the '*' or 'wpad' "
        "name is still unclaimed, low otherwise."
    ),
    "remediation": (
        "Pre-register the dangerous names as static records you control: a "
        "'wpad' record and a wildcard '*' record (e.g. a TXT record, or an A "
        "record pointing to a sinkhole) in every AD-integrated zone - "
        "Add-DnsServerResourceRecord -ZoneName <zone> -Name '*' -Txt "
        "-DescriptiveText 'blocked'. Keep 'wpad' and 'isatap' in the DNS "
        "servers' GlobalQueryBlockList (Get-DnsServerGlobalQueryBlockList). "
        "Where clients register through DHCP or only known machines need "
        "dynamic updates, remove 'Create all child objects' for "
        "Authenticated Users from the zone (dnsmgmt.msc -> zone -> "
        "Properties -> Security) and grant it to the DHCP servers / Domain "
        "Computers only as required; test before changing, because "
        "dynamic registration of new hosts depends on it. Set "
        "MachineAccountQuota to 0 so users cannot create computer accounts "
        "to work around this. Monitor dnsNode creation (event 5137)."
    ),
    "base_severity": "medium",
    "query": """
        WITH zone AS (
            SELECT z.object_guid, z.zone_name, z.partition, z.allow_update,
                   z.has_wildcard_record, z.has_wpad_record, o.dn_current
            FROM ad_dns_zone z
            JOIN directory_object o
              ON o.object_guid = z.object_guid AND o.client_id = z.client_id AND NOT o.is_deleted
            WHERE z.client_id = %(client_id)s
              AND z.valid_to IS NULL
              AND z.zone_name NOT IN ('RootDNSServers', '..TrustAnchors')
              AND z.zone_name NOT LIKE '..%%'
        ),
        grant_ace AS (
            SELECT a.object_guid, a.trustee_sid, a.access_mask, a.object_type_guid,
                   CASE
                       WHEN a.trustee_sid = 'S-1-5-11' THEN 'Authenticated Users'
                       WHEN a.trustee_sid = 'S-1-1-0' THEN 'Everyone'
                       WHEN a.trustee_sid = 'S-1-5-7' THEN 'Anonymous Logon'
                       WHEN a.trustee_sid LIKE 'S-1-5-21-%%-513' THEN 'Domain Users'
                       WHEN a.trustee_sid LIKE 'S-1-5-21-%%-515' THEN 'Domain Computers'
                   END AS trustee_label,
                   CASE
                       WHEN (a.access_mask & 268435456) <> 0 OR (a.access_mask & 983551) = 983551
                           THEN 'GenericAll'
                       WHEN (a.access_mask & 1) <> 0
                            AND (a.object_type_guid IS NULL
                                 OR a.object_type_guid = 'e0fa1e8c-9b45-11d0-afdd-00c04fd930c9')
                           THEN 'CreateChild'
                       ELSE 'GenericWrite'
                   END AS right_label
            FROM acl_edge a
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE
              AND (a.trustee_sid IN ('S-1-5-11', 'S-1-1-0', 'S-1-5-7')
                   OR a.trustee_sid LIKE 'S-1-5-21-%%-513'
                   OR a.trustee_sid LIKE 'S-1-5-21-%%-515')
              AND ((a.access_mask & 268435456) <> 0
                   OR (a.access_mask & 983551) = 983551
                   OR ((a.access_mask & 1) <> 0
                       AND (a.object_type_guid IS NULL
                            OR a.object_type_guid = 'e0fa1e8c-9b45-11d0-afdd-00c04fd930c9'))
                   OR (a.access_mask & 1073741824) <> 0
                   OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL))
        ),
        per_zone AS (
            SELECT z.object_guid, z.zone_name, z.partition, z.allow_update, z.dn_current,
                   z.has_wildcard_record, z.has_wpad_record,
                   (z.has_wildcard_record IS FALSE OR z.has_wpad_record IS FALSE) AS unclaimed,
                   string_agg(DISTINCT g.trustee_label || ' (' || g.right_label || ')', ', '
                              ORDER BY g.trustee_label || ' (' || g.right_label || ')') AS grants_label,
                   jsonb_agg(DISTINCT jsonb_build_object(
                       'trustee_sid', g.trustee_sid,
                       'trustee', g.trustee_label,
                       'right', g.right_label,
                       'access_mask', g.access_mask,
                       'object_type_guid', g.object_type_guid)) AS grants
            FROM zone z
            JOIN grant_ace g ON g.object_guid = z.object_guid
            GROUP BY z.object_guid, z.zone_name, z.partition, z.allow_update, z.dn_current,
                     z.has_wildcard_record, z.has_wpad_record
        )
        SELECT
            CASE WHEN p.unclaimed THEN 'fail' ELSE 'warn' END AS status,
            p.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN p.unclaimed THEN 'medium' ELSE 'low' END AS fd_severity,
            'AD-integrated DNS zone "' || p.zone_name || '"'
                || COALESCE(' (' || p.partition || ')', '')
                || ' grants broad principals the right to add records or change the zone: '
                || p.grants_label
                || CASE
                       WHEN p.unclaimed THEN
                           '; unclaimed names any user can register: '
                           || array_to_string(ARRAY_REMOVE(ARRAY[
                                  CASE WHEN p.has_wildcard_record IS FALSE THEN 'wildcard (*)' END,
                                  CASE WHEN p.has_wpad_record IS FALSE THEN 'wpad' END
                              ], NULL), ', ')
                       WHEN p.has_wildcard_record IS TRUE AND p.has_wpad_record IS TRUE THEN
                           ' (wildcard and wpad names already registered)'
                       ELSE ' (wildcard/wpad record presence not determined)'
                   END AS summary,
            jsonb_build_object(
                'zone_name', p.zone_name,
                'partition', p.partition,
                'zone_dn', p.dn_current,
                'allow_update', p.allow_update,
                'has_wildcard_record', p.has_wildcard_record,
                'has_wpad_record', p.has_wpad_record,
                'grants', p.grants,
                'note', 'GlobalQueryBlockList on the DNS servers (not visible over LDAP) '
                        'blocks wpad/isatap resolution by default, not * or other names'
            ) AS detail
        FROM per_zone p
    """,
}
