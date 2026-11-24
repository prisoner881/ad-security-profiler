"""
Plugin 2048: iSCSI Target Server Host -- Confirm CHAP Authentication (Disk Theft)

SpecterOps, "Mi Scusi, My SCSI: Abusing iSCSI Target Server" (2026-11-04):
the Windows iSCSI Target Server role, set up the way Microsoft's guide
describes (CHAP optional and skipped, initiators identified by IQN), lets
anyone on the network who knows -- or guesses -- an allowed initiator IQN
log in and mount the virtual disks. Initiator IQNs are predictable
(iqn.1991-05.com.microsoft:<dNSHostName>) and there is no rate limiting.
NTFS permissions do not apply to a mounted disk: the demo pulled a domain
controller's VHDX from a Hyper-V host's iSCSI storage and extracted
NTDS.dit. Unless the disks are encrypted (BitLocker), every machine whose
disks live on the target is exposed -- typically Hyper-V clusters, SQL,
Exchange DAGs and backup servers. No CVE: it is the role's design.

Finding the hosts: when the iSCSI Target service first starts on a
domain-joined server it registers servicePrincipalNames on the computer
account -- iSCSITarget/<host> and iSCSITarget/<host FQDN> in the article's
screenshot (SpecterOps found such an SPN in about half of BloodHound
Enterprise tenants). This check matches any SPN whose service class
contains "iscsi" (case-insensitive), which includes iSCSITarget. CHAP and
the target's initiator list are configured on the host, not in AD: the
finding asks for them to be confirmed.

One finding per host, status 'warn':
  * high: the host is a domain controller or Tier 0 (v_privileged_principal),
    or a Hyper-V host (it also registers "Microsoft Virtual System Migration
    Service" or "Microsoft Virtual Console Service" SPNs): its disks are
    likely to hold other servers, domain controllers included;
  * medium: any other enabled host;
  * low: the computer account is disabled.

Data: spn_edge, ad_computer, directory_object, v_privileged_principal.
Identity = the host's computer account.
"""

PLUGIN = {
    "plugin_id": 2048,
    "category": "Computer Accounts",
    "name": "iSCSI Target Server Host -- Confirm CHAP Authentication (Disk Theft)",
    "version": "1.0",
    "revision_date": "2026-11-20",
    "control_id": "COMPUTER-2048",
    "framework_tags": [
        "NIST-800-53-CM-7",
        "NIST-800-53-SC-28",
        "NIST-CSF-2.0-PR.DS-01",
        "NIST-CSF-2.0-PR.PS-01",
        "PCI-DSS-4.0-2.2.4",
        "CIS-CSC-8-4.8",
        "CIS-CSC-8-3.11",
        "ISO-27001-2022-A.8.9",
        "SOC2-CC6.1",
        "MITRE-ATTCK-T1003.003",
        "MITRE-ATTCK-T1006",
    ],
    "references": [
        {"title": "SpecterOps: Mi Scusi, My SCSI -- Abusing iSCSI Target Server (2026-11-04)",
         "url": "https://specterops.io/blog/2026/11/04/unauthenticated-iscsi-target-server/"},
        {"title": "MITRE ATT&CK T1003.003: OS Credential Dumping: NTDS",
         "url": "https://attack.mitre.org/techniques/T1003/003/"},
    ],
    "description": (
        "A computer runs the iSCSI Target Server role (it registered an iSCSI service principal "
        "name). Without CHAP authentication, anyone who guesses an allowed initiator name (they are "
        "predictable) can mount its virtual disks and read them, bypassing file permissions -- "
        "SpecterOps (November 2026) extracted a domain controller's NTDS.dit this way. High for a "
        "domain controller, Tier 0 or Hyper-V host; medium otherwise. CHAP is configured on the "
        "host, so it has to be confirmed there."
    ),
    "remediation": (
        "On each host, open Server Manager -> File and Storage Services -> iSCSI, and for every "
        "target enable CHAP (and reverse CHAP) with a long secret; identify initiators by more "
        "than their IQN where possible. Restrict TCP 3260 to the initiator hosts with the host "
        "firewall and network segmentation, or use IPsec. Encrypt the virtual disks that hold "
        "domain controllers or other sensitive servers (BitLocker inside the guest). Remove the "
        "role where it is no longer used."
    ),
    "base_severity": "high",
    "query": r"""
        WITH
        spn AS (
            SELECT s.object_guid,
                   bool_or(split_part(s.spn, '/', 1) ILIKE '%%iscsi%%') AS iscsi,
                   bool_or(split_part(s.spn, '/', 1) IN ('Microsoft Virtual System Migration Service',
                                                         'Microsoft Virtual Console Service')) AS hyperv,
                   jsonb_agg(s.spn ORDER BY s.spn) FILTER (WHERE split_part(s.spn, '/', 1) ILIKE '%%iscsi%%')
                       AS iscsi_spns
              FROM spn_edge s
             WHERE s.client_id = %(client_id)s AND s.valid_to IS NULL
             GROUP BY s.object_guid
        ),
        host AS (
            SELECT c.object_guid, COALESCE(c.dns_hostname, c.sam_account_name) AS host_name,
                   c.operating_system, c.is_enabled, c.is_domain_controller, s.hyperv, s.iscsi_spns,
                   EXISTS (SELECT 1 FROM v_privileged_principal vp
                            WHERE vp.client_id = c.client_id AND vp.object_guid = c.object_guid) AS tier0
              FROM spn s
              JOIN ad_computer c
                ON c.object_guid = s.object_guid AND c.client_id = %(client_id)s AND c.valid_to IS NULL
              JOIN directory_object o
                ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
             WHERE s.iscsi
        )
        SELECT
            'warn' AS status,
            h.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN NOT COALESCE(h.is_enabled, true) THEN 'low'
                 WHEN h.is_domain_controller OR h.tier0 OR h.hyperv THEN 'high'
                 ELSE 'medium' END AS fd_severity,
            'Computer ' || h.host_name || ' runs iSCSI Target Server'
                || CASE WHEN h.is_domain_controller THEN ' and is a domain controller'
                        WHEN h.tier0 THEN ' and is Tier 0'
                        WHEN h.hyperv THEN ' and is a Hyper-V host (its disks may hold other servers)'
                        ELSE '' END
                || ': confirm every target requires CHAP -- without it, anyone who guesses an allowed '
                || 'initiator name can mount and read its disks'
                || CASE WHEN COALESCE(h.is_enabled, true) THEN '' ELSE ' (account disabled)' END AS summary,
            jsonb_build_object(
                'host', h.host_name,
                'operating_system', h.operating_system,
                'enabled', h.is_enabled,
                'domain_controller', h.is_domain_controller,
                'tier0', h.tier0,
                'hyper_v_host', h.hyperv,
                'iscsi_spns', h.iscsi_spns,
                'note', 'CHAP and the initiator list are configured on the host and are not visible '
                        'in Active Directory.'
            ) AS detail
        FROM host h
    """,
}
