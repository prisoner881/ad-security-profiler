"""
Plugin 2045: Read-Only Domain Controller's SYSVOL Replica Is Writable

Reports read-only domain controllers (RODCs) whose DFS Replication SYSVOL
subscription is not marked read-only (msDFSR-ReadOnly not TRUE on
CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,<RODC>;
an absent value means writable).

Why it matters: RODCs are placed where physical security is weaker, on the
understanding that nothing written on them flows back. A writable SYSVOL
replica breaks that: whoever controls the RODC -- a stolen branch-office
server is enough -- can change a GPO's files or a logon script there and
DFS Replication copies the change to every writable DC. Editing the
Default Domain Controllers Policy's files that way runs code on every DC
(PingCastle P-RODCSYSVOLWrite, 5 points per RODC).

One row per RODC (object_guid = the RODC's computer object), high ('fail').
Only RODCs that have a SYSVOL subscription are judged; one without it is
reported by plugin 2046. Requires adprofiler 0.9.0 (the DCs' SYSVOL
subscriptions); with older data nothing is reported.
"""

PLUGIN = {
    "plugin_id": 2045,
    "category": "Computer Accounts",
    "name": "Read-Only Domain Controller's SYSVOL Replica Is Writable",
    "version": "1.0",
    "revision_date": "2026-10-21",
    "control_id": "COMPUTER-2045",
    "framework_tags": [
        "MITRE-ATTCK-T1207",
        "MITRE-ATTCK-T1484.001",
        "NIST-800-53-CM-6", "NIST-800-53-CM-7", "NIST-800-53-AC-3", "NIST-800-53-SI-7",
        "NIST-CSF-2.0-PR.PS-01", "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1", "ISO-27001-2022-A.8.9", "SOC2-CC7.1", "HIPAA-164.312(c)(1)",
    ],
    "references": [
        {"title": "PingCastle health check rules (P-RODCSYSVOLWrite)",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "Microsoft [MS-FRS2]: msDFSR-Subscription (msDFSR-ReadOnly, msDFSR-Enabled)",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-frs2/3588b343-4076-4776-b5c0-78e2b3d91ed3"},
        {"title": "MITRE ATT&CK T1484.001: Domain or Tenant Policy Modification: Group Policy Modification",
         "url": "https://attack.mitre.org/techniques/T1484/001/"},
        {"title": "MITRE ATT&CK T1207: Rogue Domain Controller",
         "url": "https://attack.mitre.org/techniques/T1207/"},
    ],
    "description": (
        "A read-only domain controller's SYSVOL replica is writable (msDFSR-ReadOnly not TRUE "
        "on its DFS Replication SYSVOL subscription), so a change made on the RODC -- to a "
        "GPO's files or a logon script -- replicates to every writable domain controller."
    ),
    "remediation": (
        "In ADSI Edit (default naming context), open the RODC's computer object, then "
        "CN=DFSR-LocalSettings > CN=Domain System Volume > CN=SYSVOL Subscription and set "
        "msDFSR-ReadOnly to TRUE: Set-ADObject 'CN=SYSVOL Subscription,CN=Domain System "
        "Volume,CN=DFSR-LocalSettings,<RODC DN>' -Replace @{'msDFSR-ReadOnly'=$true}. "
        "Then compare the RODC's SYSVOL with a writable DC's to confirm nothing was changed "
        "from it."
    ),
    "base_severity": "high",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'Read-only domain controller ' || COALESCE(c.dns_hostname, c.sam_account_name, o.dn_current)
                || ' has a writable SYSVOL replica (msDFSR-ReadOnly is '
                || COALESCE(c.sysvol_read_only::text, 'not set') || ')' AS summary,
            jsonb_build_object(
                'dc_name', COALESCE(c.dns_hostname, c.sam_account_name),
                'distinguished_name', o.dn_current,
                'msdfsr_read_only', c.sysvol_read_only,
                'sysvol_replication_enabled', c.sysvol_replication_enabled
            ) AS detail
        FROM ad_computer c
        JOIN directory_object o
          ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
        WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
          AND c.is_read_only_dc
          AND c.sysvol_subscription_found
          AND c.sysvol_read_only IS NOT TRUE
    """,
}
