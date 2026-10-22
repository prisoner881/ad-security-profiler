"""
Plugin 2046: Domain Controller Does Not Replicate SYSVOL

Reports domain controllers that take no part in SYSVOL replication while
the domain replicates SYSVOL with DFS Replication:
  * the DC's SYSVOL subscription has msDFSR-Enabled = FALSE -- replication
    turned off, typically left over from an authoritative SYSVOL restore or
    troubleshooting (medium);
  * the DC has no SYSVOL subscription at all (CN=SYSVOL Subscription,
    CN=Domain System Volume,CN=DFSR-LocalSettings,<DC>) -- usually an
    incomplete promotion (medium).
Such a DC serves whatever GPO files and logon scripts it last had: new or
changed policy, including security settings, never reaches the computers
that use it, and GPOs created since may be missing there altogether
(plugin 9021 sees missing folders, not the cause).

The domain counts as using DFS Replication when at least one DC has a
SYSVOL subscription; while none has (SYSVOL still on FRS, or the
subscriptions could not be read) nothing is reported. Disabled DC accounts
are skipped. One row per DC (object_guid = the DC's computer object),
'fail'. Requires adprofiler 0.9.0; with older data nothing is reported.

[v1.1] Leaves out the Microsoft Entra Kerberos server object
(CN=AzureADKerberos in the Domain Controllers OU, linked to the krbtgt-
AzureAD account), which Microsoft documents as functioning like a read-only
domain controller but which is not a server: it has no host, logons, Group
Policy or SYSVOL. Plugin 1006 reports the age of its key. Requires schema
v46.
"""

PLUGIN = {
    "plugin_id": 2046,
    "category": "Computer Accounts",
    "name": "Domain Controller Does Not Replicate SYSVOL",
    "version": "1.1",
    "revision_date": "2026-10-22",
    "control_id": "COMPUTER-2046",
    "framework_tags": [
        "NIST-800-53-CM-6", "NIST-800-53-CM-2", "NIST-800-53-SI-7",
        "NIST-CSF-2.0-PR.PS-01", "PCI-DSS-4.0-2.2.1",
        "CIS-CSC-8-4.1", "ISO-27001-2022-A.8.9", "SOC2-CC7.1", "HIPAA-164.312(c)(1)",
    ],
    "references": [
        {"title": "Microsoft: Migrate SYSVOL replication from FRS to DFS Replication",
         "url": "https://learn.microsoft.com/en-us/windows-server/storage/dfs-replication/migrate-sysvol-to-dfsr"},
        {"title": "Microsoft [MS-FRS2]: msDFSR-Subscription (msDFSR-ReadOnly, msDFSR-Enabled)",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-frs2/3588b343-4076-4776-b5c0-78e2b3d91ed3"},
        {"title": "Microsoft [MS-GPOL]: Group Policy: Core Protocol (Group Policy containers and templates)",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-gpol/62d12924-6252-4052-996f-161d2b9019f4"},
    ],
    "description": (
        "A domain controller does not replicate SYSVOL: its DFS Replication SYSVOL subscription "
        "is disabled (msDFSR-Enabled = FALSE) or missing, so it serves stale or missing GPO files "
        "and logon scripts to the computers that use it."
    ),
    "remediation": (
        "Disabled subscription: if no SYSVOL restore is in progress, set msDFSR-Enabled to TRUE on "
        "CN=SYSVOL Subscription,CN=Domain System Volume,CN=DFSR-LocalSettings,<DC DN> (or follow "
        "Microsoft's non-authoritative SYSVOL sync procedure), then run 'repadmin /syncall /AdP' and "
        "'dfsrdiag pollad' on the DC and check the DFS Replication event log (event 4614 then 4604). "
        "Missing subscription: the DC's promotion did not complete; demote and re-promote it, or "
        "rebuild the DFSR-LocalSettings objects as Microsoft documents, after confirming with "
        "'dcdiag /test:sysvolcheck'."
    ),
    "base_severity": "medium",
    "query": """
        WITH dfsr_in_use AS (
            SELECT EXISTS (SELECT 1 FROM ad_computer x
                           WHERE x.client_id = %(client_id)s AND x.valid_to IS NULL
                             AND x.is_domain_controller AND x.sysvol_subscription_found) AS yes
        ),
        dc AS (
            SELECT c.object_guid, COALESCE(c.dns_hostname, c.sam_account_name, o.dn_current) AS dc_name,
                   o.dn_current, c.is_read_only_dc, c.sysvol_subscription_found,
                   c.sysvol_replication_enabled,
                   CASE WHEN NOT c.sysvol_subscription_found THEN 'has no SYSVOL subscription'
                        WHEN c.sysvol_replication_enabled IS FALSE
                            THEN 'has SYSVOL replication disabled (msDFSR-Enabled = FALSE)' END AS problem
            FROM ad_computer c
            JOIN directory_object o
              ON o.object_guid = c.object_guid AND o.client_id = c.client_id AND NOT o.is_deleted
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
              AND c.is_domain_controller AND c.is_enabled
              AND NOT is_entra_kerberos_server(c.sam_account_name, c.krbtgt_link)
              AND c.sysvol_subscription_found IS NOT NULL
              AND (SELECT yes FROM dfsr_in_use)
        )
        SELECT
            'fail' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'medium' AS fd_severity,
            CASE WHEN d.is_read_only_dc THEN 'Read-only domain controller ' ELSE 'Domain controller ' END
                || d.dc_name || ' ' || d.problem
                || ', so it serves stale or missing GPO files and logon scripts' AS summary,
            jsonb_build_object(
                'dc_name', d.dc_name,
                'distinguished_name', d.dn_current,
                'read_only_dc', d.is_read_only_dc,
                'sysvol_subscription_found', d.sysvol_subscription_found,
                'sysvol_replication_enabled', d.sysvol_replication_enabled
            ) AS detail
        FROM dc d
        WHERE d.problem IS NOT NULL
    """,
}
