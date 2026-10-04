"""
Plugin 2041: RODC Never-Reveal List Missing Default Protections

For every read-only domain controller (ad_computer.is_read_only_dc),
checks which of the default msDS-NeverRevealGroup ("Denied") entries
are absent from its 'never_reveal' edges in rodc_prp_edge:
  - Denied RODC Password Replication Group (domain RID 572)
  - Administrators (S-1-5-32-544)
  - Server Operators (S-1-5-32-549)
  - Backup Operators (S-1-5-32-551)
  - Account Operators (S-1-5-32-548)
Groups are matched by SID, never by name.

Why it matters: the never-reveal list is what keeps privileged
credentials off an RODC regardless of what the allowed list says --
deny wins. Windows puts these five entries on every RODC at promotion;
"Denied RODC Password Replication Group" in turn holds Domain Admins,
Enterprise Admins, Schema Admins, Group Policy Creator Owners, Cert
Publishers, krbtgt and the domain controllers. Removing one of them
means the matching administrators' hashes can be cached on, and stolen
from, the RODC once they are in an allowed group (often Domain Users).
PingCastle rule P-RODCNeverReveal covers the same condition.

Data caveat: an RODC with no never_reveal edges at all may be one whose
msDS-NeverRevealGroup could not be read or resolved by the collector,
rather than one with an empty list; detail.never_reveal_entry_count and
detail.note say so. A default group that was not collected into
directory_object (detail.missing[].collected = false) could not have
been resolved either.

One row per RODC listing the missing entries. high.
"""

PLUGIN = {
    "plugin_id": 2041,
    "category": "Computer Accounts",
    "name": "RODC Never-Reveal List Missing Default Protections",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "PRIV-2041",
    "framework_tags": [
        "MITRE-ATTCK-T1003.003",
        "NIST-800-53-AC-6(5)", "NIST-CSF-2.0-PR.AA-05", "CIS-CSC-8-5.4", "ISO-27001-2022-A.8.2",
        "SOC2-CC6.3",
        "NIST-800-53-CM-6", "NIST-CSF-2.0-PR.PS-01", "CIS-CSC-8-4.1", "ISO-27001-2022-A.8.9",
    ],
    "references": [
        {"title": "Microsoft: ms-DS-Never-Reveal-Group attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-neverrevealgroup"},
        {"title": "PingCastle health check rules",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
    ],
    "description": (
        "Flags read-only domain controllers whose Denied password replication list "
        "(msDS-NeverRevealGroup) lacks one of the default entries -- Denied RODC "
        "Password Replication Group, Administrators, Server Operators, Backup "
        "Operators, Account Operators -- so the matching privileged accounts' "
        "credentials could be cached on the RODC."
    ),
    "remediation": (
        "Add the missing groups back to the RODC's Denied list: "
        "`Add-ADDomainControllerPasswordReplicationPolicy -Identity <RODC> "
        "-DeniedList 'Denied RODC Password Replication Group','Administrators',"
        "'Server Operators','Backup Operators','Account Operators'` (or Active "
        "Directory Users and Computers > RODC computer > Password Replication "
        "Policy). Verify 'Denied RODC Password Replication Group' still contains its "
        "defaults, then check `Get-ADDomainControllerPasswordReplicationPolicyUsage "
        "-Identity <RODC> -RevealedAccounts` and reset the password of any "
        "privileged account already cached."
    ),
    "base_severity": "high",
    "query": """
        WITH defaults AS (
            SELECT * FROM (VALUES
                ('Denied RODC Password Replication Group', 'S-1-5-21-%%-572', 1),
                ('Administrators', 'S-1-5-32-544', 2),
                ('Server Operators', 'S-1-5-32-549', 3),
                ('Backup Operators', 'S-1-5-32-551', 4),
                ('Account Operators', 'S-1-5-32-548', 5)
            ) v(label, sid_pattern, ord)
        ),
        rodc AS (
            SELECT c.object_guid, c.sam_account_name
            FROM ad_computer c
            JOIN directory_object d
              ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL AND c.is_read_only_dc
        ),
        never_reveal AS (
            SELECT e.rodc_guid, pd.object_sid
            FROM rodc_prp_edge e
            JOIN directory_object pd
              ON pd.object_guid = e.principal_guid AND pd.client_id = e.client_id AND NOT pd.is_deleted
            WHERE e.client_id = %(client_id)s AND e.valid_to IS NULL AND e.relation = 'never_reveal'
        ),
        missing AS (
            SELECT r.object_guid AS rodc_guid, r.sam_account_name, df.label, df.ord,
                   EXISTS (SELECT 1 FROM directory_object g
                            WHERE g.client_id = %(client_id)s AND NOT g.is_deleted
                              AND g.object_sid LIKE df.sid_pattern) AS collected
            FROM rodc r
            CROSS JOIN defaults df
            WHERE NOT EXISTS (SELECT 1 FROM never_reveal nr
                               WHERE nr.rodc_guid = r.object_guid AND nr.object_sid LIKE df.sid_pattern)
        )
        SELECT
            'fail' AS status,
            m.rodc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'high' AS fd_severity,
            'RODC ' || COALESCE(m.sam_account_name, m.rodc_guid::text)
                || ' never-reveal list is missing: '
                || string_agg(m.label, ', ' ORDER BY m.ord) AS summary,
            jsonb_build_object(
                'rodc', m.sam_account_name,
                'missing', jsonb_agg(jsonb_build_object('group', m.label, 'collected', m.collected)
                                     ORDER BY m.ord),
                'never_reveal_entry_count', nrc.cnt,
                'note', CASE WHEN nrc.cnt = 0
                             THEN 'No never-reveal entries were collected for this RODC: the list may be '
                                  'empty, or msDS-NeverRevealGroup could not be read/resolved.' END
            ) AS detail
        FROM missing m
        CROSS JOIN LATERAL (SELECT count(*) AS cnt FROM never_reveal nr WHERE nr.rodc_guid = m.rodc_guid) nrc
        GROUP BY m.rodc_guid, m.sam_account_name, nrc.cnt
        ORDER BY m.rodc_guid
    """,
}
