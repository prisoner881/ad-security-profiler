"""
Plugin 2037: Privileged Account Credentials Cached on an RODC

Detects read-only domain controllers whose msDS-RevealedList (stored as
rodc_prp_edge relation 'revealed') contains a Tier 0 principal -- an
account listed by v_privileged_principal (Domain Admins and other
protected-group members, holders of control over Tier 0 objects, DCSync
holders, ...) or an AdminSDHolder-protected group.

Why it matters: an RODC is designed to sit in a less trusted location
and to hold only the secrets of the accounts its password replication
policy allows. msDS-RevealedList records the accounts whose password
hashes have actually been replicated to it. If a Tier 0 account is in
that list, anyone who compromises the RODC (often a branch-office server
with weaker physical security) can extract that account's hash and own
the domain. PingCastle rule P-RODCAdminRevealed covers the same
condition. The account's password must be reset, because the cached
hash stays valid until it is.

Excluded: the RODC's own computer account and its own krbtgt_NNNNN
account (msDS-KrbTgtLink), which every RODC caches by design.

Data caveats: msDS-RevealedList can require elevated rights to read; an
RODC with no 'revealed' edges may simply be unreadable, so zero rows is
not proof that nothing privileged is cached. Edges whose principal
could not be resolved to a collected object are not stored by the
collector and cannot be evaluated.

One row per RODC listing every privileged cached account. critical.
"""

PLUGIN = {
    "plugin_id": 2037,
    "category": "Computer Accounts",
    "name": "Privileged Account Credentials Cached on an RODC",
    "version": "1.0",
    "revision_date": "2026-10-04",
    "control_id": "PRIV-2037",
    "framework_tags": [
        "MITRE-ATTCK-T1003.003",
        "NIST-800-53-IA-5(1)", "NIST-800-53-SC-28", "NIST-CSF-2.0-PR.DS-01", "PCI-DSS-4.0-8.3.2",
        "CIS-CSC-8-3.11", "ISO-27001-2022-A.5.17", "SOC2-CC6.1",
        "NIST-800-53-AC-6(5)", "NIST-CSF-2.0-PR.AA-05", "CIS-CSC-8-5.4", "ISO-27001-2022-A.8.2",
    ],
    "references": [
        {"title": "Microsoft: ms-DS-Revealed-List attribute",
         "url": "https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-revealedlist"},
        {"title": "PingCastle health check rules",
         "url": "https://www.pingcastle.com/PingCastleFiles/ad_hc_rules_list.html"},
        {"title": "MITRE ATT&CK T1003.003: OS Credential Dumping: NTDS",
         "url": "https://attack.mitre.org/techniques/T1003/003/"},
    ],
    "description": (
        "Flags read-only domain controllers whose msDS-RevealedList shows that the "
        "password hash of a Tier 0 account (Domain Admins member, DCSync holder, "
        "owner/controller of a Tier 0 object, or a protected group) has been "
        "replicated to and is cached on the RODC. Compromising the RODC then "
        "yields that account's credentials and the domain."
    ),
    "remediation": (
        "Reset the password of every listed account now (twice for accounts that "
        "use Kerberos keys derived from it), since the cached hash stays usable "
        "until then. Then stop it happening again: make sure the account (or a "
        "group it belongs to) is in the RODC's Denied list -- add it to 'Denied "
        "RODC Password Replication Group' or the RODC's msDS-NeverRevealGroup -- and "
        "remove it from msDS-RevealOnDemandGroup / 'Allowed RODC Password "
        "Replication Group'. Clear the revealed list entry with "
        "`repadmin /prp delete <RODC> Reveal <account DN>` after the reset, and "
        "never use Tier 0 accounts to log on at or through an RODC site."
    ),
    "base_severity": "critical",
    "query": """
        WITH tier0 AS (
            SELECT DISTINCT p.object_guid
            FROM v_privileged_principal p
            WHERE p.client_id = %(client_id)s
            UNION
            SELECT g.object_guid
            FROM ad_group g
            WHERE g.client_id = %(client_id)s AND g.valid_to IS NULL AND g.is_protected_group
        ),
        rodc AS (
            SELECT c.object_guid, c.sam_account_name, c.krbtgt_link
            FROM ad_computer c
            JOIN directory_object d
              ON d.object_guid = c.object_guid AND d.client_id = c.client_id AND NOT d.is_deleted
            WHERE c.client_id = %(client_id)s AND c.valid_to IS NULL
        ),
        hits AS (
            SELECT r.object_guid AS rodc_guid, r.sam_account_name AS rodc_name,
                   pd.object_guid AS principal_guid,
                   COALESCE(pd.sam_account_name, pd.object_sid, pd.object_guid::text) AS principal_name,
                   pd.object_sid, pd.object_class::text AS object_class
            FROM rodc_prp_edge e
            JOIN rodc r ON r.object_guid = e.rodc_guid
            JOIN directory_object pd
              ON pd.object_guid = e.principal_guid AND pd.client_id = e.client_id AND NOT pd.is_deleted
            JOIN tier0 t ON t.object_guid = e.principal_guid
            WHERE e.client_id = %(client_id)s
              AND e.valid_to IS NULL
              AND e.relation = 'revealed'
              AND e.principal_guid <> e.rodc_guid
              AND lower(pd.dn_current) IS DISTINCT FROM lower(r.krbtgt_link)
        )
        SELECT
            'fail' AS status,
            h.rodc_guid AS object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'RODC ' || COALESCE(h.rodc_name, h.rodc_guid::text)
                || ' has cached credentials of Tier 0 account(s): '
                || string_agg(h.principal_name, ', ' ORDER BY h.principal_name) AS summary,
            jsonb_build_object(
                'rodc', h.rodc_name,
                'cached_tier0_principals', jsonb_agg(jsonb_build_object(
                    'name', h.principal_name,
                    'object_sid', h.object_sid,
                    'object_class', h.object_class,
                    'object_guid', h.principal_guid,
                    'privilege_sources', (SELECT jsonb_agg(DISTINCT p.privilege_source)
                                            FROM v_privileged_principal p
                                           WHERE p.client_id = %(client_id)s
                                             AND p.object_guid = h.principal_guid)
                ) ORDER BY h.principal_name)
            ) AS detail
        FROM hits h
        GROUP BY h.rodc_guid, h.rodc_name
        ORDER BY h.rodc_guid
    """,
}
