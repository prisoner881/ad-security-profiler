"""
Plugin 1030: Password-Not-Required User Account Directly Holds DCSync or Dangerous ACL Rights

Third initial-access primitive chained against ACL data, after
Kerberoasting (1026/1027) and AS-REP roasting (1028/1029). PASSWD_NOTREQD
(plugin 1002) means AD will accept a blank password for this account --
if it's genuinely never been set, or was reset to blank, this is a
walk-up-and-authenticate scenario, arguably the lowest possible attacker
effort of any primitive this project detects. Combined into a single
finding (DCSync OR dangerous rights) rather than split like the other
two chains: PASSWD_NOTREQD is already a high-severity condition on its
own, and the exploitation story is identical either way (walk in with a
blank password), unlike Kerberoasting vs. AS-REP roasting which have
genuinely different mechanics worth distinguishing.

[v1.2] GenericAll/GenericWrite are now recognised in the form AD stores
them. ACE masks are stored already mapped: GenericAll as 0xF01FF and
GenericWrite as 0x20028 (WRITE_PROP with no object type, i.e. write
every property), so the raw GENERIC_ALL (0x10000000) / GENERIC_WRITE
(0x40000000) bits tested before essentially never matched --
GenericWrite-only grants were missed and GenericAll was labelled as
WriteDacl/WriteOwner (raw bits are still matched too). Inherit-only ACEs
(acl_edge.inherit_only, schema v34) are skipped: they grant nothing on
the object they are stored on, only on its descendants. Also requires
the trustee to actually hold DCSync or a dangerous right: any allow ACE
on those objects used to produce a finding.

[v1.3] "DCSync" now matches v_privileged_principal: CONTROL_ACCESS on
the domain root itself with BOTH Get-Changes and Get-Changes-All, or All
Extended Rights / GenericAll. v1.2 counted either replication right on
its own, and on AdminSDHolder too (where replication rights mean
nothing), and missed All Extended Rights. Severity is 'critical' for
DCSync, GenericAll, WriteDacl or WriteOwner and 'high' when the only
right is GenericWrite (writes attributes, not the ACL), as in 1027/1029.
The ad_domain test is client-scoped and the redundant DISTINCT is gone.
"""

PLUGIN = {
    "plugin_id": 1030,
    "category": "User Accounts",
    "name": "Password-Not-Required User Account Directly Holds DCSync or Dangerous ACL Rights",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Verify immediately whether this account currently has a blank "
        "password (attempt authentication with an empty password in a "
        "controlled, authorized test) -- PASSWD_NOTREQD only means AD "
        "will ACCEPT a blank password, not that one is currently set, "
        "but combined with this level of access the distinction matters "
        "little until confirmed. Set a strong password immediately "
        "regardless, clear the PASSWD_NOTREQD flag (see plugin 1002's "
        "remediation), and separately review why this account holds "
        "this level of access at all."
    ),
    "control_id": "CHAIN-105",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-IA-5",
        "NIST-800-53-IA-5(1)",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.AA-01",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "PCI-DSS-4.0-8.3.6",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-5.2",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "ISO-27001-2022-A.5.17",
        "SOC2-CC6.1",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "HIPAA-164.308(a)(5)(ii)(D)",
        "MITRE-ATTCK-T1003.006",
        "MITRE-ATTCK-T1078.002",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping -- DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
    ],
    "description": (
        "Chains two independently-true findings: this account does not "
        "require a password (plugin 1002 -- PASSWD_NOTREQD, meaning AD "
        "will accept an empty password) AND directly holds either "
        "DCSync replication rights or dangerous rights (GenericAll/"
        "GenericWrite/WriteDacl/WriteOwner) on the domain root or "
        "AdminSDHolder (GenericWrite alone, which cannot rewrite the "
        "ACL, is rated high instead of critical). If the password is genuinely blank, this "
        "requires no cracking, no offline attack, and no prior access "
        "of any kind -- arguably the lowest-effort complete path to "
        "domain compromise this project can detect."
    ),
    "base_severity": "critical",
    "query": """
        WITH secured_ace AS (
            SELECT a.trustee_sid, a.access_mask, a.object_type_guid,
                   EXISTS (SELECT 1 FROM ad_domain d
                            WHERE d.object_guid = a.object_guid AND d.client_id = a.client_id
                              AND d.valid_to IS NULL) AS is_domain_root
            FROM acl_edge a
            JOIN directory_object secured
                ON secured.object_guid = a.object_guid AND secured.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE   -- [v1.2] inherit-only: grants nothing on this object
              AND (
                    secured.dn_current ILIKE 'CN=AdminSDHolder,CN=System,%%'
                    OR EXISTS (SELECT 1 FROM ad_domain d
                                WHERE d.object_guid = secured.object_guid
                                  AND d.client_id = secured.client_id AND d.valid_to IS NULL)
                  )
        ),
        acl_flags AS (
            SELECT sa.trustee_sid,
                   -- [v1.3] DCSync exactly as v_privileged_principal defines
                   -- it: on the domain root only, CONTROL_ACCESS (0x100) with
                   -- BOTH Get-Changes and Get-Changes-All, or All Extended
                   -- Rights (null object type; GenericAll includes it).
                   (bool_or(sa.is_domain_root AND (sa.access_mask & 256) <> 0
                            AND sa.object_type_guid IS NULL)
                    OR (bool_or(sa.is_domain_root AND (sa.access_mask & 256) <> 0
                                AND sa.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2')
                        AND bool_or(sa.is_domain_root AND (sa.access_mask & 256) <> 0
                                    AND sa.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')))
                       AS has_dcsync,
                   -- Rights that let the holder rewrite the ACL.
                   bool_or((sa.access_mask & (268435456 | 262144 | 524288)) <> 0
                           OR (sa.access_mask & 983551) = 983551) AS has_acl_rewrite,
                   bool_or((sa.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                           OR (sa.access_mask & 983551) = 983551                    -- GenericAll, as stored
                           OR ((sa.access_mask & 32) <> 0 AND sa.object_type_guid IS NULL)  -- GenericWrite, as stored
                           ) AS has_dangerous
            FROM secured_ace sa
            GROUP BY sa.trustee_sid
        ),
        acl_holders AS (
            SELECT do2.object_guid,
                   bool_or(f.has_dcsync) AS has_dcsync,
                   bool_or(f.has_acl_rewrite) AS has_acl_rewrite,
                   bool_or(f.has_dangerous) AS has_dangerous
            FROM acl_flags f
            JOIN directory_object do2
                ON do2.object_sid = f.trustee_sid AND do2.client_id = %(client_id)s
               AND NOT do2.is_deleted
            -- [v1.2] Only trustees that hold one of the two; before, any
            -- allow ACE at all on the domain root/AdminSDHolder (e.g. a
            -- read grant) produced a finding labelled 'dangerous ACL rights'.
            WHERE f.has_dcsync OR f.has_dangerous
            GROUP BY do2.object_guid
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            -- [v1.3] GenericWrite alone (no DCSync, no ACL rewrite): 'high'.
            CASE WHEN ah.has_dcsync OR ah.has_acl_rewrite THEN 'critical' ELSE 'high' END AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' does not require a password (PASSWD_NOTREQD) AND directly holds '
                || (CASE WHEN ah.has_dcsync AND ah.has_dangerous THEN 'DCSync rights and dangerous ACL rights'
                         WHEN ah.has_dcsync THEN 'DCSync rights'
                         ELSE 'dangerous ACL rights (GenericAll/GenericWrite/WriteDacl/WriteOwner)' END)
                || ' on the domain root or AdminSDHolder' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'has_dcsync', ah.has_dcsync,
                'has_dangerous', ah.has_dangerous,
                'has_acl_rewrite', ah.has_acl_rewrite
            ) AS detail
        FROM ad_user u
        JOIN acl_holders ah ON ah.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND (u.user_account_control & 32) != 0
    """,
}
