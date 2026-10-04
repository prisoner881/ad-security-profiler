"""
Plugin 1029: AS-REP Roastable User Account Directly Holds Dangerous ACL Rights

Same chain as plugin 1027, using AS-REP roasting as the initial-access
primitive instead of Kerberoasting. See plugin 1028 for why AS-REP
roasting is kept as a distinct, generally more severe finding than the
Kerberoasting-based chains (1026/1027): it requires no valid domain
credentials at all.

[v1.3] GenericAll/GenericWrite are now recognised in the form AD stores
them. ACE masks are stored already mapped: GenericAll as 0xF01FF and
GenericWrite as 0x20028 (WRITE_PROP with no object type, i.e. write
every property), so the raw GENERIC_ALL (0x10000000) / GENERIC_WRITE
(0x40000000) bits tested before essentially never matched --
GenericWrite-only grants were missed and GenericAll was labelled as
WriteDacl/WriteOwner (raw bits are still matched too). Inherit-only ACEs
(acl_edge.inherit_only, schema v34) are skipped: they grant nothing on
the object they are stored on, only on its descendants.

[v1.4] Severity follows the rights actually held: 'critical' for
GenericAll, WriteDacl or WriteOwner (each lets the holder rewrite the
object's ACL and so grant itself DCSync); 'high' when the only right is
GenericWrite (write every property), which does not include the security
descriptor -- still dangerous on the domain root (gPLink,
ms-DS-MachineAccountQuota), but not an ACL rewrite. The ad_domain test is
now client-scoped.
"""

PLUGIN = {
    "plugin_id": 1029,
    "category": "User Accounts",
    "name": "AS-REP Roastable User Account Directly Holds Dangerous ACL Rights",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Treat as an active, complete attack path requiring NO prior "
        "authentication. Remove the DONT_REQ_PREAUTH flag immediately "
        "(see plugin 1013's remediation) and separately review why this "
        "account holds this level of access at all (see plugins "
        "5002/5003's remediation)."
    ),
    "control_id": "CHAIN-104",
    "framework_tags": [
        "NIST-800-53-AC-3",
        "NIST-800-53-AC-6",
        "NIST-800-53-AC-6(1)",
        "NIST-800-53-IA-5(1)",
        "NIST-800-53-SC-28",
        "NIST-800-53-IA-2(8)",
        "NIST-CSF-2.0-PR.AA-05",
        "NIST-CSF-2.0-PR.DS-01",
        "NIST-CSF-2.0-PR.AA-03",
        "PCI-DSS-4.0-7.2.1",
        "PCI-DSS-4.0-7.2.2",
        "PCI-DSS-4.0-8.3.2",
        "PCI-DSS-4.0-8.6.2",
        "CIS-CSC-8-6.8",
        "CIS-CSC-8-3.3",
        "CIS-CSC-8-3.11",
        "ISO-27001-2022-A.5.15",
        "ISO-27001-2022-A.8.3",
        "ISO-27001-2022-A.5.17",
        "ISO-27001-2022-A.8.5",
        "SOC2-CC6.1",
        "SOC2-CC6.3",
        "HIPAA-164.312(a)(1)",
        "HIPAA-164.312(a)(2)(iv)",
        "MITRE-ATTCK-T1558.004",
    ],
    "references": [
        {"title": "MITRE ATT&CK T1558.004: Steal or Forge Kerberos Tickets -- AS-REP Roasting",
         "url": "https://attack.mitre.org/techniques/T1558/004/"},
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
    ],
    "description": (
        "Chains two independently-true findings: this account is "
        "AS-REP roastable (plugin 1013) AND directly holds GenericAll, "
        "GenericWrite, WriteDacl, or WriteOwner on the domain root or "
        "AdminSDHolder (plugins 5002/5003). GenericAll/WriteDacl/"
        "WriteOwner let the holder rewrite the object's ACL (critical); "
        "GenericWrite alone writes attributes but not the ACL (high). "
        "Requires no valid domain "
        "credentials to begin exploiting -- any network path to a "
        "domain controller is sufficient."
    ),
    "base_severity": "critical",
    "query": """
        WITH dangerous_holders AS (
            SELECT do2.object_guid,
                   bool_or((a.access_mask & 983551) = 983551 OR (a.access_mask & 268435456) <> 0) AS is_generic_all,
                   bool_or(((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)
                              OR (a.access_mask & 1073741824) <> 0) AS is_generic_write,
                   bool_or((a.access_mask & 262144) != 0) AS is_write_dacl,
                   bool_or((a.access_mask & 524288) != 0) AS is_write_owner
            FROM acl_edge a
            JOIN directory_object secured
                ON secured.object_guid = a.object_guid AND secured.client_id = a.client_id
            JOIN directory_object do2 ON do2.object_sid = a.trustee_sid AND do2.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.inherit_only IS NOT TRUE   -- [v1.3] inherit-only: grants nothing on this object
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR (a.access_mask & 983551) = 983551                    -- GenericAll, as stored
                    OR ((a.access_mask & 32) <> 0 AND a.object_type_guid IS NULL)  -- GenericWrite, as stored
                  )
              AND (
                    secured.dn_current ILIKE 'CN=AdminSDHolder,%%'
                    OR EXISTS (SELECT 1 FROM ad_domain d WHERE d.object_guid = secured.object_guid AND d.client_id = secured.client_id AND d.valid_to IS NULL)
                  )
            GROUP BY do2.object_guid
        )
        SELECT
            'fail' AS status,
            u.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            -- [v1.4] GenericWrite alone cannot rewrite the ACL: 'high'.
            CASE WHEN dh.is_generic_all OR dh.is_write_dacl OR dh.is_write_owner
                 THEN 'critical' ELSE 'high' END AS fd_severity,
            'User Account ' || COALESCE(u.user_principal_name, u.sam_account_name)
                || ' is AS-REP roastable (no Kerberos pre-authentication required) AND '
                'directly holds dangerous rights (GenericAll/GenericWrite/WriteDacl/'
                'WriteOwner) on the domain root or AdminSDHolder' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'is_generic_all', dh.is_generic_all,
                'is_generic_write', dh.is_generic_write,
                'is_write_dacl', dh.is_write_dacl,
                'is_write_owner', dh.is_write_owner
            ) AS detail
        FROM ad_user u
        JOIN dangerous_holders dh ON dh.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND (u.user_account_control & 4194304) != 0
    """,
}
