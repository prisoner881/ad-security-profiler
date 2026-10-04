"""
Plugin 1027: Kerberoastable User Account Directly Holds Dangerous ACL Rights

Sibling to plugin 1026, using dangerous rights (GenericAll, GenericWrite,
WriteDacl, WriteOwner) on the domain root or AdminSDHolder instead of
the narrower DCSync extended rights. Kept as a separate finding rather
than merged into 1026: GenericAll/WriteDacl is arguably even more
dangerous than DCSync alone, since it lets the holder grant themselves
DCSync (or anything else) at will, not just replicate secrets directly --
a distinct mechanism worth its own explicit call-out.

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
    "plugin_id": 1027,
    "category": "User Accounts",
    "name": "Kerberoastable User Account Directly Holds Dangerous ACL Rights",
    "version": "1.4",
    "revision_date": "2026-10-04",
    "remediation": (
        "Treat as an active, complete attack path: anyone who can "
        "request a service ticket for this account can crack it "
        "offline and, if successful, can (with GenericAll, WriteDacl or "
        "WriteOwner) rewrite the domain root's or AdminSDHolder's ACL "
        "to grant themselves anything, including DCSync, or (with "
        "GenericWrite) change any attribute of those objects, such as "
        "the domain root's gPLink. Prioritize over an ordinary Kerberoastable or "
        "dangerous-rights finding alone. Remediate both ends: remove "
        "the SPN if not needed, enable AES-only encryption if it is, "
        "and separately review why this account holds this level of "
        "access at all (see plugins 5002/5003's remediation)."
    ),
    "control_id": "CHAIN-102",
    "framework_tags": ["MITRE-ATTCK-T1558.003"],
    "references": [
        {"title": "MITRE ATT&CK T1558.003: Steal or Forge Kerberos Tickets -- Kerberoasting",
         "url": "https://attack.mitre.org/techniques/T1558/003/"},
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
    ],
    "description": (
        "Chains two independently-true findings: this account is "
        "Kerberoastable (plugin 1009) AND directly holds GenericAll, "
        "GenericWrite, WriteDacl, or WriteOwner on the domain root or "
        "AdminSDHolder (plugins 5002/5003). An attacker who cracks the "
        "Kerberoast hash can, with GenericAll/WriteDacl/WriteOwner, "
        "rewrite either object's ACL to grant themselves DCSync or any "
        "other right at will (rated critical); GenericWrite alone "
        "writes attributes but not the ACL (rated high) -- a complete "
        "path to full domain compromise via a different mechanism than "
        "plugin 1026's DCSync-specific chain, kept as a distinct "
        "finding for that reason."
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
                || ' is Kerberoastable (has an SPN) AND directly holds dangerous rights '
                '(GenericAll/GenericWrite/WriteDacl/WriteOwner) on the domain root or '
                'AdminSDHolder' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'service_principal_names', u.service_principal_names,
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
          AND u.service_principal_names IS NOT NULL
          AND array_length(u.service_principal_names, 1) > 0
    """,
}
