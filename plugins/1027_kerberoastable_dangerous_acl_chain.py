"""
Plugin 1027: Kerberoastable User Account Directly Holds Dangerous ACL Rights

Sibling to plugin 1026, using dangerous rights (GenericAll, GenericWrite,
WriteDacl, WriteOwner) on the domain root or AdminSDHolder instead of
the narrower DCSync extended rights. Kept as a separate finding rather
than merged into 1026: GenericAll/WriteDacl is arguably even more
dangerous than DCSync alone, since it lets the holder grant themselves
DCSync (or anything else) at will, not just replicate secrets directly --
a distinct mechanism worth its own explicit call-out.
"""

PLUGIN = {
    "plugin_id": 1027,
    "category": "User Accounts",
    "name": "Kerberoastable User Account Directly Holds Dangerous ACL Rights",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Treat as an active, complete attack path: anyone who can "
        "request a service ticket for this account can crack it "
        "offline and, if successful, can rewrite the domain root's or "
        "AdminSDHolder's ACL to grant themselves anything, including "
        "DCSync. Prioritize over an ordinary Kerberoastable or "
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
        "Kerberoast hash can rewrite either object's ACL to grant "
        "themselves DCSync or any other right at will -- a complete "
        "path to full domain compromise via a different mechanism than "
        "plugin 1026's DCSync-specific chain, kept as a distinct "
        "finding for that reason."
    ),
    "base_severity": "critical",
    "query": """
        WITH dangerous_holders AS (
            SELECT do2.object_guid,
                   bool_or((a.access_mask & 268435456) != 0) AS is_generic_all,
                   bool_or((a.access_mask & 1073741824) != 0) AS is_generic_write,
                   bool_or((a.access_mask & 262144) != 0) AS is_write_dacl,
                   bool_or((a.access_mask & 524288) != 0) AS is_write_owner
            FROM acl_edge a
            JOIN directory_object secured
                ON secured.object_guid = a.object_guid AND secured.client_id = a.client_id
            JOIN directory_object do2 ON do2.object_sid = a.trustee_sid AND do2.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
              AND (
                    secured.dn_current ILIKE 'CN=AdminSDHolder,%%'
                    OR EXISTS (SELECT 1 FROM ad_domain d WHERE d.object_guid = secured.object_guid AND d.valid_to IS NULL)
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
            'critical' AS fd_severity,
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
