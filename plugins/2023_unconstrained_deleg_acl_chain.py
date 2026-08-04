"""
Plugin 2023: Computer With Unconstrained Delegation Also Directly Holds DCSync or Dangerous ACL Rights

A doubly-dangerous asset: unconstrained delegation (plugin 2001) already
means a compromised copy of this machine can extract cached TGTs of
anyone who authenticates to it, including via forced-authentication
techniques against a domain controller. If this SAME machine also
directly holds DCSync or dangerous ACL rights, an attacker who
compromises it doesn't even need to wait for or coerce a privileged
authentication event -- they already have a direct path to full domain
compromise the moment they get a foothold.
"""

PLUGIN = {
    "plugin_id": 2023,
    "category": "Computer Accounts",
    "name": "Computer With Unconstrained Delegation Also Directly Holds DCSync or Dangerous ACL Rights",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Treat as a top-priority asset. Address both independently-"
        "sufficient paths to compromise: migrate off unconstrained "
        "delegation (see plugin 2001's remediation) AND separately "
        "review why this computer account holds this level of ACL "
        "access at all (see plugins 5001/5002/5003's remediation) -- "
        "fixing only one leaves the other fully exploitable on its own."
    ),
    "control_id": "CHAIN-201",
    "framework_tags": ["MITRE-ATTCK-T1003.006"],
    "references": [
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping -- DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
    ],
    "description": (
        "Chains two independently-true findings: this computer has "
        "unconstrained Kerberos delegation enabled (plugin 2001) AND "
        "directly holds DCSync replication rights or dangerous rights "
        "(GenericAll/GenericWrite/WriteDacl/WriteOwner) on the domain "
        "root or AdminSDHolder (plugins 5001/5002/5003). Either "
        "condition alone is already severe; together, compromising this "
        "single machine gives an attacker two independently-sufficient "
        "paths to full domain compromise, with no need to wait for a "
        "privileged authentication event to abuse the delegation side."
    ),
    "base_severity": "critical",
    "query": """
        WITH acl_power AS (
            SELECT do2.object_guid,
                   bool_or((a.access_mask & 268435456) != 0) AS is_generic_all,
                   bool_or((a.access_mask & 1073741824) != 0) AS is_generic_write,
                   bool_or((a.access_mask & 262144) != 0) AS is_write_dacl,
                   bool_or((a.access_mask & 524288) != 0) AS is_write_owner,
                   bool_or(a.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') AS has_get_changes,
                   bool_or(a.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') AS has_get_changes_all
            FROM acl_edge a
            JOIN directory_object secured
                ON secured.object_guid = a.object_guid AND secured.client_id = a.client_id
            JOIN directory_object do2 ON do2.object_sid = a.trustee_sid AND do2.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND (
                    (a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0
                    OR a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                               '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
                  )
              AND (
                    secured.dn_current ILIKE 'CN=AdminSDHolder,%%'
                    OR EXISTS (SELECT 1 FROM ad_domain d WHERE d.object_guid = secured.object_guid AND d.valid_to IS NULL)
                  )
            GROUP BY do2.object_guid
        )
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Computer Account ' || c.sam_account_name
                || ' has unconstrained Kerberos delegation enabled AND directly holds '
                'DCSync or dangerous ACL rights on the domain root or AdminSDHolder' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'operating_system', c.operating_system,
                'is_generic_all', ap.is_generic_all,
                'is_generic_write', ap.is_generic_write,
                'is_write_dacl', ap.is_write_dacl,
                'is_write_owner', ap.is_write_owner,
                'has_get_changes', ap.has_get_changes,
                'has_get_changes_all', ap.has_get_changes_all
            ) AS detail
        FROM ad_computer c
        JOIN acl_power ap ON ap.object_guid = c.object_guid
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.unconstrained_delegation
          AND NOT c.is_domain_controller
    """,
}
