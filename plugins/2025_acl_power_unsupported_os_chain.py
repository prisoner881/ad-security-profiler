"""
Plugin 2025: Computer Directly Holding DCSync or Dangerous ACL Rights Runs an Unsupported Operating System

A powerful-but-vulnerable asset: this computer directly holds DCSync or
dangerous ACL rights on the domain root/AdminSDHolder (already flagged
generically by plugins 5001/5002/5003), and is ALSO running an
unsupported, no-longer-patched operating system -- meaning it's not
just unexpectedly powerful, it's an easier-than-average target for
whoever wants that power. Old, unpatched, and privileged is a
particularly unfavorable combination.
"""

PLUGIN = {
    "plugin_id": 2025,
    "category": "Computer Accounts",
    "name": "Computer Directly Holding DCSync or Dangerous ACL Rights Runs an Unsupported Operating System",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Prioritize over an ordinary unsupported-OS finding -- this "
        "machine's exposure to known, unpatched vulnerabilities is "
        "compounded by the domain-level power it already holds. Replace "
        "or upgrade the OS, and separately review why this computer "
        "holds this level of ACL access at all (see plugins "
        "5001/5002/5003's remediation)."
    ),
    "control_id": "CHAIN-203",
    "framework_tags": [],
    "references": [
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping -- DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
        {"title": "BloodHound (SpecterOps): GenericAll edge",
         "url": "https://bloodhound.specterops.io/resources/edges/generic-all"},
    ],
    "description": (
        "Chains ACL data (plugins 5001/5002/5003 -- direct DCSync or "
        "dangerous rights on the domain root/AdminSDHolder) with an "
        "unsupported, end-of-support operating system (plugin 2003). "
        "Old and unpatched is already a real exposure; combined with "
        "domain-level power, it means the easier-than-average path to "
        "compromising this machine leads directly to a complete path to "
        "domain compromise, not just a foothold."
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
                || ' directly holds DCSync or dangerous ACL rights on the domain root or '
                'AdminSDHolder AND is running an unsupported operating system ('
                || c.operating_system || ')' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
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
          AND (
                c.operating_system ILIKE '%%windows 10%%' OR c.operating_system ILIKE '%%server 2012%%'
                OR c.operating_system ILIKE '%%server 2008%%' OR c.operating_system ILIKE '%%server 2003%%'
                OR c.operating_system ILIKE '%%windows 7%%' OR c.operating_system ILIKE '%%windows 8%%'
                OR c.operating_system ILIKE '%%windows xp%%' OR c.operating_system ILIKE '%%windows vista%%'
              )
    """,
}
