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
"""

PLUGIN = {
    "plugin_id": 1030,
    "category": "User Accounts",
    "name": "Password-Not-Required User Account Directly Holds DCSync or Dangerous ACL Rights",
    "version": "1.1",
    "revision_date": "2026-07-17",
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
    "framework_tags": [],
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
        "AdminSDHolder. If the password is genuinely blank, this "
        "requires no cracking, no offline attack, and no prior access "
        "of any kind -- arguably the lowest-effort complete path to "
        "domain compromise this project can detect."
    ),
    "base_severity": "critical",
    "query": """
        WITH acl_holders AS (
            SELECT DISTINCT do2.object_guid,
                   bool_or(a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                                   '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')) AS has_dcsync,
                   bool_or((a.access_mask & (268435456 | 1073741824 | 262144 | 524288)) != 0) AS has_dangerous
            FROM acl_edge a
            JOIN directory_object secured
                ON secured.object_guid = a.object_guid AND secured.client_id = a.client_id
            JOIN directory_object do2 ON do2.object_sid = a.trustee_sid AND do2.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
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
                || ' does not require a password (PASSWD_NOTREQD) AND directly holds '
                || (CASE WHEN ah.has_dcsync AND ah.has_dangerous THEN 'DCSync rights and dangerous ACL rights'
                         WHEN ah.has_dcsync THEN 'DCSync rights'
                         ELSE 'dangerous ACL rights (GenericAll/GenericWrite/WriteDacl/WriteOwner)' END)
                || ' on the domain root or AdminSDHolder' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'has_dcsync', ah.has_dcsync,
                'has_dangerous', ah.has_dangerous
            ) AS detail
        FROM ad_user u
        JOIN acl_holders ah ON ah.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND (u.user_account_control & 32) != 0
    """,
}
