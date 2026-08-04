"""
Plugin 1026: Kerberoastable User Account Directly Holds DCSync Rights

The canonical BloodHound-style attack-path insight, made possible for
the first time by this project's ACL collection work: a Kerberoastable
account (crackable offline, no privileged access needed to attempt) that
is ALSO, independently, a direct DCSync-rights holder is a complete,
low-effort path to full domain compromise -- crack the Kerberoast hash
(plugin 1009 already flags the account as roastable), authenticate as
that account, and DCSync every credential in the domain (plugin 5001
already flags the account as an unexpected DCSync holder). This plugin
exists specifically to call out the CHAIN, not just the two
individually-true facts -- a report reader scanning 1009 and 5001
separately could easily miss that they're the same account.
"""

PLUGIN = {
    "plugin_id": 1026,
    "category": "User Accounts",
    "name": "Kerberoastable User Account Directly Holds DCSync Rights",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Treat as an active, complete attack path, not a theoretical "
        "risk: anyone who can request a service ticket for this "
        "account (any authenticated domain user, by default) can crack "
        "it offline and, if successful, has DCSync rights with no "
        "further steps. Prioritize over an ordinary Kerberoastable or "
        "DCSync finding alone. Remediate both ends: remove the SPN if "
        "it isn't genuinely needed, enable AES-only Kerberos encryption "
        "(see plugin 1024) if it is, use a long/randomly-generated "
        "password if this is a service account, and separately review "
        "why this account holds DCSync rights at all (see plugin "
        "5001's remediation)."
    ),
    "control_id": "CHAIN-101",
    "framework_tags": ["MITRE-ATTCK-T1558.003", "MITRE-ATTCK-T1003.006"],
    "references": [
        {"title": "MITRE ATT&CK T1558.003: Steal or Forge Kerberos Tickets -- Kerberoasting",
         "url": "https://attack.mitre.org/techniques/T1558/003/"},
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping -- DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
    ],
    "description": (
        "Chains two independently-true findings into a single complete "
        "attack path: this account is Kerberoastable (plugin 1009 --any "
        "authenticated user can request a crackable service ticket for "
        "it) AND directly holds DCSync replication rights on the domain "
        "root (plugin 5001 -- not via group membership, but as an "
        "explicit ACE naming this specific account). An attacker who "
        "cracks the Kerberoast hash gets DCSync with no further "
        "privilege escalation required. This is the kind of "
        "multi-primitive path BloodHound-style analysis is specifically "
        "built to surface -- scanning 1009 and 5001 as separate lists "
        "makes it easy to miss that they describe the same account."
    ),
    "base_severity": "critical",
    "query": """
        WITH dcsync_holders AS (
            SELECT do2.object_guid,
                   bool_or(a.object_type_guid = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2') AS has_get_changes,
                   bool_or(a.object_type_guid = '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2') AS has_get_changes_all
            FROM acl_edge a
            JOIN ad_domain d ON d.object_guid = a.object_guid AND d.valid_to IS NULL
            JOIN directory_object do2 ON do2.object_sid = a.trustee_sid AND do2.client_id = a.client_id
            WHERE a.client_id = %(client_id)s
              AND a.valid_to IS NULL
              AND a.ace_type = 'allow'
              AND a.object_type_guid IN ('1131f6aa-9c07-11d1-f79f-00c04fc2dcd2',
                                          '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2')
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
                || ' is Kerberoastable (has an SPN) AND directly holds DCSync replication '
                'rights on the domain root' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'service_principal_names', u.service_principal_names,
                'has_get_changes', dh.has_get_changes,
                'has_get_changes_all', dh.has_get_changes_all
            ) AS detail
        FROM ad_user u
        JOIN dcsync_holders dh ON dh.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND u.service_principal_names IS NOT NULL
          AND array_length(u.service_principal_names, 1) > 0
    """,
}
