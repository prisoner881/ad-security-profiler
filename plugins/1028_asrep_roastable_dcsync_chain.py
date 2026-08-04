"""
Plugin 1028: AS-REP Roastable User Account Directly Holds DCSync Rights

Same chain as plugin 1026, using AS-REP roasting instead of Kerberoasting
as the initial-access primitive. Arguably more severe: AS-REP roasting
requires no valid credentials or prior authentication at all (any
network access to a DC is sufficient to request the crackable
AS-REP), whereas Kerberoasting at least requires a valid, authenticated
domain account first. Kept as a distinct finding from 1026 for that
reason -- the attack complexity is meaningfully lower here.
"""

PLUGIN = {
    "plugin_id": 1028,
    "category": "User Accounts",
    "name": "AS-REP Roastable User Account Directly Holds DCSync Rights",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Treat as an active, complete attack path requiring NO prior "
        "authentication: anyone with network access to a domain "
        "controller can request and crack this account's AS-REP "
        "offline, then use the recovered password for DCSync directly. "
        "Prioritize above plugin 1026 -- this requires even less "
        "attacker capability. Remove the DONT_REQ_PREAUTH flag "
        "immediately (see plugin 1013's remediation) and separately "
        "review why this account holds DCSync rights at all."
    ),
    "control_id": "CHAIN-103",
    "framework_tags": ["MITRE-ATTCK-T1558.004", "MITRE-ATTCK-T1003.006"],
    "references": [
        {"title": "MITRE ATT&CK T1558.004: Steal or Forge Kerberos Tickets -- AS-REP Roasting",
         "url": "https://attack.mitre.org/techniques/T1558/004/"},
        {"title": "MITRE ATT&CK T1003.006: OS Credential Dumping -- DCSync",
         "url": "https://attack.mitre.org/techniques/T1003/006/"},
    ],
    "description": (
        "Chains two independently-true findings: this account is "
        "AS-REP roastable (plugin 1013 -- Kerberos pre-authentication "
        "disabled) AND directly holds DCSync replication rights on the "
        "domain root (plugin 5001). Unlike Kerberoasting, AS-REP "
        "roasting requires no valid domain credentials at all -- any "
        "network path to a domain controller is sufficient to request "
        "the crackable response. Combined with direct DCSync rights, "
        "this is one of the lowest-effort complete paths to full domain "
        "compromise this project can detect."
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
                || ' is AS-REP roastable (no Kerberos pre-authentication required) AND '
                'directly holds DCSync replication rights on the domain root' AS summary,
            jsonb_build_object(
                'sam_account_name', u.sam_account_name,
                'has_get_changes', dh.has_get_changes,
                'has_get_changes_all', dh.has_get_changes_all
            ) AS detail
        FROM ad_user u
        JOIN dcsync_holders dh ON dh.object_guid = u.object_guid
        WHERE u.valid_to IS NULL
          AND u.client_id = %(client_id)s
          AND u.is_enabled
          AND (u.user_account_control & 4194304) != 0
    """,
}
