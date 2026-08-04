"""
Plugin 2029: Computer Directly Holding DCSync or Dangerous ACL Rights Has Shadow Credentials Registered

Distinct in kind from the other chains in this batch: those combine ACL
power with a structural weakness (old OS, dormancy). This one combines
ACL power with a possible ACTIVE COMPROMISE indicator. Shadow
credentials (msDS-KeyCredentialLink) are a known persistence mechanism
-- an attacker who briefly gains write access to an already-powerful
account can register their own authentication key, retaining access to
that account's power even if the password is later rotated. Finding
this specifically on an account that already holds DCSync or dangerous
ACL rights is one of the more concerning combinations this project can
surface, and warrants investigation as a potential incident, not simply
a configuration cleanup item.
"""

PLUGIN = {
    "plugin_id": 2029,
    "category": "Computer Accounts",
    "name": "Computer Directly Holding DCSync or Dangerous ACL Rights Has Shadow Credentials Registered",
    "version": "1.2",
    "revision_date": "2026-07-17",
    "remediation": (
        "Treat as a potential active compromise, not a routine finding: "
        "review the registered key credential(s) for legitimacy "
        "(`Get-ADComputer -Filter * -Properties msDS-KeyCredentialLink`, "
        "or Whisker/similar tooling to enumerate and inspect), and if "
        "not explainable, assume this account's power has already been "
        "used maliciously -- investigate accordingly rather than simply "
        "removing the shadow credential and moving on. Rotating the "
        "account's password alone will NOT remove this persistence "
        "mechanism."
    ),
    "control_id": "CHAIN-207",
    "framework_tags": ["MITRE-ATTCK-T1556"],
    "references": [
        {"title": "MITRE ATT&CK T1556: Modify Authentication Process",
         "url": "https://attack.mitre.org/techniques/T1556/"},
    ],
    "description": (
        "Distinct in kind from this batch's other chains: those combine "
        "ACL power (plugins 5001/5002/5003) with a structural weakness; "
        "this combines it with a possible active-compromise indicator "
        "(plugin 2013 -- msDS-KeyCredentialLink populated). Shadow "
        "credentials are a known persistence mechanism: an attacker who "
        "briefly gains write access to an already-powerful account can "
        "register their own authentication key, retaining that "
        "account's power even after a password rotation. Finding this "
        "on an account that already holds DCSync or dangerous ACL "
        "rights is one of the more concerning combinations this project "
        "can surface."
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
                'AdminSDHolder AND has ' || c.key_credential_count || ' Shadow Credential(s) '
                'registered' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'key_credential_count', c.key_credential_count,
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
          AND c.key_credential_count IS NOT NULL
          AND c.key_credential_count > 0
    """,
}
