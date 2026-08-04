"""
Plugin 2013: Computer Account Has Shadow Credentials Registered

Same technique as user-account plugin 1022, applied to computer objects.
Presence is not itself evidence of compromise, but computer objects have
less legitimate reason to carry Windows Hello for Business key material
than user accounts do, making an unexplained entry here somewhat more
noteworthy than the equivalent user-account finding.
"""

PLUGIN = {
    "plugin_id": 2013,
    "category": "Computer Accounts",
    "name": "Computer Account Has Shadow Credentials Registered",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Review each entry's legitimacy. Computer objects have "
        "considerably less legitimate reason to carry Windows Hello for "
        "Business key material than user accounts do, so treat an "
        "unexplained entry here with somewhat more suspicion than the "
        "equivalent user-account finding. If an entry can't be attributed "
        "to a known, expected cause, investigate who or what held the "
        "delegated rights needed to write msDS-KeyCredentialLink on this "
        "computer object -- writing this attribute requires specific "
        "elevated rights."
    ),
    "control_id": "CRED-107",
    "framework_tags": ["MITRE-ATTCK-T1556"],
    "references": [
        {"title": "MITRE ATT&CK T1556: Modify Authentication Process",
         "url": "https://attack.mitre.org/techniques/T1556/"},
    ],
    "description": (
        "msDS-KeyCredentialLink stores Key Credential material used for "
        "passwordless authentication via PKINIT -- the same 'Shadow "
        "Credentials' technique (MITRE ATT&CK T1556) covered for user "
        "accounts by plugin 1022. Anyone with write access to this "
        "attribute can add a rogue key and authenticate as the account "
        "without ever touching its password. Computer objects have "
        "considerably less legitimate reason to carry this kind of key "
        "material than user accounts (which commonly do via WHfB device "
        "enrollment), so an entry here -- while still not automatic proof "
        "of compromise -- is somewhat more noteworthy than the equivalent "
        "user-account finding and worth a closer look. Downgraded when "
        "disabled: PKINIT authentication goes through the same AS-REQ "
        "path as ordinary password authentication, so a disabled "
        "account's AS-REQ should be rejected regardless of which "
        "credential type is presented."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'warn' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE GREATEST(0,
                (CASE WHEN c.is_domain_controller THEN 2 ELSE 1 END)
                - (CASE WHEN c.is_enabled THEN 0 ELSE 2 END)
            )
                WHEN 2 THEN 'high'
                WHEN 1 THEN 'medium'
                ELSE 'low'
            END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || c.sam_account_name
                || ' has ' || c.key_credential_count || ' Shadow Credential(s) registered '
                || '-- review for legitimacy'
                || CASE WHEN NOT c.is_enabled
                        THEN ' (severity reduced: account is disabled)'
                        ELSE '' END AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'key_credential_count', c.key_credential_count,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.key_credential_count IS NOT NULL
          AND c.key_credential_count > 0
    """,
}
