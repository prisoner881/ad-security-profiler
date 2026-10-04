"""
Plugin 2011: Computer Account Password Stored Using Reversible Encryption

Same reasoning as user-account plugin 1003, applied to computer objects.
Rare to find set on any account type; essentially unheard of on a
computer object specifically, since no normal provisioning path enables it.

[v1.3] Severity recalibrated from a flat critical to high on a DC and
medium otherwise. The reversible copy sits in supplementalCredentials,
readable only by principals with DCSync/DC-level access, who already get
the account's NT hash; for a machine account the plaintext is a random
120-character secret. Description corrected accordingly.
"""

PLUGIN = {
    "plugin_id": 2011,
    "category": "Computer Accounts",
    "name": "Computer Account Password Stored Using Reversible Encryption",
    "version": "1.3",
    "revision_date": "2026-10-04",
    "remediation": (
        "Remove the reversible-encryption UAC flag, then force the "
        "computer account's password to rotate (it will do so "
        "automatically on its next scheduled rotation, or can be forced "
        "immediately via `Reset-ComputerMachinePassword` run on the "
        "affected machine, or `Test-ComputerSecureChannel -Repair`) -- "
        "simply clearing the flag does not purge the already-stored "
        "recoverable password. Investigate how this flag came to be set, "
        "since no normal provisioning process enables it on a computer "
        "object."
    ),
    "control_id": "CRED-105",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Store passwords using reversible encryption",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption"},
    ],
    "description": (
        "Storing a password with reversible encryption is functionally "
        "equivalent to storing it in plaintext. The reversible copy is "
        "kept in the supplementalCredentials attribute, which only "
        "principals with replication (DCSync) or DC-level access can "
        "read -- the same principals who can already extract the "
        "account's NT hash -- and a machine account's password is a "
        "random 120-character secret, so the direct gain is limited. "
        "Rated high on a domain controller and medium otherwise (in line "
        "with PingCastle's treatment of reversible encryption as a "
        "hygiene rule). Rare to find on any account type "
        "(see user-account plugin 1003); essentially unheard of on a "
        "computer object specifically, since no normal domain-join or "
        "provisioning process enables this flag for a machine account. "
        "As with the other anomalous-UAC-bit findings on computer "
        "objects, worth investigating how this was set rather than "
        "assuming routine misconfiguration. "
        "NOT downgraded when disabled: the recoverable password material already sits in AD's database regardless of the account's enabled state."
    ),
    "base_severity": "medium",
    "query": """
        SELECT
            'fail' AS status,
            c.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            CASE WHEN c.is_domain_controller THEN 'high' ELSE 'medium' END AS fd_severity,
            (CASE WHEN c.is_domain_controller THEN 'Domain Controller ' ELSE '' END)
                || 'Computer Account ' || COALESCE(c.sam_account_name, c.object_guid::text)
                || ' stores its password using reversible encryption' AS summary,
            jsonb_build_object(
                'sam_account_name', c.sam_account_name,
                'dns_hostname', c.dns_hostname,
                'pwd_last_set', c.pwd_last_set,
                'is_enabled', c.is_enabled,
                'is_domain_controller', c.is_domain_controller
            ) AS detail
        FROM ad_computer c
        WHERE c.valid_to IS NULL
          AND c.client_id = %(client_id)s
          AND c.user_account_control IS NOT NULL
          AND (c.user_account_control & 128) != 0
    """,
}
