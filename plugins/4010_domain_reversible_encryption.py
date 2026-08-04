"""
Plugin 4010: Domain-Wide Reversible Encryption Password Storage Enabled

Distinct from and more consequential than the per-account reversible-
encryption checks already built (plugins 1003, 2011): this is the
DOMAIN-WIDE DEFAULT. If enabled, every account's password gets stored
recoverably by default, not just individually-flagged ones -- the
difference between "some accounts have this problem" and "every account
has this problem unless something else overrides it."
"""

PLUGIN = {
    "plugin_id": 4010,
    "category": "Domain",
    "name": "Domain-Wide Reversible Encryption Password Storage Enabled",
    "version": "1.2",
    "revision_date": "2026-07-15",
    "remediation": (
        "Disable \"Store passwords using reversible encryption\" in the "
        "Default Domain Policy (Computer Configuration >> Windows "
        "Settings >> Security Settings >> Account Policies >> Password "
        "Policy). Disabled by default in Active Directory; only "
        "required for specific legacy authentication methods such as "
        "CHAP or Digest Authentication in IIS. After disabling, "
        "affected accounts still need a password reset to actually "
        "purge the already-stored recoverable value -- disabling the "
        "policy alone does not retroactively re-hash existing "
        "passwords."
    ),
    "control_id": "POLICY-010",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: Store passwords using reversible encryption",
         "url": "https://learn.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/store-passwords-using-reversible-encryption"},
    ],
    "description": (
        "pwdProperties bit 0x10 (DOMAIN_PASSWORD_STORE_CLEARTEXT) is "
        "the domain-WIDE default for reversible password encryption -- "
        "distinct from and more consequential than the per-account "
        "checks already built (plugins 1003 for users, 2011 for "
        "computers). If this domain-wide default is enabled, every "
        "account's password gets stored in a functionally-recoverable "
        "form by default, not just individually-flagged ones. Disabled "
        "by default in Active Directory; finding this enabled at the "
        "domain level, rather than on a handful of individual accounts, "
        "suggests either a very old legacy requirement still in force "
        "domain-wide, or a serious misconfiguration."
    ),
    "base_severity": "critical",
    "query": """
        SELECT
            'fail' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'critical' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' stores passwords using reversible encryption by default' AS summary,
            jsonb_build_object(
                'dns_root', d.dns_root,
                'pwd_reversible_encryption_domain_wide', d.pwd_reversible_encryption_domain_wide
            ) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND d.pwd_reversible_encryption_domain_wide
    """,
}
