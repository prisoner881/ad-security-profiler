"""
Plugin 4014: Domain Does Not Allow Administrator Account Lockout for Network Logons

pwdProperties bit 0x8 (DOMAIN_LOCKOUT_ADMINS). Confirmed directly
against Microsoft's own ntsecapi.h: when set, allows the built-in
Administrator account to be locked out specifically for network logons.
Directly relevant to plugin 1004 (built-in Administrator account is
enabled): that finding's own text notes the account "is immune to
account lockout policy regardless of domain configuration" -- true for
interactive/console logon, which is hardcoded and this setting can't
change, but network-logon lockout specifically CAN be enabled via this
bit, and by default it is not.
"""

PLUGIN = {
    "plugin_id": 4014,
    "category": "Domain",
    "name": "Domain Does Not Allow Administrator Account Lockout for Network Logons",
    "version": "1.1",
    "revision_date": "2026-07-15",
    "remediation": (
        "Enable DOMAIN_LOCKOUT_ADMINS (pwdProperties bit 0x8) to allow "
        "the built-in Administrator account to be locked out for "
        "network logon attempts specifically -- typically requires "
        "direct LDAP modification of the domain object's pwdProperties "
        "attribute, since this specific bit isn't exposed as a named "
        "checkbox in most GUI tooling. This does not affect interactive/"
        "console logon lockout immunity, which is hardcoded behavior "
        "unrelated to this setting (see plugin 1004) -- but it does "
        "close the network-logon password-guessing gap for the one "
        "account that plugin 1004 already flags as otherwise immune."
    ),
    "control_id": "POLICY-014",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: DOMAIN_PASSWORD_INFORMATION structure (pwdProperties bit definitions)",
         "url": "https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-domain_password_information"},
    ],
    "description": (
        "pwdProperties bit 0x8 (DOMAIN_LOCKOUT_ADMINS). Confirmed "
        "directly against Microsoft's own ntsecapi.h documentation: "
        "when set, \"allows the built-in administrator account to be "
        "locked out from network logons.\" Directly relevant to plugin "
        "1004 (built-in Administrator account is enabled), whose own "
        "text notes the account \"is immune to account lockout policy "
        "regardless of domain configuration\" -- true specifically for "
        "interactive/console logon, which is hardcoded and unaffected "
        "by this setting, but network-logon lockout specifically CAN "
        "be enabled via this bit, and by default it is not. Worth "
        "reading alongside plugin 1004's finding, if present, rather "
        "than in isolation -- this is the one lever available to "
        "partially mitigate that account's otherwise-unconditional "
        "lockout immunity."
    ),
    "base_severity": "low",
    "query": """
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'low' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' does not allow the built-in Administrator account to be locked '
                'out for network logons (pwdProperties DOMAIN_LOCKOUT_ADMINS not set) '
                '-- see plugin 1004 if the Administrator account is also enabled' AS summary,
            jsonb_build_object('dns_root', d.dns_root, 'pwd_allows_admin_lockout', d.pwd_allows_admin_lockout) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND NOT COALESCE(d.pwd_allows_admin_lockout, FALSE)
    """,
}
