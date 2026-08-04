"""
Plugin 4013: Domain Permits Cleartext Password Changes

pwdProperties bit 0x4 (DOMAIN_PASSWORD_NO_CLEAR_CHANGE). Confirmed
directly against MS-SAMR's own protocol behavior, not inferred: when
this bit IS set, the KDC actively rejects a specific class of cleartext
password-change requests at the protocol level. Its absence -- the
condition this plugin flags -- is a genuine, protocol-verifiable
weakness, not a soft inference from a vaguely-named flag.
"""

PLUGIN = {
    "plugin_id": 4013,
    "category": "Domain",
    "name": "Domain Permits Cleartext Password Changes",
    "version": "1.1",
    "revision_date": "2026-07-15",
    "remediation": (
        "Enable \"Network security: Force logoff when logon hours "
        "expire\"-adjacent hardening is not the fix here -- this "
        "specific bit is set via the domain's password policy "
        "configuration (DOMAIN_PASSWORD_NO_CLEAR_CHANGE, pwdProperties "
        "0x4) rather than a named GPO checkbox in most tooling; setting "
        "it typically requires direct LDAP modification of the domain "
        "object's pwdProperties attribute or an equivalent scripted "
        "approach, since many GUI tools don't expose this specific bit "
        "directly. Confirm no legacy client or application in this "
        "environment depends on cleartext password-change support "
        "before enabling it, since MS-SAMR confirms enabling this "
        "causes the KDC to actively reject that specific request class."
    ),
    "control_id": "POLICY-013",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: DOMAIN_PASSWORD_INFORMATION structure (pwdProperties bit definitions)",
         "url": "https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-domain_password_information"},
    ],
    "description": (
        "pwdProperties bit 0x4 (DOMAIN_PASSWORD_NO_CLEAR_CHANGE). "
        "Confirmed directly against MS-SAMR's own protocol "
        "specification, not inferred from the flag's name alone: "
        "\"If the pwdProperties attribute value on the account domain "
        "object contains the DOMAIN_PASSWORD_NO_CLEAR_CHANGE bit, the "
        "server MUST abort the request and return an error status\" for "
        "a specific cleartext password-change operation. This means "
        "the bit's ABSENCE -- the condition this plugin flags -- is a "
        "genuine, protocol-verifiable permission for a weaker password-"
        "change path to succeed, not a soft inference from a vaguely-"
        "named legacy flag."
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
                || ' permits a cleartext password-change protocol path '
                '(pwdProperties DOMAIN_PASSWORD_NO_CLEAR_CHANGE not set)' AS summary,
            jsonb_build_object('dns_root', d.dns_root, 'pwd_no_clear_change', d.pwd_no_clear_change) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND NOT COALESCE(d.pwd_no_clear_change, FALSE)
    """,
}
