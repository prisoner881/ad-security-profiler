"""
Plugin 4013: Domain Password Policy Flag DOMAIN_PASSWORD_NO_CLEAR_CHANGE Not Set

pwdProperties bit 0x4 (DOMAIN_PASSWORD_NO_CLEAR_CHANGE). Per the
DOMAIN_PASSWORD_INFORMATION documentation it "forces the client to use
a protocol that does not allow the domain controller to get the
plaintext password". It is evaluated by the SAM RPC server (MS-SAMR)
when a password change arrives over SAMR, and restricts which legacy
SAMR change methods are accepted.

[v1.2] Corrected and demoted to informational. Earlier versions said the
KDC enforces this bit and called its absence a "cleartext password
change" path. Neither is right: the KDC (Kerberos kpasswd) does not
consult it, and SAMR change payloads are never sent unencrypted on the
wire. The bit is clear by default in essentially every domain, and no
mainstream benchmark (DISA STIG, CIS, PingCastle, Purple Knight)
requires it, so reporting it as a weakness was noise. It is kept as an
info-level observation; the summary wording changed accordingly and the
garbled remediation text was rewritten.
"""

PLUGIN = {
    "plugin_id": 4013,
    "category": "Domain",
    "name": "Domain Password Policy Flag DOMAIN_PASSWORD_NO_CLEAR_CHANGE Not Set",
    "version": "1.2",
    "revision_date": "2026-10-04",
    "remediation": (
        "No action is normally required: this bit is clear by default "
        "and no mainstream hardening benchmark requires it. If you want "
        "to set it, it is not exposed as a Group Policy setting; set bit "
        "0x4 in the domain object's pwdProperties directly (for example "
        "`$d = Get-ADObject (Get-ADDomain).DistinguishedName -Properties "
        "pwdProperties; Set-ADObject $d -Replace @{pwdProperties = "
        "($d.pwdProperties -bor 4)}`), after testing that no legacy "
        "client or application changes passwords through the SAMR "
        "methods it blocks. Confirm the bit is still set after the next "
        "Group Policy refresh on the PDC emulator."
    ),
    "control_id": "POLICY-013",
    "framework_tags": [],
    "references": [
        {"title": "Microsoft: DOMAIN_PASSWORD_INFORMATION structure (pwdProperties bit definitions)",
         "url": "https://learn.microsoft.com/en-us/windows/win32/api/ntsecapi/ns-ntsecapi-domain_password_information"},
        {"title": "Microsoft: [MS-SAMR] Security Account Manager (SAM) Remote Protocol",
         "url": "https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-samr/4df07fab-1bbc-452f-8e92-7853a3c7e380"},
    ],
    "description": (
        "Informational. pwdProperties bit 0x4 "
        "(DOMAIN_PASSWORD_NO_CLEAR_CHANGE) \"forces the client to use a "
        "protocol that does not allow the domain controller to get the "
        "plaintext password\". The SAM RPC server (MS-SAMR) checks it "
        "when a password change arrives over SAMR and rejects the "
        "change methods it rules out; the KDC does not use it, and it "
        "has nothing to do with passwords sent unencrypted on the wire. "
        "It is clear by default and no mainstream benchmark (DISA STIG, "
        "CIS, PingCastle, Purple Knight) requires it, so this is "
        "reported for information only."
    ),
    "base_severity": "info",
    "query": """
        SELECT
            'warn' AS status,
            d.object_guid,
            NULL AS stig_severity,
            NULL AS stig_reference,
            NULL AS tool_severity,
            NULL AS tool_reference,
            'info' AS fd_severity,
            'Domain ' || COALESCE(d.dns_root, '(this domain)')
                || ' does not set pwdProperties DOMAIN_PASSWORD_NO_CLEAR_CHANGE (0x4); '
                'informational, clear by default and not required by common benchmarks' AS summary,
            jsonb_build_object('dns_root', d.dns_root, 'pwd_no_clear_change', d.pwd_no_clear_change) AS detail
        FROM ad_domain d
        WHERE d.valid_to IS NULL
          AND d.client_id = %(client_id)s
          AND NOT COALESCE(d.pwd_no_clear_change, FALSE)
    """,
}
